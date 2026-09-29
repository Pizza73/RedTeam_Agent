"""One-shot Tuoni HTTPS worker for the Ubuntu local-process transport.

This module is launched only through ``python -I -m`` by the fixed parent
transport.  It reads a root/service-owned credential file, logs in over a
certificate-pinned loopback TLS connection, performs exactly one allowlisted
wire request without retries, returns a bounded response, and exits.  JWT and
credential values never cross stdout/stderr or survive the worker process.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import ssl
import stat
import sys
from collections.abc import Callable, Mapping
from hmac import compare_digest
from pathlib import Path

from redteam_agent.adapters.tuoni_linux_transport import (
    TUONI_CA_BUNDLE_FILE,
    TUONI_CREDENTIAL_FILE,
    TUONI_WORKER_MAX_INPUT_BYTES,
    TuoniWorkerRequest,
    TuoniWorkerResponse,
)
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.immutable import thaw
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import C2AdapterTransportError

_LOGIN_PATH = "/api/v1/auth/login"
_JWT_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,4096}$"
)
_LOGIN_RESPONSE_MAX_BYTES = 16 * 1024
_CREDENTIAL_FILE_MAX_BYTES = 16 * 1024
type _ConnectionFactory = Callable[..., http.client.HTTPSConnection]


class _Credential:
    __slots__ = ("password", "username", "version_id")

    def __init__(self, *, version_id: str, username: str, password: str) -> None:
        self.version_id = version_id
        self.username = username
        self.password = password

    def __repr__(self) -> str:
        return "<_Credential redacted>"


class _Response:
    __slots__ = ("body", "content_type", "status_code")

    def __init__(self, *, status_code: int, content_type: str, body: bytes) -> None:
        self.status_code = status_code
        self.content_type = content_type
        self.body = body


def _secure_regular_file(path: Path, *, secret: bool) -> int:
    if not path.is_absolute():
        raise C2AdapterTransportError("Tuoni worker file path is not absolute")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise C2AdapterTransportError("Tuoni worker file is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise C2AdapterTransportError("Tuoni worker file is unavailable") from exc
    allowed_write_mask = 0o077 if secret else 0o022
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & allowed_write_mask
    ):
        os.close(descriptor)
        raise C2AdapterTransportError("Tuoni worker file ownership or mode is unsafe")
    return descriptor


def _read_credentials(path: Path = Path(TUONI_CREDENTIAL_FILE)) -> _Credential:
    descriptor = _secure_regular_file(path, secret=True)
    try:
        chunks: list[bytes] = []
        remaining = _CREDENTIAL_FILE_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > _CREDENTIAL_FILE_MAX_BYTES:
        raise C2AdapterTransportError("Tuoni credential file exceeded the size limit")
    try:
        value = parse_json_no_duplicate_keys(raw)
    except Exception as exc:
        raise C2AdapterTransportError("Tuoni credential file is malformed") from exc
    if not isinstance(value, dict) or set(value) != {"version_id", "username", "password"}:
        raise C2AdapterTransportError("Tuoni credential file shape is invalid")
    version_id = value["version_id"]
    username = value["username"]
    password = value["password"]
    if (
        type(version_id) is not str
        or type(username) is not str
        or type(password) is not str
        or not version_id
        or len(version_id) > 512
        or not version_id.isascii()
        or any(ord(character) < 33 or ord(character) > 126 for character in version_id)
        or version_id != version_id.strip()
        or not username
        or len(username) > 256
        or not username.isascii()
        or any(ord(character) < 32 or ord(character) > 126 for character in username)
        or ":" in username
        or "\r" in username
        or "\n" in username
        or not password
        or len(password) > 4096
        or not password.isascii()
        or any(ord(character) < 32 or ord(character) > 126 for character in password)
        or "\r" in password
        or "\n" in password
    ):
        raise C2AdapterTransportError("Tuoni credential file values are invalid")
    return _Credential(version_id=version_id, username=username, password=password)


def _ssl_context(path: Path = Path(TUONI_CA_BUNDLE_FILE)) -> ssl.SSLContext:
    descriptor = _secure_regular_file(path, secret=False)
    try:
        # Load the exact already-validated inode. Reopening ``path`` here would
        # permit a rename race between the ownership/mode check and CA parsing.
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=f"/proc/self/fd/{descriptor}",
        )
    except (OSError, ssl.SSLError) as exc:
        raise C2AdapterTransportError("Tuoni CA bundle is invalid") from exc
    finally:
        os.close(descriptor)
    # Tuoni's lab certificate may identify localhost rather than the literal
    # loopback IP. Chain validation plus exact leaf pinning owns server identity.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _https_request(
    *,
    method: str,
    relative_path: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout_seconds: int,
    max_response_bytes: int,
    tls_certificate_sha256: str,
    context: ssl.SSLContext,
    connection_factory: _ConnectionFactory = http.client.HTTPSConnection,
) -> _Response:
    connection = connection_factory(
        "127.0.0.1", 8443, timeout=timeout_seconds, context=context
    )
    try:
        connection.connect()
        sock = connection.sock
        if sock is None:
            raise C2AdapterTransportError("Tuoni TLS socket was not established")
        certificate = sock.getpeercert(binary_form=True)
        if type(certificate) is not bytes:
            raise C2AdapterTransportError("Tuoni TLS peer certificate is unavailable")
        observed = hashlib.sha256(certificate).hexdigest()
        if not compare_digest(observed, tls_certificate_sha256):
            raise C2AdapterTransportError("Tuoni TLS certificate pin mismatch")
        connection.request(method, relative_path, body=body, headers=dict(headers))
        response = connection.getresponse()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_response_bytes:
                raise C2AdapterTransportError("Tuoni HTTPS response exceeded the size limit")
            chunks.append(chunk)
        content_type = response.getheader("Content-Type") or "application/octet-stream"
        return _Response(
            status_code=response.status,
            content_type=content_type,
            body=b"".join(chunks),
        )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise C2AdapterTransportError("Tuoni HTTPS request failed") from exc
    finally:
        connection.close()


def _jwt_from_login(response: _Response) -> str:
    if response.status_code != 200:
        raise C2AdapterTransportError("Tuoni login was rejected")
    media_type = response.content_type.partition(";")[0].strip().lower()
    try:
        if media_type == "application/json":
            parsed = parse_json_no_duplicate_keys(response.body)
            if type(parsed) is not str:
                raise C2AdapterTransportError("Tuoni login JSON is not a token")
            token = parsed
        elif media_type == "text/plain":
            token = response.body.decode("ascii")
        else:
            raise C2AdapterTransportError("Tuoni login media type is invalid")
    except UnicodeError as exc:
        raise C2AdapterTransportError("Tuoni login token encoding is invalid") from exc
    if _JWT_PATTERN.fullmatch(token) is None:
        raise C2AdapterTransportError("Tuoni login token shape is invalid")
    return token


def _execute(
    request: TuoniWorkerRequest,
    *,
    credential: _Credential,
    context: ssl.SSLContext,
    connection_factory: _ConnectionFactory = http.client.HTTPSConnection,
) -> TuoniWorkerResponse:
    if credential.version_id != request.credential_secret_version_id:
        raise C2AdapterTransportError("Tuoni credential version binding mismatch")
    basic_value = base64.b64encode(
        f"{credential.username}:{credential.password}".encode("ascii")
    ).decode("ascii")
    login = _https_request(
        method="POST",
        relative_path=_LOGIN_PATH,
        headers={"Accept": "text/plain", "Authorization": f"Basic {basic_value}"},
        body=None,
        timeout_seconds=request.timeout_seconds,
        max_response_bytes=_LOGIN_RESPONSE_MAX_BYTES,
        tls_certificate_sha256=request.tls_certificate_sha256,
        context=context,
        connection_factory=connection_factory,
    )
    jwt = _jwt_from_login(login)
    body = (
        None
        if request.request.json_body is None
        else canonical_dumps(thaw(request.request.json_body))
    )
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {jwt}",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    response = _https_request(
        method=request.request.method,
        relative_path=request.request.relative_path,
        headers=headers,
        body=body,
        timeout_seconds=request.timeout_seconds,
        max_response_bytes=request.max_response_bytes,
        tls_certificate_sha256=request.tls_certificate_sha256,
        context=context,
        connection_factory=connection_factory,
    )
    return TuoniWorkerResponse(
        transport_attestation_digest=request.transport_attestation_digest,
        operation=request.operation,
        status_code=response.status_code,
        content_type=response.content_type,
        body_base64=base64.b64encode(response.body).decode("ascii"),
    )


def _run(raw_request: bytes) -> bytes:
    request = TuoniWorkerRequest.from_untrusted_json(raw_request)
    credential = _read_credentials()
    context = _ssl_context()
    response = _execute(request, credential=credential, context=context)
    return response.model_dump_json().encode("utf-8")


def main() -> int:
    raw_request = sys.stdin.buffer.read(TUONI_WORKER_MAX_INPUT_BYTES + 1)
    if len(raw_request) > TUONI_WORKER_MAX_INPUT_BYTES:
        return 2
    try:
        response = _run(raw_request)
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # The parent receives only a fixed exit code. Never print provider,
        # credential, JWT, request body, certificate, or exception content.
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised as a process in deployment
    raise SystemExit(main())


__all__ = ["main"]
