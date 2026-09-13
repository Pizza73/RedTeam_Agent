"""Ubuntu 24.04/x86_64 one-shot process transport for local Tuoni.

Each provider request executes in a fresh isolated Python process.  The child
owns credential-file access, Basic login, the short-lived JWT, TLS certificate
pin verification, and the HTTPS socket.  The parent sends only a closed
``TuoniWireRequest`` over stdin and receives one bounded response over stdout.
There is no shell, retry, proxy, redirect, hostname resolution, environment
credential, caller-selected endpoint, or JWT return path.
"""

from __future__ import annotations

import base64
import binascii
import platform
import subprocess
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.adapters.tuoni_contract import TuoniOperation, TuoniWireRequest
from redteam_agent.adapters.tuoni_transport import (
    TuoniTransportAttestation,
    TuoniTransportResponse,
)
from redteam_agent.errors import C2AdapterTransportError
from redteam_agent.models.base import StrictImmutableBoundaryModel

TUONI_CREDENTIAL_FILE = (
    "/run/credentials/redteam-agent.service/tuoni-credential.json"
)
TUONI_CA_BUNDLE_FILE = "/etc/redteam-agent/tuoni-ca.pem"
TUONI_WORKER_MODULE = "redteam_agent.adapters.tuoni_worker"
TUONI_WORKER_PROTOCOL_REVISION = "tuoni-worker-ipc-v1"
TUONI_WORKER_MAX_INPUT_BYTES = 2 * 1024 * 1024
TUONI_WORKER_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class TuoniWorkerRequest(StrictImmutableBoundaryModel):
    protocol_revision: Literal["tuoni-worker-ipc-v1"] = "tuoni-worker-ipc-v1"
    transport_attestation_digest: str = Field(pattern=_SHA256_PATTERN)
    operation: TuoniOperation
    request: TuoniWireRequest
    tls_certificate_sha256: str = Field(pattern=_SHA256_PATTERN)
    credential_secret_version_id: str = Field(
        min_length=1,
        max_length=512,
        pattern=r"^[\x21-\x7e]+$",
    )
    timeout_seconds: int = Field(ge=1, le=300)
    max_response_bytes: int = Field(ge=1, le=TUONI_WORKER_MAX_RESPONSE_BYTES)

    @model_validator(mode="after")
    def _operation_matches_request(self) -> TuoniWorkerRequest:
        if self.operation != self.request.operation:
            raise ValueError("worker operation does not match the wire request")
        return self


class TuoniWorkerResponse(StrictImmutableBoundaryModel):
    protocol_revision: Literal["tuoni-worker-ipc-v1"] = "tuoni-worker-ipc-v1"
    transport_attestation_digest: str = Field(pattern=_SHA256_PATTERN)
    operation: TuoniOperation
    status_code: int = Field(ge=100, le=599)
    content_type: str = Field(min_length=1, max_length=256)
    body_base64: str = Field(max_length=24 * 1024 * 1024)


class TuoniLinuxProcessTransport:
    """Fixed local process channel for Ubuntu 24.04 LTS on x86_64."""

    def __init__(self, attestation: TuoniTransportAttestation) -> None:
        _verify_ubuntu_24_04_x86_64()
        if (
            attestation.control_vm_operating_system != "ubuntu_24_04_lts"
            or attestation.control_vm_architecture != "x86_64"
            or attestation.adapter_placement != "same_control_vm_loopback"
            or attestation.channel_type != "process_isolated_https_loopback"
        ):
            raise C2AdapterTransportError(
                "Tuoni transport attestation is not valid for this Linux channel"
            )
        self._attestation = attestation

    @property
    def attestation(self) -> TuoniTransportAttestation:
        return self._attestation

    def request(
        self,
        request: TuoniWireRequest,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> TuoniTransportResponse:
        if timeout_seconds < 1 or timeout_seconds > 300:
            raise C2AdapterTransportError("Tuoni worker timeout is outside policy")
        if max_response_bytes < 1 or max_response_bytes > TUONI_WORKER_MAX_RESPONSE_BYTES:
            raise C2AdapterTransportError("Tuoni worker response limit is outside policy")
        worker_request = TuoniWorkerRequest(
            transport_attestation_digest=self._attestation.attestation_digest,
            operation=request.operation,
            request=request,
            tls_certificate_sha256=self._attestation.tls_certificate_sha256,
            credential_secret_version_id=(
                self._attestation.credential_secret_version_id
            ),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        encoded = worker_request.model_dump_json().encode("utf-8")
        if len(encoded) > TUONI_WORKER_MAX_INPUT_BYTES:
            raise C2AdapterTransportError("Tuoni worker request exceeded the IPC limit")
        executable = Path(sys.executable)
        if not executable.is_absolute():
            raise C2AdapterTransportError("Tuoni worker Python executable is not absolute")
        try:
            completed = subprocess.run(  # noqa: S603 - fixed interpreter/module, no shell
                [str(executable), "-I", "-m", TUONI_WORKER_MODULE],
                input=encoded,
                stdout=subprocess.PIPE,
                # The worker intentionally emits no diagnostics. Discard the
                # channel so provider or secret content can never be retained
                # in a CompletedProcess or copied into a parent exception.
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout_seconds + 5,
                cwd="/",
                env={"PYTHONUTF8": "1"},
                close_fds=True,
                start_new_session=True,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise C2AdapterTransportError("Tuoni worker process failed") from exc
        if completed.returncode != 0:
            raise C2AdapterTransportError("Tuoni worker rejected the provider request")
        if len(completed.stdout) > 24 * 1024 * 1024:
            raise C2AdapterTransportError("Tuoni worker IPC response exceeded the limit")
        try:
            response = TuoniWorkerResponse.from_untrusted_json(completed.stdout)
            body = base64.b64decode(response.body_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise C2AdapterTransportError("Tuoni worker returned an invalid response") from exc
        except Exception as exc:
            raise C2AdapterTransportError("Tuoni worker response validation failed") from exc
        if (
            response.transport_attestation_digest
            != self._attestation.attestation_digest
            or response.operation != request.operation
            or len(body) > max_response_bytes
        ):
            raise C2AdapterTransportError("Tuoni worker response binding mismatch")
        return TuoniTransportResponse(
            status_code=response.status_code,
            content_type=response.content_type,
            body=body,
        )


def _verify_ubuntu_24_04_x86_64() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise C2AdapterTransportError("Tuoni worker requires Linux x86_64")
    try:
        entries = _parse_os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
    except OSError as exc:
        raise C2AdapterTransportError("Control VM OS identity is unavailable") from exc
    if entries.get("ID") != "ubuntu" or entries.get("VERSION_ID") != "24.04":
        raise C2AdapterTransportError("Tuoni worker requires Ubuntu 24.04 LTS")


def _parse_os_release(raw: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in raw.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not key.isascii() or not key.replace("_", "").isalnum():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        entries[key] = value
    return entries


__all__ = [
    "TUONI_CA_BUNDLE_FILE",
    "TUONI_CREDENTIAL_FILE",
    "TUONI_WORKER_MAX_INPUT_BYTES",
    "TUONI_WORKER_MAX_RESPONSE_BYTES",
    "TUONI_WORKER_MODULE",
    "TUONI_WORKER_PROTOCOL_REVISION",
    "TuoniLinuxProcessTransport",
    "TuoniWorkerRequest",
    "TuoniWorkerResponse",
]
