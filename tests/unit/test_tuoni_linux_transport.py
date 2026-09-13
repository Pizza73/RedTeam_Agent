"""Offline tests for the Ubuntu one-shot Tuoni process transport."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import redteam_agent.adapters.tuoni_linux_transport as linux_transport
import redteam_agent.adapters.tuoni_worker as worker
from redteam_agent.adapters.tuoni import (
    TUONI_SERVER_IMAGE_DIGEST_PIN,
    TUONI_SOURCE_COMMIT_PIN,
    TUONI_VERSION_PIN,
)
from redteam_agent.adapters.tuoni_contract import TuoniApiContractV0161
from redteam_agent.adapters.tuoni_linux_transport import (
    TuoniLinuxProcessTransport,
    TuoniWorkerRequest,
    TuoniWorkerResponse,
)
from redteam_agent.adapters.tuoni_transport import (
    TuoniTransportAttestation,
    finalize_tuoni_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterTransportError

NOW = datetime(2026, 9, 13, 5, 0, tzinfo=UTC)
TLS_CERTIFICATE = b"pinned-leaf-certificate"
TLS_DIGEST = hashlib.sha256(TLS_CERTIFICATE).hexdigest()
SECRET_VERSION = "secret://tuoni/service-account#v1"
OPENAPI_DIGEST = "3" * 64


def _attestation() -> TuoniTransportAttestation:
    ds = DigestService()
    return finalize_tuoni_transport_attestation(
        TuoniTransportAttestation(
            adapter_profile_digest="1" * 64,
            contract_digest="2" * 64,
            server_version=TUONI_VERSION_PIN,
            openapi_sha256=OPENAPI_DIGEST,
            container_image_digest=TUONI_SERVER_IMAGE_DIGEST_PIN,
            source_commit=TUONI_SOURCE_COMMIT_PIN,
            tls_certificate_sha256=TLS_DIGEST,
            credential_secret_version_id=SECRET_VERSION,
            vcenter_port_group_name="isolated-tuoni-lab",
            attested_at=NOW,
            attestation_digest="0" * 64,
        ),
        ds,
    )


def test_parent_process_transport_uses_fixed_module_and_bounded_ipc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _attestation()
    contract = TuoniApiContractV0161()
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = argv
        captured.update(kwargs)
        request = TuoniWorkerRequest.from_untrusted_json(kwargs["input"])
        response = TuoniWorkerResponse(
            transport_attestation_digest=request.transport_attestation_digest,
            operation=request.operation,
            status_code=200,
            content_type="application/json",
            body_base64=base64.b64encode(b"[]").decode(),
        )
        return subprocess.CompletedProcess(argv, 0, response.model_dump_json().encode(), b"")

    monkeypatch.setattr(linux_transport, "_verify_ubuntu_24_04_x86_64", lambda: None)
    monkeypatch.setattr(linux_transport.subprocess, "run", fake_run)
    transport = TuoniLinuxProcessTransport(attestation)

    response = transport.request(
        contract.list_active_agents(), timeout_seconds=30, max_response_bytes=4096
    )

    assert response.body == b"[]"
    assert captured["argv"][1:] == [
        "-I",
        "-m",
        "redteam_agent.adapters.tuoni_worker",
    ]
    raw_ipc = cast(bytes, captured["input"])
    assert b"127.0.0.1" not in raw_ipc
    assert b"password" not in raw_ipc.lower()
    assert captured["cwd"] == "/"
    assert captured["env"] == {"PYTHONUTF8": "1"}
    assert captured["start_new_session"] is True


def test_parent_process_timeout_is_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timed_out(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired("secret-command", 35)

    monkeypatch.setattr(linux_transport, "_verify_ubuntu_24_04_x86_64", lambda: None)
    monkeypatch.setattr(linux_transport.subprocess, "run", timed_out)
    transport = TuoniLinuxProcessTransport(_attestation())

    with pytest.raises(C2AdapterTransportError) as caught:
        transport.request(
            TuoniApiContractV0161().list_active_agents(),
            timeout_seconds=30,
            max_response_bytes=4096,
        )

    assert "secret-command" not in str(caught.value)


def test_parent_process_crash_is_content_free_and_discards_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def crashed(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 2, b"", b"provider-secret")

    monkeypatch.setattr(linux_transport, "_verify_ubuntu_24_04_x86_64", lambda: None)
    monkeypatch.setattr(linux_transport.subprocess, "run", crashed)
    transport = TuoniLinuxProcessTransport(_attestation())

    with pytest.raises(C2AdapterTransportError) as caught:
        transport.request(
            TuoniApiContractV0161().list_active_agents(),
            timeout_seconds=30,
            max_response_bytes=4096,
        )

    assert "provider-secret" not in str(caught.value)
    assert captured["stderr"] is subprocess.DEVNULL


def test_parent_rejects_worker_response_bound_to_another_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _attestation()

    def confused(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        response = TuoniWorkerResponse(
            transport_attestation_digest=attestation.attestation_digest,
            operation="get_command",
            status_code=200,
            content_type="application/json",
            body_base64="e30=",
        )
        return subprocess.CompletedProcess(argv, 0, response.model_dump_json().encode(), b"")

    monkeypatch.setattr(linux_transport, "_verify_ubuntu_24_04_x86_64", lambda: None)
    monkeypatch.setattr(linux_transport.subprocess, "run", confused)
    transport = TuoniLinuxProcessTransport(attestation)

    with pytest.raises(C2AdapterTransportError):
        transport.request(
            TuoniApiContractV0161().list_active_agents(),
            timeout_seconds=30,
            max_response_bytes=4096,
        )


class _FakeSocket:
    def getpeercert(self, *, binary_form: bool = False) -> bytes:
        assert binary_form is True
        return TLS_CERTIFICATE


class _FakeHttpResponse:
    def __init__(self, status: int, content_type: str, body: bytes) -> None:
        self.status = status
        self._content_type = content_type
        self._body = body
        self._read = False

    def read(self, _size: int) -> bytes:
        if self._read:
            return b""
        self._read = True
        return self._body

    def getheader(self, name: str) -> str | None:
        return self._content_type if name == "Content-Type" else None


class _FakeHttpsConnection:
    def __init__(
        self,
        response: _FakeHttpResponse,
        calls: list[dict[str, object]],
        host: str,
        port: int,
        **kwargs: object,
    ) -> None:
        self.sock = _FakeSocket()
        self._response = response
        self._calls = calls
        self._host = host
        self._port = port
        self._kwargs = kwargs

    def connect(self) -> None:
        pass

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None,
        headers: dict[str, str],
    ) -> None:
        self._calls.append(
            {
                "host": self._host,
                "port": self._port,
                "method": method,
                "path": path,
                "body": body,
                "headers": headers,
                "options": self._kwargs,
            }
        )

    def getresponse(self) -> _FakeHttpResponse:
        return self._response

    def close(self) -> None:
        pass


def test_worker_pins_each_tls_connection_and_keeps_jwt_inside_child() -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _FakeHttpResponse(200, "text/plain", b"header.payload.signature"),
        _FakeHttpResponse(200, "application/json", b"[]"),
    ]

    def factory(host: str, port: int, **kwargs: object) -> _FakeHttpsConnection:
        return _FakeHttpsConnection(responses.pop(0), calls, host, port, **kwargs)

    wire = TuoniApiContractV0161().list_active_agents()
    request = TuoniWorkerRequest(
        transport_attestation_digest="3" * 64,
        operation=wire.operation,
        request=wire,
        tls_certificate_sha256=TLS_DIGEST,
        credential_secret_version_id=SECRET_VERSION,
        timeout_seconds=30,
        max_response_bytes=4096,
    )
    credential = worker._Credential(
        version_id=SECRET_VERSION, username="service", password="test-password"
    )

    response = worker._execute(
        request,
        credential=credential,
        context=cast(Any, object()),
        connection_factory=cast(Any, factory),
    )

    assert base64.b64decode(response.body_base64) == b"[]"
    assert [(item["host"], item["port"]) for item in calls] == [
        ("127.0.0.1", 8443),
        ("127.0.0.1", 8443),
    ]
    assert calls[0]["path"] == "/api/v1/auth/login"
    assert cast(dict[str, str], calls[0]["headers"])["Authorization"].startswith(
        "Basic "
    )
    assert calls[1]["path"] == "/api/v1/agents/active"
    assert cast(dict[str, str], calls[1]["headers"])["Authorization"] == (
        "Bearer header.payload.signature"
    )
    assert "header.payload.signature" not in response.model_dump_json()


def test_worker_rejects_wrong_tls_pin_before_sending_http_request() -> None:
    calls: list[dict[str, object]] = []

    def factory(host: str, port: int, **kwargs: object) -> _FakeHttpsConnection:
        return _FakeHttpsConnection(
            _FakeHttpResponse(200, "text/plain", b"header.payload.signature"),
            calls,
            host,
            port,
            **kwargs,
        )

    with pytest.raises(C2AdapterTransportError):
        worker._https_request(
            method="GET",
            relative_path="/api/v1/agents/active",
            headers={},
            body=None,
            timeout_seconds=30,
            max_response_bytes=4096,
            tls_certificate_sha256="0" * 64,
            context=cast(Any, object()),
            connection_factory=cast(Any, factory),
        )

    assert calls == []


def test_worker_reads_only_owner_private_versioned_credential_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "credential.json"
    path.write_text(
        json.dumps(
            {
                "version_id": SECRET_VERSION,
                "username": "service",
                "password": "test-password",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    credential = worker._read_credentials(path)

    assert credential.version_id == SECRET_VERSION
    assert "test-password" not in repr(credential)

    path.chmod(0o644)
    with pytest.raises(C2AdapterTransportError):
        worker._read_credentials(path)


@pytest.mark.parametrize(
    "field, value",
    [
        ("version_id", "version with spaces"),
        ("version_id", "v" * 513),
        ("username", "service\taccount"),
        ("username", "service:account"),
        ("password", "password\x00suffix"),
        ("password", "pässword"),
    ],
)
def test_worker_rejects_noncanonical_credential_values(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    payload = {
        "version_id": SECRET_VERSION,
        "username": "service",
        "password": "test-password",
    }
    payload[field] = value
    path = tmp_path / "credential.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(C2AdapterTransportError):
        worker._read_credentials(path)
