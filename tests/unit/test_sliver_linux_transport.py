"""Offline tests for the one-shot Sliver operator worker."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

import redteam_agent.adapters.sliver_linux_transport as linux_transport
import redteam_agent.adapters.sliver_worker as worker
import support
from redteam_agent.adapters.sliver_contract import SliverRpcContractV177
from redteam_agent.adapters.sliver_linux_transport import (
    SliverLinuxProcessTransport,
    SliverWorkerRequest,
    SliverWorkerResponse,
)
from redteam_agent.adapters.sliver_transport import (
    SliverTransportAttestation,
    finalize_sliver_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterTransportError

CONFIG_RAW = json.dumps(
    {
        "operator": "joe",
        "lhost": "10.0.0.2",
        "lport": 31337,
        "token": "operator-token",
        "ca_certificate": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
        "private_key": "-----BEGIN EC PRIVATE KEY-----\nKEY\n-----END EC PRIVATE KEY-----\n",
        "certificate": "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n",
    },
    separators=(",", ":"),
).encode()


def _attestation() -> SliverTransportAttestation:
    return finalize_sliver_transport_attestation(
        SliverTransportAttestation(
            evidence_kind="test_double",
            production_eligible=False,
            adapter_profile_digest="1" * 64,
            contract_digest="2" * 64,
            operator_config_secret_version_id="secret://sliver/operator#v1",
            operator_config_sha256=hashlib.sha256(CONFIG_RAW).hexdigest(),
            server_address="10.0.0.2",
            server_port=31337,
            server_tls_name="multiplayer",
            ca_certificate_sha256=hashlib.sha256(
                b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"
            ).hexdigest(),
            operator_certificate_sha256=hashlib.sha256(
                b"-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n"
            ).hexdigest(),
            server_identity_verified=False,
            operator_identity_verified=False,
            http_beacon_verified=False,
            attested_at=support.T0,
            attestation_digest="0" * 64,
        ),
        DigestService(),
    )


def _worker_request(operation: str = "get_version") -> SliverWorkerRequest:
    attestation = _attestation()
    contract = SliverRpcContractV177()
    wire = {
        "get_version": contract.get_version(),
        "list_sessions": contract.list_sessions(),
        "list_beacons": contract.list_beacons(),
    }[operation]
    return SliverWorkerRequest(
        transport_attestation_digest=attestation.attestation_digest,
        operation=wire.operation,
        request=wire,
        operator_config_secret_version_id=attestation.operator_config_secret_version_id,
        operator_config_sha256=attestation.operator_config_sha256,
        server_address=attestation.server_address,
        server_port=attestation.server_port,
        server_tls_name=attestation.server_tls_name,
        ca_certificate_sha256=attestation.ca_certificate_sha256,
        operator_certificate_sha256=attestation.operator_certificate_sha256,
        timeout_seconds=30,
        max_response_bytes=4096,
    )


def _field(number: int, value: int | bytes | str) -> bytes:
    if isinstance(value, int):
        return worker._encode_varint(number << 3) + worker._encode_varint(value)
    encoded = value.encode() if isinstance(value, str) else value
    return worker._encode_varint((number << 3) | 2) + worker._encode_varint(len(encoded)) + encoded


def test_parent_uses_a_fixed_worker_and_never_sends_operator_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = argv
        captured.update(kwargs)
        request = SliverWorkerRequest.from_untrusted_json(kwargs["input"])
        response = SliverWorkerResponse(
            transport_attestation_digest=request.transport_attestation_digest,
            operation=request.operation,
            body_base64=base64.b64encode(b'{"sessions":[]}').decode(),
        )
        return subprocess.CompletedProcess(argv, 0, response.model_dump_json().encode(), b"")

    monkeypatch.setattr(linux_transport.subprocess, "run", fake_run)
    transport = SliverLinuxProcessTransport(_attestation())
    response = transport.request(
        SliverRpcContractV177().list_sessions(), timeout_seconds=30, max_response_bytes=4096
    )

    assert response.body == b'{"sessions":[]}'
    assert captured["argv"][1:] == ["-I", "-m", "redteam_agent.adapters.sliver_worker"]
    ipc = cast(bytes, captured["input"])
    assert b"operator-token" not in ipc
    assert b"PRIVATE KEY" not in ipc
    assert captured["stderr"] is subprocess.DEVNULL
    assert captured["cwd"] == "/"


def test_worker_reads_only_an_owner_private_exact_operator_config(tmp_path: Path) -> None:
    path = tmp_path / "joe.cfg"
    path.write_bytes(CONFIG_RAW)
    path.chmod(0o600)
    config = worker._read_operator_config(path)

    assert config.operator == "joe"
    assert config.lhost == "10.0.0.2"
    assert "operator-token" not in repr(config)

    path.chmod(0o644)
    with pytest.raises(C2AdapterTransportError):
        worker._read_operator_config(path)


def test_worker_rejects_unknown_config_fields_without_echoing_secrets(tmp_path: Path) -> None:
    path = tmp_path / "joe.cfg"
    value = json.loads(CONFIG_RAW)
    value["proxy"] = "http://untrusted"
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(C2AdapterTransportError) as caught:
        worker._read_operator_config(path)
    assert "operator-token" not in str(caught.value)


def test_worker_builds_empty_and_id_only_protobuf_requests() -> None:
    contract = SliverRpcContractV177()
    assert worker._protobuf_request(contract.get_version()) == b""
    encoded = worker._protobuf_request(contract.get_beacon("beacon-1"))
    assert encoded == _field(1, "beacon-1")


def test_worker_normalizes_version_without_returning_credentials() -> None:
    config_path_value = worker._OperatorConfig(
        operator="joe",
        lhost="10.0.0.2",
        lport=31337,
        token="operator-token",
        ca_certificate="-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
        private_key="-----BEGIN EC PRIVATE KEY-----\nKEY\n-----END EC PRIVATE KEY-----\n",
        certificate="-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n",
        raw_sha256=hashlib.sha256(CONFIG_RAW).hexdigest(),
    )
    raw_version = b"".join(
        (
            _field(1, 1), _field(2, 7), _field(3, 7), _field(4, "0aa7e5bf"),
            _field(5, 0), _field(7, "linux"), _field(8, "amd64"),
        )
    )

    response = worker._execute(
        _worker_request(),
        config=config_path_value,
        grpc_call=lambda **_kwargs: raw_version,
    )
    normalized = base64.b64decode(response.body_base64)

    assert b'"major":1' in normalized
    assert b'"commit":"0aa7e5bf"' in normalized
    assert b"operator-token" not in normalized
    assert b"PRIVATE KEY" not in normalized


def test_worker_normalizes_session_and_http_beacon_inventory() -> None:
    endpoint = b"".join(
        (
            _field(1, "endpoint-1"), _field(2, "WIN11"), _field(3, "WIN11"),
            _field(5, "LAB\\joe"), _field(8, "windows"), _field(9, "x86_64"),
            _field(10, "http(s)"), _field(14, 10), _field(15, "http://10.0.10.212"),
            _field(18, 0), _field(25, 20),
        )
    )
    sessions = worker._normalize_response(
        SliverRpcContractV177().list_sessions(), _field(1, endpoint)
    )
    beacons = worker._normalize_response(
        SliverRpcContractV177().list_beacons(), _field(2, endpoint)
    )
    assert b'"transport":"http(s)"' in sessions
    assert b'"next_checkin":20' in beacons


def test_worker_rejects_malformed_or_duplicated_protobuf_scalars() -> None:
    request = SliverRpcContractV177().get_version()
    with pytest.raises(C2AdapterTransportError):
        worker._normalize_response(request, b"\x80")
    duplicate = _field(1, 1) + _field(1, 2)
    with pytest.raises(C2AdapterTransportError):
        worker._normalize_response(request, duplicate)
