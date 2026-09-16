"""Secret-owning one-shot Sliver gRPC/mTLS worker."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from collections.abc import Callable
from hmac import compare_digest
from pathlib import Path

from redteam_agent.adapters.sliver_contract import SliverWireRequest
from redteam_agent.adapters.sliver_linux_transport import (
    SLIVER_OPERATOR_CONFIG_FILE,
    SLIVER_WORKER_MAX_INPUT_BYTES,
    SliverWorkerRequest,
    SliverWorkerResponse,
)
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import C2AdapterTransportError

_OPERATOR_CONFIG_MAX_BYTES = 128 * 1024
type _GrpcCall = Callable[..., bytes]


class _OperatorConfig:
    __slots__ = (
        "ca_certificate",
        "certificate",
        "lhost",
        "lport",
        "operator",
        "private_key",
        "raw_sha256",
        "token",
    )

    def __init__(
        self,
        *,
        operator: str,
        lhost: str,
        lport: int,
        token: str,
        ca_certificate: str,
        private_key: str,
        certificate: str,
        raw_sha256: str,
    ) -> None:
        self.operator = operator
        self.lhost = lhost
        self.lport = lport
        self.token = token
        self.ca_certificate = ca_certificate
        self.private_key = private_key
        self.certificate = certificate
        self.raw_sha256 = raw_sha256

    def __repr__(self) -> str:
        return "<_OperatorConfig redacted>"


def _read_operator_config(
    path: Path = Path(SLIVER_OPERATOR_CONFIG_FILE),
) -> _OperatorConfig:
    if not path.is_absolute():
        raise C2AdapterTransportError("Sliver operator config path is not absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise C2AdapterTransportError("Sliver operator config is unavailable") from exc
    try:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise C2AdapterTransportError("Sliver operator config ownership or mode is unsafe")
        chunks: list[bytes] = []
        remaining = _OPERATOR_CONFIG_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > _OPERATOR_CONFIG_MAX_BYTES:
        raise C2AdapterTransportError("Sliver operator config exceeded the size limit")
    try:
        value = parse_json_no_duplicate_keys(raw)
    except Exception as exc:
        raise C2AdapterTransportError("Sliver operator config is malformed") from exc
    expected = {
        "operator",
        "lhost",
        "lport",
        "token",
        "ca_certificate",
        "private_key",
        "certificate",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise C2AdapterTransportError("Sliver operator config shape is invalid")
    operator = value["operator"]
    lhost = value["lhost"]
    lport = value["lport"]
    token = value["token"]
    ca_certificate = value["ca_certificate"]
    private_key = value["private_key"]
    certificate = value["certificate"]
    if (
        type(operator) is not str
        or operator != "joe"
        or type(lhost) is not str
        or not lhost
        or len(lhost) > 255
        or lhost != lhost.strip()
        or any(character in lhost for character in "/@:#")
        or type(lport) is not int
        or lport < 1
        or lport > 65535
        or type(token) is not str
        or not token
        or len(token) > 4096
        or "\r" in token
        or "\n" in token
        or type(ca_certificate) is not str
        or type(private_key) is not str
        or type(certificate) is not str
        or not ca_certificate.startswith("-----BEGIN CERTIFICATE-----")
        or not certificate.startswith("-----BEGIN CERTIFICATE-----")
        or not private_key.startswith("-----BEGIN ")
        or "PRIVATE KEY-----" not in private_key.partition("\n")[0]
    ):
        raise C2AdapterTransportError("Sliver operator config values are invalid")
    return _OperatorConfig(
        operator=operator,
        lhost=lhost,
        lport=lport,
        token=token,
        ca_certificate=ca_certificate,
        private_key=private_key,
        certificate=certificate,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _verify_config_binding(config: _OperatorConfig, request: SliverWorkerRequest) -> None:
    if (
        config.operator != request.operator_name
        or config.lhost != request.server_address
        or config.lport != request.server_port
        or not compare_digest(config.raw_sha256, request.operator_config_sha256)
        or not compare_digest(
            hashlib.sha256(config.ca_certificate.encode("utf-8")).hexdigest(),
            request.ca_certificate_sha256,
        )
        or not compare_digest(
            hashlib.sha256(config.certificate.encode("utf-8")).hexdigest(),
            request.operator_certificate_sha256,
        )
    ):
        raise C2AdapterTransportError("Sliver operator config binding mismatch")


def _protobuf_request(request: SliverWireRequest) -> bytes:
    if request.request_message == "commonpb.Empty":
        if request.fields:
            raise C2AdapterTransportError("Sliver Empty request contains fields")
        return b""
    identifier = request.fields.get("ID")
    if type(identifier) is not str or len(request.fields) != 1:
        raise C2AdapterTransportError("Sliver request fields are invalid")
    encoded = identifier.encode("utf-8")
    return _encode_varint((1 << 3) | 2) + _encode_varint(len(encoded)) + encoded


def _grpc_call(
    *,
    config: _OperatorConfig,
    request: SliverWorkerRequest,
    protobuf_request: bytes,
) -> bytes:
    try:
        import grpc  # type: ignore[import-untyped]
    except ImportError as exc:
        raise C2AdapterTransportError("Sliver gRPC runtime is unavailable") from exc
    credentials = grpc.ssl_channel_credentials(
        root_certificates=config.ca_certificate.encode("utf-8"),
        private_key=config.private_key.encode("utf-8"),
        certificate_chain=config.certificate.encode("utf-8"),
    )
    endpoint = f"{config.lhost}:{config.lport}"
    options = (
        ("grpc.ssl_target_name_override", request.server_tls_name),
        ("grpc.default_authority", request.server_tls_name),
        ("grpc.max_receive_message_length", request.max_response_bytes),
        ("grpc.enable_retries", 0),
    )
    try:
        with grpc.secure_channel(endpoint, credentials, options=options) as channel:
            grpc.channel_ready_future(channel).result(timeout=request.timeout_seconds)
            method = channel.unary_unary(
                request.request.rpc_method,
                request_serializer=lambda value: value,
                response_deserializer=lambda value: value,
            )
            response = method(
                protobuf_request,
                timeout=request.timeout_seconds,
                metadata=(("authorization", f"Bearer {config.token}"),),
                wait_for_ready=False,
            )
    except Exception as exc:
        raise C2AdapterTransportError("Sliver gRPC request failed") from exc
    if type(response) is not bytes or len(response) > request.max_response_bytes:
        raise C2AdapterTransportError("Sliver gRPC response exceeded the bound")
    return response


def _normalize_response(request: SliverWireRequest, raw: bytes) -> bytes:
    operation = request.operation
    if operation == "get_version":
        body: object = _decode_version(raw)
    elif operation == "list_sessions":
        body = {"sessions": [_decode_endpoint(item, beacon=False) for item in _messages(raw, 1)]}
    elif operation == "list_beacons":
        body = {"beacons": [_decode_endpoint(item, beacon=True) for item in _messages(raw, 2)]}
    elif operation == "get_beacon":
        body = {"beacon": _decode_endpoint(raw, beacon=True)}
    elif operation == "list_beacon_tasks":
        beacon_id = request.fields.get("ID")
        if type(beacon_id) is not str:
            raise C2AdapterTransportError("Sliver Beacon Task response binding is absent")
        body = {
            "beacon_id": _string(raw, 1, required=False) or beacon_id,
            "tasks": [_decode_task(item) for item in _messages(raw, 2)],
        }
    elif operation in {"get_beacon_task_content", "cancel_beacon_task"}:
        body = {"task": _decode_task(raw)}
    else:  # pragma: no cover - closed Literal and contract validator
        raise C2AdapterTransportError("Sliver RPC operation is not approved")
    return canonical_dumps(body)


def _decode_version(raw: bytes) -> dict[str, object]:
    return {
        "major": _integer(raw, 1),
        "minor": _integer(raw, 2),
        "patch": _integer(raw, 3),
        "commit": _string(raw, 4),
        "dirty": bool(_integer(raw, 5)),
        "os": _string(raw, 7),
        "arch": _string(raw, 8),
    }


def _decode_endpoint(raw: bytes, *, beacon: bool) -> dict[str, object]:
    result: dict[str, object] = {
        "id": _string(raw, 1),
        "name": _string(raw, 2, required=False),
        "hostname": _string(raw, 3, required=False),
        "username": _string(raw, 5, required=False),
        "os": _string(raw, 8),
        "arch": _string(raw, 9),
        "transport": _string(raw, 10),
        "active_c2": _string(raw, 15, required=False),
        "last_checkin": _integer(raw, 14),
        "is_dead": bool(_integer(raw, 18)),
    }
    if beacon:
        result["next_checkin"] = _integer(raw, 25)
    return result


def _decode_task(raw: bytes) -> dict[str, object]:
    state = _string(raw, 4)
    if state not in {"pending", "sent", "completed", "canceled"}:
        raise C2AdapterTransportError("Sliver Beacon Task state is invalid")
    return {
        "id": _string(raw, 1),
        "beacon_id": _string(raw, 2),
        "created_at": _integer(raw, 3),
        "state": state,
        "sent_at": _integer(raw, 5),
        "completed_at": _integer(raw, 6),
        "description": _string(raw, 9, required=False),
    }


def _fields(raw: bytes) -> list[tuple[int, int, int | bytes]]:
    fields: list[tuple[int, int, int | bytes]] = []
    offset = 0
    while offset < len(raw):
        key, offset = _read_varint(raw, offset)
        number = key >> 3
        wire_type = key & 7
        value: int | bytes
        if number < 1:
            raise C2AdapterTransportError("Sliver protobuf field number is invalid")
        if wire_type == 0:
            value, offset = _read_varint(raw, offset)
        elif wire_type == 1:
            if offset + 8 > len(raw):
                raise C2AdapterTransportError("Sliver protobuf fixed64 is truncated")
            value = raw[offset : offset + 8]
            offset += 8
        elif wire_type == 2:
            length, offset = _read_varint(raw, offset)
            if length > len(raw) - offset:
                raise C2AdapterTransportError("Sliver protobuf field is truncated")
            value = raw[offset : offset + length]
            offset += length
        elif wire_type == 5:
            if offset + 4 > len(raw):
                raise C2AdapterTransportError("Sliver protobuf fixed32 is truncated")
            value = raw[offset : offset + 4]
            offset += 4
        else:
            raise C2AdapterTransportError("Sliver protobuf wire type is unsupported")
        fields.append((number, wire_type, value))
        if len(fields) > 10_000:
            raise C2AdapterTransportError("Sliver protobuf field count exceeded the bound")
    return fields


def _read_varint(raw: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < len(raw) and shift < 70:
        value = raw[offset]
        offset += 1
        result |= (value & 0x7F) << shift
        if not value & 0x80:
            return result, offset
        shift += 7
    raise C2AdapterTransportError("Sliver protobuf varint is invalid")


def _encode_varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _values(raw: bytes, number: int, wire_type: int) -> list[int | bytes]:
    return [value for field, wire, value in _fields(raw) if field == number and wire == wire_type]


def _integer(raw: bytes, number: int) -> int:
    values = _values(raw, number, 0)
    if len(values) > 1:
        raise C2AdapterTransportError("Sliver protobuf scalar is duplicated")
    return int(values[0]) if values else 0


def _string(raw: bytes, number: int, *, required: bool = True) -> str:
    values = _values(raw, number, 2)
    if len(values) > 1:
        raise C2AdapterTransportError("Sliver protobuf string is duplicated")
    if not values:
        if required:
            raise C2AdapterTransportError("Sliver protobuf required string is absent")
        return ""
    value = values[0]
    assert isinstance(value, bytes)
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise C2AdapterTransportError("Sliver protobuf string is invalid") from exc


def _messages(raw: bytes, number: int) -> list[bytes]:
    values = _values(raw, number, 2)
    result: list[bytes] = []
    for value in values:
        assert isinstance(value, bytes)
        result.append(value)
    return result


def _execute(
    request: SliverWorkerRequest,
    *,
    config: _OperatorConfig,
    grpc_call: _GrpcCall = _grpc_call,
) -> SliverWorkerResponse:
    _verify_config_binding(config, request)
    raw = grpc_call(
        config=config,
        request=request,
        protobuf_request=_protobuf_request(request.request),
    )
    normalized = _normalize_response(request.request, raw)
    if len(normalized) > request.max_response_bytes:
        raise C2AdapterTransportError("Sliver normalized response exceeded the bound")
    import base64

    return SliverWorkerResponse(
        transport_attestation_digest=request.transport_attestation_digest,
        operation=request.operation,
        body_base64=base64.b64encode(normalized).decode("ascii"),
    )


def _run(raw_request: bytes) -> bytes:
    request = SliverWorkerRequest.from_untrusted_json(raw_request)
    response = _execute(request, config=_read_operator_config())
    return response.model_dump_json().encode("utf-8")


def main() -> int:
    raw_request = sys.stdin.buffer.read(SLIVER_WORKER_MAX_INPUT_BYTES + 1)
    if len(raw_request) > SLIVER_WORKER_MAX_INPUT_BYTES:
        return 2
    try:
        sys.stdout.buffer.write(_run(raw_request))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
