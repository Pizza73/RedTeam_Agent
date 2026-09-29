"""Registered Windows payload validation and transport boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Protocol

from pydantic import Field

from ad_mcp.errors import ConfigurationError
from ad_mcp.models import StrictModel


class PayloadRecord(StrictModel):
    operation_id: str
    file: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    version: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PayloadManifest(StrictModel):
    schema_version: str
    payloads: tuple[PayloadRecord, ...]


class RemoteTransport(Protocol):
    async def execute(
        self, *, target: str, payload: Path, arguments: tuple[str, ...], timeout_seconds: int
    ) -> int: ...


class DisabledRemoteTransport:
    async def execute(
        self, *, target: str, payload: Path, arguments: tuple[str, ...], timeout_seconds: int
    ) -> int:
        del target, payload, arguments, timeout_seconds
        raise ConfigurationError("REMOTE_TRANSPORT_UNCONFIGURED")


def load_and_verify_payload(manifest_path: Path, payload_root: Path, operation_id: str) -> Path:
    try:
        manifest = PayloadManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ConfigurationError("PAYLOAD_MANIFEST_INVALID") from exc
    record = next((item for item in manifest.payloads if item.operation_id == operation_id), None)
    if record is None:
        raise ConfigurationError("PAYLOAD_NOT_REGISTERED")
    root = payload_root.resolve(strict=True)
    path = (root / record.file).resolve(strict=True)
    if root not in path.parents or not path.is_file():
        raise ConfigurationError("PAYLOAD_PATH_INVALID")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not hmac_compare(digest, record.sha256):
        raise ConfigurationError("PAYLOAD_DIGEST_MISMATCH")
    return path


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
