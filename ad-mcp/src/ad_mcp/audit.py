"""Private append-only JSONL operational audit."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from ad_mcp.models import ProjectAuthorization, utc_now

_SENSITIVE_KEYS = frozenset(
    {"password", "credential", "secret", "token", "hash", "aes_key", "private_key"}
)


def redact(value: object, *, key: str = "") -> object:
    if any(part in key.lower() for part in _SENSITIVE_KEYS):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, key=key) for item in value]
    if isinstance(value, str) and len(value) > 4096:
        return f"<string:{len(value)} bytes>"
    return value


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    async def write(
        self,
        event: str,
        auth: ProjectAuthorization,
        *,
        operation_id: str | None = None,
        job_id: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "schema_version": "ad-mcp-audit-v1",
            "timestamp": utc_now().isoformat(),
            "event": event,
            "actor_id": auth.actor_id,
            "mission_id": auth.mission_id,
            "execution_id": auth.execution_id,
            "approval_id": auth.approval_id,
            "operation_id": operation_id,
            "job_id": job_id,
            "details": redact(details or {}),
        }
        encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        async with self._lock:
            descriptor = os.open(
                self._path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
