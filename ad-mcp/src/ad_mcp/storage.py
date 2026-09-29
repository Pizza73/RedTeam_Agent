"""Private raw-output storage with completion metadata."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from ad_mcp.models import JobState, utc_now


class RawExecution:
    __slots__ = ("directory", "metadata", "stderr", "stdout")

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.stdout = directory / "stdout.log"
        self.stderr = directory / "stderr.log"
        self.metadata = directory / "metadata.json"


class RawStorage:
    def __init__(self, root: Path, retention_hours: int) -> None:
        self._root = root.resolve(strict=True)
        self._retention = timedelta(hours=retention_hours)

    def create(self, job_id: str) -> RawExecution:
        if not job_id or any(character not in "0123456789abcdef-" for character in job_id):
            raise ValueError("invalid job identifier")
        directory = self._root / job_id
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        os.chmod(directory, 0o700)
        result = RawExecution(directory)
        for path in (result.stdout, result.stderr):
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        return result

    def commit(
        self,
        raw: RawExecution,
        *,
        state: JobState,
        exit_code: int | None,
        complete: bool,
    ) -> None:
        now = utc_now()
        data = {
            "schema_version": "ad-mcp-raw-v1",
            "state": state.value,
            "exit_code": exit_code,
            "complete": complete,
            "committed_at": now.isoformat(),
            "retention_until": (now + self._retention).isoformat(),
            "streams": {
                name: {
                    "size": path.stat().st_size,
                    "sha256": _sha256(path),
                }
                for name, path in (("stdout", raw.stdout), ("stderr", raw.stderr))
            },
        }
        temporary = raw.metadata.with_suffix(".json.part")
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, json.dumps(data, sort_keys=True).encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        temporary.replace(raw.metadata)

    def delete_expired(self) -> tuple[str, ...]:
        deleted: list[str] = []
        now = utc_now()
        for directory in self._root.iterdir():
            metadata = directory / "metadata.json"
            if not directory.is_dir() or directory.is_symlink() or not metadata.is_file():
                continue
            try:
                value = json.loads(metadata.read_text(encoding="utf-8"))
                deadline = datetime.fromisoformat(value["retention_until"])
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
            if deadline <= now:
                shutil.rmtree(directory)
                deleted.append(directory.name)
        return tuple(deleted)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
