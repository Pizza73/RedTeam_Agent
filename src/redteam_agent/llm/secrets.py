"""Secret-file loading for the remote vLLM API credential.

Only a file *path* is configuration.  The credential value is read just before an
HTTP request, is never placed in a Pydantic model / digest / repr, and is returned only
through the narrow :class:`APIKeySource` protocol.
"""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Protocol

from redteam_agent.errors import LLMTransportError


class APIKeySource(Protocol):
    """Provides the current vLLM API key without exposing storage details."""

    def read(self) -> str:
        ...


class FileAPIKeySource:
    """Read a root/service-owned API key from a non-symlink regular file."""

    def __init__(self, path: str | Path) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise LLMTransportError("vLLM API key path must be absolute", reason="config_error")
        self._path = candidate

    @property
    def path(self) -> str:
        """Non-secret configured path, useful for diagnostics without key disclosure."""
        return str(self._path)

    def read(self) -> str:
        try:
            metadata = self._path.lstat()
        except OSError:
            raise LLMTransportError("vLLM API key file is unavailable", reason="config_error") from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise LLMTransportError(
                "vLLM API key path must be a regular non-symlink file", reason="config_error"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise LLMTransportError(
                "vLLM API key file permissions are too broad", reason="config_error"
            )
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError:
            raise LLMTransportError("vLLM API key file cannot be read", reason="config_error") from None
        key = raw.rstrip("\r\n")
        if not key or key != key.strip() or "\n" in key or "\r" in key or len(key) > 4096:
            raise LLMTransportError("vLLM API key file is malformed", reason="config_error")
        # Defend against a file replacement between lstat and read.  This is not a
        # substitute for deployment ownership, but it fails closed on a common race.
        try:
            after = self._path.stat()
        except OSError:
            raise LLMTransportError("vLLM API key file changed while reading", reason="config_error") from None
        if metadata.st_dev != after.st_dev or metadata.st_ino != after.st_ino:
            raise LLMTransportError("vLLM API key file changed while reading", reason="config_error")
        return key


def authorization_headers(source: APIKeySource | None) -> dict[str, str]:
    """Build request-local headers; callers must not persist or log the result."""
    return {} if source is None else {"Authorization": f"Bearer {source.read()}"}


__all__ = ["APIKeySource", "FileAPIKeySource", "authorization_headers"]
