"""In-memory, loopback-only operator sessions for the local UI.

The long-lived bootstrap token is supplied by the composition root from an
owner-private credential file.  The browser exchanges it once for an opaque
HttpOnly session cookie; neither the token nor its digest is written to the
application database or returned by an API.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from redteam_agent.ui.control_plane import UIControlPlaneError

MIN_OPERATOR_TOKEN_BYTES = 32
MAX_OPERATOR_TOKEN_BYTES = 4096
DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60
MAX_ACTIVE_SESSIONS = 8


class UIAuthenticationError(UIControlPlaneError):
    """An operator credential or session is absent, invalid, or expired."""


@dataclass(frozen=True)
class AuthenticatedUISession:
    principal_id: str
    expires_at: datetime


Clock = Callable[[], datetime]
TokenFactory = Callable[[], str]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def read_operator_token(path: Path) -> bytearray:
    """Read one owner-private regular file without following symlinks."""
    if not path.is_absolute():
        raise UIAuthenticationError("operator credential path must be absolute")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise UIAuthenticationError("operator credential ownership or mode is unsafe")
        value = bytearray(os.read(descriptor, MAX_OPERATOR_TOKEN_BYTES + 2))
    except OSError as exc:
        raise UIAuthenticationError("operator credential is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if value.endswith(b"\n"):
        value.pop()
    if value.endswith(b"\r"):
        value.pop()
    if not MIN_OPERATOR_TOKEN_BYTES <= len(value) <= MAX_OPERATOR_TOKEN_BYTES:
        for index in range(len(value)):
            value[index] = 0
        raise UIAuthenticationError("operator credential size is invalid")
    if any(byte < 0x21 or byte > 0x7E for byte in value):
        for index in range(len(value)):
            value[index] = 0
        raise UIAuthenticationError("operator credential must be printable ASCII")
    return value


class OperatorSessionAuthenticator:
    """Authenticate one fixed operator and issue restart-ephemeral sessions."""

    def __init__(
        self,
        *,
        principal_id: str,
        operator_token: bytearray,
        session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        clock: Clock = _utc_now,
        token_factory: TokenFactory = lambda: secrets.token_urlsafe(32),
    ) -> None:
        if not principal_id or principal_id != principal_id.strip() or len(principal_id) > 200:
            raise ValueError("operator principal id is invalid")
        if not MIN_OPERATOR_TOKEN_BYTES <= len(operator_token) <= MAX_OPERATOR_TOKEN_BYTES:
            raise ValueError("operator credential size is invalid")
        if not 60 <= session_ttl_seconds <= 24 * 60 * 60:
            raise ValueError("operator session TTL is outside policy")
        self._principal_id = principal_id
        self._token_digest = hashlib.sha256(operator_token).digest()
        for index in range(len(operator_token)):
            operator_token[index] = 0
        self._ttl = session_ttl_seconds
        self._clock = clock
        self._token_factory = token_factory
        self._sessions: dict[bytes, datetime] = {}
        self._lock = threading.Lock()

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def session_ttl_seconds(self) -> int:
        return self._ttl

    @staticmethod
    def _session_digest(session_id: str) -> bytes:
        return hashlib.sha256(session_id.encode("ascii", errors="strict")).digest()

    def login(self, supplied_token: str) -> tuple[str, AuthenticatedUISession]:
        if not supplied_token or len(supplied_token.encode("utf-8")) > MAX_OPERATOR_TOKEN_BYTES:
            raise UIAuthenticationError("operator credential is invalid")
        supplied = bytearray(supplied_token.encode("utf-8"))
        try:
            valid = hmac.compare_digest(hashlib.sha256(supplied).digest(), self._token_digest)
        finally:
            for index in range(len(supplied)):
                supplied[index] = 0
        if not valid:
            raise UIAuthenticationError("operator credential is invalid")
        now = self._clock().astimezone(UTC)
        expires_at = now + timedelta(seconds=self._ttl)
        session_id = self._token_factory()
        if not 32 <= len(session_id) <= 200 or not session_id.isascii():
            raise UIAuthenticationError("operator session issuance failed")
        digest = self._session_digest(session_id)
        with self._lock:
            self._discard_expired(now)
            if digest in self._sessions or len(self._sessions) >= MAX_ACTIVE_SESSIONS:
                raise UIAuthenticationError("operator session issuance failed")
            self._sessions[digest] = expires_at
        return session_id, AuthenticatedUISession(
            principal_id=self._principal_id,
            expires_at=expires_at,
        )

    def authenticate(self, session_id: str | None) -> AuthenticatedUISession | None:
        if session_id is None or not 32 <= len(session_id) <= 200 or not session_id.isascii():
            return None
        now = self._clock().astimezone(UTC)
        digest = self._session_digest(session_id)
        with self._lock:
            self._discard_expired(now)
            expires_at = self._sessions.get(digest)
        if expires_at is None:
            return None
        return AuthenticatedUISession(principal_id=self._principal_id, expires_at=expires_at)

    def logout(self, session_id: str | None) -> None:
        if session_id is None or not session_id.isascii():
            return
        digest = self._session_digest(session_id)
        with self._lock:
            self._sessions.pop(digest, None)

    def _discard_expired(self, now: datetime) -> None:
        expired = tuple(digest for digest, expires_at in self._sessions.items() if now >= expires_at)
        for digest in expired:
            self._sessions.pop(digest, None)


__all__ = [
    "DEFAULT_SESSION_TTL_SECONDS",
    "MAX_ACTIVE_SESSIONS",
    "MAX_OPERATOR_TOKEN_BYTES",
    "MIN_OPERATOR_TOKEN_BYTES",
    "AuthenticatedUISession",
    "OperatorSessionAuthenticator",
    "UIAuthenticationError",
    "read_operator_token",
]
