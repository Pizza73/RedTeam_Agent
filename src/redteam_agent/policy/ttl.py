"""Short-lived authorization TTL invariants (SystemDesign §21).

The TTL of a grant/snapshot/decision/approval must not exceed mission validity
(or a parent artifact's expiry). Rather than silently clamping to the mission
window (which would make an over-long request succeed quietly), out-of-range
TTLs are rejected explicitly. This is enforced at issue time and re-checked at
use time.
"""

from __future__ import annotations

from datetime import datetime

from redteam_agent.errors import AuthorizationTtlError


def enforce_ttl(
    *,
    label: str,
    issued_at: datetime,
    expires_at: datetime,
    mission_valid_until: datetime,
    parent_expires_at: datetime | None = None,
) -> None:
    """Raise :class:`AuthorizationTtlError` if the TTL is out of range."""
    if not (issued_at < expires_at):
        raise AuthorizationTtlError(f"{label}: expires_at must be after issued_at")
    if expires_at > mission_valid_until:
        raise AuthorizationTtlError(f"{label}: expires_at exceeds mission validity")
    if parent_expires_at is not None and expires_at > parent_expires_at:
        raise AuthorizationTtlError(f"{label}: expires_at exceeds parent artifact validity")
