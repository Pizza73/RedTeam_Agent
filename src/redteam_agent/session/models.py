"""Session security context and its digest (SystemDesign §20.1)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel

PrivilegeContext = Literal[
    "standard",
    "windows_system",
    "windows_high_integrity",
    "linux_uid0",
]

_PRIVILEGED_CONTEXTS: frozenset[str] = frozenset(
    {"windows_system", "windows_high_integrity", "linux_uid0"}
)


class SessionSecurityContext(StrictImmutableBoundaryModel):
    """Security-relevant session fields (the inputs to the context digest).

    Telemetry timestamps (``last_seen``/``refreshed_at``) are deliberately not
    modelled here; they must not enter the digest (SystemDesign §20.1).
    """

    session_id: str = Field(min_length=1)
    host: str = Field(min_length=1)
    os: Literal["windows", "linux", "macos", "other"]
    architecture: str = Field(min_length=1)
    current_principal: str = Field(min_length=1)
    effective_privilege_context: PrivilegeContext
    session_capabilities: frozenset[str]
    network_context: str
    security_status: str

    @property
    def privileged(self) -> bool:
        return self.effective_privilege_context in _PRIVILEGED_CONTEXTS


class SessionSecurityContextSnapshot(StrictImmutableBoundaryModel):
    """A trusted session context plus its freshness bound."""

    session_id: str = Field(min_length=1)
    context: SessionSecurityContext
    session_fresh_until: datetime
    observed_at: datetime

    @model_validator(mode="after")
    def _identity_consistent(self) -> SessionSecurityContextSnapshot:
        if self.session_id != self.context.session_id:
            raise ValueError("snapshot session_id must equal context.session_id")
        return self


def _context_payload(context: SessionSecurityContext) -> dict[str, object]:
    return {
        "session_id": context.session_id,
        "host": context.host,
        "os": context.os,
        "architecture": context.architecture,
        "current_principal": context.current_principal,
        "effective_privilege_context": context.effective_privilege_context,
        "session_capabilities": sorted(context.session_capabilities),
        "network_context": context.network_context,
        "security_status": context.security_status,
    }


def compute_session_security_context_digest(
    contexts: tuple[SessionSecurityContext, ...],
    digest_service: DigestService,
) -> str:
    """Digest of a session set, sorted by stable id, security-relevant fields only."""
    ordered = sorted(contexts, key=lambda ctx: ctx.session_id)
    payload = {"sessions": [_context_payload(ctx) for ctx in ordered]}
    return digest_service.compute("session_security_context_digest", payload)
