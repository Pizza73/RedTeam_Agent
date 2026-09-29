"""Principal authentication (SystemDesign §2.6).

Phase 0A provides a Root-fixed static resolver test double mapping opaque actor
tokens to authenticated principals. There is no public path that turns a
caller-supplied id or role string into authority.
"""

from __future__ import annotations

from typing import Protocol

from redteam_agent.auth.models import AuthenticatedPrincipal


class PrincipalResolver(Protocol):
    def authenticate(self, actor_token: str) -> AuthenticatedPrincipal | None:
        """Return the authenticated principal for a token, or None."""
        ...


class StaticPrincipalResolver:
    """Fixed mapping of tokens to principals, installed by the composition root."""

    def __init__(self, principals_by_token: dict[str, AuthenticatedPrincipal] | None = None) -> None:
        self._by_token = dict(principals_by_token or {})

    def register(self, actor_token: str, principal: AuthenticatedPrincipal) -> None:
        """Install a token -> principal mapping (composition-root use only)."""
        self._by_token[actor_token] = principal

    def authenticate(self, actor_token: str) -> AuthenticatedPrincipal | None:
        return self._by_token.get(actor_token)
