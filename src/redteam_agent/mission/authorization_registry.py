"""Trusted exercise authorization references used by MissionManager."""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.errors import MissionValidationError


@dataclass(frozen=True)
class AuthorizationReferenceRegistry:
    authorized_references: frozenset[str]

    def require(self, reference: str) -> None:
        if reference not in self.authorized_references:
            raise MissionValidationError("mission authorization reference is not registered")
