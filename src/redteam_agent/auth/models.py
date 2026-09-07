"""Authentication/RBAC models (SystemDesign §2.6)."""

from __future__ import annotations

from pydantic import Field

from redteam_agent.models.base import StrictImmutableBoundaryModel


class AuthenticatedPrincipal(StrictImmutableBoundaryModel):
    """The result of authenticating an actor. Never caller-constructed as input."""

    principal_id: str = Field(min_length=1)
    roles: frozenset[str]


class MissionRoleAssignment(StrictImmutableBoundaryModel):
    """A role granted to a principal for a specific mission."""

    mission_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    active: bool = True
