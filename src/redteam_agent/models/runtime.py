"""Explicit current-state selectors for authorization inputs."""

from __future__ import annotations

from pydantic import Field

from .base import StrictImmutableBoundaryModel
from .common import UtcDatetime


class PolicyState(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    state_version: int = Field(ge=0)
    policy_version: str = Field(min_length=1)
    policy_digest: str = Field(min_length=1)
    updated_at: UtcDatetime


class AuthorizationRuntimeBinding(StrictImmutableBoundaryModel):
    """Explicit Source-of-Truth pointers; recency is never inferred by timestamp."""

    mission_id: str = Field(min_length=1)
    binding_version: int = Field(ge=0)
    binding_digest: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    policy_version: str = Field(min_length=1)
    registry_revision: int = Field(ge=1)
    registry_digest: str = Field(min_length=1)
    available_tool_snapshot_id: str = Field(min_length=1)
    session_security_context_snapshot_id: str = Field(min_length=1)
    adapter_capability_snapshot_id: str = Field(min_length=1)
    sandbox_capability_snapshot_id: str = Field(min_length=1)
    remote_mcp_trust_snapshot_id: str = Field(min_length=1)
    updated_at: UtcDatetime
