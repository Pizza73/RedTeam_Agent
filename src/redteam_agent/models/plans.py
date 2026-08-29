"""LLM proposal and application-owned execution plan models."""

from __future__ import annotations

from pydantic import Field

from redteam_agent.canonical.models import CanonicalJsonObject

from .base import StrictImmutableBoundaryModel
from .common import OperationalPhase, UtcDatetime
from .scope import TargetReference
from .tools import ToolRef


class ExecutionPlanProposal(StrictImmutableBoundaryModel):
    objective: str = Field(min_length=1)
    phase: OperationalPhase
    tool_ref: ToolRef
    requested_targets: tuple[TargetReference, ...]
    session_id: str | None
    arguments: CanonicalJsonObject


class ExecutionPlan(StrictImmutableBoundaryModel):
    plan_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    proposal_schema_version: str = Field(min_length=1)
    proposal: ExecutionPlanProposal
    proposal_digest: str = Field(min_length=1)
    available_tool_snapshot_id: str = Field(min_length=1)
    available_tool_snapshot_digest: str = Field(min_length=1)
    session_security_context_digest: str = Field(min_length=1)
    adapter_capabilities_digest: str = Field(min_length=1)
    sandbox_capabilities_digest: str = Field(min_length=1)
    remote_mcp_trust_policy_digest: str = Field(min_length=1)
    created_at: UtcDatetime
