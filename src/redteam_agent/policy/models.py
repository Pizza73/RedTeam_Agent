"""PolicyDecision and grant models (SystemDesign §22).

A ``PolicyDecision`` is an immutable execution authorization envelope. It is the
only source of execution authority; a caller can neither mint nor mutate one
(B-02). One executable decision yields at most one execution.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ResourceBinding, ToolRef
from redteam_agent.policy.data_access import DataAccessOperation, ResourceType
from redteam_agent.policy.risk_policy import RiskLevel
from redteam_agent.policy.scope_models import NormalizedTarget
from redteam_agent.policy.target_binding import TargetDispatchBinding


class DataAccessGrant(StrictImmutableBoundaryModel):
    resource_type: ResourceType
    resource: ResourceBinding
    authorization_state_digest: str = Field(min_length=1)
    operations: frozenset[DataAccessOperation] = Field(min_length=1)


class SessionContextGrant(StrictImmutableBoundaryModel):
    authorized_session_ids: tuple[str, ...]
    session_security_context_digest: str = Field(min_length=1)


class PolicyDecision(StrictImmutableBoundaryModel):
    decision_id: str = Field(min_length=1)
    decision_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    plan_id: str = Field(min_length=1)
    tool_ref: ToolRef
    proposal_digest: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    registry_digest: str = Field(min_length=1)
    available_tool_snapshot_id: str = Field(min_length=1)
    available_tool_snapshot_digest: str = Field(min_length=1)
    resolved_adapter: Literal["c2", "mcp", "local"]
    resolved_adapter_id: str = Field(min_length=1)
    decision: Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
    normalized_targets: tuple[NormalizedTarget, ...]
    target_dispatch_bindings: tuple[TargetDispatchBinding, ...]
    authorized_data_access: tuple[DataAccessGrant, ...]
    effective_risk: RiskLevel
    reason_codes: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
