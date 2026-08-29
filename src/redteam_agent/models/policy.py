"""Immutable authorization decision envelope."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .base import StrictImmutableBoundaryModel
from .common import RiskLevel, SideEffect, UtcDatetime
from .context import DataAccessGrant
from .scope import NormalizedTarget
from .tools import ToolRef


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
    session_security_context_digest: str = Field(min_length=1)
    adapter_capabilities_digest: str = Field(min_length=1)
    sandbox_capabilities_digest: str = Field(min_length=1)
    remote_mcp_trust_policy_digest: str = Field(min_length=1)
    resolved_adapter: Literal["c2", "mcp", "local"]
    resolved_adapter_id: str = Field(min_length=1)
    decision: Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
    normalized_targets: tuple[NormalizedTarget, ...]
    authorized_data_access: tuple[DataAccessGrant, ...]
    validated_arguments_digest: str = Field(min_length=1)
    effective_risk: RiskLevel
    side_effect: SideEffect
    approval_rule: Literal["policy", "always"]
    reason_codes: tuple[str, ...]
    issued_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def valid_interval(self) -> "PolicyDecision":
        if self.issued_at >= self.expires_at:
            raise ValueError("decision issued_at must be before expires_at")
        if tuple(sorted(set(self.reason_codes))) != self.reason_codes:
            raise ValueError("reason codes must be sorted and unique")
        return self

