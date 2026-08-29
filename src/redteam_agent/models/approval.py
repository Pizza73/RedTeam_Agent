"""Human presentation and human decision are distinct immutable records."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.canonical.models import CanonicalJsonObject

from .base import StrictImmutableBoundaryModel
from .common import RiskLevel, SideEffect, UtcDatetime
from .scope import NormalizedTarget
from .tools import ToolRef

HumanApprovalDecision = Literal["APPROVED", "REJECTED"]


class ApprovalPresentation(StrictImmutableBoundaryModel):
    tool_ref: ToolRef
    tool_display_name: str = Field(min_length=1)
    normalized_targets: tuple[NormalizedTarget, ...]
    redacted_arguments: CanonicalJsonObject
    effective_risk: RiskLevel
    side_effect: SideEffect
    resolved_adapter_id: str = Field(min_length=1)


class ApprovalRequest(StrictImmutableBoundaryModel):
    approval_request_id: str = Field(min_length=1)
    request_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    policy_decision_id: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    approval_presentation_digest: str = Field(min_length=1)
    presentation: ApprovalPresentation
    redacted_arguments_summary: str
    issued_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def valid_interval(self) -> "ApprovalRequest":
        if self.issued_at >= self.expires_at:
            raise ValueError("approval request issued_at must be before expires_at")
        return self


class ApprovalRecord(StrictImmutableBoundaryModel):
    approval_id: str = Field(min_length=1)
    record_digest: str = Field(min_length=1)
    approval_request_id: str = Field(min_length=1)
    approval_request_digest: str = Field(min_length=1)
    approval_presentation_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    policy_decision_id: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    decision: HumanApprovalDecision
    approver_id: str = Field(min_length=1)
    approver_role: str = Field(min_length=1)
    issued_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def valid_interval(self) -> "ApprovalRecord":
        if self.issued_at >= self.expires_at:
            raise ValueError("approval record issued_at must be before expires_at")
        return self
