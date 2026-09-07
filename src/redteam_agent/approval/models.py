"""Approval presentation, request and record models (SystemDesign §23)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ResourceBinding, ToolRef
from redteam_agent.policy.data_access import DataAccessOperation
from redteam_agent.policy.risk_policy import RiskLevel, SideEffect
from redteam_agent.policy.scope_models import NormalizedTarget
from redteam_agent.policy.target_binding import TargetDispatchBinding


class ApprovalSecretReferenceSummary(StrictImmutableBoundaryModel):
    credential_type: str = Field(min_length=1)
    reference_count: int = Field(gt=0)
    secret_version_ids: tuple[str, ...] = Field(min_length=1)
    associated_principal_refs: tuple[str, ...]


class ApprovalDataAccessSummary(StrictImmutableBoundaryModel):
    resource_type: str = Field(min_length=1)
    operations: frozenset[DataAccessOperation] = Field(min_length=1)
    resource_count: int = Field(gt=0)
    resource_reference_ids: tuple[str, ...] = Field(min_length=1)
    resource_bindings: tuple[ResourceBinding, ...] = Field(min_length=1)


class ApprovalPresentation(StrictImmutableBoundaryModel):
    tool_ref: ToolRef
    tool_display_name: str = Field(min_length=1)
    normalized_targets: tuple[NormalizedTarget, ...]
    target_dispatch_bindings: tuple[TargetDispatchBinding, ...]
    target_count: int = Field(ge=0)
    session_id: str | None
    current_principal_ref: str | None
    current_principal_display: str | None
    redacted_arguments: CanonicalJsonObject
    secret_reference_summaries: tuple[ApprovalSecretReferenceSummary, ...]
    authorized_data_access_summary: tuple[ApprovalDataAccessSummary, ...]
    timeout_seconds: int = Field(gt=0)
    effective_risk: RiskLevel
    side_effect: SideEffect
    truncation_reason_codes: tuple[str, ...]
    presentation_digest: str = Field(min_length=1)


class ApprovalRequest(StrictImmutableBoundaryModel):
    approval_request_id: str = Field(min_length=1)
    request_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    policy_decision_id: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    presentation: ApprovalPresentation
    issued_at: datetime
    expires_at: datetime


class ApprovalRecord(StrictImmutableBoundaryModel):
    approval_id: str = Field(min_length=1)
    record_digest: str = Field(min_length=1)
    approval_request_id: str = Field(min_length=1)
    approval_request_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    policy_decision_id: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    decision: Literal["APPROVED", "REJECTED"]
    approver_id: str = Field(min_length=1)
    approver_role: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
