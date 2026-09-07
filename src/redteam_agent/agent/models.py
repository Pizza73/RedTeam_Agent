"""Workflow-only state. Application repositories remain the source of truth."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.context.models import RankedContextCandidate
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.plan.models import OperationalPhase
from redteam_agent.policy.scope_models import TargetReference

ControllerAction = Literal["SECURITY_STOP", "STOP", "RECOVER", "FINALIZE", "PLAN", "WAIT", "PAUSE"]
ControllerReason = Literal[
    "SECURITY_ERROR", "MISSION_NOT_RUNNING", "HARD_LIMIT", "EXECUTION_IN_PROGRESS",
    "GOAL_ACHIEVED", "CANDIDATES_READY", "SOURCE_REFRESH_PENDING",
    "NO_ACTION_IN_SUPPORTED_MODEL", "PLANNING_SEARCH_LIMIT", "BUDGET_EXHAUSTED",
]


class ControllerDecision(StrictImmutableBoundaryModel):
    action: ControllerAction
    reason_code: ControllerReason
    goal_evaluation_id: str | None
    candidate_ids: tuple[str, ...]


class AgentCheckpoint(StrictImmutableBoundaryModel):
    """Only operation/repository identifiers and a non-authoritative budget cache."""

    checkpoint_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    goal_evaluation_id: str | None
    planner_context_id: str | None
    active_execution_id: str | None
    operation_id: str = Field(min_length=1)
    iteration_cache: int = Field(ge=0)
    updated_at: datetime
    checkpoint_digest: str = Field(min_length=1)


class ActionCandidateSeed(StrictImmutableBoundaryModel):
    """Application-produced target binding offered to the finite projector."""

    tool_ref: ToolRef
    canonical_target_binding: tuple[TargetReference, ...]
    satisfied_precondition_refs: tuple[str, ...]
    objective_dependency_ids: tuple[str, ...]


class ActionCandidate(StrictImmutableBoundaryModel):
    candidate_id: str = Field(min_length=1)
    tool_ref: ToolRef
    action_contract_ref: ActionContractReference
    canonical_target_binding: tuple[TargetReference, ...]
    satisfied_precondition_refs: tuple[str, ...]
    objective_dependency_ids: tuple[str, ...]
    eligible_session_ids: tuple[str, ...]
    requires_session: bool


class ActionCandidateProjection(StrictImmutableBoundaryModel):
    schema_version: Literal["action-candidate-projection-v1"] = "action-candidate-projection-v1"
    available_tool_snapshot_id: str = Field(min_length=1)
    available_tool_snapshot_digest: str = Field(min_length=1)
    source_version_digests: tuple[str, ...]
    candidates: tuple[ActionCandidate, ...] = Field(max_length=32)
    search_limited: bool
    projection_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_candidates(self) -> ActionCandidateProjection:
        ids = [item.candidate_id for item in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("candidate ids must be unique")
        return self


class RecentExecutionSummary(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    result_reference_ids: tuple[str, ...]


class PlannerFeedback(StrictImmutableBoundaryModel):
    reason_code: Literal[
        "POLICY_DENIED", "APPROVAL_REQUIRED", "STALE_CONTEXT", "INVALID_PROPOSAL",
        "EXECUTION_FAILED", "NO_VALID_PROPOSAL",
    ]
    safe_summary: str
    visible_tool_ref: ToolRef | None = None


class PlannerContextEnvelope(StrictImmutableBoundaryModel):
    planner_context_id: str = Field(min_length=1)
    envelope_revision: int = Field(ge=1)
    parent_context_id: str | None
    context_rebuild_count: int = Field(ge=0, le=2)
    goal_evaluation_id: str = Field(min_length=1)
    goal_evaluation_digest: str = Field(min_length=1)
    action_candidate_projection: ActionCandidateProjection
    action_candidate_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    iteration: int = Field(ge=0)
    context_grant_id: str = Field(min_length=1)
    context_grant_digest: str = Field(min_length=1)
    available_tool_snapshot_id: str = Field(min_length=1)
    available_tool_snapshot_digest: str = Field(min_length=1)
    authorized_context: CanonicalJsonObject
    ranked_candidate_metadata: tuple[RankedContextCandidate, ...]
    recent_execution_summaries: tuple[RecentExecutionSummary, ...] = Field(max_length=5)
    feedback: tuple[PlannerFeedback, ...] = Field(max_length=5)
    working_state_id: str | None
    operational_phase: OperationalPhase
    truncation_reason_codes: tuple[str, ...]
    created_at: datetime
    expires_at: datetime
    envelope_digest: str = Field(min_length=1)
