"""Mission identity, immutable authorization revision and OCC lifecycle state."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .base import StrictImmutableBoundaryModel
from .common import UtcDatetime
from .goals import SuccessCondition
from .scope import ApprovalPolicy, DataAccessPolicy, ExecutionScopeRule


MissionLifecycleState = Literal[
    "DRAFT",
    "VALIDATED",
    "RUNNING",
    "PAUSED",
    "FINALIZING",
    "WAITING_HUMAN_REVIEW",
    "COMPLETED",
    "COMPLETED_WITH_UNRESOLVED_EXECUTIONS",
    "FAILED",
    "ABORTED",
]


class MissionRoot(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    created_at: UtcDatetime
    created_by: str = Field(min_length=1)


class MissionRevision(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    llm_profile_revision: str = Field(min_length=1)
    llm_profile_digest: str = Field(min_length=1)
    description: str = Field(min_length=1)
    authorization_reference: str = Field(min_length=1)
    authorized_by: str = Field(min_length=1)
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    allowed_execution_scope: tuple[ExecutionScopeRule, ...] = Field(min_length=1)
    prohibited_execution_scope: tuple[ExecutionScopeRule, ...] = ()
    data_access_policy: DataAccessPolicy
    objectives: tuple[str, ...] = Field(min_length=1)
    success_conditions: tuple[SuccessCondition, ...] = Field(min_length=1)
    success_mode: Literal["all", "any"] = "all"
    max_iterations: int = Field(gt=0)
    max_runtime_minutes: int = Field(gt=0)
    max_indeterminate_retries: int = Field(default=3, gt=0)
    approval_policy: ApprovalPolicy

    @model_validator(mode="after")
    def mission_revision_invariants(self) -> "MissionRevision":
        if self.valid_from >= self.valid_until:
            raise ValueError("valid_from must be earlier than valid_until")
        condition_ids = [condition.condition_id for condition in self.success_conditions]
        if len(condition_ids) != len(set(condition_ids)):
            raise ValueError("condition_id must be unique within a mission revision")
        if any(not objective.strip() for objective in self.objectives):
            raise ValueError("objectives must be non-empty")
        return self


class MissionState(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    mission_state_version: int = Field(ge=0)
    authorization_epoch: int = Field(ge=0)
    state: MissionLifecycleState
    updated_at: UtcDatetime


class Mission(StrictImmutableBoundaryModel):
    """Application read model joined from root, revision and state repositories."""

    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    mission_state_version: int = Field(ge=0)
    authorization_epoch: int = Field(ge=0)
    state: MissionLifecycleState
    llm_profile_revision: str = Field(min_length=1)
    llm_profile_digest: str = Field(min_length=1)
    description: str = Field(min_length=1)
    authorization_reference: str = Field(min_length=1)
    authorized_by: str = Field(min_length=1)
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    allowed_execution_scope: tuple[ExecutionScopeRule, ...] = Field(min_length=1)
    prohibited_execution_scope: tuple[ExecutionScopeRule, ...] = ()
    data_access_policy: DataAccessPolicy
    objectives: tuple[str, ...] = Field(min_length=1)
    success_conditions: tuple[SuccessCondition, ...] = Field(min_length=1)
    success_mode: Literal["all", "any"] = "all"
    max_iterations: int = Field(gt=0)
    max_runtime_minutes: int = Field(gt=0)
    max_indeterminate_retries: int = Field(default=3, gt=0)
    approval_policy: ApprovalPolicy

    @model_validator(mode="after")
    def mission_invariants(self) -> "Mission":
        if self.valid_from >= self.valid_until:
            raise ValueError("valid_from must be earlier than valid_until")
        ids = [condition.condition_id for condition in self.success_conditions]
        if len(ids) != len(set(ids)):
            raise ValueError("condition_id must be unique within a mission revision")
        return self

    def revision_record(self) -> MissionRevision:
        return MissionRevision.model_validate(
            self.model_dump(
                mode="python",
                exclude={"mission_state_version", "authorization_epoch", "state"},
            )
        )

    def state_record(self, *, updated_at: UtcDatetime) -> MissionState:
        return MissionState(
            mission_id=self.mission_id,
            mission_state_version=self.mission_state_version,
            authorization_epoch=self.authorization_epoch,
            state=self.state,
            updated_at=updated_at,
        )

