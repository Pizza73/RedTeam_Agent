"""Three-valued goal evaluation records (SystemDesign §24)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.models.base import StrictImmutableBoundaryModel

GoalTruth = Literal["achieved", "not_achieved", "indeterminate"]
GoalReasonCode = Literal[
    "CONDITION_MATCHED", "CONDITION_ABSENT", "SESSION_REFRESH_FAILED",
    "RECONCILIATION_UNAVAILABLE", "EVIDENCE_CONTRADICTED", "PRINCIPAL_UNCONFIRMED",
    "ARTIFACT_UNVERIFIED", "EVIDENCE_NOT_COLLECTED", "EVIDENCE_EXPIRED",
    "EVIDENCE_SOURCE_UNAVAILABLE",
]


class EvidenceReference(StrictImmutableBoundaryModel):
    source_type: Literal["session", "finding", "artifact", "execution"]
    source_id: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    proof_references: tuple[str, ...]
    verification_state: Literal["confirmed", "contradicted", "unavailable"]


class ConditionEvaluation(StrictImmutableBoundaryModel):
    condition_id: str = Field(min_length=1)
    status: GoalTruth
    reason_code: GoalReasonCode
    evidence_references: tuple[EvidenceReference, ...]


class GoalStatus(StrictImmutableBoundaryModel):
    status: GoalTruth
    achieved_conditions: tuple[str, ...]
    remaining_conditions: tuple[str, ...]
    indeterminate_conditions: tuple[ConditionEvaluation, ...]
    evidence_references: tuple[EvidenceReference, ...]

    @model_validator(mode="after")
    def _condition_sets_disjoint(self) -> GoalStatus:
        achieved = set(self.achieved_conditions)
        remaining = set(self.remaining_conditions)
        unknown = {item.condition_id for item in self.indeterminate_conditions}
        if achieved & remaining or achieved & unknown or remaining & unknown:
            raise ValueError("goal condition result sets must be disjoint")
        return self


class GoalEvaluationRecord(StrictImmutableBoundaryModel):
    evaluation_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    mission_state_version: int = Field(ge=0)
    knowledge_head_id: str = Field(min_length=1)
    knowledge_head_digest: str = Field(min_length=1)
    source_snapshot_digest: str = Field(min_length=1)
    status: GoalStatus
    evaluated_at: datetime
    evaluation_digest: str = Field(min_length=1)
