"""Context candidate, index record and read-grant models (SystemDesign §18 / §22)."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.policy.data_access import ResourceType
from redteam_agent.policy.models import DataAccessGrant, SessionContextGrant
from redteam_agent.policy.scope_models import TargetReference

ServiceIdentity = str  # "planner_context" | "analyzer_context" (validated below)


class CandidateContextResource(StrictImmutableBoundaryModel):
    resource_id: str = Field(min_length=1)
    resource_type: ResourceType
    mission_id: str = Field(min_length=1)
    target_references: tuple[TargetReference, ...]
    verification_state: str
    observed_at: datetime
    classification: str
    summary_metadata: CanonicalJsonObject


class RankedContextCandidate(StrictImmutableBoundaryModel):
    candidate: CandidateContextResource
    selection_reason_codes: tuple[str, ...]
    rank_vector: tuple[int, ...]
    stable_tiebreaker: str
    ranking_policy_version: str


class ContextResourceIndexRecord(StrictImmutableBoundaryModel):
    """Derived index metadata. Never contains artifact/knowledge bodies."""

    resource_id: str = Field(min_length=1)
    resource_type: ResourceType
    mission_id: str = Field(min_length=1)
    target_references: tuple[TargetReference, ...]
    verification_state: str
    observed_at: datetime
    classification: str
    summary_metadata: CanonicalJsonObject
    origin_record_id: str = Field(min_length=1)
    origin_record_version: str = Field(min_length=1)
    origin_record_digest: str = Field(min_length=1)

    def to_candidate(self) -> CandidateContextResource:
        return CandidateContextResource(
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            mission_id=self.mission_id,
            target_references=self.target_references,
            verification_state=self.verification_state,
            observed_at=self.observed_at,
            classification=self.classification,
            summary_metadata=self.summary_metadata,
        )


class ContextDataAccessGrant(StrictImmutableBoundaryModel):
    grant_id: str = Field(min_length=1)
    grant_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    service_identity: str = Field(pattern=r"^(planner_context|analyzer_context)$")
    resources: tuple[DataAccessGrant, ...]
    session_context: SessionContextGrant
    policy_version: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
