"""Knowledge records whose trust classes remain separate (SystemDesign §16)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.models.base import StrictImmutableBoundaryModel


class KnowledgeSecurityHead(StrictImmutableBoundaryModel):
    head_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    security_version: int = Field(ge=1)
    previous_head_digest: str | None
    fact_state_root_digest: str = Field(min_length=1)
    entity_state_root_digest: str = Field(min_length=1)
    source_state_root_digest: str = Field(min_length=1)
    evidence_rule_catalog_digest: str = Field(min_length=1)
    recorded_at: datetime
    head_digest: str = Field(min_length=1)


class KnowledgeObservation(StrictImmutableBoundaryModel):
    """Unconfirmed analyzer output. It is never included in the security head."""

    observation_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    source_execution_id: str = Field(min_length=1)
    observation_type: Literal["asset", "identity", "relationship", "finding"]
    subject_ref: str = Field(min_length=1)
    predicate: str = Field(min_length=1)
    object_ref: str | None
    attributes: CanonicalJsonObject
    source_artifact_ids: tuple[str, ...]
    llm_confidence: float = Field(ge=0.0, le=1.0)
    observed_at: datetime
    observation_digest: str = Field(min_length=1)


class AnalyzerCandidateObservation(StrictImmutableBoundaryModel):
    """Untrusted typed Analyzer proposal; the reducer rebinds every reference."""

    observation_id: str = Field(min_length=1)
    condition_id: str = Field(min_length=1)
    source_execution_id: str = Field(min_length=1)
    observation_type: Literal["asset", "identity", "relationship", "finding"]
    subject_ref: str = Field(min_length=1)
    predicate: str = Field(min_length=1)
    object_ref: str | None
    attributes: CanonicalJsonObject
    source_artifact_ids: tuple[str, ...]
    llm_confidence: float = Field(ge=0.0, le=1.0)
