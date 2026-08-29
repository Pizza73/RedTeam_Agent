"""Context resource index and read-authorization envelopes."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from redteam_agent.canonical.models import CanonicalJsonObject

from .base import StrictImmutableBoundaryModel
from .common import OperationalPhase, UtcDatetime
from .scope import DataAccessOperation, DataResourceType, TargetReference


class ResourceBinding(StrictImmutableBoundaryModel):
    resource_id: str = Field(min_length=1)
    resource_version: str = Field(min_length=1)
    resource_digest: str = Field(min_length=1)


class DataAccessGrant(StrictImmutableBoundaryModel):
    resource_type: DataResourceType
    resource: ResourceBinding
    operations: frozenset[DataAccessOperation] = Field(min_length=1)


class SessionContextGrant(StrictImmutableBoundaryModel):
    authorized_session_ids: tuple[str, ...]
    session_security_context_digest: str = Field(min_length=1)

    @field_validator("authorized_session_ids")
    @classmethod
    def sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or value != tuple(sorted(value)):
            raise ValueError("authorized_session_ids must be sorted and unique")
        return value


class ContextDataAccessGrant(StrictImmutableBoundaryModel):
    grant_id: str = Field(min_length=1)
    grant_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    service_identity: Literal["planner_context", "analyzer_context"]
    resources: tuple[DataAccessGrant, ...]
    session_context: SessionContextGrant
    policy_version: str = Field(min_length=1)
    issued_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def valid_interval(self) -> "ContextDataAccessGrant":
        if self.issued_at >= self.expires_at:
            raise ValueError("grant issued_at must be before expires_at")
        if self.service_identity in {"planner_context", "analyzer_context"}:
            if any("resolve" in item.operations for item in self.resources):
                raise ValueError("LLM context grants may not resolve secret values")
        return self


class ContextResourceIndexRecord(StrictImmutableBoundaryModel):
    index_id: str = Field(min_length=1)
    binding: ResourceBinding
    resource_type: DataResourceType
    mission_id: str = Field(min_length=1)
    target_references: tuple[TargetReference, ...]
    verification_state: Literal["confirmed", "candidate", "contradicted", "unavailable"]
    observed_at: UtcDatetime
    classification: Literal["normal", "sensitive", "secret"]
    size_bytes: int = Field(ge=0)
    summary_metadata: CanonicalJsonObject

    @model_validator(mode="after")
    def no_content_in_metadata(self) -> "ContextResourceIndexRecord":
        forbidden = {
            "body",
            "content",
            "secret",
            "secret_value",
            "raw_tool_output",
            "raw_stdout",
            "raw_stderr",
            "encrypted_raw_artifact",
        }

        def inspect(value: object) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if key.casefold() in forbidden:
                        raise ValueError(f"context index metadata may not contain {key}")
                    inspect(item)
            elif isinstance(value, list):
                for item in value:
                    inspect(item)

        inspect(self.summary_metadata.to_dict())
        return self


class CandidateContextResource(StrictImmutableBoundaryModel):
    binding: ResourceBinding
    resource_type: DataResourceType
    verification_state: str = Field(min_length=1)
    classification: str = Field(min_length=1)
    source_index_id: str = Field(min_length=1)


class ContextSelectionRequest(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    current_targets: tuple[TargetReference, ...]
    candidate_session_ids: tuple[str, ...]
    operational_phase: OperationalPhase

