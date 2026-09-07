"""Secret lifecycle models (SystemDesign §34 / R10).

``secret_id`` is the stable logical id; ``secret_version_id`` is the immutable value
version id. None of these models carry a secret value, ciphertext or key handle.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.models.base import StrictImmutableBoundaryModel

SecretLifecycleState = Literal["DETECTED", "CONFIRMED", "REVOKED", "SUPERSEDED"]


class SecretVersionRecord(StrictImmutableBoundaryModel):
    secret_id: str = Field(min_length=1)
    secret_version_id: str = Field(min_length=1)
    version: int = Field(ge=1)
    supersedes_secret_version_id: str | None
    mission_id: str = Field(min_length=1)
    credential_type: str = Field(min_length=1)
    associated_principal_ref: str | None
    encryption_metadata_id: str = Field(min_length=1)
    created_at: datetime
    expires_at: datetime | None
    metadata_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _first_version_has_no_predecessor(self) -> SecretVersionRecord:
        if self.version == 1 and self.supersedes_secret_version_id is not None:
            raise ValueError("the first version has no predecessor")
        if self.version > 1 and self.supersedes_secret_version_id is None:
            raise ValueError("a non-first version records its predecessor")
        return self


class SecretLifecycleEvent(StrictImmutableBoundaryModel):
    event_id: str = Field(min_length=1)
    secret_version_id: str = Field(min_length=1)
    sequence_number: int = Field(ge=1)
    event_type: SecretLifecycleState
    actor_id: str = Field(min_length=1)
    actor_role: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=1)
    confirmation_record_id: str | None
    reason_code: str = Field(min_length=1)
    occurred_at: datetime
    previous_event_digest: str | None
    event_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _confirmation_only_on_confirmed(self) -> SecretLifecycleEvent:
        if self.event_type == "CONFIRMED" and self.confirmation_record_id is None:
            raise ValueError("a CONFIRMED event requires a confirmation record id")
        if self.event_type != "CONFIRMED" and self.confirmation_record_id is not None:
            raise ValueError("only a CONFIRMED event may carry a confirmation record id")
        if self.sequence_number == 1:
            if self.event_type != "DETECTED":
                raise ValueError("the first lifecycle event must be DETECTED")
            if self.previous_event_digest is not None:
                raise ValueError("the first lifecycle event has no previous digest")
        elif self.previous_event_digest is None:
            raise ValueError("a non-first lifecycle event requires a previous digest")
        return self


class SecretConfirmationRecord(StrictImmutableBoundaryModel):
    confirmation_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    secret_version_id: str = Field(min_length=1)
    secret_metadata_digest: str = Field(min_length=1)
    expected_lifecycle_head_digest: str = Field(min_length=1)
    expected_logical_version_head_digest: str = Field(min_length=1)
    replaces_active_version_id: str | None
    source_evidence_digest: str = Field(min_length=1)
    method: Literal["operator_review"] = "operator_review"
    approver_id: str = Field(min_length=1)
    approver_role: Literal["approver"] = "approver"
    confirmed_at: datetime
    record_digest: str = Field(min_length=1)


class SecretLogicalHead(StrictImmutableBoundaryModel):
    secret_id: str = Field(min_length=1)
    head_version: int = Field(ge=1)
    head_version_id: str = Field(min_length=1)
    head_digest: str = Field(min_length=1)


class SecretActiveHead(StrictImmutableBoundaryModel):
    secret_id: str = Field(min_length=1)
    active_version_id: str | None
    revision: int = Field(ge=1)
    head_digest: str = Field(min_length=1)
