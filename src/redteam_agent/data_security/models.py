"""Strict Phase 0C data-security boundary models."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.canonical.models import CanonicalJsonObject
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import UtcDatetime

KeyDomain = Literal[
    "secret_store",
    "raw_result_quarantine",
    "artifact_store",
    "audit_signing",
]
RotationState = Literal["active", "decrypt_only", "revoked", "destroyed"]


class EncryptionMetadata(StrictImmutableBoundaryModel):
    key_domain: KeyDomain
    key_id: str = Field(min_length=1)
    key_version: int = Field(ge=1)
    encryption_algorithm: str = Field(min_length=1)
    key_separation_tag: str = Field(min_length=1)
    created_at: UtcDatetime
    rotation_state: RotationState


class EncryptedPayload(StrictImmutableBoundaryModel):
    metadata: EncryptionMetadata
    nonce: str = Field(min_length=1)
    ciphertext: str
    authentication_tag: str = Field(min_length=1)
    aad_digest: str = Field(min_length=1)


class ArtifactReference(StrictImmutableBoundaryModel):
    artifact_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    classification: Literal["normal", "sensitive", "secret"]
    variant: Literal["redacted", "encrypted_raw"]
    encrypted: bool
    encryption_metadata_id: str | None
    derived_from_artifact_id: str | None
    created_at: UtcDatetime
    retention_until: UtcDatetime | None

    @model_validator(mode="after")
    def encryption_invariants(self) -> ArtifactReference:
        if self.encrypted != (self.encryption_metadata_id is not None):
            raise ValueError("artifact encryption metadata is inconsistent")
        if self.variant == "encrypted_raw" and (
            self.classification != "secret" or not self.encrypted
        ):
            raise ValueError("encrypted raw artifacts must be encrypted and secret")
        if self.retention_until is not None and self.retention_until <= self.created_at:
            raise ValueError("artifact retention must follow creation")
        return self


class SecretDiscoveryReference(StrictImmutableBoundaryModel):
    secret_reference_id: str = Field(min_length=1)
    credential_type: str = Field(min_length=1)
    associated_principal_ref: str | None
    source_execution_id: str = Field(min_length=1)
    verification_state: Literal["detected", "confirmed", "revoked"]


class RedactionMetadata(StrictImmutableBoundaryModel):
    rule_version: str = Field(min_length=1)
    redaction_count: int = Field(ge=0)
    secret_detection_count: int = Field(ge=0)


class SecureIngestionResult(StrictImmutableBoundaryModel):
    ingestion_id: str = Field(min_length=1)
    ingestion_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redacted_artifacts: tuple[ArtifactReference, ...]
    encrypted_raw_artifacts: tuple[ArtifactReference, ...]
    detected_secrets: tuple[SecretDiscoveryReference, ...]
    redaction_metadata: RedactionMetadata


class SecretReferenceMetadata(StrictImmutableBoundaryModel):
    secret_reference_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    credential_type: str = Field(min_length=1)
    associated_principal_ref: str | None
    encryption_metadata_id: str = Field(min_length=1)
    created_at: UtcDatetime
    expires_at: UtcDatetime | None
    verification_state: Literal["detected", "confirmed", "revoked"]

    @model_validator(mode="after")
    def valid_expiry(self) -> SecretReferenceMetadata:
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("secret expiry must follow creation")
        return self


class QuarantineReference(StrictImmutableBoundaryModel):
    quarantine_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    execution_id: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    encryption_metadata_id: str = Field(min_length=1)
    created_at: UtcDatetime
    retention_until: UtcDatetime

    @model_validator(mode="after")
    def valid_retention(self) -> QuarantineReference:
        if self.retention_until <= self.created_at:
            raise ValueError("quarantine retention must follow creation")
        return self


class AuditEvent(StrictImmutableBoundaryModel):
    event_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    chain_scope: Literal["mission"]
    sequence_number: int = Field(ge=1)
    previous_event_hash: str | None
    event_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    event_type: str = Field(min_length=1)
    canonical_payload: CanonicalJsonObject
    occurred_at: UtcDatetime
