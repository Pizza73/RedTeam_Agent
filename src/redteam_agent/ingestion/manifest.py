"""Secure ingestion manifest / redaction metadata / result (SystemDesign §33 / §33.2).

The manifest is a metadata ledger of which input produced which outputs; it is not
authority or proof of an LLM finding. It never contains a secret value, ciphertext,
key handle or provider temp path.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from redteam_agent.ingestion.artifact_store import ArtifactReference
from redteam_agent.models.base import StrictImmutableBoundaryModel


class RedactionMetadata(StrictImmutableBoundaryModel):
    rule_version: str = Field(min_length=1)
    redaction_count: int = Field(ge=0)
    secret_detection_count: int = Field(ge=0)
    publication_rule_id: str = Field(min_length=1)
    publication_rule_digest: str = Field(min_length=1)
    omitted_reason_codes: tuple[str, ...]
    redaction_metadata_digest: str = Field(min_length=1)


class SecretVersionManifestEntry(StrictImmutableBoundaryModel):
    secret_id: str = Field(min_length=1)
    secret_version_id: str = Field(min_length=1)
    metadata_digest: str = Field(min_length=1)
    lifecycle_head_digest: str = Field(min_length=1)


class SecureIngestionManifest(StrictImmutableBoundaryModel):
    manifest_id: str = Field(min_length=1)
    ingestion_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    receipt_id: str = Field(min_length=1)
    receipt_digest: str = Field(min_length=1)
    quarantine_id: str = Field(min_length=1)
    quarantine_ciphertext_digest: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    output_publication_rule_id: str = Field(min_length=1)
    output_publication_rule_digest: str = Field(min_length=1)
    result_task_binding_digest: str = Field(min_length=1)
    redacted_artifacts: tuple[ArtifactReference, ...]
    encrypted_raw_artifacts: tuple[ArtifactReference, ...]
    detected_secrets: tuple[SecretVersionManifestEntry, ...]
    redaction_metadata_digest: str = Field(min_length=1)
    execution_result_projection_id: str = Field(min_length=1)
    execution_result_projection_digest: str = Field(min_length=1)
    created_at: datetime
    manifest_digest: str = Field(min_length=1)
