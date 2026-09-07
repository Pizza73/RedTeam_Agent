"""Non-secret key metadata and envelope records (SystemDesign §34.1).

The normal application database stores only these non-secret metadata records and
digests. Domain KEK material, resource DEK material and wrapped-key bytes are never
stored here; they live in the key provider's own storage. Every model is a strict,
frozen boundary model whose object-integrity digest is verified on write and read.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.models.base import StrictImmutableBoundaryModel

KeyDomain = Literal["secret_store", "raw_result_quarantine", "artifact_store", "audit_signing"]

RotationState = Literal["active", "decrypt_only", "revoked", "destroyed"]

KeyDestructionState = Literal["NOT_STARTED", "CONFIRMED", "UNKNOWN", "FAILED"]


class DomainKeyMetadata(StrictImmutableBoundaryModel):
    key_domain: KeyDomain
    domain_key_id: str = Field(min_length=1)
    domain_key_version: int = Field(ge=1)
    provider_identity: str = Field(min_length=1)
    key_separation_tag: str = Field(min_length=1)
    algorithm: str = Field(min_length=1)
    rotation_state: RotationState
    metadata_digest: str = Field(min_length=1)


class EncryptionMetadata(StrictImmutableBoundaryModel):
    key_domain: KeyDomain
    resource_key_id: str = Field(min_length=1)
    resource_key_version: int = Field(ge=1)
    resource_binding_type: str = Field(min_length=1)
    resource_binding_id: str = Field(min_length=1)
    domain_key_id: str = Field(min_length=1)
    domain_key_version: int = Field(ge=1)
    wrapped_resource_key_digest: str = Field(min_length=1)
    encryption_algorithm: str = Field(min_length=1)
    nonce_strategy_revision: str = Field(min_length=1)
    created_at: datetime
    rotation_state: RotationState
    metadata_digest: str = Field(min_length=1)


class KeyDestructionResult(StrictImmutableBoundaryModel):
    erasure_id: str = Field(min_length=1)
    resource_key_id: str = Field(min_length=1)
    key_metadata_digest: str = Field(min_length=1)
    state: KeyDestructionState
    provider_operation_id: str | None
    resource_copy_inventory_digest: str = Field(min_length=1)
    erasure_evidence_digest: str | None
    result_digest: str = Field(min_length=1)


class EnvelopeCiphertext(StrictImmutableBoundaryModel):
    """A stored ciphertext: non-secret decryption metadata plus the ciphertext+tag.

    The plaintext body is never present. ``aad_digest`` records the exact AAD used so
    a mismatched domain/mission/execution/resource binding is detected before the
    AEAD authentication check.
    """

    encryption_metadata_id: str = Field(min_length=1)
    key_domain: KeyDomain
    algorithm_id: str = Field(min_length=1)
    nonce: str = Field(min_length=1)  # hex-encoded, unique per resource key
    ciphertext: str = Field(min_length=0)  # hex-encoded ciphertext + appended tag
    aad_digest: str = Field(min_length=1)
    ciphertext_digest: str = Field(min_length=1)
