"""Audit / generation-witness models (SystemDesign §34.2 / §34.2.1 / §34.2.2).

These are strict, frozen boundary models. The authority for the current committed
state is the pair (TPM current NV Extend digest, the exact authenticated record/blob
that reproduces it); a logical generation number alone is never authority.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.models.base import StrictImmutableBoundaryModel

GenerationNamespace = Literal["audit_head", "wrapped_key_state"]
NvRole = Literal["audit_head", "wrapped_key_state", "deployment_epoch"]


# --- mission-scoped audit hash chain --------------------------------------


class AuditEvent(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    sequence_number: int = Field(ge=1)
    event_type: str = Field(min_length=1)
    payload_digest: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    previous_event_digest: str | None
    occurred_at_iso: str = Field(min_length=1)
    event_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _genesis_has_no_previous(self) -> AuditEvent:
        if self.sequence_number == 1 and self.previous_event_digest is not None:
            raise ValueError("the first audit event must have no previous digest")
        if self.sequence_number > 1 and self.previous_event_digest is None:
            raise ValueError("a non-first audit event requires a previous digest")
        return self


class AuditChainHead(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    head_sequence: int = Field(ge=1)
    head_event_digest: str = Field(min_length=1)
    updated_at_iso: str = Field(min_length=1)
    head_digest: str = Field(min_length=1)


# --- TPM-witnessed generation commit --------------------------------------


class GenerationCommitRecord(StrictImmutableBoundaryModel):
    namespace: GenerationNamespace
    trust_epoch: int = Field(ge=1)
    generation: int = Field(ge=0)
    immutable_blob_id: str = Field(min_length=1)
    state_digest: str = Field(min_length=1)
    previous_anchor_digest: str | None
    schema_version: str = Field(min_length=1)
    digest_catalog_revision: str = Field(min_length=1)
    tpm_nv_index_identity: str = Field(min_length=1)
    witness_mode: Literal["nv_extend_sha256_v1"] = "nv_extend_sha256_v1"
    previous_witness_digest: str = Field(min_length=1)
    commit_payload_digest: str = Field(min_length=1)
    witness_digest: str = Field(min_length=1)
    record_digest: str = Field(min_length=1)
    record_authentication_tag: str = Field(min_length=1)

    @model_validator(mode="after")
    def _genesis_previous_anchor(self) -> GenerationCommitRecord:
        if self.generation == 0 and self.previous_anchor_digest is not None:
            raise ValueError("logical generation 0 must have previous_anchor_digest=None")
        if self.generation > 0 and self.previous_anchor_digest is None:
            raise ValueError("a non-genesis generation requires a previous anchor digest")
        return self


class ImmutableGenerationBlob(StrictImmutableBoundaryModel):
    """Content-addressed immutable blob referenced by a generation record."""

    blob_id: str = Field(min_length=1)
    namespace: GenerationNamespace
    content_kind: Literal["audit_head_set", "wrapped_key_state"]
    content: str = Field(min_length=1)  # canonical-JSON payload (encrypted for wrapped_key_state)
    blob_digest: str = Field(min_length=1)


class WrappedKeyState(StrictImmutableBoundaryModel):
    state_revision: str = Field(min_length=1)
    provider_identity: str = Field(min_length=1)
    domain_key_metadata_digests: tuple[str, ...]
    wrapped_provider_state_blob_id: str = Field(min_length=1)
    wrapped_provider_state_digest: str = Field(min_length=1)
    active_domain_key_bindings_digest: str = Field(min_length=1)
    previous_state_digest: str | None
    state_digest: str = Field(min_length=1)


class GenerationWitnessPolicy(StrictImmutableBoundaryModel):
    policy_revision: str = Field(min_length=1)
    max_unwitnessed_events: int = Field(gt=0)
    max_unwitnessed_seconds: int = Field(gt=0)
    force_event_types: frozenset[str]
    critical_state_catalog_revision: str = Field(min_length=1)
    critical_state_catalog_digest: str = Field(min_length=1)
    policy_digest: str = Field(min_length=1)


class SecurityStateBinding(StrictImmutableBoundaryModel):
    record_type: str = Field(min_length=1)
    record_id: str = Field(min_length=1)
    state_version: int = Field(ge=1)
    security_projection_digest: str = Field(min_length=1)
    audit_event_digest: str = Field(min_length=1)
    binding_digest: str = Field(min_length=1)


class CriticalWitnessIntent(StrictImmutableBoundaryModel):
    witness_intent_id: str = Field(min_length=1)
    operation_id: str = Field(min_length=1)
    input_digest: str = Field(min_length=1)
    expected_generation: int = Field(ge=0)
    expected_witness_digest: str = Field(min_length=1)
    trust_epoch: int = Field(ge=1)
    tpm_nv_index_identity: str = Field(min_length=1)
    bindings: tuple[SecurityStateBinding, ...]
    intent_digest: str = Field(min_length=1)


# --- fixed NV identity / dynamic state (F7, SystemDesign §34.2.2) ---------


class ProvisionedNvIdentity(StrictImmutableBoundaryModel):
    identity_schema: Literal["nv-index-identity-v1"] = "nv-index-identity-v1"
    registered_device_identity_digest: str = Field(min_length=1)
    trust_epoch: int = Field(ge=1)
    provisioning_incarnation_id: str = Field(min_length=1)
    nv_index: int = Field(ge=0)
    role: NvRole
    name_algorithm: Literal["sha256"] = "sha256"
    static_attributes: int = Field(ge=0)
    auth_policy_digest: str = Field(min_length=1)
    data_size: int = Field(gt=0)
    identity_digest: str = Field(min_length=1)


class NvPublicArea(StrictImmutableBoundaryModel):
    """The dynamic NV public area read back from the device (F7)."""

    role: NvRole
    nv_index: int = Field(ge=0)
    name_algorithm: Literal["sha256"] = "sha256"
    static_attributes: int = Field(ge=0)
    written: bool
    write_locked: bool
    read_locked: bool
    auth_policy_digest: str = Field(min_length=1)
    data_size: int = Field(gt=0)
    name: str = Field(min_length=1)  # full TPM NV Name (hex), computed from the public area


# --- explicit offline trust recovery ------------------------------------


class RecoveryNamespaceAdoption(StrictImmutableBoundaryModel):
    namespace: GenerationNamespace
    last_verified_record_digest: str = Field(min_length=1)
    last_verified_witness_digest: str = Field(min_length=1)
    adopted_state_digest: str = Field(min_length=1)
    adopted_blob_id: str = Field(min_length=1)
    adopted_content_digest: str = Field(min_length=1)


class TrustRecoveryApproval(StrictImmutableBoundaryModel):
    approval_id: str = Field(min_length=1)
    old_trust_epoch: int = Field(ge=1)
    new_trust_epoch: int = Field(ge=1)
    old_nv_identity_digests: tuple[str, str, str]
    new_nv_identity_digests: tuple[str, str, str]
    adoptions: tuple[RecoveryNamespaceAdoption, RecoveryNamespaceAdoption]
    worker_stop_evidence_digest: str = Field(min_length=1)
    adoption_reason: str = Field(min_length=1)
    approver_id: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    approval_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _valid_epoch_and_namespaces(self) -> TrustRecoveryApproval:
        if self.new_trust_epoch <= self.old_trust_epoch:
            raise ValueError("trust recovery must advance the trust epoch")
        if {item.namespace for item in self.adoptions} != {"audit_head", "wrapped_key_state"}:
            raise ValueError("trust recovery must adopt both generation namespaces exactly once")
        if self.expires_at <= self.issued_at:
            raise ValueError("trust recovery approval must have a positive validity window")
        return self


class TrustRecoveryConsumption(StrictImmutableBoundaryModel):
    consumption_id: str = Field(min_length=1)
    approval_id: str = Field(min_length=1)
    approval_digest: str = Field(min_length=1)
    new_trust_epoch: int = Field(ge=1)
    new_witness_digests: tuple[str, str]
    deployment_epoch: int = Field(ge=1)
    worker_stop_evidence_digest: str = Field(min_length=1)
    invalidated_authorization_count: int = Field(ge=0)
    invalidated_authorization_digest: str = Field(min_length=1)
    audit_discontinuity_digest: str = Field(min_length=1)
    consumed_at: datetime
    consumption_digest: str = Field(min_length=1)
