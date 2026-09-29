"""Execution-safety records and state literals (SystemDesign §10, Phase 0B).

Provider execution state and result-ingestion state are kept in *separate*
durable records so an ingestion state can never be mistaken for provider
progress or dispatch authority. Every record here is a strict, frozen boundary
model; discriminated unions (``ResultTaskBinding``) reject unknown modes and a
missing discriminated branch. Digests are object-integrity digests verified on
write and read by the repositories.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ToolRef

# --- state literals (SystemDesign §10) ------------------------------------

ProviderExecutionState = Literal[
    "PLANNED",
    "AUTHORIZED",
    "DISPATCH_CLAIMED",
    "DISPATCHED",
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "BLOCKED",
    "CANCEL_REQUESTED",
    "CANCELLED",
    "RECONCILING",
    "OUTCOME_UNKNOWN",
]

PreDispatchBlockReason = Literal[
    "SESSION_STALE",
    "MISSION_NOT_RUNNING",
    "POLICY_STALE",
    "SNAPSHOT_STALE",
    "SANDBOX_CAPABILITY_MISMATCH",
    "ADAPTER_CAPABILITY_MISMATCH",
    "APPROVAL_INVALID",
    "AUTHORIZATION_TTL_EXPIRED",
    "AUTHORIZATION_EPOCH_MISMATCH",
    "REMOTE_MCP_TRUST_MISMATCH",
    "ENCRYPTION_KEY_UNAVAILABLE",
    "SECRET_VERSION_STALE",
    "MISSION_EXPIRED",
    "DIGEST_INTEGRITY_FAILURE",
]

ResultCollectionStatus = Literal[
    "NOT_STARTED",
    "STREAMING",
    "COMMITTED_METADATA_PENDING",
    "COMPLETE",
    "ABANDONED",
]

ResultIngestionStatus = Literal[
    "NOT_AVAILABLE",
    "PENDING",
    "INGESTING",
    "DELETE_PENDING",
    "ERASURE_CLAIMED",
    "QUARANTINE_ERASED",
    "SUCCEEDED",
    "FAILED",
    "QUARANTINED",
    "EVIDENCE_RETENTION_EXPIRED",
    "ERASURE_COMPLETED_UNRESOLVED",
]

ClaimState = Literal["unconsumed", "consumed", "invalidated"]

ResultDeliveryMode = Literal["provider_task", "local_result"]


# --- result task binding (SystemDesign §10 / §10.5) -----------------------


class ProviderTaskBinding(StrictImmutableBoundaryModel):
    binding_type: Literal["provider_task"] = "provider_task"
    task_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    adapter_identity_digest: str = Field(min_length=1)
    provider_identity_digest: str = Field(min_length=1)
    provider_task_id: str = Field(min_length=1)
    dispatch_claim_id: str = Field(min_length=1)
    binding_digest: str = Field(min_length=1)


class LocalResultBinding(StrictImmutableBoundaryModel):
    binding_type: Literal["local_result"] = "local_result"
    task_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    adapter_identity_digest: str = Field(min_length=1)
    dispatch_claim_id: str = Field(min_length=1)
    capture_id: str = Field(min_length=1)
    binding_digest: str = Field(min_length=1)


# A provider_task | local_result discriminated union. ``local_capture``, an
# unknown discriminant, or a branch missing its required fields is rejected by
# pydantic at the boundary; there is no alias conversion (SystemDesign §10.5).
ResultTaskBinding = Annotated[
    ProviderTaskBinding | LocalResultBinding,
    Field(discriminator="binding_type"),
]


# --- raw result metadata (SystemDesign §10) -------------------------------


class RawArtifactMetadata(StrictImmutableBoundaryModel):
    artifact_sequence: int = Field(ge=0)
    suggested_name: str | None
    media_type: str | None
    declared_size: int | None = Field(default=None, ge=0)


class RawResultReceipt(StrictImmutableBoundaryModel):
    receipt_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    quarantine_id: str = Field(min_length=1)
    task_binding_digest: str = Field(min_length=1)
    stdout_bytes: int = Field(ge=0)
    stderr_bytes: int = Field(ge=0)
    artifact_count: int = Field(ge=0)
    ciphertext_digest: str = Field(min_length=1)
    committed_at: datetime


class RawControlMetadataRecord(StrictImmutableBoundaryModel):
    control_record_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    task_binding_digest: str = Field(min_length=1)
    receipt_id: str = Field(min_length=1)
    receipt_digest: str = Field(min_length=1)
    status_normalization_rule_id: str = Field(min_length=1)
    provider_status: Literal["succeeded", "failed", "cancelled"]
    exit_code: int | None
    timed_out: bool
    provider_started_at: datetime
    provider_finished_at: datetime
    trusted_received_at: datetime
    record_digest: str = Field(min_length=1)


class ExecutionResultProjection(StrictImmutableBoundaryModel):
    projection_id: str = Field(min_length=1)
    projection_digest: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    task_binding: ResultTaskBinding
    receipt_id: str = Field(min_length=1)
    receipt_digest: str = Field(min_length=1)
    provider_status: Literal["succeeded", "failed", "cancelled"]
    exit_code: int | None
    timed_out: bool
    started_at: datetime
    finished_at: datetime
    stdout_preview_artifact_id: str | None
    stderr_preview_artifact_id: str | None
    redaction_metadata_digest: str = Field(min_length=1)


class AdapterRawResult(StrictImmutableBoundaryModel):
    """Compatibility term for control metadata + receipt only, never raw bytes."""

    execution_id: str = Field(min_length=1)
    task_binding: ResultTaskBinding
    provider_status: str = Field(min_length=1)
    receipt: RawResultReceipt
    exit_code: int | None
    timed_out: bool
    started_at: datetime
    finished_at: datetime


class ExecutionResult(StrictImmutableBoundaryModel):
    """Application-normalized result. Built only from manifest/projection metadata.

    ``provider_task_id`` is a UI-compatibility, non-authorization projection: it
    is the exact provider task id for a provider_task binding and ``None`` for a
    local_result binding (SystemDesign §10.5). No ``detected_secrets`` field.
    """

    execution_id: str = Field(min_length=1)
    provider_task_id: str | None
    adapter_id: str = Field(min_length=1)
    tool_ref: ToolRef
    policy_decision_id: str = Field(min_length=1)
    secure_ingestion_id: str = Field(min_length=1)
    status: Literal["SUCCEEDED", "FAILED", "CANCELLED"]
    timed_out: bool
    started_at: datetime
    finished_at: datetime
    stdout_preview: str | None
    stderr_preview: str | None
    redacted_artifact_ids: tuple[str, ...]
    exit_code: int | None


# --- durable execution / dispatch records (SystemDesign §10 / §10.1) ------


class ExecutionRecord(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    execution_state_version: int = Field(ge=1)
    record_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    plan_id: str = Field(min_length=1)
    policy_decision_id: str = Field(min_length=1)
    proposal_digest: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    tool_ref: ToolRef
    resolved_adapter_id: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)
    adapter_capabilities_digest: str = Field(min_length=1)
    sandbox_capabilities_digest: str = Field(min_length=1)
    remote_mcp_trust_policy_digest: str = Field(min_length=1)
    provider_execution_state: ProviderExecutionState
    pre_dispatch_block_reason: PreDispatchBlockReason | None
    result_collection_state_id: str | None
    result_ingestion_state: ResultIngestionStatus
    raw_result_quarantine_id: str | None
    result_task_binding_id: str | None
    dispatch_attempts: int = Field(ge=0, le=1)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def _block_reason_consistency(self) -> ExecutionRecord:
        # A block reason exists iff the state is BLOCKED.
        if self.provider_execution_state == "BLOCKED":
            if self.pre_dispatch_block_reason is None:
                raise ValueError("BLOCKED execution requires a pre_dispatch_block_reason")
        elif self.pre_dispatch_block_reason is not None:
            raise ValueError("pre_dispatch_block_reason is only valid for a BLOCKED execution")
        if self.provider_execution_state in ("PLANNED", "AUTHORIZED") and self.dispatch_attempts != 0:
            raise ValueError("pre-dispatch execution must have zero dispatch attempts")
        if self.provider_execution_state not in ("PLANNED", "AUTHORIZED", "BLOCKED") \
                and self.dispatch_attempts != 1:
            raise ValueError("post-claim execution must have exactly one dispatch attempt")
        if self.provider_execution_state == "BLOCKED":
            if self.pre_dispatch_block_reason != "SECRET_VERSION_STALE" and self.dispatch_attempts != 0:
                raise ValueError("pre-dispatch BLOCKED execution must have zero attempts")
            if self.result_task_binding_id is not None or self.raw_result_quarantine_id is not None:
                raise ValueError("BLOCKED execution must not carry result bindings")
            if self.result_ingestion_state != "NOT_AVAILABLE":
                raise ValueError("BLOCKED execution cannot have result ingestion state")
        return self


class DispatchClaim(StrictImmutableBoundaryModel):
    claim_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    execution_state_version: int = Field(ge=1)
    policy_decision_id: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    tool_ref: ToolRef
    resolved_adapter_id: str = Field(min_length=1)
    approval_request_id: str | None
    approval_record_id: str | None
    secret_version_bindings_digest: str = Field(min_length=1)
    secret_lifecycle_heads_digest: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    claim_state: ClaimState
    consumption_id: str | None
    consumed_at: datetime | None
    invalidated_at: datetime | None
    invalidation_reason: str | None
    record_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _state_field_consistency(self) -> DispatchClaim:
        # unconsumed: all consumption/invalidation fields None.
        # consumed: consumption fields set, invalidation fields None.
        # invalidated: invalidation fields set, consumption fields None.
        consumption_set = self.consumption_id is not None or self.consumed_at is not None
        invalidation_set = self.invalidated_at is not None or self.invalidation_reason is not None
        if self.claim_state == "unconsumed":
            if consumption_set or invalidation_set:
                raise ValueError("unconsumed claim must have no consumption/invalidation fields")
        elif self.claim_state == "consumed":
            if self.consumption_id is None or self.consumed_at is None:
                raise ValueError("consumed claim requires consumption_id and consumed_at")
            if invalidation_set:
                raise ValueError("consumed claim must not carry invalidation fields")
        else:  # invalidated
            if self.invalidated_at is None or self.invalidation_reason is None:
                raise ValueError("invalidated claim requires invalidated_at and invalidation_reason")
            if consumption_set:
                raise ValueError("invalidated claim must not carry consumption fields")
        return self


# --- result collection (SystemDesign §10 / §10.3) -------------------------


class ResultCollectionAuthority(StrictImmutableBoundaryModel):
    collection_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    task_binding: ResultTaskBinding
    tool_ref: ToolRef
    tool_registry_digest: str = Field(min_length=1)
    max_output_bytes: int = Field(gt=0)
    collection_started_at: datetime
    collection_deadline: datetime
    retention_until: datetime
    sink_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def _time_window_is_positive(self) -> ResultCollectionAuthority:
        if not (self.collection_started_at < self.collection_deadline):
            raise ValueError("collection deadline must follow collection start")
        if not (self.collection_started_at < self.retention_until):
            raise ValueError("retention must follow collection start")
        return self


class ResultCollectionStateRecord(StrictImmutableBoundaryModel):
    collection_state_id: str = Field(min_length=1)
    collection_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    state_version: int = Field(ge=1)
    status: ResultCollectionStatus
    receipt_id: str | None
    receipt_digest: str | None
    last_committed_chunk_sequence: int = Field(ge=0)
    last_progress_digest: str = Field(min_length=1)
    updated_at: datetime
    record_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _receipt_fields_match_state(self) -> ResultCollectionStateRecord:
        pair_set = self.receipt_id is not None and self.receipt_digest is not None
        pair_empty = self.receipt_id is None and self.receipt_digest is None
        if not (pair_set or pair_empty):
            raise ValueError("receipt id and digest must be present together")
        if self.status in ("NOT_STARTED", "STREAMING") and not pair_empty:
            raise ValueError("uncommitted collection cannot carry a receipt")
        if self.status in ("COMMITTED_METADATA_PENDING", "COMPLETE") and not pair_set:
            raise ValueError("committed collection requires a receipt")
        return self


class AdapterCollectionControl(StrictImmutableBoundaryModel):
    """Control metadata only (no raw bytes): the adapter streamed content to the
    sink and returns normalization inputs (SystemDesign §10)."""

    provider_status: Literal["succeeded", "failed", "cancelled"]
    exit_code: int | None
    timed_out: bool
    started_at: datetime
    finished_at: datetime
    status_normalization_rule_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def _timestamps_are_ordered(self) -> AdapterCollectionControl:
        if self.finished_at < self.started_at:
            raise ValueError("collection finish precedes start")
        return self


class CollectionResumeCursor(StrictImmutableBoundaryModel):
    """A non-authority resume control bound to the exact task binding and sink.

    It carries only progress needed to resume a bounded read; it is never an
    authorization and cannot be reused across task, sink or mode (SystemDesign §10.3.1).
    """

    collection_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    result_delivery_mode: ResultDeliveryMode
    task_binding_digest: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    last_committed_chunk_sequence: int = Field(ge=0)
    receipt_id: str | None

    @model_validator(mode="after")
    def _progress_fields_match(self) -> CollectionResumeCursor:
        if self.last_committed_chunk_sequence == 0 and self.receipt_id is not None:
            raise ValueError("initial resume cursor must not carry a receipt")
        if self.last_committed_chunk_sequence > 0 and self.receipt_id is None:
            raise ValueError("committed resume progress requires a receipt")
        return self


class CollectionCancellation(StrictImmutableBoundaryModel):
    """A non-authority receive-stop control (not a provider cancel), bound to the
    exact task binding and sink (SystemDesign §10.3.1)."""

    collection_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    task_binding_digest: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    reason: str


class LeaseFence(StrictImmutableBoundaryModel):
    trust_epoch: int = Field(ge=1)
    deployment_epoch: int = Field(ge=1)
    fencing_token: int = Field(ge=1)


class ResultCollectionLease(StrictImmutableBoundaryModel):
    collection_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    authority_digest: str = Field(min_length=1)
    task_binding: ResultTaskBinding
    sink_id: str = Field(min_length=1)
    owner_id: str = Field(min_length=1)
    lease_id: str = Field(min_length=1)
    fence: LeaseFence
    expected_execution_state_version: int = Field(ge=1)
    acquired_at: datetime
    lease_expires_at: datetime
    lease_deadline_monotonic_ns: int = Field(ge=1)
    released_at: datetime | None
    updated_at: datetime
    record_digest: str = Field(min_length=1)


class SecureIngestionLease(StrictImmutableBoundaryModel):
    ingestion_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    receipt_digest: str = Field(min_length=1)
    quarantine_digest: str = Field(min_length=1)
    evidence_retention_until: datetime
    owner_id: str = Field(min_length=1)
    lease_id: str = Field(min_length=1)
    fence: LeaseFence
    expected_ingestion_state_version: int = Field(ge=1)
    acquired_at: datetime
    lease_expires_at: datetime
    lease_deadline_monotonic_ns: int = Field(ge=1)
    released_at: datetime | None
    updated_at: datetime
    record_digest: str = Field(min_length=1)


# --- result ingestion (SystemDesign §10 / §10.4) --------------------------


class ResultIngestionStateRecord(StrictImmutableBoundaryModel):
    """Independent ingestion state, separate from the provider execution record."""

    ingestion_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    collection_id: str = Field(min_length=1)
    state_version: int = Field(ge=1)
    status: ResultIngestionStatus
    receipt_id: str | None
    receipt_digest: str | None
    quarantine_id: str | None
    attempt_count: int = Field(ge=0)
    manifest_id: str | None
    manifest_digest: str | None
    ingested_durable_at: datetime | None
    evidence_retention_until: datetime
    updated_at: datetime
    record_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _ingestion_evidence_is_consistent(self) -> ResultIngestionStateRecord:
        if (self.receipt_id is None) != (self.receipt_digest is None):
            raise ValueError("ingestion receipt id and digest must be present together")
        if (self.manifest_id is None) != (self.manifest_digest is None):
            raise ValueError("ingestion manifest id and digest must be present together")
        if self.status != "NOT_AVAILABLE" and (
            self.receipt_id is None or self.quarantine_id is None
        ):
            raise ValueError("available ingestion state requires receipt and quarantine bindings")
        if self.ingested_durable_at is not None and self.manifest_id is None:
            raise ValueError("durable ingestion milestone requires a manifest")
        return self


class SecureIngestionRetryPolicy(StrictImmutableBoundaryModel):
    policy_revision: str = Field(min_length=1)
    max_attempts_per_ingestion: int = Field(gt=0)
    require_same_receipt_digest: Literal[True] = True
    require_same_quarantine_digest: Literal[True] = True
    require_same_rule_version: Literal[True] = True
    require_same_projection_schema: Literal[True] = True


class SecureIngestionAttempt(StrictImmutableBoundaryModel):
    ingestion_id: str = Field(min_length=1)
    attempt_number: int = Field(ge=1)
    receipt_digest: str = Field(min_length=1)
    quarantine_digest: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    projection_schema_digest: str = Field(min_length=1)
    reason_code: str
    started_at: datetime
    attempt_digest: str = Field(min_length=1)


# --- recovery / cancel (SystemDesign §21.1.1 / §21.1.2) -------------------

RecoveryOperation = Literal["reconcile", "cancel", "collect_result"]


class ExecutionRecoveryAuthority(StrictImmutableBoundaryModel):
    """Purpose-limited, single-use authority for recovering an existing execution.

    Not a bearer token: services re-load the current record before use. TTL is
    ``issued_at < expires_at <= min(issued_at + 60s, mission.recovery_until)``.
    """

    authority_id: str = Field(min_length=1)
    authority_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    execution_id: str = Field(min_length=1)
    origin_authorization_digest: str = Field(min_length=1)
    resolved_adapter_id: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)
    allowed_operation: RecoveryOperation
    expected_execution_state_version: int = Field(ge=1)
    result_task_binding_id: str | None
    recovery_policy_revision: str = Field(min_length=1)
    reason: str
    issued_at: datetime
    expires_at: datetime


CancelAttemptState = Literal["CLAIMED", "ACKNOWLEDGED", "CONFIRMED", "UNKNOWN", "FAILED"]


class CancelAttempt(StrictImmutableBoundaryModel):
    cancel_attempt_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    provider_task_id: str = Field(min_length=1)
    resolved_adapter_id: str = Field(min_length=1)
    recovery_authority_id: str = Field(min_length=1)
    cancel_intent_digest: str = Field(min_length=1)
    reason: str
    attempt_state: CancelAttemptState
    consumption_id: str = Field(min_length=1)
    pre_transition_execution_state_version: int = Field(ge=1)
    post_transition_execution_state_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    record_digest: str = Field(min_length=1)


# --- durable mission execution budget (SystemDesign §27.1) ----------------


class MissionExecutionBudget(StrictImmutableBoundaryModel):
    """Durable, OCC-guarded per-mission dispatch budget (no in-memory counting)."""

    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    budget_version: int = Field(ge=1)
    max_dispatch_claims: int = Field(gt=0)
    consumed_dispatch_claims: int = Field(ge=0)
    updated_at: datetime
    record_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _within_budget(self) -> MissionExecutionBudget:
        if self.consumed_dispatch_claims > self.max_dispatch_claims:
            raise ValueError("consumed dispatch claims exceed the budget")
        return self
