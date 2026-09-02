"""Phase 0B execution, reconciliation, and result-ingestion boundaries."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.canonical.models import CanonicalJsonObject

from .base import StrictImmutableBoundaryModel
from .common import RiskLevel, SideEffect, UtcDatetime
from .context import DataAccessGrant
from .scope import NormalizedTarget
from .tools import ToolRef

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
ResultIngestionStatus = Literal[
    "NOT_AVAILABLE",
    "PENDING",
    "INGESTING",
    "INGESTED_DURABLE",
    "DELETE_PENDING",
    "QUARANTINE_ERASED",
    "SUCCEEDED",
    "FAILED",
    "QUARANTINED",
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
    "MISSION_EXPIRED",
    "DIGEST_INTEGRITY_FAILURE",
]
ReconciliationStatus = Literal[
    "NOT_FOUND",
    "QUEUED",
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "CANCELLED",
    "UNKNOWN",
    "UNSUPPORTED",
]


class DispatchClaim(StrictImmutableBoundaryModel):
    """Durable, non-bearer evidence that one provider submit attempt was claimed."""

    claim_id: str = Field(min_length=1)
    claim_digest: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    execution_state_version: int = Field(ge=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    policy_decision_id: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    tool_ref: ToolRef
    adapter_id: str = Field(min_length=1)
    approval_request_id: str | None = None
    approval_record_id: str | None = None
    idempotency_key: str = Field(min_length=1)
    issued_at: UtcDatetime
    expires_at: UtcDatetime
    consumed_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def claim_window_is_valid(self) -> DispatchClaim:
        if self.issued_at >= self.expires_at:
            raise ValueError("dispatch claim expiry must follow issuance")
        if self.consumed_at is not None and not (
            self.issued_at <= self.consumed_at < self.expires_at
        ):
            raise ValueError("dispatch claim consumption is outside its validity window")
        return self


class ResultCollectionAuthority(StrictImmutableBoundaryModel):
    """Persisted exact-tool authority for one provider-result collection stream."""

    authority_id: str = Field(min_length=1)
    authority_digest: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    provider_task_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    tool_ref: ToolRef
    registry_digest: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    max_result_bytes: int = Field(gt=0)
    system_hard_output_cap: int = Field(gt=0)
    collection_started_at: UtcDatetime
    retention_until: UtcDatetime

    @model_validator(mode="after")
    def collection_window_is_valid(self) -> ResultCollectionAuthority:
        if self.collection_started_at >= self.retention_until:
            raise ValueError("result collection retention must follow collection start")
        if self.max_result_bytes > self.system_hard_output_cap:
            raise ValueError("result collection limit exceeds the system hard cap")
        return self


class DurableIngestionResource(StrictImmutableBoundaryModel):
    resource_type: Literal[
        "redacted_artifact", "encrypted_raw_artifact", "secret_reference"
    ]
    resource_id: str = Field(min_length=1)
    resource_digest: str = Field(min_length=1)


class SecureIngestionManifest(StrictImmutableBoundaryModel):
    """Read-back-verifiable application commit preceding quarantine erasure."""

    manifest_id: str = Field(min_length=1)
    manifest_digest: str = Field(min_length=1)
    ingestion_id: str = Field(min_length=1)
    secure_ingestion_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    receipt_id: str = Field(min_length=1)
    receipt_digest: str = Field(min_length=1)
    quarantine_id: str = Field(min_length=1)
    quarantine_digest: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    resources: tuple[DurableIngestionResource, ...]
    redaction_metadata_digest: str = Field(min_length=1)
    created_at: UtcDatetime


class QuarantineDeletionIntent(StrictImmutableBoundaryModel):
    """Durable manifest-bound authorization to erase one quarantine object."""

    intent_id: str = Field(min_length=1)
    intent_digest: str = Field(min_length=1)
    ingestion_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    manifest_id: str = Field(min_length=1)
    manifest_digest: str = Field(min_length=1)
    receipt_id: str = Field(min_length=1)
    quarantine_id: str = Field(min_length=1)
    created_at: UtcDatetime


class ExecutionRetryPolicy(StrictImmutableBoundaryModel):
    """Explicitly separates execution from safe, bounded read/reconcile retries."""

    max_external_dispatch_attempts: Literal[1] = 1
    automatic_transport_retries: Literal[0] = 0
    langgraph_dispatch_retry: Literal[False] = False
    reconcile_before_manual_retry: Literal[True] = True


class ExecutionRequest(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    policy_decision_id: str = Field(min_length=1)
    authorization_digest: str = Field(min_length=1)
    proposal_digest: str = Field(min_length=1)
    validated_arguments_digest: str = Field(min_length=1)
    tool_ref: ToolRef
    adapter_id: str = Field(min_length=1)
    provider_operation: str = Field(min_length=1)
    session_id: str | None
    normalized_targets: tuple[NormalizedTarget, ...]
    authorized_data_access: tuple[DataAccessGrant, ...]
    effective_risk: RiskLevel
    side_effect: SideEffect
    arguments: CanonicalJsonObject
    approval_request_id: str | None = None
    approval_record_id: str | None = None


class ExecutionRecord(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    record_digest: str = Field(min_length=1)
    state_version: int = Field(ge=0)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    run_id: str = Field(min_length=1)
    thread_id: str = Field(min_length=1)
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
    pre_dispatch_block_reason: PreDispatchBlockReason | None = None
    result_ingestion_state: ResultIngestionStatus = "NOT_AVAILABLE"
    raw_result_quarantine_id: str | None = None
    provider_task_id: str | None = None
    dispatch_attempts: int = Field(default=0, ge=0, le=1)
    approval_request_id: str | None = None
    approval_record_id: str | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime

    @model_validator(mode="after")
    def execution_invariants(self) -> ExecutionRecord:
        if self.updated_at < self.created_at:
            raise ValueError("execution update cannot precede creation")
        expected_thread = f"{self.mission_id}:{self.mission_revision}:{self.run_id}"
        if self.thread_id != expected_thread:
            raise ValueError("execution thread_id binding mismatch")
        if self.provider_execution_state == "BLOCKED":
            if self.pre_dispatch_block_reason is None:
                raise ValueError("BLOCKED execution requires a reason")
            if (
                self.provider_task_id is not None
                or self.raw_result_quarantine_id is not None
                or self.result_ingestion_state != "NOT_AVAILABLE"
                or self.dispatch_attempts != 0
            ):
                raise ValueError("BLOCKED execution cannot contain provider/result state")
        elif self.pre_dispatch_block_reason is not None:
            raise ValueError("block reason is valid only for BLOCKED")
        if self.provider_execution_state in {"PLANNED", "AUTHORIZED"} and (
            self.provider_task_id is not None or self.dispatch_attempts != 0
        ):
            raise ValueError("pre-dispatch execution cannot contain provider state")
        post_dispatch = {
            "DISPATCH_CLAIMED",
            "DISPATCHED",
            "RUNNING",
            "SUCCEEDED",
            "FAILED",
            "CANCEL_REQUESTED",
            "CANCELLED",
            "RECONCILING",
            "OUTCOME_UNKNOWN",
        }
        if self.provider_execution_state in post_dispatch and self.dispatch_attempts != 1:
            raise ValueError("claimed/post-dispatch execution requires one submit claim")
        confirmed_task_states = {
            "RUNNING",
            "SUCCEEDED",
            "FAILED",
            "CANCEL_REQUESTED",
            "CANCELLED",
        }
        if (
            self.provider_execution_state in confirmed_task_states
            and self.provider_task_id is None
        ):
            raise ValueError("confirmed provider state requires a provider task ID")
        if self.result_ingestion_state == "NOT_AVAILABLE" and (
            self.raw_result_quarantine_id is not None
        ):
            raise ValueError("quarantine requires an available result-ingestion state")
        return self


class RawArtifactMetadata(StrictImmutableBoundaryModel):
    artifact_sequence: int = Field(ge=0)
    suggested_name: str | None = None
    media_type: str | None = None
    declared_size: int | None = Field(default=None, ge=0)


class RawResultReceipt(StrictImmutableBoundaryModel):
    receipt_id: str = Field(min_length=1)
    receipt_digest: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    quarantine_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    stdout_bytes: int = Field(ge=0)
    stderr_bytes: int = Field(ge=0)
    artifact_count: int = Field(ge=0)
    ciphertext_digest: str = Field(min_length=1)
    committed_at: UtcDatetime


class AdapterRawResult(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    provider_task_id: str = Field(min_length=1)
    provider_status: Literal["SUCCEEDED", "FAILED", "CANCELLED"]
    receipt: RawResultReceipt
    exit_code: int | None
    started_at: UtcDatetime
    finished_at: UtcDatetime

    @model_validator(mode="after")
    def metadata_only_bindings(self) -> AdapterRawResult:
        if self.receipt.execution_id != self.execution_id:
            raise ValueError("adapter result/receipt execution mismatch")
        if self.finished_at < self.started_at:
            raise ValueError("adapter result finished before it started")
        return self


class RawResultRecoveryMetadata(StrictImmutableBoundaryModel):
    recovery_id: str = Field(min_length=1)
    recovery_digest: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    quarantine_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    state: Literal["OPEN", "COMMITTED", "RECOVERY_REQUIRED", "ABORTED"]
    bytes_received: int = Field(ge=0)
    last_chunk_sequence: int = Field(ge=-1)
    receipt_id: str | None = None
    updated_at: UtcDatetime


class ResultIngestionRecord(StrictImmutableBoundaryModel):
    ingestion_id: str = Field(min_length=1)
    ingestion_digest: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    state_version: int = Field(ge=0)
    status: ResultIngestionStatus
    receipt_id: str | None = None
    quarantine_id: str | None = None
    adapter_metadata_digest: str | None = None
    lease_id: str | None = None
    lease_expires_at: UtcDatetime | None = None
    attempt_count: int = Field(default=0, ge=0)
    failure_code: str | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime

    @model_validator(mode="after")
    def ingestion_invariants(self) -> ResultIngestionRecord:
        if self.updated_at < self.created_at:
            raise ValueError("ingestion update cannot precede creation")
        if self.status == "NOT_AVAILABLE" and any(
            value is not None
            for value in (self.receipt_id, self.quarantine_id, self.adapter_metadata_digest)
        ):
            raise ValueError("NOT_AVAILABLE ingestion cannot reference raw-result metadata")
        if self.status in {
            "PENDING",
            "INGESTING",
            "INGESTED_DURABLE",
            "DELETE_PENDING",
            "QUARANTINE_ERASED",
            "SUCCEEDED",
            "FAILED",
            "QUARANTINED",
        } and (self.receipt_id is None or self.quarantine_id is None):
            raise ValueError("available ingestion requires receipt and quarantine bindings")
        if self.status == "INGESTING" and self.lease_id is None:
            raise ValueError("INGESTING requires a lease")
        if self.status == "INGESTING" and self.lease_expires_at is None:
            raise ValueError("INGESTING requires a lease expiry")
        if (
            self.status == "INGESTING"
            and self.lease_expires_at is not None
            and self.lease_expires_at <= self.updated_at
        ):
            raise ValueError("ingestion lease expiry must follow its update time")
        if self.status != "INGESTING" and (
            self.lease_id is not None or self.lease_expires_at is not None
        ):
            raise ValueError("ingestion lease is valid only while INGESTING")
        if self.status in {"FAILED", "QUARANTINED"} and self.failure_code is None:
            raise ValueError("failed ingestion requires a typed failure code")
        if self.status not in {"FAILED", "QUARANTINED"} and self.failure_code is not None:
            raise ValueError("failure code is valid only for failed ingestion")
        return self


class SecureIngestionSummary(StrictImmutableBoundaryModel):
    secure_ingestion_id: str = Field(min_length=1)
    stdout_preview: str | None = None
    stderr_preview: str | None = None
    redacted_artifact_references: tuple[str, ...] = ()


class ExecutionResult(StrictImmutableBoundaryModel):
    result_id: str = Field(min_length=1)
    result_digest: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    provider_task_id: str = Field(min_length=1)
    adapter_id: str = Field(min_length=1)
    tool_ref: ToolRef
    policy_decision_id: str = Field(min_length=1)
    secure_ingestion_id: str = Field(min_length=1)
    normalized_targets: tuple[NormalizedTarget, ...]
    session_id: str | None
    status: Literal["SUCCEEDED", "FAILED", "CANCELLED"]
    timed_out: bool
    started_at: UtcDatetime
    finished_at: UtcDatetime
    stdout_preview: str | None = None
    stderr_preview: str | None = None
    redacted_artifact_references: tuple[str, ...] = ()
    exit_code: int | None

    @model_validator(mode="after")
    def result_invariants(self) -> ExecutionResult:
        if self.finished_at < self.started_at:
            raise ValueError("execution result finished before it started")
        return self


class TaskHandle(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    provider_task_id: str = Field(min_length=1)
    state: Literal["queued", "running", "completed"]
    submitted_at: UtcDatetime


class TaskStatus(StrictImmutableBoundaryModel):
    task_id: str = Field(min_length=1)
    state: Literal["queued", "running", "succeeded", "failed", "cancelled", "unknown"]
    updated_at: UtcDatetime


class CancelResult(StrictImmutableBoundaryModel):
    task_id: str = Field(min_length=1)
    requested: bool
    confirmed: bool


class ReconciliationResult(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    status: ReconciliationStatus
    provider_task_id: str | None = None
    checked_at: UtcDatetime

    @model_validator(mode="after")
    def reconciliation_bindings(self) -> ReconciliationResult:
        if self.status in {
            "QUEUED",
            "RUNNING",
            "SUCCEEDED",
            "FAILED",
            "CANCELLED",
        } and self.provider_task_id is None:
            raise ValueError("confirmed reconciliation requires provider task ID")
        return self


class WorkflowRunBinding(StrictImmutableBoundaryModel):
    run_id: str = Field(min_length=1, pattern=r"^[^:]+$")
    run_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1, pattern=r"^[^:]+$")
    mission_revision: int = Field(ge=1)
    thread_id: str = Field(min_length=1)
    created_at: UtcDatetime

    @model_validator(mode="after")
    def thread_binding(self) -> WorkflowRunBinding:
        if self.thread_id != f"{self.mission_id}:{self.mission_revision}:{self.run_id}":
            raise ValueError("workflow thread_id binding mismatch")
        return self
