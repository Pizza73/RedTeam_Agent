"""Result ingestion coordinator (SystemDesign §10 / §10.4 / §33.2 boundary).

Ingestion state is independent of provider execution state and of collection
state. It advances NOT_AVAILABLE -> PENDING -> INGESTING -> DELETE_PENDING on the
normal path (the INGESTED_DURABLE milestone: manifest + projection published, the
ExecutionResult rebuilt from the projection). A processing failure goes to
FAILED; a bounded, same-input retry returns to PENDING (create-or-verify), and an
exhausted budget goes to QUARANTINED. A crash resumes ingestion only, never
re-running the external action.

Phase 0B has no quarantine encryption or verified erasure (Phase 0C); the normal
success milestone is DELETE_PENDING with a durable manifest/projection. The
actual erasure transitions (DELETE_PENDING -> ... -> SUCCEEDED) are Phase 0C.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import ResultIngestionError
from redteam_agent.execution.models import (
    ExecutionRecord,
    ExecutionResult,
    ExecutionResultProjection,
    LocalResultBinding,
    ProviderTaskBinding,
    RawControlMetadataRecord,
    ResultIngestionStateRecord,
    ResultIngestionStatus,
    ResultTaskBinding,
    SecureIngestionRetryPolicy,
)
from redteam_agent.execution.records import finalize_object_digest
from redteam_agent.execution.state_machine import is_legal_ingestion_edge
from redteam_agent.models.common import ToolRef
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionResultProjectionRepository,
    ExecutionResultRepository,
    RawControlMetadataRepository,
    ResultIngestionStateRepository,
    ResultTaskBindingRepository,
)
from redteam_agent.storage.guard import WriteGuard

_RESULT_STATUS = {"succeeded": "SUCCEEDED", "failed": "FAILED", "cancelled": "CANCELLED"}


@dataclass(frozen=True)
class IngestionResult:
    ingestion_id: str
    status: ResultIngestionStatus
    execution_result_present: bool


class ResultIngestionCoordinator:
    def __init__(
        self,
        *,
        database: Database,
        ingestion_repository: ResultIngestionStateRepository,
        projection_repository: ExecutionResultProjectionRepository,
        result_repository: ExecutionResultRepository,
        control_metadata_repository: RawControlMetadataRepository,
        task_binding_repository: ResultTaskBindingRepository,
        execution_repository: ExecutionRecordRepository,
        clock: Clock,
        digest_service: DigestService,
        write_guard: WriteGuard,
        retry_policy: SecureIngestionRetryPolicy,
    ) -> None:
        self._db = database
        self._ingestion = ingestion_repository
        self._projections = projection_repository
        self._results = result_repository
        self._control = control_metadata_repository
        self._bindings = task_binding_repository
        self._executions = execution_repository
        self._clock = clock
        self._ds = digest_service
        self._guard = write_guard
        self._retry_policy = retry_policy
        self._retired = False

    def retire_for_phase0c(self, *, guard: WriteGuard) -> None:
        """Irreversibly close the Phase 0B plaintext ingestion entry points."""
        if guard is not self._guard:
            raise ResultIngestionError("ingestion retirement requires the composition guard")
        self._retired = True

    def _require_active(self) -> None:
        if self._retired:
            raise ResultIngestionError("Phase 0B ingestion is retired after Phase 0C composition")

    def ingest(self, *, execution_id: str) -> IngestionResult:
        self._require_active()
        state = self._require_state(execution_id)
        expired = self._expire_if_due(state)
        if expired is not None:
            return expired
        if state.status in ("DELETE_PENDING", "ERASURE_CLAIMED", "QUARANTINE_ERASED", "SUCCEEDED"):
            return IngestionResult(state.ingestion_id, state.status, self._results.get(execution_id) is not None)
        if state.status not in ("PENDING", "INGESTING"):
            raise ResultIngestionError(f"cannot ingest from state {state.status}")

        if state.status == "PENDING":
            state = self._advance(state, "INGESTING", attempt_count=state.attempt_count + 1)

        record = self._require_execution(execution_id)
        binding = self._bindings.find_by_execution(execution_id)
        control = self._control.find_by_execution(execution_id)
        if binding is None or control is None:
            raise ResultIngestionError("missing task binding or control metadata for ingestion")

        projection = self._build_projection(record=record, binding=binding, control=control, state=state)
        # Create-or-verify the projection so a resume after a crash is idempotent.
        existing = self._projections.find_by_execution(execution_id)
        if existing is not None and existing.projection_digest != projection.projection_digest:
            raise ResultIngestionError("projection digest changed on re-ingestion (fixed-rule violation)")
        result = self._build_result(record=record, binding=binding, control=control)
        manifest_id = f"manifest-{execution_id}"
        manifest_digest = self._ds.compute(
            "result_progress_digest",
            {"kind": "manifest", "execution_id": execution_id, "projection_digest": projection.projection_digest},
        )
        durable = finalize_object_digest(
            state.model_copy(
                update={
                    "state_version": state.state_version + 1,
                    "status": "DELETE_PENDING",
                    "manifest_id": manifest_id,
                    "manifest_digest": manifest_digest,
                    "ingested_durable_at": self._clock.now(),
                    "updated_at": self._clock.now(),
                }
            ),
            digest_field="record_digest", digest_name="result_ingestion_state_digest", digest_service=self._ds,
        )
        if not is_legal_ingestion_edge(state.status, "DELETE_PENDING"):
            raise ResultIngestionError("illegal ingestion transition to DELETE_PENDING")
        mirror = self._mirror(record, "DELETE_PENDING")
        with UnitOfWork(self._db):
            if existing is None:
                self._projections.create(projection, guard=self._guard)
            self._results.upsert(result, guard=self._guard)
            self._ingestion.update(durable, expected_version=state.state_version, guard=self._guard)
            self._executions.transition(mirror, expected_version=record.execution_state_version, guard=self._guard)
        return IngestionResult(state.ingestion_id, "DELETE_PENDING", True)

    def fail(self, *, execution_id: str, reason: str) -> IngestionResult:
        self._require_active()
        state = self._require_state(execution_id)
        if state.status != "INGESTING":
            raise ResultIngestionError("only an INGESTING ingestion can fail")
        failed = self._advance(state, "FAILED", attempt_count=state.attempt_count)
        record = self._require_execution(execution_id)
        self._transition_mirror(record, "FAILED")
        return IngestionResult(failed.ingestion_id, "FAILED", False)

    def retry(self, *, execution_id: str) -> IngestionResult:
        self._require_active()
        state = self._require_state(execution_id)
        expired = self._expire_if_due(state)
        if expired is not None:
            return expired
        if state.status != "FAILED":
            raise ResultIngestionError("only a FAILED ingestion can be retried")
        if state.attempt_count >= self._retry_policy.max_attempts_per_ingestion:
            quarantined = self._advance(state, "QUARANTINED", attempt_count=state.attempt_count)
            record = self._require_execution(execution_id)
            self._transition_mirror(record, "QUARANTINED")
            return IngestionResult(quarantined.ingestion_id, "QUARANTINED", False)
        pending = self._advance(state, "PENDING", attempt_count=state.attempt_count)
        record = self._require_execution(execution_id)
        self._transition_mirror(record, "PENDING")
        return IngestionResult(pending.ingestion_id, "PENDING", False)

    # --- helpers ----------------------------------------------------------

    def _expire_if_due(self, state: ResultIngestionStateRecord) -> IngestionResult | None:
        if self._clock.now() < state.evidence_retention_until:
            return None
        if state.status == "EVIDENCE_RETENTION_EXPIRED":
            return IngestionResult(state.ingestion_id, state.status, False)
        if not is_legal_ingestion_edge(state.status, "EVIDENCE_RETENTION_EXPIRED"):
            return None
        expired = finalize_object_digest(
            state.model_copy(
                update={
                    "state_version": state.state_version + 1,
                    "status": "EVIDENCE_RETENTION_EXPIRED",
                    "updated_at": self._clock.now(),
                }
            ),
            digest_field="record_digest",
            digest_name="result_ingestion_state_digest",
            digest_service=self._ds,
        )
        record = self._require_execution(state.execution_id)
        mirror = self._mirror(record, "EVIDENCE_RETENTION_EXPIRED")
        with UnitOfWork(self._db):
            self._ingestion.update(expired, expected_version=state.state_version, guard=self._guard)
            self._executions.transition(
                mirror, expected_version=record.execution_state_version, guard=self._guard
            )
        return IngestionResult(state.ingestion_id, "EVIDENCE_RETENTION_EXPIRED", False)

    def _advance(
        self, state: ResultIngestionStateRecord, status: ResultIngestionStatus, *, attempt_count: int
    ) -> ResultIngestionStateRecord:
        if not is_legal_ingestion_edge(state.status, status):
            raise ResultIngestionError(f"illegal ingestion transition {state.status} -> {status}")
        nxt = finalize_object_digest(
            state.model_copy(
                update={
                    "state_version": state.state_version + 1, "status": status,
                    "attempt_count": attempt_count, "updated_at": self._clock.now(),
                }
            ),
            digest_field="record_digest", digest_name="result_ingestion_state_digest", digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            self._ingestion.update(nxt, expected_version=state.state_version, guard=self._guard)
        return nxt

    def _mirror(self, record: ExecutionRecord, status: ResultIngestionStatus) -> ExecutionRecord:
        return finalize_object_digest(
            record.model_copy(
                update={
                    "result_ingestion_state": status,
                    "execution_state_version": record.execution_state_version + 1,
                    "updated_at": self._clock.now(),
                }
            ),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )

    def _transition_mirror(self, record: ExecutionRecord, status: ResultIngestionStatus) -> None:
        mirror = self._mirror(record, status)
        with UnitOfWork(self._db):
            self._executions.transition(mirror, expected_version=record.execution_state_version, guard=self._guard)

    def _build_projection(
        self, *, record: ExecutionRecord, binding: ResultTaskBinding, control: RawControlMetadataRecord,
        state: ResultIngestionStateRecord,
    ) -> ExecutionResultProjection:
        redaction_digest = self._ds.compute(
            "result_progress_digest",
            {"kind": "redaction", "receipt_digest": state.receipt_digest, "rule": "redaction-v1"},
        )
        model = ExecutionResultProjection(
            projection_id=f"projection-{record.execution_id}",
            projection_digest="pending",
            execution_id=record.execution_id,
            task_binding=binding,
            receipt_id=control.receipt_id,
            receipt_digest=control.receipt_digest,
            provider_status=control.provider_status,
            exit_code=control.exit_code,
            timed_out=control.timed_out,
            started_at=control.provider_started_at,
            finished_at=control.provider_finished_at,
            stdout_preview_artifact_id=None,
            stderr_preview_artifact_id=None,
            redaction_metadata_digest=redaction_digest,
        )
        return finalize_object_digest(
            model, digest_field="projection_digest", digest_name="execution_result_projection_digest",
            digest_service=self._ds,
        )

    def _build_result(
        self, *, record: ExecutionRecord, binding: ResultTaskBinding, control: RawControlMetadataRecord
    ) -> ExecutionResult:
        provider_task_id = binding.provider_task_id if isinstance(binding, ProviderTaskBinding) else None
        if isinstance(binding, LocalResultBinding):
            provider_task_id = None
        status = _RESULT_STATUS[control.provider_status]
        return ExecutionResult(
            execution_id=record.execution_id,
            provider_task_id=provider_task_id,
            adapter_id=record.resolved_adapter_id,
            tool_ref=ToolRef(tool_id=record.tool_ref.tool_id, registry_revision=record.tool_ref.registry_revision),
            policy_decision_id=record.policy_decision_id,
            secure_ingestion_id=f"ingestion-{record.execution_id}",
            status=status,  # type: ignore[arg-type]
            timed_out=control.timed_out,
            started_at=control.provider_started_at,
            finished_at=control.provider_finished_at,
            stdout_preview=None,
            stderr_preview=None,
            redacted_artifact_ids=(),
            exit_code=control.exit_code,
        )

    def _require_state(self, execution_id: str) -> ResultIngestionStateRecord:
        state = self._ingestion.get(f"ingestion-{execution_id}")
        if state is None:
            raise ResultIngestionError("ingestion state not found")
        return state

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self._executions.get(execution_id)
        if record is None:
            raise ResultIngestionError("execution not found")
        return record
