"""Phase 0B execution, workflow-run, and result repositories."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from redteam_agent.canonical import digest_model, stable_id, verify_model_digest
from redteam_agent.errors import (
    DigestIntegrityError,
    DuplicateExecutionError,
    ExecutionStateTransitionError,
    RepositoryConflictError,
    WorkflowRunBindingError,
)
from redteam_agent.models.execution import (
    ExecutionRecord,
    ExecutionResult,
    PreDispatchBlockReason,
    ProviderExecutionState,
    RawResultReceipt,
    RawResultRecoveryMetadata,
    ResultIngestionRecord,
    ResultIngestionStatus,
    WorkflowRunBinding,
)
from redteam_agent.repositories.approval import (
    ApprovalRecordRepository,
    ApprovalRequestRepository,
)
from redteam_agent.repositories.plans import PlanRepository
from redteam_agent.repositories.policy import PolicyDecisionRepository

from .base import ImmutableJsonRepository, model_json


def execution_record_digest(record: ExecutionRecord) -> str:
    return digest_model(record, exclude={"record_digest"})


def ingestion_record_digest(record: ResultIngestionRecord) -> str:
    return digest_model(record, exclude={"ingestion_digest"})


class WorkflowRunRepository(ImmutableJsonRepository[WorkflowRunBinding]):
    table = "workflow_runs"
    id_column = "run_id"
    model_type = WorkflowRunBinding

    def verify_integrity(self, model: WorkflowRunBinding) -> None:
        verify_model_digest(model, model.run_digest, exclude={"run_digest"})

    def verify_row_binding(self, identifier: str | int, model: WorkflowRunBinding) -> None:
        row = self.database.connection.execute(
            "SELECT run_digest, mission_id, mission_revision, thread_id "
            "FROM workflow_runs WHERE run_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or not (
            model.run_id == identifier
            and row["run_digest"] == model.run_digest
            and row["mission_id"] == model.mission_id
            and row["mission_revision"] == model.mission_revision
            and row["thread_id"] == model.thread_id
        ):
            raise DigestIntegrityError("workflow run row binding mismatch")

    def add(self, run: WorkflowRunBinding) -> WorkflowRunBinding:
        self.verify_integrity(run)
        payload = model_json(run)
        self._insert_or_same(
            "INSERT INTO workflow_runs"
            "(run_id, run_digest, mission_id, mission_revision, thread_id, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                run.run_id,
                run.run_digest,
                run.mission_id,
                run.mission_revision,
                run.thread_id,
                payload,
            ),
            payload,
        )
        return run

    def get_by_thread_id(self, thread_id: str) -> WorkflowRunBinding | None:
        row = self.database.connection.execute(
            "SELECT run_id FROM workflow_runs WHERE thread_id = ?", (thread_id,)
        ).fetchone()
        return None if row is None else self.get(str(row["run_id"]))


class ExecutionRepository(ImmutableJsonRepository[ExecutionRecord]):
    table = "execution_records"
    id_column = "execution_id"
    model_type = ExecutionRecord

    _allowed_provider_transitions: dict[str, frozenset[str]] = {
        "PLANNED": frozenset({"AUTHORIZED"}),
        "AUTHORIZED": frozenset({"BLOCKED", "DISPATCHED"}),
        "DISPATCHED": frozenset(
            {
                "RUNNING",
                "SUCCEEDED",
                "FAILED",
                "CANCEL_REQUESTED",
                "CANCELLED",
                "RECONCILING",
                "OUTCOME_UNKNOWN",
            }
        ),
        "RUNNING": frozenset(
            {
                "SUCCEEDED",
                "FAILED",
                "CANCEL_REQUESTED",
                "CANCELLED",
                "RECONCILING",
                "OUTCOME_UNKNOWN",
            }
        ),
        "CANCEL_REQUESTED": frozenset({"RUNNING", "CANCELLED", "OUTCOME_UNKNOWN"}),
        "RECONCILING": frozenset(
            {
                "DISPATCHED",
                "RUNNING",
                "SUCCEEDED",
                "FAILED",
                "CANCELLED",
                "OUTCOME_UNKNOWN",
            }
        ),
        "SUCCEEDED": frozenset(),
        "FAILED": frozenset(),
        "BLOCKED": frozenset(),
        "CANCELLED": frozenset(),
        "OUTCOME_UNKNOWN": frozenset(),
    }
    _allowed_ingestion_transitions: dict[str, frozenset[str]] = {
        "NOT_AVAILABLE": frozenset({"PENDING"}),
        "PENDING": frozenset({"INGESTING"}),
        "INGESTING": frozenset({"SUCCEEDED", "FAILED"}),
        "FAILED": frozenset({"INGESTING", "QUARANTINED"}),
        "SUCCEEDED": frozenset(),
        "QUARANTINED": frozenset(),
    }

    def verify_integrity(self, model: ExecutionRecord) -> None:
        verify_model_digest(model, model.record_digest, exclude={"record_digest"})
        identity = {
            "schema_version": "execution-v1",
            "policy_decision_id": model.policy_decision_id,
            "run_id": model.run_id,
        }
        if model.execution_id != stable_id("execution", identity):
            raise DigestIntegrityError("execution ID mismatch")
        key_identity = {
            "schema_version": "execution-idempotency-v1",
            "mission_id": model.mission_id,
            "mission_revision": model.mission_revision,
            "execution_id": model.execution_id,
            "authorization_digest": model.authorization_digest,
            "resolved_adapter_id": model.resolved_adapter_id,
        }
        if model.idempotency_key != stable_id("idem", key_identity):
            raise DigestIntegrityError("execution idempotency key mismatch")
        self._verify_parent_bindings(model)

    def _verify_parent_bindings(self, model: ExecutionRecord) -> None:
        decision = PolicyDecisionRepository(self.database).get(model.policy_decision_id)
        plan = PlanRepository(self.database).get(model.plan_id)
        run = WorkflowRunRepository(self.database).get(model.run_id)
        if decision is None or plan is None or run is None:
            raise DigestIntegrityError("execution parent envelope is incomplete")
        if not (
            decision.decision != "DENY"
            and decision.plan_id == plan.plan_id == model.plan_id
            and decision.mission_id == plan.mission_id == model.mission_id
            and decision.mission_revision
            == plan.mission_revision
            == model.mission_revision
            and decision.authorization_epoch
            == plan.authorization_epoch
            == model.authorization_epoch
            and decision.proposal_digest == plan.proposal_digest == model.proposal_digest
            and decision.authorization_digest == model.authorization_digest
            and decision.tool_ref == plan.proposal.tool_ref == model.tool_ref
            and decision.resolved_adapter_id == model.resolved_adapter_id
            and decision.adapter_capabilities_digest
            == plan.adapter_capabilities_digest
            == model.adapter_capabilities_digest
            and decision.sandbox_capabilities_digest
            == plan.sandbox_capabilities_digest
            == model.sandbox_capabilities_digest
            and decision.remote_mcp_trust_policy_digest
            == plan.remote_mcp_trust_policy_digest
            == model.remote_mcp_trust_policy_digest
            and run.mission_id == model.mission_id
            and run.mission_revision == model.mission_revision
            and run.thread_id == model.thread_id
        ):
            raise DigestIntegrityError("execution parent binding mismatch")
        if decision.decision == "ALLOW":
            if model.approval_request_id is not None or model.approval_record_id is not None:
                raise DigestIntegrityError("ALLOW execution cannot carry approval evidence")
            return
        if model.approval_request_id is None or model.approval_record_id is None:
            raise DigestIntegrityError("approval-required execution lacks approval evidence")
        request = ApprovalRequestRepository(self.database).get(model.approval_request_id)
        approval = ApprovalRecordRepository(self.database).get(model.approval_record_id)
        if request is None or approval is None or not (
            request.policy_decision_id == decision.decision_id
            and request.authorization_digest == decision.authorization_digest
            and approval.policy_decision_id == decision.decision_id
            and approval.authorization_digest == decision.authorization_digest
            and approval.approval_request_id == request.approval_request_id
            and approval.approval_request_digest == request.request_digest
            and approval.approval_presentation_digest
            == request.approval_presentation_digest
            and approval.decision == "APPROVED"
        ):
            raise DigestIntegrityError("execution approval evidence binding mismatch")

    def verify_row_binding(self, identifier: str | int, model: ExecutionRecord) -> None:
        row = self.database.connection.execute(
            "SELECT record_digest, state_version, mission_id, mission_revision, plan_id, "
            "policy_decision_id, idempotency_key, provider_execution_state, "
            "result_ingestion_state, provider_task_id FROM execution_records "
            "WHERE execution_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or not (
            model.execution_id == identifier
            and row["record_digest"] == model.record_digest
            and row["state_version"] == model.state_version
            and row["mission_id"] == model.mission_id
            and row["mission_revision"] == model.mission_revision
            and row["plan_id"] == model.plan_id
            and row["policy_decision_id"] == model.policy_decision_id
            and row["idempotency_key"] == model.idempotency_key
            and row["provider_execution_state"] == model.provider_execution_state
            and row["result_ingestion_state"] == model.result_ingestion_state
            and row["provider_task_id"] == model.provider_task_id
        ):
            raise DigestIntegrityError("execution row binding mismatch")

    def add_planned(self, record: ExecutionRecord) -> ExecutionRecord:
        if record.provider_execution_state != "PLANNED" or record.state_version != 0:
            raise ExecutionStateTransitionError("new execution must start at PLANNED version 0")
        self.verify_integrity(record)
        run = WorkflowRunRepository(self.database).get(record.run_id)
        if run is None or not (
            run.thread_id == record.thread_id
            and run.mission_id == record.mission_id
            and run.mission_revision == record.mission_revision
        ):
            raise WorkflowRunBindingError("execution is not bound to a trusted workflow run")
        payload = model_json(record)
        try:
            self.database.connection.execute(
                "INSERT INTO execution_records"
                "(execution_id, record_digest, state_version, mission_id, mission_revision, "
                "plan_id, policy_decision_id, idempotency_key, provider_execution_state, "
                "result_ingestion_state, provider_task_id, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.execution_id,
                    record.record_digest,
                    record.state_version,
                    record.mission_id,
                    record.mission_revision,
                    record.plan_id,
                    record.policy_decision_id,
                    record.idempotency_key,
                    record.provider_execution_state,
                    record.result_ingestion_state,
                    record.provider_task_id,
                    payload,
                ),
            )
        except sqlite3.IntegrityError as exc:
            by_decision = self.get_by_policy_decision(record.policy_decision_id)
            if by_decision is not None:
                if by_decision == record:
                    return by_decision
                raise DuplicateExecutionError(
                    "a PolicyDecision is already bound to another execution"
                ) from exc
            existing = self.get(record.execution_id)
            if existing is not None and existing == record:
                return existing
            raise RepositoryConflictError("execution identity constraint conflict") from exc
        return record

    def get_by_policy_decision(self, policy_decision_id: str) -> ExecutionRecord | None:
        row = self.database.connection.execute(
            "SELECT execution_id FROM execution_records WHERE policy_decision_id = ?",
            (policy_decision_id,),
        ).fetchone()
        return None if row is None else self.get(str(row["execution_id"]))

    def transition_provider(
        self,
        execution_id: str,
        *,
        expected_state_version: int,
        new_state: ProviderExecutionState,
        now: datetime,
        provider_task_id: str | None = None,
        block_reason: PreDispatchBlockReason | None = None,
        dispatch_attempts: int | None = None,
    ) -> ExecutionRecord:
        current = self.get(execution_id)
        if current is None or current.state_version != expected_state_version:
            raise ExecutionStateTransitionError("execution state version is stale")
        if new_state not in self._allowed_provider_transitions[current.provider_execution_state]:
            raise ExecutionStateTransitionError("provider execution transition is not allowed")
        updated = ExecutionRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "state_version": current.state_version + 1,
                "provider_execution_state": new_state,
                "pre_dispatch_block_reason": block_reason,
                "provider_task_id": (
                    current.provider_task_id
                    if provider_task_id is None
                    else provider_task_id
                ),
                "dispatch_attempts": (
                    current.dispatch_attempts
                    if dispatch_attempts is None
                    else dispatch_attempts
                ),
                "updated_at": now,
                "record_digest": "pending",
            }
        )
        updated = updated.model_copy(
            update={"record_digest": execution_record_digest(updated)}
        )
        self._occ_update(current, updated)
        return updated

    def transition_ingestion(
        self,
        execution_id: str,
        *,
        expected_state_version: int,
        new_state: ResultIngestionStatus,
        now: datetime,
        quarantine_id: str | None = None,
    ) -> ExecutionRecord:
        current = self.get(execution_id)
        if current is None or current.state_version != expected_state_version:
            raise ExecutionStateTransitionError("execution state version is stale")
        if new_state not in self._allowed_ingestion_transitions[current.result_ingestion_state]:
            raise ExecutionStateTransitionError("result-ingestion transition is not allowed")
        ingestion = ResultIngestionRepository(self.database).get_by_execution(execution_id)
        if ingestion is None or ingestion.status != new_state:
            raise ExecutionStateTransitionError(
                "execution/result-ingestion repository state mismatch"
            )
        if quarantine_id is not None and ingestion.quarantine_id != quarantine_id:
            raise ExecutionStateTransitionError("execution quarantine binding mismatch")
        updated = ExecutionRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "state_version": current.state_version + 1,
                "result_ingestion_state": new_state,
                "raw_result_quarantine_id": (
                    current.raw_result_quarantine_id
                    if quarantine_id is None
                    else quarantine_id
                ),
                "updated_at": now,
                "record_digest": "pending",
            }
        )
        updated = updated.model_copy(
            update={"record_digest": execution_record_digest(updated)}
        )
        self._occ_update(current, updated)
        return updated

    def _occ_update(self, current: ExecutionRecord, updated: ExecutionRecord) -> None:
        self.verify_integrity(updated)
        cursor = self.database.connection.execute(
            "UPDATE execution_records SET record_digest = ?, state_version = ?, "
            "provider_execution_state = ?, result_ingestion_state = ?, "
            "provider_task_id = ?, payload_json = ? "
            "WHERE execution_id = ? AND state_version = ? AND record_digest = ?",
            (
                updated.record_digest,
                updated.state_version,
                updated.provider_execution_state,
                updated.result_ingestion_state,
                updated.provider_task_id,
                model_json(updated),
                updated.execution_id,
                current.state_version,
                current.record_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise ExecutionStateTransitionError("execution state OCC update failed")

    def list_unresolved(self, mission_id: str) -> tuple[ExecutionRecord, ...]:
        rows = self.database.connection.execute(
            "SELECT execution_id FROM execution_records WHERE mission_id = ? AND "
            "provider_execution_state IN "
            "('DISPATCHED', 'RUNNING', 'CANCEL_REQUESTED', 'RECONCILING', 'OUTCOME_UNKNOWN') "
            "ORDER BY execution_id",
            (mission_id,),
        ).fetchall()
        records = tuple(self.get(str(row["execution_id"])) for row in rows)
        if any(record is None for record in records):
            raise DigestIntegrityError("unresolved execution disappeared during read")
        return tuple(record for record in records if record is not None)


class RawResultReceiptRepository(ImmutableJsonRepository[RawResultReceipt]):
    table = "raw_result_receipts"
    id_column = "receipt_id"
    model_type = RawResultReceipt

    def verify_integrity(self, model: RawResultReceipt) -> None:
        verify_model_digest(model, model.receipt_digest, exclude={"receipt_digest"})
        identity = {
            "schema_version": "raw-result-receipt-v1",
            "execution_id": model.execution_id,
            "quarantine_id": model.quarantine_id,
            "sink_id": model.sink_id,
        }
        if model.receipt_id != stable_id("receipt", identity):
            raise DigestIntegrityError("raw-result receipt ID mismatch")
        execution = ExecutionRepository(self.database).get(model.execution_id)
        if execution is None or execution.provider_execution_state not in {
            "RUNNING",
            "SUCCEEDED",
            "FAILED",
            "CANCELLED",
        }:
            raise DigestIntegrityError("raw-result receipt has no confirmed execution task")

    def verify_row_binding(self, identifier: str | int, model: RawResultReceipt) -> None:
        row = self.database.connection.execute(
            "SELECT receipt_digest, execution_id, quarantine_id FROM raw_result_receipts "
            "WHERE receipt_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or not (
            model.receipt_id == identifier
            and row["receipt_digest"] == model.receipt_digest
            and row["execution_id"] == model.execution_id
            and row["quarantine_id"] == model.quarantine_id
        ):
            raise DigestIntegrityError("raw-result receipt row binding mismatch")

    def add(self, receipt: RawResultReceipt) -> RawResultReceipt:
        self.verify_integrity(receipt)
        payload = model_json(receipt)
        self._insert_or_same(
            "INSERT INTO raw_result_receipts"
            "(receipt_id, receipt_digest, execution_id, quarantine_id, payload_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                receipt.receipt_id,
                receipt.receipt_digest,
                receipt.execution_id,
                receipt.quarantine_id,
                payload,
            ),
            payload,
        )
        return receipt

    def get_by_execution(self, execution_id: str) -> RawResultReceipt | None:
        row = self.database.connection.execute(
            "SELECT receipt_id FROM raw_result_receipts WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        return None if row is None else self.get(str(row["receipt_id"]))


class RawResultRecoveryRepository(ImmutableJsonRepository[RawResultRecoveryMetadata]):
    table = "raw_result_recovery_metadata"
    id_column = "recovery_id"
    model_type = RawResultRecoveryMetadata

    def verify_integrity(self, model: RawResultRecoveryMetadata) -> None:
        verify_model_digest(model, model.recovery_digest, exclude={"recovery_digest"})
        identity = {
            "schema_version": "raw-result-recovery-v1",
            "execution_id": model.execution_id,
            "quarantine_id": model.quarantine_id,
        }
        if model.recovery_id != stable_id("recovery", identity):
            raise DigestIntegrityError("raw-result recovery ID mismatch")
        execution = ExecutionRepository(self.database).get(model.execution_id)
        if execution is None or execution.provider_execution_state in {
            "PLANNED",
            "AUTHORIZED",
            "BLOCKED",
        }:
            raise DigestIntegrityError("raw-result recovery has no dispatched execution")

    def verify_row_binding(
        self, identifier: str | int, model: RawResultRecoveryMetadata
    ) -> None:
        row = self.database.connection.execute(
            "SELECT recovery_digest, execution_id, quarantine_id, state "
            "FROM raw_result_recovery_metadata WHERE recovery_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or not (
            model.recovery_id == identifier
            and row["recovery_digest"] == model.recovery_digest
            and row["execution_id"] == model.execution_id
            and row["quarantine_id"] == model.quarantine_id
            and row["state"] == model.state
        ):
            raise DigestIntegrityError("raw-result recovery row binding mismatch")

    def set_current(self, metadata: RawResultRecoveryMetadata) -> RawResultRecoveryMetadata:
        self.verify_integrity(metadata)
        payload = model_json(metadata)
        existing = self.get(metadata.recovery_id)
        if existing is None:
            self.database.connection.execute(
                "INSERT INTO raw_result_recovery_metadata"
                "(recovery_id, recovery_digest, execution_id, quarantine_id, state, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    metadata.recovery_id,
                    metadata.recovery_digest,
                    metadata.execution_id,
                    metadata.quarantine_id,
                    metadata.state,
                    payload,
                ),
            )
        elif existing != metadata:
            same_terminal_metadata = (
                existing.state == metadata.state == "COMMITTED"
                and metadata.execution_id == existing.execution_id
                and metadata.quarantine_id == existing.quarantine_id
                and metadata.sink_id == existing.sink_id
                and metadata.bytes_received == existing.bytes_received
                and metadata.last_chunk_sequence == existing.last_chunk_sequence
                and metadata.receipt_id == existing.receipt_id
            )
            if same_terminal_metadata:
                return existing
            allowed = {
                "OPEN": frozenset({"OPEN", "COMMITTED", "RECOVERY_REQUIRED", "ABORTED"}),
                "RECOVERY_REQUIRED": frozenset(
                    {"RECOVERY_REQUIRED", "COMMITTED", "ABORTED"}
                ),
                "COMMITTED": frozenset(),
                "ABORTED": frozenset(),
            }
            if not (
                metadata.execution_id == existing.execution_id
                and metadata.quarantine_id == existing.quarantine_id
                and metadata.sink_id == existing.sink_id
                and metadata.bytes_received >= existing.bytes_received
                and metadata.last_chunk_sequence >= existing.last_chunk_sequence
                and metadata.state in allowed[existing.state]
            ):
                raise ExecutionStateTransitionError(
                    "raw-result recovery transition is invalid"
                )
            cursor = self.database.connection.execute(
                "UPDATE raw_result_recovery_metadata SET recovery_digest = ?, state = ?, "
                "payload_json = ? WHERE recovery_id = ? AND recovery_digest = ?",
                (
                    metadata.recovery_digest,
                    metadata.state,
                    payload,
                    metadata.recovery_id,
                    existing.recovery_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise ExecutionStateTransitionError("raw-result recovery OCC update failed")
        return metadata


class ResultIngestionRepository(ImmutableJsonRepository[ResultIngestionRecord]):
    table = "result_ingestions"
    id_column = "ingestion_id"
    model_type = ResultIngestionRecord

    _allowed: dict[str, frozenset[str]] = {
        "PENDING": frozenset({"INGESTING"}),
        "INGESTING": frozenset({"SUCCEEDED", "FAILED"}),
        "FAILED": frozenset({"INGESTING", "QUARANTINED"}),
        "NOT_AVAILABLE": frozenset(),
        "SUCCEEDED": frozenset(),
        "QUARANTINED": frozenset(),
    }

    def verify_integrity(self, model: ResultIngestionRecord) -> None:
        verify_model_digest(model, model.ingestion_digest, exclude={"ingestion_digest"})
        if model.receipt_id is None:
            raise DigestIntegrityError("persisted result ingestion requires a receipt")
        identity = {
            "schema_version": "result-ingestion-v1",
            "execution_id": model.execution_id,
            "receipt_id": model.receipt_id,
        }
        if model.ingestion_id != stable_id("ingestion", identity):
            raise DigestIntegrityError("result-ingestion ID mismatch")
        receipt = RawResultReceiptRepository(self.database).get(model.receipt_id)
        execution_row = self.database.connection.execute(
            "SELECT execution_id FROM execution_records WHERE execution_id = ?",
            (model.execution_id,),
        ).fetchone()
        if receipt is None or execution_row is None or not (
            receipt.execution_id == model.execution_id
            and receipt.quarantine_id == model.quarantine_id
        ):
            raise DigestIntegrityError("result-ingestion receipt binding mismatch")

    def verify_row_binding(self, identifier: str | int, model: ResultIngestionRecord) -> None:
        row = self.database.connection.execute(
            "SELECT ingestion_digest, execution_id, state_version, status "
            "FROM result_ingestions WHERE ingestion_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or not (
            model.ingestion_id == identifier
            and row["ingestion_digest"] == model.ingestion_digest
            and row["execution_id"] == model.execution_id
            and row["state_version"] == model.state_version
            and row["status"] == model.status
        ):
            raise DigestIntegrityError("result-ingestion row binding mismatch")

    def add_pending(self, record: ResultIngestionRecord) -> ResultIngestionRecord:
        if record.status != "PENDING" or record.state_version != 0:
            raise ExecutionStateTransitionError("new ingestion must start at PENDING version 0")
        self.verify_integrity(record)
        payload = model_json(record)
        self._insert_or_same(
            "INSERT INTO result_ingestions"
            "(ingestion_id, ingestion_digest, execution_id, state_version, status, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                record.ingestion_id,
                record.ingestion_digest,
                record.execution_id,
                record.state_version,
                record.status,
                payload,
            ),
            payload,
        )
        return record

    def get_by_execution(self, execution_id: str) -> ResultIngestionRecord | None:
        row = self.database.connection.execute(
            "SELECT ingestion_id FROM result_ingestions WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        return None if row is None else self.get(str(row["ingestion_id"]))

    def transition(
        self,
        ingestion_id: str,
        *,
        expected_state_version: int,
        status: ResultIngestionStatus,
        now: datetime,
        lease_id: str | None = None,
        failure_code: str | None = None,
    ) -> ResultIngestionRecord:
        current = self.get(ingestion_id)
        if current is None or current.state_version != expected_state_version:
            raise ExecutionStateTransitionError("ingestion state version is stale")
        if status not in self._allowed[current.status]:
            raise ExecutionStateTransitionError("ingestion transition is not allowed")
        updated = ResultIngestionRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "state_version": current.state_version + 1,
                "status": status,
                "lease_id": lease_id,
                "attempt_count": current.attempt_count + (1 if status == "INGESTING" else 0),
                "failure_code": failure_code,
                "updated_at": now,
                "ingestion_digest": "pending",
            }
        )
        updated = updated.model_copy(
            update={"ingestion_digest": ingestion_record_digest(updated)}
        )
        cursor = self.database.connection.execute(
            "UPDATE result_ingestions SET ingestion_digest = ?, state_version = ?, status = ?, "
            "payload_json = ? WHERE ingestion_id = ? AND state_version = ? "
            "AND ingestion_digest = ?",
            (
                updated.ingestion_digest,
                updated.state_version,
                updated.status,
                model_json(updated),
                ingestion_id,
                current.state_version,
                current.ingestion_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise ExecutionStateTransitionError("ingestion OCC update failed")
        return updated


class ExecutionResultRepository(ImmutableJsonRepository[ExecutionResult]):
    table = "execution_results"
    id_column = "result_id"
    model_type = ExecutionResult

    def verify_integrity(self, model: ExecutionResult) -> None:
        verify_model_digest(model, model.result_digest, exclude={"result_digest"})
        ingestion = ResultIngestionRepository(self.database).get_by_execution(
            model.execution_id
        )
        if (
            ingestion is None
            or ingestion.receipt_id is None
            or ingestion.status not in {"INGESTING", "SUCCEEDED"}
        ):
            raise DigestIntegrityError("execution result is not bound to result ingestion")
        identity = {
            "schema_version": "execution-result-v1",
            "execution_id": model.execution_id,
            "receipt_id": ingestion.receipt_id,
            "secure_ingestion_id": model.secure_ingestion_id,
        }
        if model.result_id != stable_id("result", identity):
            raise DigestIntegrityError("execution result ID mismatch")
        execution = ExecutionRepository(self.database).get(model.execution_id)
        if execution is None or execution.provider_execution_state != model.status:
            raise DigestIntegrityError("execution result provider state mismatch")
        decision = PolicyDecisionRepository(self.database).get(model.policy_decision_id)
        plan = None if decision is None else PlanRepository(self.database).get(decision.plan_id)
        if decision is None or plan is None or not (
            execution.provider_task_id == model.provider_task_id
            and execution.resolved_adapter_id == model.adapter_id
            and execution.policy_decision_id == model.policy_decision_id
            and decision.tool_ref == model.tool_ref
            and decision.normalized_targets == model.normalized_targets
            and plan.proposal.session_id == model.session_id
        ):
            raise DigestIntegrityError("execution result authorization binding mismatch")

    def verify_row_binding(self, identifier: str | int, model: ExecutionResult) -> None:
        row = self.database.connection.execute(
            "SELECT result_digest, execution_id FROM execution_results WHERE result_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or not (
            model.result_id == identifier
            and row["result_digest"] == model.result_digest
            and row["execution_id"] == model.execution_id
        ):
            raise DigestIntegrityError("execution result row binding mismatch")

    def add(self, result: ExecutionResult) -> ExecutionResult:
        self.verify_integrity(result)
        payload = model_json(result)
        self._insert_or_same(
            "INSERT INTO execution_results"
            "(result_id, result_digest, execution_id, payload_json) VALUES (?, ?, ?, ?)",
            (result.result_id, result.result_digest, result.execution_id, payload),
            payload,
        )
        return result

    def get_by_execution(self, execution_id: str) -> ExecutionResult | None:
        row = self.database.connection.execute(
            "SELECT result_id FROM execution_results WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        return None if row is None else self.get(str(row["result_id"]))
