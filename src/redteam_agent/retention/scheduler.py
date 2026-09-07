"""Local retention scheduler (SystemDesign §10.3 / §21.3 / §33.2).

This is the only path that confirms expiry. It reads current root / clock / anchor and
the stored retention deadline, checks the expected state version and the current lease
snapshot (or its absence) under one OCC transaction, and atomically commits the expiry
state, the typed deletion intent, the lease invalidation and the audit event. It never
reads or publishes output, dispatches, or resolves secrets, and it never shortens a
quarantine's own retention. Erasure is left to the dedicated eraser via the intent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.erasure.models import QuarantineDeletionIntent
from redteam_agent.errors import ResultIngestionError
from redteam_agent.execution.models import ExecutionRecord, ResultIngestionStateRecord, ResultIngestionStatus
from redteam_agent.execution.records import finalize_object_digest
from redteam_agent.execution.state_machine import is_legal_ingestion_edge
from redteam_agent.leases.service import DeploymentEpochService, LeaseService
from redteam_agent.quarantine.models import RawResultQuarantineMetadata
from redteam_agent.quarantine.store import EncryptedQuarantineStore
from redteam_agent.runtime.clock import ClockIntegrityGuard
from redteam_agent.storage.database import CriticalMutation, Database
from redteam_agent.storage.execution_repositories import ExecutionRecordRepository, ResultIngestionStateRepository
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.unit_of_work import ApplicationUnitOfWork, compute_input_digest

_INTENT_NS = "quarantine_deletion_intent"
_UNPUBLISHED = ("PENDING", "INGESTING", "FAILED", "QUARANTINED")


@dataclass(frozen=True)
class RetentionExpiryOutcome:
    kind: str
    deletion_intent_id: str | None
    ingestion_status: str | None
    quarantine_status: str | None


class LocalRetentionScheduler:
    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        clock_guard: ClockIntegrityGuard,
        epoch_service: DeploymentEpochService,
        lease_service: LeaseService,
        ingestion_repository: ResultIngestionStateRepository,
        execution_repository: ExecutionRecordRepository,
        quarantine_store: EncryptedQuarantineStore,
        audit_store: AuditStore,
        exec_guard: WriteGuard,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._guard_clock = clock_guard
        self._epoch = epoch_service
        self._leases = lease_service
        self._ingestion = ingestion_repository
        self._executions = execution_repository
        self._quarantine = quarantine_store
        self._audit = audit_store
        self._guard = exec_guard

    def _trusted_now(self) -> datetime:
        # Reads through the clock integrity guard so a UTC rollback / divergence stops
        # the scheduler with ClockIntegrityError.
        return self._guard_clock.read().utc

    def _anchor_ok(self) -> None:
        if self._epoch.current() is None:
            raise ResultIngestionError("no deployment epoch mirror; scheduler cannot run")

    # --- evidence-retention expiry (committed quarantine, unpublished ingestion) ---

    def expire_evidence_retention(self, *, ingestion_id: str, expected_state_version: int) -> RetentionExpiryOutcome:
        self._anchor_ok()
        now = self._trusted_now()
        state = self._ingestion.get(ingestion_id)
        if state is None:
            raise ResultIngestionError("ingestion state not found")
        if state.status not in _UNPUBLISHED:
            return RetentionExpiryOutcome("noop", None, state.status, None)
        if state.state_version != expected_state_version:
            raise ResultIngestionError("expected ingestion state version mismatch")
        quarantine = self._quarantine.get_metadata(state.quarantine_id or "")
        if quarantine is None or quarantine.status != "COMMITTED":
            raise ResultIngestionError("evidence-retention expiry requires a committed quarantine")
        if now < quarantine.retention_until:
            return RetentionExpiryOutcome("not_due", None, state.status, quarantine.status)
        record = self._require_execution(state.execution_id)
        intent = self._build_retention_intent(state=state, record=record, quarantine=quarantine, now=now)
        expired = self._advance(state, "EVIDENCE_RETENTION_EXPIRED", now)
        delete_pending = self._advance(expired, "DELETE_PENDING", now)
        op = compute_input_digest({"retention-expiry": ingestion_id, "v": expected_state_version})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="IngestionPublicationAggregate",
            operation_id=f"retention-expiry-{ingestion_id}", input_digest=op,
        ) as uow:
            if not uow.already_applied:
                self._db.occ_insert_idempotent(_INTENT_NS, intent.deletion_intent_id, 1, _dump(intent))
                self._ingestion.update(expired, expected_version=state.state_version, guard=self._guard)
                self._ingestion.update(delete_pending, expected_version=expired.state_version, guard=self._guard)
                self._executions.transition(self._mirror(record, "DELETE_PENDING"),
                                            expected_version=record.execution_state_version, guard=self._guard)
                self._leases.invalidate_ingestion_lease(ingestion_id=ingestion_id)
                self._audit.append_in_txn(mission_id=record.mission_id, event_type="EVIDENCE_RETENTION_EXPIRED",
                                          payload_digest=intent.intent_digest, actor_id="retention-scheduler",
                                          occurred_at_iso=_iso(now), record_type="quarantine_deletion_intent",
                                          record_id=intent.deletion_intent_id,
                                          state_version=delete_pending.state_version,
                                          security_projection_digest=intent.intent_digest)
                self._db.record_critical_mutation(
                    CriticalMutation(
                        mission_id=record.mission_id,
                        event_type="INGESTION_STATE_CHANGED",
                        actor_id="retention-scheduler",
                        occurred_at_iso=_iso(now),
                        record_type="result_ingestion_state",
                        record_id=delete_pending.ingestion_id,
                        state_version=delete_pending.state_version,
                        security_projection_digest=delete_pending.record_digest,
                    )
                )
                uow.record_result(intent.intent_digest)
        return RetentionExpiryOutcome("retention_expiry", intent.deletion_intent_id, "DELETE_PENDING", "COMMITTED")

    # --- incomplete-collection expiry (quarantine never committed) ---------

    def expire_incomplete_collection(self, *, quarantine_id: str, execution_id: str) -> RetentionExpiryOutcome:
        self._anchor_ok()
        now = self._trusted_now()
        quarantine = self._quarantine.get_metadata(quarantine_id)
        if quarantine is None:
            raise ResultIngestionError("quarantine not found")
        if quarantine.status in ("DELETED", "RETENTION_EXPIRED"):
            return RetentionExpiryOutcome("noop", f"delintent-incomplete-{quarantine_id}", None, quarantine.status)
        if quarantine.status == "COMMITTED":
            raise ResultIngestionError("committed collection uses the evidence-retention path, not incomplete")
        if now < quarantine.retention_until:
            return RetentionExpiryOutcome("not_due", None, None, quarantine.status)
        record = self._require_execution(execution_id)
        intent = self._build_incomplete_intent(quarantine=quarantine, record=record, now=now)
        op = compute_input_digest({"incomplete-expiry": quarantine_id})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="QuarantineAggregate",
            operation_id=f"incomplete-expiry-{quarantine_id}", input_digest=op,
        ) as uow:
            if not uow.already_applied:
                self._db.occ_insert_idempotent(_INTENT_NS, intent.deletion_intent_id, 1, _dump(intent))
                self._quarantine.set_status(quarantine_id, "RETENTION_EXPIRED")
                self._audit.append_in_txn(mission_id=record.mission_id, event_type="INCOMPLETE_COLLECTION_EXPIRED",
                                          payload_digest=intent.intent_digest, actor_id="retention-scheduler",
                                          occurred_at_iso=_iso(now), record_type="quarantine_deletion_intent",
                                          record_id=intent.deletion_intent_id, state_version=1,
                                          security_projection_digest=intent.intent_digest)
                uow.record_result(intent.intent_digest)
        return RetentionExpiryOutcome(
            "incomplete_collection_expiry", intent.deletion_intent_id, None, "RETENTION_EXPIRED")

    # --- builders ---------------------------------------------------------

    def _build_retention_intent(
        self, *, state: ResultIngestionStateRecord, record: ExecutionRecord,
        quarantine: RawResultQuarantineMetadata, now: datetime,
    ) -> QuarantineDeletionIntent:
        model = QuarantineDeletionIntent(
            deletion_intent_id=f"delintent-retention-{state.ingestion_id}", intent_type="retention_expiry",
            reason="EVIDENCE_RETENTION_EXPIRED", quarantine_id=quarantine.quarantine_id,
            execution_id=record.execution_id, ingestion_id=state.ingestion_id,
            encryption_metadata_id=quarantine.encryption_metadata_id,
            key_metadata_digest=self._quarantine.encryption_key_metadata_digest(quarantine.quarantine_id),
            resource_copy_inventory_digest=self._copy_inventory_digest(quarantine.quarantine_id),
            quarantine_ciphertext_digest=quarantine.ciphertext_digest,
            result_task_binding_digest=quarantine.task_binding.binding_digest,
            retention_deadline=quarantine.retention_until,
            manifest_id=None, manifest_digest=None, receipt_id=state.receipt_id, receipt_digest=state.receipt_digest,
            final_ingestion_state=state.status, last_committed_chunk_sequence=None, quarantine_status=None,
            created_at=now, intent_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="intent_digest", digest_name="deletion_intent_digest", digest_service=self._ds
        )

    def _build_incomplete_intent(
        self, *, quarantine: RawResultQuarantineMetadata, record: ExecutionRecord, now: datetime,
    ) -> QuarantineDeletionIntent:
        model = QuarantineDeletionIntent(
            deletion_intent_id=f"delintent-incomplete-{quarantine.quarantine_id}",
            intent_type="incomplete_collection_expiry", reason="INCOMPLETE_COLLECTION_EXPIRED",
            quarantine_id=quarantine.quarantine_id, execution_id=record.execution_id, ingestion_id=None,
            encryption_metadata_id=quarantine.encryption_metadata_id,
            key_metadata_digest=self._quarantine.encryption_key_metadata_digest(quarantine.quarantine_id),
            resource_copy_inventory_digest=self._copy_inventory_digest(quarantine.quarantine_id),
            quarantine_ciphertext_digest=quarantine.ciphertext_digest,
            result_task_binding_digest=quarantine.task_binding.binding_digest,
            retention_deadline=quarantine.retention_until,
            manifest_id=None, manifest_digest=None, receipt_id=None, receipt_digest=None, final_ingestion_state=None,
            last_committed_chunk_sequence=quarantine.chunk_count, quarantine_status=quarantine.status, created_at=now,
            intent_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="intent_digest", digest_name="deletion_intent_digest", digest_service=self._ds
        )

    def _copy_inventory_digest(self, quarantine_id: str) -> str:
        return self._ds.compute("copy_inventory_digest", {"quarantine_id": quarantine_id, "class": "encrypted_blob"})

    def _advance(
        self, state: ResultIngestionStateRecord, status: ResultIngestionStatus, now: datetime
    ) -> ResultIngestionStateRecord:
        if not is_legal_ingestion_edge(state.status, status):
            raise ResultIngestionError(f"illegal ingestion transition {state.status} -> {status}")
        return finalize_object_digest(
            state.model_copy(update={
                "state_version": state.state_version + 1, "status": status, "updated_at": now,
            }),
            digest_field="record_digest", digest_name="result_ingestion_state_digest", digest_service=self._ds,
        )

    def _mirror(self, record: ExecutionRecord, status: ResultIngestionStatus) -> ExecutionRecord:
        return finalize_object_digest(
            record.model_copy(update={
                "result_ingestion_state": status, "execution_state_version": record.execution_state_version + 1,
                "updated_at": self._guard_clock.read().utc,
            }),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self._executions.get(execution_id)
        if record is None:
            raise ResultIngestionError("execution not found")
        return record


def _dump(model: object) -> str:
    assert hasattr(model, "model_dump")
    return json.dumps(model.model_dump(mode="json"), sort_keys=True)  # type: ignore[attr-defined]


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
