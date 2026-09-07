"""Phase 0C encrypted-quarantine collection (SystemDesign §10.3 / §33.1).

This is the 0C equivalent of collection completion: it streams a dispatched execution's
raw result into the encrypted quarantine under a fenced collection lease, then atomically
commits the committed-quarantine metadata, the control metadata, the receipt binding and
a PENDING ingestion state (reusing the Phase 0B ingestion-state record). Secure ingestion
consumes the resulting ``ingestion_id``. Provider results are never re-submitted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import RawResultQuarantineError
from redteam_agent.execution.models import (
    AdapterCollectionControl,
    ExecutionRecord,
    RawControlMetadataRecord,
    RawResultReceipt,
    ResultIngestionStateRecord,
    ResultTaskBinding,
)
from redteam_agent.execution.records import compute_receipt_digest, finalize_object_digest
from redteam_agent.leases.service import LeaseService
from redteam_agent.quarantine.store import EncryptedQuarantineStore
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    RawControlMetadataRepository,
    ResultIngestionStateRepository,
    ResultTaskBindingRepository,
)
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.unit_of_work import ApplicationUnitOfWork, compute_input_digest


@dataclass(frozen=True)
class QuarantineCollectionResult:
    quarantine_id: str
    ingestion_id: str
    receipt_id: str


class QuarantineCollectionService:
    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        clock: Clock,
        exec_guard: WriteGuard,
        context_resolver: AuthorizationContextResolver,
        execution_repository: ExecutionRecordRepository,
        task_binding_repository: ResultTaskBindingRepository,
        control_metadata_repository: RawControlMetadataRepository,
        ingestion_repository: ResultIngestionStateRepository,
        quarantine_store: EncryptedQuarantineStore,
        lease_service: LeaseService,
        audit_store: AuditStore,
        quarantine_retention_seconds: int,
        owner_id: str = "collection-worker-1",
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._guard = exec_guard
        self._resolver = context_resolver
        self._executions = execution_repository
        self._bindings = task_binding_repository
        self._control = control_metadata_repository
        self._ingestion = ingestion_repository
        self._quarantine = quarantine_store
        self._leases = lease_service
        self._audit = audit_store
        self._retention_seconds = quarantine_retention_seconds
        self._owner_id = owner_id

    def collect(
        self, *, execution_id: str, stdout: bytes, stderr: bytes, control: AdapterCollectionControl,
    ) -> QuarantineCollectionResult:
        record = self._require_execution(execution_id)
        if record.provider_execution_state not in ("DISPATCHED", "RUNNING", "DISPATCH_CLAIMED", "RECONCILING"):
            raise RawResultQuarantineError("collection requires a dispatched execution")
        binding = self._bindings.find_by_execution(execution_id)
        if binding is None:
            raise RawResultQuarantineError("no result task binding for collection")
        mission = self._resolver.resolve(record.mission_id, now=self._clock.now()).mission
        started = self._clock.now()
        retention_until = min(started + timedelta(seconds=self._retention_seconds), mission.evidence_retention_until)
        quarantine_id = f"q-{execution_id}"
        collection_id = f"collection-{execution_id}"
        ingestion_id = f"ingestion-{execution_id}"
        authority_digest = self._ds.compute(
            "result_progress_digest", {"authority": collection_id, "task": binding.binding_digest})

        lease = self._leases.acquire_collection_lease(
            collection_id=collection_id, execution_id=execution_id, authority_digest=authority_digest,
            task_binding=binding, sink_id=f"sink-{execution_id}", owner_id=self._owner_id,
            expected_execution_state_version=record.execution_state_version,
            caps=(mission.recovery_until, retention_until),
        )
        # Create the encrypted quarantine (fence-specific staging), then stream.
        with ApplicationUnitOfWork(
            self._db, aggregate_name="QuarantineAggregate", operation_id=f"quarantine-create-{execution_id}",
            input_digest=compute_input_digest({"create": quarantine_id}),
        ) as uow:
            if not uow.already_applied:
                self._quarantine.create_quarantine(
                    quarantine_id=quarantine_id, mission_id=record.mission_id,
                    mission_revision=record.mission_revision, execution_id=execution_id, task_binding=binding,
                    deployment_epoch=lease.fence.deployment_epoch, fencing_token=lease.fence.fencing_token,
                    retention_until=retention_until,
                )
                uow.record_result(quarantine_id)

        sink = self._quarantine.open_writer(
            quarantine_id, sink_id=lease.sink_id, task_binding_digest=binding.binding_digest,
            max_output_bytes=8 * 1024 * 1024,
        )
        if stdout:
            sink.write_stdout(stdout)
        if stderr:
            sink.write_stderr(stderr)
        receipt = sink.commit()
        receipt_digest = compute_receipt_digest(receipt, self._ds)
        control_record = self._build_control(record=record, binding=binding, receipt=receipt,
                                             receipt_digest=receipt_digest, control=control)
        ingestion = self._build_ingestion(record=record, receipt=receipt, receipt_digest=receipt_digest,
                                         quarantine_id=quarantine_id, collection_id=collection_id,
                                         retention_until=retention_until)
        mirror = self._mirror(record)
        op = compute_input_digest({"collect": execution_id, "receipt": receipt_digest})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="CollectionLeaseAggregate", operation_id=f"collect-{execution_id}",
            input_digest=op,
        ) as uow:
            if not uow.already_applied:
                self._leases.validate_collection_lease(
                    collection_id=collection_id, owner_id=self._owner_id, lease_id=lease.lease_id,
                    fence=lease.fence, authority_digest=authority_digest,
                    expected_execution_state_version=record.execution_state_version,
                )
                self._quarantine.commit_metadata(quarantine_id, receipt=receipt, chunk_count=sink.chunk_count,
                                                 size_bytes=sink.size_bytes)
                if self._control.find_by_execution(execution_id) is None:
                    self._control.create(control_record, guard=self._guard)
                if self._ingestion.find_by_execution(execution_id) is None:
                    self._ingestion.create(ingestion, guard=self._guard)
                self._executions.transition(mirror, expected_version=record.execution_state_version, guard=self._guard)
                self._leases.release_collection_lease(collection_id=collection_id, owner_id=self._owner_id)
                self._audit.append_in_txn(mission_id=record.mission_id, event_type="COLLECTION_COMMITTED",
                                          payload_digest=receipt_digest, actor_id="collection-worker",
                                          occurred_at_iso=_iso(self._clock.now()),
                                          record_type="result_ingestion_state",
                                          record_id=ingestion.ingestion_id,
                                          state_version=ingestion.state_version,
                                          security_projection_digest=ingestion.record_digest)
                uow.record_result(receipt_digest)
        return QuarantineCollectionResult(quarantine_id=quarantine_id, ingestion_id=ingestion_id,
                                          receipt_id=receipt.receipt_id)

    # --- builders ---------------------------------------------------------

    def _build_control(
        self, *, record: ExecutionRecord, binding: ResultTaskBinding, receipt: RawResultReceipt,
        receipt_digest: str, control: AdapterCollectionControl,
    ) -> RawControlMetadataRecord:
        model = RawControlMetadataRecord(
            control_record_id=f"control-{record.execution_id}", execution_id=record.execution_id,
            task_binding_digest=binding.binding_digest, receipt_id=receipt.receipt_id, receipt_digest=receipt_digest,
            status_normalization_rule_id=control.status_normalization_rule_id, provider_status=control.provider_status,
            exit_code=control.exit_code, timed_out=control.timed_out, provider_started_at=control.started_at,
            provider_finished_at=control.finished_at, trusted_received_at=self._clock.now(), record_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="record_digest", digest_name="raw_control_metadata_digest", digest_service=self._ds)

    def _build_ingestion(
        self, *, record: ExecutionRecord, receipt: RawResultReceipt, receipt_digest: str, quarantine_id: str,
        collection_id: str, retention_until: datetime,
    ) -> ResultIngestionStateRecord:
        model = ResultIngestionStateRecord(
            ingestion_id=f"ingestion-{record.execution_id}", execution_id=record.execution_id,
            collection_id=collection_id, state_version=1, status="PENDING", receipt_id=receipt.receipt_id,
            receipt_digest=receipt_digest, quarantine_id=quarantine_id, attempt_count=0, manifest_id=None,
            manifest_digest=None, ingested_durable_at=None, evidence_retention_until=retention_until,
            updated_at=self._clock.now(), record_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="record_digest", digest_name="result_ingestion_state_digest", digest_service=self._ds)

    def _mirror(self, record: ExecutionRecord) -> ExecutionRecord:
        # Only advance the ingestion mirror; the provider terminal-state transition is a
        # separate Phase 0B concern and is not driven from quarantine collection.
        updates: dict[str, object] = {
            "result_ingestion_state": "PENDING",
            "execution_state_version": record.execution_state_version + 1, "updated_at": self._clock.now(),
        }
        return finalize_object_digest(
            record.model_copy(update=updates), digest_field="record_digest", digest_name="execution_record_digest",
            digest_service=self._ds,
        )

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self._executions.get(execution_id)
        if record is None:
            raise RawResultQuarantineError("execution not found")
        return record


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
