"""Phase 0C encrypted-quarantine collection (SystemDesign §10.3 / §33.1).

This is the 0C equivalent of collection completion: it streams a dispatched execution's
raw result into the encrypted quarantine under a fenced collection lease, then atomically
commits the committed-quarantine metadata, the control metadata, the receipt binding and
a PENDING ingestion state (reusing the Phase 0B ingestion-state record). Secure ingestion
consumes the resulting ``ingestion_id``. Provider results are never re-submitted.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import RawResultQuarantineError
from redteam_agent.execution.adapter import ExecutionAdapter
from redteam_agent.execution.models import (
    AdapterCollectionControl,
    ExecutionRecord,
    LeaseFence,
    RawControlMetadataRecord,
    RawResultReceipt,
    ResultIngestionStateRecord,
    ResultTaskBinding,
)
from redteam_agent.execution.records import compute_receipt_digest, finalize_object_digest
from redteam_agent.leases.service import LeaseService
from redteam_agent.mission.models import Mission
from redteam_agent.quarantine.store import EncryptedQuarantineStore, EncryptedStreamingQuarantineSink
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionRecoveryAuthorityRepository,
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

    @property
    def collection_id(self) -> str:
        return f"collection-{self.quarantine_id.removeprefix('q-')}"

    @property
    def status(self) -> str:
        return "COMPLETE"


@dataclass(frozen=True)
class _CollectionContext:
    record: ExecutionRecord
    binding: ResultTaskBinding
    collection_id: str
    quarantine_id: str
    ingestion_id: str
    authority_digest: str
    retention_until: datetime
    lease_id: str
    lease_fence: LeaseFence


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
        recovery_repository: ExecutionRecoveryAuthorityRepository,
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
        self._recovery = recovery_repository
        self._quarantine = quarantine_store
        self._leases = lease_service
        self._audit = audit_store
        self._retention_seconds = quarantine_retention_seconds
        self._owner_id = owner_id

    def collect(
        self, *, execution_id: str, stdout: bytes, stderr: bytes, control: AdapterCollectionControl,
        recovery_authority_id: str | None = None,
    ) -> QuarantineCollectionResult:
        return self.collect_streams(
            execution_id=execution_id,
            stdout_chunks=_bounded_chunks(stdout),
            stderr_chunks=_bounded_chunks(stderr),
            control=control,
            recovery_authority_id=recovery_authority_id,
        )

    def collect_streams(
        self, *, execution_id: str, stdout_chunks: Iterable[bytes],
        stderr_chunks: Iterable[bytes], control: AdapterCollectionControl,
        recovery_authority_id: str | None = None,
    ) -> QuarantineCollectionResult:
        context, sink = self._prepare_collection(
            execution_id=execution_id, recovery_authority_id=recovery_authority_id
        )
        for chunk in stdout_chunks:
            if chunk:
                sink.write_stdout(chunk)
        for chunk in stderr_chunks:
            if chunk:
                sink.write_stderr(chunk)
        return self._finalize_collection(context=context, sink=sink, control=control)

    def collect_from_adapter(
        self, *, execution_id: str, adapter: ExecutionAdapter,
        recovery_authority_id: str | None = None,
    ) -> QuarantineCollectionResult:
        """Provider-result entry point; the adapter streams directly into encrypted quarantine."""
        context, sink = self._prepare_collection(
            execution_id=execution_id, recovery_authority_id=recovery_authority_id
        )
        control = adapter.collect_result(execution_id, context.binding, sink)
        return self._finalize_collection(context=context, sink=sink, control=control)

    def prepare_local_collection(
        self, *, execution_id: str, binding: ResultTaskBinding
    ) -> tuple[_CollectionContext, EncryptedStreamingQuarantineSink]:
        if binding.binding_type != "local_result":
            raise RawResultQuarantineError("local collection requires a local_result binding")
        return self._prepare_collection(execution_id=execution_id, local_binding=binding)

    def finalize_local_collection(
        self, *, execution_id: str, sink: EncryptedStreamingQuarantineSink,
        control: AdapterCollectionControl,
    ) -> QuarantineCollectionResult:
        lease = self._leases.get_collection_lease(f"collection-{execution_id}")
        binding = self._bindings.find_by_execution(execution_id)
        metadata = self._quarantine.get_metadata(f"q-{execution_id}")
        record = self._require_execution(execution_id)
        if lease is None or binding is None or metadata is None:
            raise RawResultQuarantineError("local collection preparation is incomplete")
        context = _CollectionContext(
            record=record,
            binding=binding,
            collection_id=lease.collection_id,
            quarantine_id=metadata.quarantine_id,
            ingestion_id=f"ingestion-{execution_id}",
            authority_digest=lease.authority_digest,
            retention_until=metadata.retention_until,
            lease_id=lease.lease_id,
            lease_fence=lease.fence,
        )
        return self._finalize_collection(context=context, sink=sink, control=control)

    def _prepare_collection(
        self, *, execution_id: str, local_binding: ResultTaskBinding | None = None,
        recovery_authority_id: str | None = None,
    ) -> tuple[_CollectionContext, EncryptedStreamingQuarantineSink]:
        record = self._require_execution(execution_id)
        if record.provider_execution_state not in (
            "DISPATCHED",
            "RUNNING",
            "DISPATCH_CLAIMED",
            "RECONCILING",
            "SUCCEEDED",
            "FAILED",
            "CANCELLED",
        ):
            raise RawResultQuarantineError("collection requires a dispatched execution")
        binding = self._bindings.find_by_execution(execution_id)
        if binding is None and local_binding is not None:
            with UnitOfWork(self._db):
                self._bindings.create(local_binding, guard=self._guard)
                self._db.record_critical_mutation(CriticalMutation(
                    mission_id=record.mission_id,
                    event_type="RESULT_TASK_BOUND",
                    actor_id="encrypted-quarantine-collection",
                    occurred_at_iso=_iso(self._clock.now()),
                    record_type="result_task_binding",
                    record_id=local_binding.task_id,
                    state_version=record.execution_state_version,
                    security_projection_digest=local_binding.binding_digest,
                ))
            binding = local_binding
        if binding is None:
            raise RawResultQuarantineError("no result task binding for collection")
        if local_binding is not None and binding.binding_digest != local_binding.binding_digest:
            raise RawResultQuarantineError("local result binding conflicts with the stored binding")
        mission = self._enforce_recovery_window(
            record, recovery_authority_id=recovery_authority_id
        )
        started = self._clock.now()
        retention_until = min(started + timedelta(seconds=self._retention_seconds), mission.evidence_retention_until)
        quarantine_id = f"q-{execution_id}"
        collection_id = f"collection-{execution_id}"
        authority_digest = self._ds.compute(
            "result_progress_digest", {"authority": collection_id, "task": binding.binding_digest})
        lease = self._leases.acquire_collection_lease(
            collection_id=collection_id, execution_id=execution_id, authority_digest=authority_digest,
            task_binding=binding, sink_id=f"sink-{execution_id}", owner_id=self._owner_id,
            expected_execution_state_version=record.execution_state_version,
            caps=(mission.recovery_until, retention_until),
        )
        with ApplicationUnitOfWork(
            self._db, aggregate_name="QuarantineAggregate",
            operation_id=f"quarantine-create-{execution_id}-{lease.fence.fencing_token}",
            input_digest=compute_input_digest({"create": quarantine_id, "fence": lease.fence.fencing_token}),
        ) as uow:
            if not uow.already_applied:
                self._quarantine.create_quarantine(
                    quarantine_id=quarantine_id, mission_id=record.mission_id,
                    mission_revision=record.mission_revision, execution_id=execution_id, task_binding=binding,
                    deployment_epoch=lease.fence.deployment_epoch, fencing_token=lease.fence.fencing_token,
                    retention_until=retention_until,
                )
                uow.record_result(quarantine_id)
        context = _CollectionContext(
            record=record, binding=binding, collection_id=collection_id, quarantine_id=quarantine_id,
            ingestion_id=f"ingestion-{execution_id}", authority_digest=authority_digest,
            retention_until=retention_until, lease_id=lease.lease_id, lease_fence=lease.fence,
        )
        sink = self._quarantine.open_writer(
            quarantine_id, sink_id=lease.sink_id, task_binding_digest=binding.binding_digest,
            max_output_bytes=8 * 1024 * 1024,
            deployment_epoch=lease.fence.deployment_epoch,
            fencing_token=lease.fence.fencing_token,
            authorize_mutation=lambda mutation: self._leases.run_collection_mutation(
                collection_id=collection_id, owner_id=self._owner_id, lease_id=lease.lease_id,
                fence=lease.fence, authority_digest=authority_digest,
                expected_execution_state_version=record.execution_state_version, mutation=mutation,
            ),
        )
        return context, sink

    def validate_collection_request(
        self, *, execution_id: str, recovery_authority_id: str | None = None,
    ) -> None:
        """Validate a compatibility start request without creating parallel state."""
        record = self._require_execution(execution_id)
        binding = self._bindings.find_by_execution(execution_id)
        if binding is None:
            raise RawResultQuarantineError("no result task binding for collection")
        self._enforce_recovery_window(record, recovery_authority_id=recovery_authority_id)

    def _enforce_recovery_window(
        self, record: ExecutionRecord, *, recovery_authority_id: str | None,
    ) -> Mission:
        now = self._clock.now()
        mission = self._resolver.resolve(record.mission_id, now=now).mission
        if not (now < mission.recovery_until):
            raise RawResultQuarantineError("recovery window has passed; no provider operation permitted")
        if now < mission.valid_until:
            return mission
        if recovery_authority_id is None:
            raise RawResultQuarantineError(
                "a purpose-limited recovery authority is required after valid_until"
            )
        authority = self._recovery.get(recovery_authority_id)
        binding = self._bindings.find_by_execution(record.execution_id)
        binding_id = binding.task_id if binding is not None else None
        if (
            authority is None
            or authority.allowed_operation != "collect_result"
            or authority.mission_id != record.mission_id
            or authority.execution_id != record.execution_id
            or not (now < authority.expires_at)
            or authority.mission_revision != mission.mission_revision
            or authority.authorization_epoch != mission.authorization_epoch
            or authority.origin_authorization_digest != record.authorization_digest
            or authority.resolved_adapter_id != record.resolved_adapter_id
            or authority.idempotency_key != record.idempotency_key
            or authority.expected_execution_state_version != record.execution_state_version
            or authority.result_task_binding_id != binding_id
        ):
            raise RawResultQuarantineError("recovery authority is missing, expired, or wrongly bound")
        return mission

    def _finalize_collection(
        self, *, context: _CollectionContext, sink: EncryptedStreamingQuarantineSink,
        control: AdapterCollectionControl,
    ) -> QuarantineCollectionResult:
        record = context.record
        binding = context.binding
        receipt = sink.commit()
        receipt_digest = compute_receipt_digest(receipt, self._ds)
        control_record = self._build_control(record=record, binding=binding, receipt=receipt,
                                             receipt_digest=receipt_digest, control=control)
        ingestion = self._build_ingestion(record=record, receipt=receipt, receipt_digest=receipt_digest,
                                         quarantine_id=context.quarantine_id, collection_id=context.collection_id,
                                         retention_until=context.retention_until)
        mirror = self._mirror(record, control)
        op = compute_input_digest({"collect": record.execution_id, "receipt": receipt_digest})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="CollectionLeaseAggregate", operation_id=f"collect-{record.execution_id}",
            input_digest=op,
        ) as uow:
            if not uow.already_applied:
                self._leases.validate_collection_lease(
                    collection_id=context.collection_id, owner_id=self._owner_id, lease_id=context.lease_id,
                    fence=context.lease_fence, authority_digest=context.authority_digest,
                    expected_execution_state_version=record.execution_state_version,
                )
                self._quarantine.commit_metadata(context.quarantine_id, receipt=receipt, chunk_count=sink.chunk_count,
                                                 size_bytes=sink.size_bytes)
                if self._control.find_by_execution(record.execution_id) is None:
                    self._control.create(control_record, guard=self._guard)
                if self._ingestion.find_by_execution(record.execution_id) is None:
                    self._ingestion.create(ingestion, guard=self._guard)
                self._executions.transition(mirror, expected_version=record.execution_state_version, guard=self._guard)
                self._leases.release_collection_lease(collection_id=context.collection_id, owner_id=self._owner_id)
                self._audit.append_in_txn(mission_id=record.mission_id, event_type="COLLECTION_COMMITTED",
                                          payload_digest=receipt_digest, actor_id="collection-worker",
                                          occurred_at_iso=_iso(self._clock.now()),
                                          record_type="result_ingestion_state",
                                          record_id=ingestion.ingestion_id,
                                          state_version=ingestion.state_version,
                                          security_projection_digest=ingestion.record_digest)
                uow.record_result(receipt_digest)
        return QuarantineCollectionResult(quarantine_id=context.quarantine_id, ingestion_id=context.ingestion_id,
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

    def _mirror(self, record: ExecutionRecord, control: AdapterCollectionControl) -> ExecutionRecord:
        terminal = {"succeeded": "SUCCEEDED", "failed": "FAILED", "cancelled": "CANCELLED"}[
            control.provider_status
        ]
        if (
            record.provider_execution_state in {"SUCCEEDED", "FAILED", "CANCELLED"}
            and record.provider_execution_state != terminal
        ):
            raise RawResultQuarantineError(
                "collection control conflicts with the reconciled terminal outcome"
            )
        updates: dict[str, object] = {
            "result_ingestion_state": "PENDING",
            "provider_execution_state": terminal,
            "raw_result_quarantine_id": f"q-{record.execution_id}",
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


def _bounded_chunks(value: bytes, size: int = 1024 * 1024) -> Iterable[bytes]:
    for offset in range(0, len(value), size):
        yield value[offset:offset + size]
