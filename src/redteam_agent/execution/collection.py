"""Result collection coordinator (SystemDesign §10 / §10.3 / §21.1.1).

Collection is a recoverable process separate from provider execution. The
executor owns a trusted clock read once at collection start; the authority fixes
the collection deadline (mission.recovery_until), the quarantine retention
(min(start + policy, evidence_retention_until)) and the tool output cap
(min(tool.max_output_bytes, hard cap)). None of these are recomputed on restart,
none come from a caller timestamp, and the tool cap cannot be widened.

Window enforcement: before ``mission.valid_until`` an existing-execution
collection may proceed; at/after ``valid_until`` (and before ``recovery_until``)
collection requires an exact purpose-limited ``ExecutionRecoveryAuthority``
(``collect_result``); at/after ``recovery_until`` no provider operation runs.

Provider mode streams to a composition-owned sink chunk-by-chunk (never buffering
the whole result), resumes metadata-only after a commit crash, and never
re-submits. Local mode streams inline during dispatch, is completed from the
durable control metadata, and never queries the provider to fill missing data.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import ResultCollectionError
from redteam_agent.execution.adapter import ExecutionAdapter
from redteam_agent.execution.models import (
    AdapterCollectionControl,
    CollectionResumeCursor,
    ExecutionRecord,
    ProviderExecutionState,
    RawControlMetadataRecord,
    ResultCollectionAuthority,
    ResultCollectionStateRecord,
    ResultCollectionStatus,
    ResultIngestionStateRecord,
    ResultTaskBinding,
)
from redteam_agent.execution.records import (
    compute_progress_digest,
    compute_receipt_digest,
    finalize_object_digest,
)
from redteam_agent.execution.sink import RawResultSink, StreamingQuarantineSink
from redteam_agent.execution.state_machine import is_legal_collection_edge, is_legal_provider_edge
from redteam_agent.mission.models import Mission
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionRecoveryAuthorityRepository,
    RawControlMetadataRepository,
    ResultCollectionAuthorityRepository,
    ResultCollectionStateRepository,
    ResultIngestionStateRepository,
    ResultTaskBindingRepository,
)
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import ToolRegistryRepository

_TERMINAL_BY_PROVIDER_STATUS: dict[str, ProviderExecutionState] = {
    "succeeded": "SUCCEEDED",
    "failed": "FAILED",
    "cancelled": "CANCELLED",
}


@dataclass(frozen=True)
class CollectionResult:
    collection_id: str
    status: ResultCollectionStatus
    receipt_id: str | None
    ingestion_id: str | None


class ResultCollectionCoordinator:
    def __init__(
        self,
        *,
        database: Database,
        execution_repository: ExecutionRecordRepository,
        authority_repository: ResultCollectionAuthorityRepository,
        state_repository: ResultCollectionStateRepository,
        control_metadata_repository: RawControlMetadataRepository,
        ingestion_repository: ResultIngestionStateRepository,
        task_binding_repository: ResultTaskBindingRepository,
        recovery_repository: ExecutionRecoveryAuthorityRepository,
        registry_repository: ToolRegistryRepository,
        context_resolver: AuthorizationContextResolver,
        adapters: Mapping[str, ExecutionAdapter],
        clock: Clock,
        digest_service: DigestService,
        write_guard: WriteGuard,
        registry_revision: int,
        quarantine_retention_seconds: int,
        system_hard_output_cap: int,
    ) -> None:
        self._db = database
        self._executions = execution_repository
        self._authorities = authority_repository
        self._states = state_repository
        self._control = control_metadata_repository
        self._ingestion = ingestion_repository
        self._bindings = task_binding_repository
        self._recovery = recovery_repository
        self._registry_repo = registry_repository
        self._resolver = context_resolver
        self._adapters = dict(adapters)
        self._clock = clock
        self._ds = digest_service
        self._guard = write_guard
        self._registry_revision = registry_revision
        self._quarantine_retention_seconds = quarantine_retention_seconds
        self._system_hard_output_cap = system_hard_output_cap
        self._retired = False

    def retire_for_phase0c(self, *, guard: WriteGuard) -> None:
        """Irreversibly close the Phase 0B plaintext collection entry points."""
        if guard is not self._guard:
            raise ResultCollectionError("collection retirement requires the composition guard")
        self._retired = True

    def _require_active(self) -> None:
        if self._retired:
            raise ResultCollectionError("Phase 0B collection is retired after Phase 0C composition")

    # --- authority --------------------------------------------------------

    def start_collection(
        self, *, execution_id: str, recovery_authority_id: str | None = None
    ) -> ResultCollectionAuthority:
        self._require_active()
        existing = self._authorities.find_by_execution(execution_id)
        if existing is not None:
            return existing  # retention/deadline are fixed; never recomputed on resume
        record = self._require_execution(execution_id)
        if record.provider_execution_state not in ("DISPATCHED", "RUNNING", "RECONCILING"):
            raise ResultCollectionError("collection requires a dispatched execution")
        binding = self._bindings.find_by_execution(execution_id)
        if binding is None:
            raise ResultCollectionError("no result task binding for collection")
        mission = self._enforce_recovery_window(
            record, operation="collect_result", recovery_authority_id=recovery_authority_id
        )
        tool_max = self._require_tool_max_output(record)
        started = self._clock.now()  # trusted clock, read once
        if not (started < mission.recovery_until):
            raise ResultCollectionError("mission recovery window has passed; no new collection authority")
        retention_until = min(
            started + timedelta(seconds=self._quarantine_retention_seconds), mission.evidence_retention_until
        )
        authority = ResultCollectionAuthority(
            collection_id=f"collection-{execution_id}",
            execution_id=execution_id,
            task_binding=binding,
            tool_ref=record.tool_ref,
            tool_registry_digest=self._registry_digest(),
            max_output_bytes=min(tool_max, self._system_hard_output_cap),
            collection_started_at=started,
            collection_deadline=mission.recovery_until,
            retention_until=retention_until,
            sink_id=f"sink-{execution_id}",
        )
        state = self._build_state(
            collection_id=authority.collection_id, execution_id=execution_id, state_version=1,
            status="NOT_STARTED", receipt_id=None, receipt_digest=None, last_chunk=0,
        )
        mirror = self._mirror_collection(record, state.collection_state_id)
        with UnitOfWork(self._db):
            self._authorities.create(authority, guard=self._guard)
            self._states.create(state, guard=self._guard)
            self._executions.transition(mirror, expected_version=record.execution_state_version, guard=self._guard)
        return authority

    # --- provider collect -------------------------------------------------

    def collect(self, *, execution_id: str, recovery_authority_id: str | None = None) -> CollectionResult:
        self._require_active()
        authority = self._authorities.find_by_execution(execution_id)
        if authority is None:
            raise ResultCollectionError("collection authority not found; start collection first")
        record = self._require_execution(execution_id)
        state = self._require_state(execution_id)
        if state.status in ("COMPLETE", "ABANDONED"):
            ingestion = self._ingestion.find_by_execution(execution_id)
            return CollectionResult(
                collection_id=authority.collection_id, status=state.status,
                receipt_id=state.receipt_id, ingestion_id=ingestion.ingestion_id if ingestion else None,
            )
        binding = authority.task_binding
        if binding.binding_type == "local_result":
            # Local mode is completed from the durable capture, never by querying
            # the provider. Only a metadata-only completion from stored control is
            # allowed here.
            return self._complete_local_from_stored(authority=authority, record=record, state=state)

        mission = self._enforce_recovery_window(
            record, operation="collect_result", recovery_authority_id=recovery_authority_id
        )
        now = self._clock.now()
        if not (now < authority.collection_deadline) or not (now < mission.recovery_until):
            raise ResultCollectionError("collection deadline reached; no further provider read")
        adapter = self._adapters.get(record.resolved_adapter_id)
        if adapter is None:
            raise ResultCollectionError("no trusted adapter for collection")

        if state.status in ("NOT_STARTED", "STREAMING"):
            if state.status == "NOT_STARTED":
                state = self._advance(state, "STREAMING", receipt_id=None, receipt_digest=None, last_chunk=0)
                record = self._settle_provider_running(record)
            sink: RawResultSink = self._new_sink(authority, binding.binding_digest)
            resume = CollectionResumeCursor(
                collection_id=authority.collection_id, execution_id=execution_id,
                result_delivery_mode="provider_task", task_binding_digest=binding.binding_digest,
                sink_id=authority.sink_id, last_committed_chunk_sequence=state.last_committed_chunk_sequence,
                receipt_id=state.receipt_id,
            )
            control = adapter.collect_result(execution_id, binding, sink, resume=resume)
            receipt = sink.commit()
            receipt_digest = compute_receipt_digest(receipt, self._ds)
            self._verify_control_binding(control=control, binding=binding, adapter_id=record.resolved_adapter_id)
            state = self._advance(
                state, "COMMITTED_METADATA_PENDING", receipt_id=receipt.receipt_id,
                receipt_digest=receipt_digest, last_chunk=state.last_committed_chunk_sequence + 1,
            )
        else:
            # COMMITTED_METADATA_PENDING resume: metadata only, do not re-stream.
            record = self._settle_provider_running(record)
            control = adapter.get_task_control(execution_id, binding)
            self._verify_control_binding(control=control, binding=binding, adapter_id=record.resolved_adapter_id)

        record = self._require_execution(execution_id)
        return self._complete(authority=authority, record=record, state=state, binding=binding, control=control)

    # --- local dispatch-time collection -----------------------------------

    def prepare_local_collection(
        self, *, execution_id: str, binding: ResultTaskBinding
    ) -> tuple[ResultCollectionAuthority, RawResultSink]:
        self._require_active()
        if binding.binding_type != "local_result":
            raise ResultCollectionError("prepare_local_collection requires a local_result binding")
        record = self._require_execution(execution_id)
        if record.provider_execution_state != "DISPATCH_CLAIMED":
            raise ResultCollectionError("local collection is prepared during dispatch (DISPATCH_CLAIMED)")
        mission = self._resolver.resolve(record.mission_id, now=self._clock.now()).mission
        tool_max = self._require_tool_max_output(record)
        started = self._clock.now()
        if not (started < mission.recovery_until):
            raise ResultCollectionError("mission recovery window has passed; no local collection")
        retention_until = min(
            started + timedelta(seconds=self._quarantine_retention_seconds), mission.evidence_retention_until
        )
        authority = ResultCollectionAuthority(
            collection_id=f"collection-{execution_id}",
            execution_id=execution_id,
            task_binding=binding,
            tool_ref=record.tool_ref,
            tool_registry_digest=self._registry_digest(),
            max_output_bytes=min(tool_max, self._system_hard_output_cap),
            collection_started_at=started,
            collection_deadline=mission.recovery_until,
            retention_until=retention_until,
            sink_id=f"sink-{execution_id}",
        )
        state = self._build_state(
            collection_id=authority.collection_id, execution_id=execution_id, state_version=1,
            status="STREAMING", receipt_id=None, receipt_digest=None, last_chunk=0,
        )
        with UnitOfWork(self._db):
            self._bindings.create(binding, guard=self._guard)
            self._authorities.create(authority, guard=self._guard)
            self._states.create(state, guard=self._guard)
            self._db.record_critical_mutation(
                CriticalMutation(
                    mission_id=record.mission_id,
                    event_type="RESULT_TASK_BOUND",
                    actor_id="result-collection-coordinator",
                    occurred_at_iso=started.isoformat(),
                    record_type="result_task_binding",
                    record_id=binding.task_id,
                    state_version=record.execution_state_version,
                    security_projection_digest=binding.binding_digest,
                )
            )
        return authority, self._new_sink(authority, binding.binding_digest)

    def finalize_local_collection(
        self, *, execution_id: str, sink: RawResultSink, control: AdapterCollectionControl
    ) -> CollectionResult:
        self._require_active()
        authority = self._authorities.find_by_execution(execution_id)
        if authority is None:
            raise ResultCollectionError("local collection authority not found")
        binding = authority.task_binding
        record = self._require_execution(execution_id)
        state = self._require_state(execution_id)
        self._verify_control_binding(control=control, binding=binding, adapter_id=record.resolved_adapter_id)
        receipt = sink.commit()
        receipt_digest = compute_receipt_digest(receipt, self._ds)
        control_record = self._build_control_metadata(
            record=record, binding=binding, receipt_id=receipt.receipt_id,
            receipt_digest=receipt_digest, control=control,
        )
        # Persist receipt + control at COMMITTED_METADATA_PENDING so a crash before
        # completion can resume metadata-only from the durable capture.
        committed = self._next_state(
            state, "COMMITTED_METADATA_PENDING", receipt_id=receipt.receipt_id, receipt_digest=receipt_digest,
            last_chunk=state.last_committed_chunk_sequence + 1,
        )
        with UnitOfWork(self._db):
            self._control.create(control_record, guard=self._guard)
            self._states.update(committed, expected_version=state.state_version, guard=self._guard)
        record = self._require_execution(execution_id)
        return self._complete(authority=authority, record=record, state=committed, binding=binding, control=control)

    def _complete_local_from_stored(
        self, *, authority: ResultCollectionAuthority, record: ExecutionRecord, state: ResultCollectionStateRecord
    ) -> CollectionResult:
        if state.status != "COMMITTED_METADATA_PENDING":
            raise ResultCollectionError("local collection can only resume from committed metadata (no provider read)")
        stored = self._control.find_by_execution(execution_id=record.execution_id)
        if stored is None:
            raise ResultCollectionError("local collection has no durable control metadata to resume from")
        control = AdapterCollectionControl(
            provider_status=stored.provider_status, exit_code=stored.exit_code, timed_out=stored.timed_out,
            started_at=stored.provider_started_at, finished_at=stored.provider_finished_at,
            status_normalization_rule_id=stored.status_normalization_rule_id,
        )
        return self._complete(
            authority=authority, record=record, state=state, binding=authority.task_binding, control=control,
            control_already_persisted=True,
        )

    # --- completion -------------------------------------------------------

    def _complete(
        self, *, authority: ResultCollectionAuthority, record: ExecutionRecord,
        state: ResultCollectionStateRecord, binding: ResultTaskBinding, control: AdapterCollectionControl,
        control_already_persisted: bool = False,
    ) -> CollectionResult:
        if state.receipt_id is None or state.receipt_digest is None:
            raise ResultCollectionError("cannot complete collection without a committed receipt")
        control_record = self._build_control_metadata(
            record=record, binding=binding, receipt_id=state.receipt_id,
            receipt_digest=state.receipt_digest, control=control,
        )
        complete = self._next_state(
            state, "COMPLETE", receipt_id=state.receipt_id, receipt_digest=state.receipt_digest,
            last_chunk=state.last_committed_chunk_sequence,
        )
        ingestion = self._build_ingestion(
            record=record, collection_id=authority.collection_id, receipt_id=state.receipt_id,
            receipt_digest=state.receipt_digest, evidence_retention_until=authority.retention_until,
        )
        terminal = _TERMINAL_BY_PROVIDER_STATUS[control.provider_status]
        updates: dict[str, object] = {
            "execution_state_version": record.execution_state_version + 1,
            "result_collection_state_id": state.collection_state_id,
            "result_ingestion_state": "PENDING",
            "result_task_binding_id": binding.task_id,
            "updated_at": self._clock.now(),
        }
        # Settle the provider terminal state from the confirmed control metadata,
        # from whichever non-terminal state the execution is in on completion:
        # DISPATCH_CLAIMED for a local inline result, or DISPATCHED/RUNNING/
        # RECONCILING for a provider result (including a crash-resume).
        if record.provider_execution_state in ("DISPATCH_CLAIMED", "DISPATCHED", "RUNNING", "RECONCILING"):
            self._require_provider_edge(record.provider_execution_state, terminal)
            updates["provider_execution_state"] = terminal
        mirror = finalize_object_digest(
            record.model_copy(update=updates),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            if not control_already_persisted and self._control.find_by_execution(record.execution_id) is None:
                self._control.create(control_record, guard=self._guard)
            self._states.update(complete, expected_version=state.state_version, guard=self._guard)
            self._ingestion.create(ingestion, guard=self._guard)
            self._executions.transition(mirror, expected_version=record.execution_state_version, guard=self._guard)
        return CollectionResult(
            collection_id=authority.collection_id, status="COMPLETE",
            receipt_id=state.receipt_id, ingestion_id=ingestion.ingestion_id,
        )

    def abandon(self, *, execution_id: str, reason: str) -> CollectionResult:
        self._require_active()
        authority = self._authorities.find_by_execution(execution_id)
        if authority is None:
            raise ResultCollectionError("collection authority not found")
        state = self._require_state(execution_id)
        if state.status == "COMPLETE":
            raise ResultCollectionError("cannot abandon a completed collection")
        if state.status == "ABANDONED":
            return CollectionResult(authority.collection_id, "ABANDONED", state.receipt_id, None)
        abandoned = self._advance(
            state, "ABANDONED", receipt_id=state.receipt_id, receipt_digest=state.receipt_digest,
            last_chunk=state.last_committed_chunk_sequence,
        )
        return CollectionResult(authority.collection_id, abandoned.status, abandoned.receipt_id, None)

    # --- window enforcement -----------------------------------------------

    def _enforce_recovery_window(
        self, record: ExecutionRecord, *, operation: str, recovery_authority_id: str | None
    ) -> Mission:
        now = self._clock.now()
        mission = self._resolver.resolve(record.mission_id, now=now).mission
        if not (now < mission.recovery_until):
            raise ResultCollectionError("recovery window has passed; no provider operation permitted")
        if now >= mission.valid_until:
            # After valid_until only recovery of an existing execution is allowed,
            # and only with an exact current purpose-limited authority.
            if recovery_authority_id is None:
                raise ResultCollectionError("a purpose-limited recovery authority is required after valid_until")
            authority = self._recovery.get(recovery_authority_id)
            if (
                authority is None
                or authority.allowed_operation != operation
                or authority.mission_id != record.mission_id
                or authority.execution_id != record.execution_id
                or not (now < authority.expires_at)
                or authority.mission_revision != mission.mission_revision
                or authority.authorization_epoch != mission.authorization_epoch
                or authority.origin_authorization_digest != record.authorization_digest
                or authority.resolved_adapter_id != record.resolved_adapter_id
                or authority.idempotency_key != record.idempotency_key
                or authority.expected_execution_state_version != record.execution_state_version
            ):
                raise ResultCollectionError("recovery authority is missing, expired, or wrongly bound")
            binding = self._bindings.find_by_execution(record.execution_id)
            binding_id = binding.task_id if binding is not None else None
            if authority.result_task_binding_id != binding_id:
                raise ResultCollectionError("recovery authority task binding is stale")
        return mission

    # --- helpers ----------------------------------------------------------

    def _new_sink(self, authority: ResultCollectionAuthority, task_binding_digest: str) -> RawResultSink:
        return StreamingQuarantineSink(
            sink_id=authority.sink_id, execution_id=authority.execution_id, quarantine_id=f"q-{authority.execution_id}",
            task_binding_digest=task_binding_digest, max_output_bytes=authority.max_output_bytes,
            committed_at=self._clock.now(),
        )

    def _verify_control_binding(
        self, *, control: AdapterCollectionControl, binding: ResultTaskBinding, adapter_id: str
    ) -> None:
        adapter = self._adapters.get(adapter_id)
        if adapter is None:
            raise ResultCollectionError("no trusted adapter to verify control metadata")
        if binding.adapter_identity_digest != adapter.identity().adapter_identity_digest:
            raise ResultCollectionError("collection control adapter identity does not match the bound adapter")
        if control.status_normalization_rule_id != "status-normalization-v1":
            raise ResultCollectionError("collection control uses an unexpected normalization rule")

    def _settle_provider_running(self, record: ExecutionRecord) -> ExecutionRecord:
        if record.provider_execution_state != "DISPATCHED":
            return record
        updated = finalize_object_digest(
            record.model_copy(
                update={
                    "provider_execution_state": "RUNNING",
                    "execution_state_version": record.execution_state_version + 1,
                    "updated_at": self._clock.now(),
                }
            ),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            self._executions.transition(updated, expected_version=record.execution_state_version, guard=self._guard)
        return updated

    def _mirror_collection(self, record: ExecutionRecord, collection_state_id: str) -> ExecutionRecord:
        return finalize_object_digest(
            record.model_copy(
                update={
                    "result_collection_state_id": collection_state_id,
                    "execution_state_version": record.execution_state_version + 1,
                    "updated_at": self._clock.now(),
                }
            ),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )

    def _advance(
        self, state: ResultCollectionStateRecord, status: ResultCollectionStatus, *,
        receipt_id: str | None, receipt_digest: str | None, last_chunk: int,
    ) -> ResultCollectionStateRecord:
        nxt = self._next_state(
            state, status, receipt_id=receipt_id, receipt_digest=receipt_digest, last_chunk=last_chunk
        )
        with UnitOfWork(self._db):
            self._states.update(nxt, expected_version=state.state_version, guard=self._guard)
        return nxt

    def _next_state(
        self, state: ResultCollectionStateRecord, status: ResultCollectionStatus, *,
        receipt_id: str | None, receipt_digest: str | None, last_chunk: int,
    ) -> ResultCollectionStateRecord:
        if not is_legal_collection_edge(state.status, status):
            raise ResultCollectionError(f"illegal collection transition {state.status} -> {status}")
        return self._build_state(
            collection_id=state.collection_id, execution_id=state.execution_id,
            state_version=state.state_version + 1, status=status, receipt_id=receipt_id,
            receipt_digest=receipt_digest, last_chunk=last_chunk,
        )

    def _require_provider_edge(self, current: ProviderExecutionState, target: ProviderExecutionState) -> None:
        if not is_legal_provider_edge(current, target):
            raise ResultCollectionError(f"illegal provider transition {current} -> {target}")

    def _build_state(
        self, *, collection_id: str, execution_id: str, state_version: int, status: ResultCollectionStatus,
        receipt_id: str | None, receipt_digest: str | None, last_chunk: int,
    ) -> ResultCollectionStateRecord:
        progress = compute_progress_digest(
            collection_id=collection_id, status=status, last_committed_chunk_sequence=last_chunk,
            receipt_digest=receipt_digest, digest_service=self._ds,
        )
        state = ResultCollectionStateRecord(
            collection_state_id=f"collection-state-{execution_id}",
            collection_id=collection_id, execution_id=execution_id, state_version=state_version, status=status,
            receipt_id=receipt_id, receipt_digest=receipt_digest, last_committed_chunk_sequence=last_chunk,
            last_progress_digest=progress, updated_at=self._clock.now(), record_digest="pending",
        )
        return finalize_object_digest(
            state, digest_field="record_digest", digest_name="result_collection_state_digest",
            digest_service=self._ds,
        )

    def _build_control_metadata(
        self, *, record: ExecutionRecord, binding: ResultTaskBinding, receipt_id: str,
        receipt_digest: str, control: AdapterCollectionControl,
    ) -> RawControlMetadataRecord:
        model = RawControlMetadataRecord(
            control_record_id=f"control-{record.execution_id}",
            execution_id=record.execution_id,
            task_binding_digest=binding.binding_digest,
            receipt_id=receipt_id,
            receipt_digest=receipt_digest,
            status_normalization_rule_id=control.status_normalization_rule_id,
            provider_status=control.provider_status,
            exit_code=control.exit_code,
            timed_out=control.timed_out,
            provider_started_at=control.started_at,
            provider_finished_at=control.finished_at,
            trusted_received_at=self._clock.now(),
            record_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="record_digest", digest_name="raw_control_metadata_digest", digest_service=self._ds
        )

    def _build_ingestion(
        self, *, record: ExecutionRecord, collection_id: str, receipt_id: str, receipt_digest: str,
        evidence_retention_until: datetime,
    ) -> ResultIngestionStateRecord:
        model = ResultIngestionStateRecord(
            ingestion_id=f"ingestion-{record.execution_id}",
            execution_id=record.execution_id,
            collection_id=collection_id,
            state_version=1,
            status="PENDING",
            receipt_id=receipt_id,
            receipt_digest=receipt_digest,
            quarantine_id=f"q-{record.execution_id}",
            attempt_count=0,
            manifest_id=None,
            manifest_digest=None,
            ingested_durable_at=None,
            evidence_retention_until=evidence_retention_until,
            updated_at=self._clock.now(),
            record_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="record_digest", digest_name="result_ingestion_state_digest", digest_service=self._ds
        )

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self._executions.get(execution_id)
        if record is None:
            raise ResultCollectionError("execution not found")
        return record

    def _require_state(self, execution_id: str) -> ResultCollectionStateRecord:
        state = self._states.get(f"collection-state-{execution_id}")
        if state is None:
            raise ResultCollectionError("collection state not found")
        return state

    def _require_tool_max_output(self, record: ExecutionRecord) -> int:
        registry = self._registry_repo.get(self._registry_revision)
        if registry is None:
            raise ResultCollectionError("tool registry not found")
        tool = registry.by_ref(record.tool_ref.tool_id, record.tool_ref.registry_revision)
        if tool is None:
            raise ResultCollectionError("tool not found for collection")
        return tool.max_output_bytes

    def _registry_digest(self) -> str:
        registry = self._registry_repo.get(self._registry_revision)
        if registry is None:
            raise ResultCollectionError("tool registry not found")
        return registry.registry_digest
