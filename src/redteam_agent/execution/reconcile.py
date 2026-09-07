"""Reconciliation and the trusted adapter read/recovery port (SystemDesign §10.1 / §28).

Reconciliation is a read-only recovery step: it re-checks provider/local state
through a trusted read port and never resubmits. An ``UNSUPPORTED``,
``UNKNOWN``, or uncertain/confirmed ``NOT_FOUND`` outcome is recorded as
``OUTCOME_UNKNOWN`` so a non-idempotent action is never auto-resent (a later
human review decides). A confirmed running/terminal provider outcome advances the
execution to the matching state.

The read port wraps the same fixed adapter registry as dispatch, so provider
read primitives (reconcile/cancel/get_task) are reachable only from the
executor/recovery port, not as public adapter methods.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import ExecutionRecordError
from redteam_agent.execution.adapter import ExecutionAdapter, ReconciliationResult
from redteam_agent.execution.models import (
    ExecutionRecord,
    ProviderExecutionState,
    ProviderTaskBinding,
    ResultTaskBinding,
)
from redteam_agent.execution.records import finalize_object_digest
from redteam_agent.execution.state_machine import is_legal_provider_edge
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionRecoveryAuthorityRepository,
    ResultTaskBindingRepository,
)
from redteam_agent.storage.guard import WriteGuard


@dataclass(frozen=True)
class ReconcileOutcome:
    execution_id: str
    provider_execution_state: ProviderExecutionState
    reason_code: str


# Reconcile status -> provider execution state (uncertain -> OUTCOME_UNKNOWN).
_TERMINAL_BY_PROVIDER_STATUS: dict[str, ProviderExecutionState] = {
    "succeeded": "SUCCEEDED",
    "failed": "FAILED",
    "cancelled": "CANCELLED",
}


class ReconciliationService:
    def __init__(
        self,
        *,
        database: Database,
        execution_repository: ExecutionRecordRepository,
        task_binding_repository: ResultTaskBindingRepository,
        recovery_repository: ExecutionRecoveryAuthorityRepository,
        context_resolver: AuthorizationContextResolver,
        adapters: Mapping[str, ExecutionAdapter],
        clock: Clock,
        digest_service: DigestService,
        write_guard: WriteGuard,
    ) -> None:
        self._db = database
        self._executions = execution_repository
        self._bindings = task_binding_repository
        self._recovery = recovery_repository
        self._resolver = context_resolver
        self._adapters = dict(adapters)
        self._clock = clock
        self._ds = digest_service
        self._guard = write_guard

    def reconcile(self, *, execution_id: str, recovery_authority_id: str | None = None) -> ReconcileOutcome:
        record = self._executions.get(execution_id)
        if record is None:
            raise ExecutionRecordError("execution not found for reconciliation")
        self._enforce_recovery_window(record, recovery_authority_id=recovery_authority_id)
        # Enter the read-only RECONCILING state first (no external resubmit).
        record = self._enter_reconciling(record)
        if record.provider_execution_state != "RECONCILING":
            # Already terminal: no provider read for a settled execution.
            return ReconcileOutcome(record.execution_id, record.provider_execution_state, "ALREADY_TERMINAL")
        adapter = self._adapters.get(record.resolved_adapter_id)
        if adapter is None:
            return self._settle(record, target="OUTCOME_UNKNOWN", reason="ADAPTER_UNAVAILABLE")
        binding = self._bindings.find_by_execution(execution_id)
        result = adapter.reconcile(execution_id, binding)
        self._verify_reconcile_result(record=record, binding=binding, result=result)
        target = self._map_status(result)
        return self._settle(record, target=target, reason=f"RECONCILE_{result.status}")

    def _enforce_recovery_window(
        self, record: ExecutionRecord, *, recovery_authority_id: str | None
    ) -> None:
        now = self._clock.now()
        mission = self._resolver.resolve(record.mission_id, now=now).mission
        if not (now < mission.recovery_until):
            raise ExecutionRecordError("recovery window has passed; no reconciliation provider read")
        if now >= mission.valid_until:
            if recovery_authority_id is None:
                raise ExecutionRecordError("a purpose-limited recovery authority is required after valid_until")
            authority = self._recovery.get(recovery_authority_id)
            if (
                authority is None
                or authority.allowed_operation != "reconcile"
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
                raise ExecutionRecordError("reconcile recovery authority is missing, expired, or wrongly bound")
            binding = self._bindings.find_by_execution(record.execution_id)
            binding_id = binding.task_id if binding is not None else None
            if authority.result_task_binding_id != binding_id:
                raise ExecutionRecordError("reconcile recovery authority task binding is stale")

    def _verify_reconcile_result(
        self, *, record: ExecutionRecord, binding: ResultTaskBinding | None, result: ReconciliationResult
    ) -> None:
        # A returned result must match the durable request/binding before it can
        # change any state (defend against a malicious/confused adapter).
        if result.execution_id != record.execution_id:
            raise ExecutionRecordError("reconcile result execution id does not match")
        if result.status == "FOUND_TERMINAL":
            if result.task_binding is None or binding is None:
                raise ExecutionRecordError("terminal reconcile result must carry the bound task")
            if result.task_binding.binding_digest != binding.binding_digest:
                raise ExecutionRecordError("reconcile result task binding does not match the durable binding")
            if isinstance(binding, ProviderTaskBinding) and result.provider_task_id != binding.provider_task_id:
                raise ExecutionRecordError("reconcile result provider task id does not match the durable binding")

    def _enter_reconciling(self, record: ExecutionRecord) -> ExecutionRecord:
        if record.provider_execution_state == "RECONCILING":
            return record
        if not is_legal_provider_edge(record.provider_execution_state, "RECONCILING"):
            return record
        now = self._clock.now()
        updated = finalize_object_digest(
            record.model_copy(
                update={
                    "provider_execution_state": "RECONCILING",
                    "execution_state_version": record.execution_state_version + 1, "updated_at": now,
                }
            ),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            self._executions.transition(updated, expected_version=record.execution_state_version, guard=self._guard)
        return updated

    def _map_status(self, result: ReconciliationResult) -> ProviderExecutionState:
        if result.status == "FOUND_RUNNING":
            return "RUNNING"
        if result.status == "FOUND_TERMINAL" and result.provider_status is not None:
            return _TERMINAL_BY_PROVIDER_STATUS[result.provider_status]
        # UNSUPPORTED / UNKNOWN / NOT_FOUND_* -> uncertain, never auto-resubmit.
        return "OUTCOME_UNKNOWN"

    def _settle(
        self, record: ExecutionRecord, *, target: ProviderExecutionState, reason: str
    ) -> ReconcileOutcome:
        if record.provider_execution_state == target:
            return ReconcileOutcome(record.execution_id, target, reason)
        if not is_legal_provider_edge(record.provider_execution_state, target):
            # Keep RECONCILING if the mapped edge is not legal from the current state.
            return ReconcileOutcome(record.execution_id, record.provider_execution_state, f"{reason}_NO_EDGE")
        now = self._clock.now()
        updated = finalize_object_digest(
            record.model_copy(
                update={
                    "provider_execution_state": target,
                    "execution_state_version": record.execution_state_version + 1,
                    "updated_at": now,
                }
            ),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            self._executions.transition(updated, expected_version=record.execution_state_version, guard=self._guard)
        return ReconcileOutcome(record.execution_id, target, reason)
