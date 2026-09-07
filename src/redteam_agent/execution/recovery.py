"""Execution recovery authority + single-consume cancel (SystemDesign §21.1.1 / §21.1.2).

``ExecutionRecoveryAuthority`` is the single issuing owner for recovering an
existing execution (reconcile / cancel / collect_result). It binds the current
mission/epoch, the origin execution and authorization digest, the immutable
idempotency key, the expected execution state version and an allowed operation,
with TTL ``issued_at < expires_at <= min(issued_at + 60s, mission.recovery_until)``.
It is not a bearer token: the cancel coordinator reloads the current record before
use.

Cancel consumes exactly one ``CancelAttempt`` per (execution, provider task),
enforced by a database unique constraint, transitions the execution to
CANCEL_REQUESTED in the same transaction, and calls the adapter cancel once. A
finalization cancel never reaches the adapter without a bound recovery authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import CancelAttemptError, ExecutionRecoveryAuthorityError
from redteam_agent.execution.adapter import ExecutionAdapter
from redteam_agent.execution.models import (
    CancelAttempt,
    ExecutionRecord,
    ExecutionRecoveryAuthority,
    ProviderTaskBinding,
    RecoveryOperation,
)
from redteam_agent.execution.records import (
    compute_cancel_intent_digest,
    finalize_object_digest,
)
from redteam_agent.execution.state_machine import is_legal_provider_edge
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    CancelAttemptRepository,
    ExecutionRecordRepository,
    ExecutionRecoveryAuthorityRepository,
    ResultTaskBindingRepository,
)
from redteam_agent.storage.guard import WriteGuard

_MISSION_STATES_BY_OPERATION: dict[RecoveryOperation, frozenset[str]] = {
    "reconcile": frozenset({"RUNNING", "PAUSED", "FINALIZING", "WAITING_HUMAN_REVIEW"}),
    "cancel": frozenset({"RUNNING", "PAUSED", "FINALIZING", "WAITING_HUMAN_REVIEW"}),
    "collect_result": frozenset({"RUNNING", "PAUSED", "FINALIZING", "WAITING_HUMAN_REVIEW"}),
}
_EXECUTION_STATES_BY_OPERATION: dict[RecoveryOperation, frozenset[str]] = {
    "reconcile": frozenset(
        {"DISPATCH_CLAIMED", "DISPATCHED", "RUNNING", "CANCEL_REQUESTED", "RECONCILING", "OUTCOME_UNKNOWN"}
    ),
    "cancel": frozenset({"DISPATCHED", "RUNNING"}),
    "collect_result": frozenset(
        {"DISPATCHED", "RUNNING", "RECONCILING", "SUCCEEDED", "FAILED", "CANCELLED"}
    ),
}
_RECOVERY_TTL_SECONDS = 60


@dataclass(frozen=True)
class CancelResult:
    cancel_attempt_id: str
    attempt_state: str
    reached_adapter: bool


class ExecutionRecoveryService:
    def __init__(
        self,
        *,
        database: Database,
        execution_repository: ExecutionRecordRepository,
        recovery_repository: ExecutionRecoveryAuthorityRepository,
        task_binding_repository: ResultTaskBindingRepository,
        cancel_repository: CancelAttemptRepository,
        context_resolver: AuthorizationContextResolver,
        adapters: Mapping[str, ExecutionAdapter],
        clock: Clock,
        digest_service: DigestService,
        write_guard: WriteGuard,
        recovery_policy_revision: str = "recovery-policy-v1",
    ) -> None:
        self._db = database
        self._executions = execution_repository
        self._recovery = recovery_repository
        self._bindings = task_binding_repository
        self._cancels = cancel_repository
        self._resolver = context_resolver
        self._adapters = dict(adapters)
        self._clock = clock
        self._ds = digest_service
        self._guard = write_guard
        self._policy_revision = recovery_policy_revision

    def issue_authority(
        self, *, authority_id: str, execution_id: str, allowed_operation: RecoveryOperation, reason: str
    ) -> ExecutionRecoveryAuthority:
        record = self._require_execution(execution_id)
        now = self._clock.now()
        mission = self._resolver.resolve(record.mission_id, now=now).mission
        if not (now < mission.recovery_until):
            raise ExecutionRecoveryAuthorityError("mission recovery window has passed")
        if mission.state not in _MISSION_STATES_BY_OPERATION[allowed_operation]:
            raise ExecutionRecoveryAuthorityError(
                f"mission state {mission.state} does not permit {allowed_operation}"
            )
        if record.provider_execution_state not in _EXECUTION_STATES_BY_OPERATION[allowed_operation]:
            raise ExecutionRecoveryAuthorityError(
                f"execution state {record.provider_execution_state} does not permit {allowed_operation}"
            )
        expires_at = min(now + timedelta(seconds=_RECOVERY_TTL_SECONDS), mission.recovery_until)
        if not (now < expires_at):
            raise ExecutionRecoveryAuthorityError("recovery authority TTL is non-positive")
        binding = self._bindings.find_by_execution(execution_id)
        authority = ExecutionRecoveryAuthority(
            authority_id=authority_id,
            authority_digest="pending",
            mission_id=record.mission_id,
            mission_revision=mission.mission_revision,
            authorization_epoch=mission.authorization_epoch,
            execution_id=execution_id,
            origin_authorization_digest=record.authorization_digest,
            resolved_adapter_id=record.resolved_adapter_id,
            idempotency_key=record.idempotency_key,
            allowed_operation=allowed_operation,
            expected_execution_state_version=record.execution_state_version,
            result_task_binding_id=binding.task_id if binding is not None else None,
            recovery_policy_revision=self._policy_revision,
            reason=reason,
            issued_at=now,
            expires_at=expires_at,
        )
        authority = finalize_object_digest(
            authority, digest_field="authority_digest", digest_name="execution_recovery_authority_digest",
            digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            self._recovery.create(authority, guard=self._guard)
        return authority

    def request_cancel(
        self, *, cancel_attempt_id: str, execution_id: str, recovery_authority_id: str, reason: str
    ) -> CancelResult:
        authority = self._recovery.get(recovery_authority_id)
        if authority is None or authority.allowed_operation != "cancel" or authority.execution_id != execution_id:
            raise CancelAttemptError("a cancel-bound recovery authority is required")
        now = self._clock.now()
        if not (now < authority.expires_at):
            raise CancelAttemptError("recovery authority has expired")
        record = self._require_execution(execution_id)
        if record.provider_execution_state not in ("DISPATCHED", "RUNNING"):
            raise CancelAttemptError("cancel requires a DISPATCHED or RUNNING execution")
        # The authority is not a bearer token: it binds the exact execution state
        # version it was issued against. If the execution has since advanced, the
        # authority is stale and must be re-issued from the current record.
        if authority.expected_execution_state_version != record.execution_state_version:
            raise CancelAttemptError("recovery authority is stale (execution state version advanced)")
        # Re-verify the current mission window/epoch for this authority.
        mission = self._resolver.resolve(record.mission_id, now=now).mission
        if not (now < mission.recovery_until):
            raise CancelAttemptError("mission recovery window has passed")
        if (
            authority.mission_id != record.mission_id
            or authority.mission_revision != mission.mission_revision
            or authority.authorization_epoch != mission.authorization_epoch
            or authority.origin_authorization_digest != record.authorization_digest
            or authority.resolved_adapter_id != record.resolved_adapter_id
            or authority.idempotency_key != record.idempotency_key
        ):
            raise CancelAttemptError("recovery authority mission binding is stale")
        binding = self._bindings.find_by_execution(execution_id)
        if not isinstance(binding, ProviderTaskBinding):
            raise CancelAttemptError("cancel requires a provider_task binding with an exact task id")
        if authority.result_task_binding_id != binding.task_id:
            raise CancelAttemptError("recovery authority task binding is stale")
        provider_task_id = binding.provider_task_id
        if self._cancels.find(execution_id, provider_task_id) is not None:
            raise CancelAttemptError("a cancel attempt already exists for this execution/task")
        adapter = self._adapters.get(record.resolved_adapter_id)
        if adapter is None:
            raise CancelAttemptError("no trusted adapter for cancel")

        intent_digest = compute_cancel_intent_digest(
            execution_id=execution_id, provider_task_id=provider_task_id,
            resolved_adapter_id=record.resolved_adapter_id, recovery_authority_id=recovery_authority_id,
            reason=reason, digest_service=self._ds,
        )
        pre_version = record.execution_state_version
        post_version = pre_version + 1
        attempt = finalize_object_digest(
            CancelAttempt(
                cancel_attempt_id=cancel_attempt_id, execution_id=execution_id,
                provider_task_id=provider_task_id, resolved_adapter_id=record.resolved_adapter_id,
                recovery_authority_id=recovery_authority_id, cancel_intent_digest=intent_digest,
                reason=reason, attempt_state="CLAIMED",
                consumption_id=f"cancel-consumption-{cancel_attempt_id}",
                pre_transition_execution_state_version=pre_version,
                post_transition_execution_state_version=post_version,
                created_at=now, updated_at=now, record_digest="pending",
            ),
            digest_field="record_digest", digest_name="cancel_attempt_digest", digest_service=self._ds,
        )
        if not is_legal_provider_edge(record.provider_execution_state, "CANCEL_REQUESTED"):
            raise CancelAttemptError("illegal transition to CANCEL_REQUESTED")
        requested = finalize_object_digest(
            record.model_copy(
                update={
                    "provider_execution_state": "CANCEL_REQUESTED",
                    "execution_state_version": post_version, "updated_at": now,
                }
            ),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )
        # Claim the single cancel attempt + transition, all in one transaction.
        with UnitOfWork(self._db):
            self._cancels.create(attempt, guard=self._guard)
            self._executions.transition(requested, expected_version=pre_version, guard=self._guard)
            self._db.record_critical_mutation(
                CriticalMutation(
                    mission_id=record.mission_id,
                    event_type="CANCEL_ATTEMPT_CHANGED",
                    actor_id="execution-recovery-service",
                    occurred_at_iso=attempt.created_at.isoformat(),
                    record_type="cancel_attempt",
                    record_id=attempt.cancel_attempt_id,
                    state_version=attempt.post_transition_execution_state_version,
                    security_projection_digest=attempt.record_digest,
                )
            )
        # Only the OCC winner reaches the adapter, exactly once.
        outcome = adapter.cancel(execution_id, provider_task_id)
        updated = finalize_object_digest(
            attempt.model_copy(update={"attempt_state": outcome.result, "updated_at": self._clock.now()}),
            digest_field="record_digest", digest_name="cancel_attempt_digest", digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            self._cancels.update(updated, guard=self._guard)
            self._db.record_critical_mutation(
                CriticalMutation(
                    mission_id=record.mission_id,
                    event_type="CANCEL_ATTEMPT_CHANGED",
                    actor_id="execution-recovery-service",
                    occurred_at_iso=updated.updated_at.isoformat(),
                    record_type="cancel_attempt",
                    record_id=updated.cancel_attempt_id,
                    state_version=updated.post_transition_execution_state_version,
                    security_projection_digest=updated.record_digest,
                )
            )
        return CancelResult(cancel_attempt_id=cancel_attempt_id, attempt_state=outcome.result, reached_adapter=True)

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self._executions.get(execution_id)
        if record is None:
            raise ExecutionRecoveryAuthorityError("execution not found")
        return record
