"""Executor: pre-dispatch enforcement, single dispatch claim, JIT secret injection.

The public entry points accept only identifiers and the authorized plan; they
never accept a caller-supplied secret value, clock, sink, adapter, broker,
channel or callback. The plan's arguments carry secret *references* only, and the
gate re-derives the authorization from trusted state and rejects any forged or
drifted plan. The executor:

* creates one execution per policy decision (``PLANNED -> AUTHORIZED``); the
  database enforces one-decision-one-execution;
* revalidates every pre-dispatch condition and, on any mismatch, transitions
  ``AUTHORIZED -> BLOCKED`` with a versioned reason, ``dispatch_attempts=0`` and
  no claim, calling no provider API and creating no ExecutionResult;
* on success, atomically transitions ``AUTHORIZED -> DISPATCH_CLAIMED`` and
  creates one unconsumed dispatch claim (``dispatch_attempts=1``);
* re-verifies the exact secret versions, durably consumes the claim
  (``unconsumed -> consumed``), mints a single-use consumption token, and injects
  secrets just-in-time through the fixed dispatch port once;
* never auto-resubmits: a secret-version conflict blocks (claim invalidated), and
  a post-consumption crash / uncertain submit goes to reconciliation, which maps
  an uncertain outcome to ``OUTCOME_UNKNOWN``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    ExecutionRecordError,
    ExecutorAuthorizationError,
)
from redteam_agent.execution.adapter import ExecutionRequest, TaskHandle
from redteam_agent.execution.budget import MissionExecutionBudgetService
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.collection import ResultCollectionCoordinator
from redteam_agent.execution.dispatch_port import TrustedAdapterDispatchPort
from redteam_agent.execution.models import (
    DispatchClaim,
    ExecutionRecord,
    LocalResultBinding,
    PreDispatchBlockReason,
    ProviderExecutionState,
    ProviderTaskBinding,
    ResultTaskBinding,
)
from redteam_agent.execution.reconcile import ReconciliationService
from redteam_agent.execution.records import (
    compute_consumption_id,
    compute_secret_lifecycle_heads_digest,
    compute_secret_version_bindings_digest,
    finalize_local_result_binding,
    finalize_object_digest,
    finalize_provider_task_binding,
)
from redteam_agent.execution.secret_injection import (
    SecretBindingSpec,
    _open_dispatch_continuation,
    _SecretDispatchContinuation,
)
from redteam_agent.execution.secret_source import TrustedSecretSource
from redteam_agent.execution.state_machine import is_legal_provider_edge
from redteam_agent.executor.authorization_gate import ExecutorAuthorizationGate
from redteam_agent.plan.models import ExecutionPlan
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.resources.secret_metadata import SecretMetadataReader
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    DispatchClaimRepository,
    ExecutionRecordRepository,
    ResultTaskBindingRepository,
)
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    ApprovalRecordRepository,
    ApprovalRequestRepository,
    PolicyDecisionRepository,
    ToolRegistryRepository,
)
from redteam_agent.tools.models import ToolDefinition
from redteam_agent.tools.secret_argument_path import _discover_secret_reference_paths, resolve_pointer

# Gate reason code -> versioned pre-dispatch block reason.
_BLOCK_REASON_MAP: dict[str, PreDispatchBlockReason] = {
    "MISSION_NOT_RUNNING": "MISSION_NOT_RUNNING",
    "MISSION_OUTSIDE_VALIDITY_WINDOW": "MISSION_EXPIRED",
    "MISSION_REVISION_STALE": "AUTHORIZATION_EPOCH_MISMATCH",
    "AUTHORIZATION_EPOCH_STALE": "AUTHORIZATION_EPOCH_MISMATCH",
    "PLAN_EPOCH_STALE": "AUTHORIZATION_EPOCH_MISMATCH",
    "POLICY_VERSION_STALE": "POLICY_STALE",
    "REGISTRY_STALE": "SNAPSHOT_STALE",
    "DECISION_EXPIRED": "AUTHORIZATION_TTL_EXPIRED",
    "DECISION_TTL_EXCEEDS_VALIDITY": "AUTHORIZATION_TTL_EXPIRED",
    "SNAPSHOT_NOT_FOUND": "SNAPSHOT_STALE",
    "SNAPSHOT_DIGEST_MISMATCH": "SNAPSHOT_STALE",
    "PLAN_SNAPSHOT_ID_MISMATCH": "SNAPSHOT_STALE",
    "PLAN_SNAPSHOT_DIGEST_MISMATCH": "SNAPSHOT_STALE",
    "PLAN_ADAPTER_DIGEST_STALE": "ADAPTER_CAPABILITY_MISMATCH",
    "PLAN_SANDBOX_DIGEST_STALE": "SANDBOX_CAPABILITY_MISMATCH",
    "PLAN_SESSION_DIGEST_STALE": "SESSION_STALE",
    "PLAN_REMOTE_TRUST_DIGEST_STALE": "REMOTE_MCP_TRUST_MISMATCH",
    "APPROVAL_MISSING": "APPROVAL_INVALID",
    "APPROVAL_NOT_APPROVED": "APPROVAL_INVALID",
    "APPROVAL_EXPIRED": "APPROVAL_INVALID",
    "APPROVAL_BINDING_MISMATCH": "APPROVAL_INVALID",
    "APPROVAL_TTL_EXCEEDS_PARENT": "APPROVAL_INVALID",
    "APPROVAL_AUTHORITY_REVOKED": "APPROVAL_INVALID",
    "APPROVAL_ROLE_INVALID": "APPROVAL_INVALID",
    "MISLEADING_PRESENTATION": "APPROVAL_INVALID",
}


def _block_reason_for(gate_reason: str) -> PreDispatchBlockReason:
    return _BLOCK_REASON_MAP.get(gate_reason, "DIGEST_INTEGRITY_FAILURE")


@dataclass(frozen=True)
class DispatchOutcome:
    execution_id: str
    provider_execution_state: ProviderExecutionState
    pre_dispatch_block_reason: PreDispatchBlockReason | None
    task_binding: ResultTaskBinding | None
    dispatch_attempts: int
    reason_code: str


class Executor:
    def __init__(
        self,
        *,
        database: Database,
        gate: ExecutorAuthorizationGate,
        execution_repository: ExecutionRecordRepository,
        claim_repository: DispatchClaimRepository,
        task_binding_repository: ResultTaskBindingRepository,
        decision_repository: PolicyDecisionRepository,
        request_repository: ApprovalRequestRepository,
        record_repository: ApprovalRecordRepository,
        registry_repository: ToolRegistryRepository,
        secret_metadata_reader: SecretMetadataReader,
        secret_source: TrustedSecretSource,
        dispatch_port: TrustedAdapterDispatchPort,
        reconciliation: ReconciliationService,
        collection_coordinator: ResultCollectionCoordinator,
        budget_service: MissionExecutionBudgetService,
        clock: Clock,
        digest_service: DigestService,
        write_guard: WriteGuard,
        registry_revision: int,
    ) -> None:
        self._db = database
        self._gate = gate
        self._executions = execution_repository
        self._claims = claim_repository
        self._bindings = task_binding_repository
        self._decisions = decision_repository
        self._requests = request_repository
        self._records = record_repository
        self._registry_repo = registry_repository
        self._secret_metadata = secret_metadata_reader
        # The secret source and dispatch port are private executor dependencies:
        # they are never exported on any public surface, so no caller can reach
        # plaintext or the adapter (SystemDesign §10.2).
        self._secret_source = secret_source
        self._dispatch_port = dispatch_port
        self._reconciliation = reconciliation
        self._collection = collection_coordinator
        self._budget = budget_service
        self._clock = clock
        self._ds = digest_service
        self._guard = write_guard
        self._registry_revision = registry_revision
        self._phase0c_dependencies_bound = False
        # Repository ownership is bound once by the composition root (the same
        # guard is shared by every execution-safety service), so no service binds
        # ownership in its constructor.

    def bind_phase0c_dependencies(
        self, *, guard: WriteGuard, collection_coordinator: ResultCollectionCoordinator,
        secret_source: TrustedSecretSource, secret_metadata_reader: SecretMetadataReader,
    ) -> None:
        """Replace Phase 0B test-only plaintext paths at the Phase 0C composition root."""
        if guard is not self._guard:
            raise ExecutionRecordError("Phase 0C dependency replacement is composition-owned")
        if self._phase0c_dependencies_bound:
            raise ExecutionRecordError("Phase 0C dependencies are already bound")
        self._collection = collection_coordinator
        self._secret_source = secret_source
        self._secret_metadata = secret_metadata_reader
        self._phase0c_dependencies_bound = True

    # --- create (PLANNED -> AUTHORIZED) -----------------------------------

    def create_execution(
        self, *, execution_id: str, task_id: str, decision_id: str, plan: ExecutionPlan
    ) -> ExecutionRecord:
        gate_result = self._gate.authorize_execution(decision_id=decision_id, plan=plan)
        if not gate_result.authorized:
            raise ExecutorAuthorizationError(f"decision not executable: {gate_result.reason_code}")
        decision = self._require_decision(decision_id)
        tool = self._require_tool(decision)
        now = self._clock.now()
        idempotency_key = self._compute_idempotency_key(execution_id=execution_id, decision=decision)
        planned = self._new_record(
            execution_id=execution_id, task_id=task_id, decision=decision, tool=tool, plan=plan,
            idempotency_key=idempotency_key, state="PLANNED", version=1, attempts=0, now=now,
        )
        authorized = self._finalize_execution(
            planned.model_copy(
                update={"provider_execution_state": "AUTHORIZED", "execution_state_version": 2, "updated_at": now}
            )
        )
        with UnitOfWork(self._db):
            if self._executions.get_by_decision(decision_id) is not None:
                raise ExecutionRecordError("an execution already exists for this policy decision")
            self._executions.create(planned, guard=self._guard)
            self._executions.transition(authorized, expected_version=1, guard=self._guard)
        return authorized

    # --- dispatch ---------------------------------------------------------

    def dispatch(self, *, execution_id: str, plan: ExecutionPlan) -> DispatchOutcome:
        record = self._require_execution(execution_id)
        if record.provider_execution_state != "AUTHORIZED":
            raise ExecutionRecordError("dispatch requires an AUTHORIZED execution")
        decision = self._require_decision(record.policy_decision_id)
        if plan.plan_id != record.plan_id:
            raise ExecutionRecordError("plan does not match the authorized execution")
        tool = self._require_tool(decision)

        # 1. Pre-dispatch revalidation: re-run the gate over current trusted state.
        gate_result = self._gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
        if not gate_result.authorized:
            blocked = self._block(record, reason=_block_reason_for(gate_result.reason_code))
            return self._blocked_outcome(blocked, attempts=0, reason=gate_result.reason_code)

        # 2. Build secret binding specs and re-check versions are CONFIRMED now.
        specs = self._secret_specs(plan=plan)
        version_ids = tuple(spec.secret_version_id for spec in specs)
        heads = self._current_lifecycle_heads(version_ids)
        if self._first_stale_version(version_ids) is not None:
            blocked = self._block(record, reason="SECRET_VERSION_STALE")
            return self._blocked_outcome(blocked, attempts=0, reason="SECRET_VERSION_STALE")

        # 3. Atomic AUTHORIZED -> DISPATCH_CLAIMED + create the unconsumed claim.
        claim = self._claim_execution(record=record, decision=decision, version_ids=version_ids, heads=heads)

        # 4. Consume the claim durably, re-verifying versions in the same transaction.
        consumption_id = self._consume_claim(
            execution_id=execution_id, claim=claim, version_ids=version_ids, heads=heads
        )
        if consumption_id is None:
            blocked = self._require_execution(execution_id)
            return self._blocked_outcome(blocked, attempts=1, reason="SECRET_VERSION_STALE")

        # 5. Just-in-time secret injection + single external submit (no retry).
        return self._inject_and_submit(
            execution_id=execution_id, decision=decision, tool=tool, plan=plan, specs=specs,
            claim_id=claim.claim_id, consumption_id=consumption_id,
        )

    # --- state transitions ------------------------------------------------

    def _block(self, record: ExecutionRecord, *, reason: PreDispatchBlockReason) -> ExecutionRecord:
        return self._transition_record(record, target="BLOCKED", reason=reason)

    def _blocked_outcome(self, record: ExecutionRecord, *, attempts: int, reason: str) -> DispatchOutcome:
        return DispatchOutcome(
            execution_id=record.execution_id, provider_execution_state="BLOCKED",
            pre_dispatch_block_reason=record.pre_dispatch_block_reason, task_binding=None,
            dispatch_attempts=attempts, reason_code=reason,
        )

    def _claim_execution(
        self, *, record: ExecutionRecord, decision: PolicyDecision, version_ids: tuple[str, ...],
        heads: dict[str, str],
    ) -> DispatchClaim:
        now = self._clock.now()
        claimed_version = record.execution_state_version + 1
        claimed = self._finalize_execution(
            record.model_copy(
                update={
                    "provider_execution_state": "DISPATCH_CLAIMED",
                    "execution_state_version": claimed_version,
                    "dispatch_attempts": 1,
                    "updated_at": now,
                }
            )
        )
        request = (
            self._requests.find_by_decision(decision.decision_id)
            if decision.decision == "REQUIRE_APPROVAL"
            else None
        )
        approval_record = (
            self._records.find_by_request(request.approval_request_id) if request is not None else None
        )
        claim = DispatchClaim(
            claim_id=f"claim-{record.execution_id}",
            execution_id=record.execution_id,
            execution_state_version=claimed_version,
            policy_decision_id=decision.decision_id,
            authorization_digest=decision.authorization_digest,
            mission_revision=decision.mission_revision,
            authorization_epoch=decision.authorization_epoch,
            tool_ref=decision.tool_ref,
            resolved_adapter_id=decision.resolved_adapter_id,
            approval_request_id=request.approval_request_id if request is not None else None,
            approval_record_id=approval_record.approval_id if approval_record is not None else None,
            secret_version_bindings_digest=compute_secret_version_bindings_digest(version_ids, self._ds),
            secret_lifecycle_heads_digest=compute_secret_lifecycle_heads_digest(heads, self._ds),
            issued_at=now,
            expires_at=decision.expires_at,
            claim_state="unconsumed",
            consumption_id=None,
            consumed_at=None,
            invalidated_at=None,
            invalidation_reason=None,
            record_digest="pending",
        )
        claim = finalize_object_digest(
            claim, digest_field="record_digest", digest_name="dispatch_claim_digest", digest_service=self._ds
        )
        self._require_edge(record.provider_execution_state, "DISPATCH_CLAIMED")
        with UnitOfWork(self._db):
            # Reserve the durable dispatch budget in the same transaction, before
            # the claim exists. An exhausted budget rolls back the whole unit of
            # work, so no claim is created and no provider call happens.
            self._reserve_budget(record)
            self._executions.transition(claimed, expected_version=record.execution_state_version, guard=self._guard)
            self._claims.create(claim, guard=self._guard)
            self._record_claim_mutation(record.mission_id, claim)
        return claim

    def _reserve_budget(self, record: ExecutionRecord) -> None:
        self._budget.reserve_in_txn(mission_id=record.mission_id, mission_revision=record.mission_revision)

    def _consume_claim(
        self, *, execution_id: str, claim: DispatchClaim, version_ids: tuple[str, ...], heads: dict[str, str]
    ) -> str | None:
        """Consume the claim (OCC winner only) and return the deterministic
        ``consumption_id``; return ``None`` when a secret version went stale."""
        now = self._clock.now()
        consumption_id = compute_consumption_id(
            claim_id=claim.claim_id, authorization_digest=claim.authorization_digest,
            execution_state_version=claim.execution_state_version, digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            current = self._claims.get(claim.claim_id)
            if current is None or current.claim_state != "unconsumed":
                raise ExecutionRecordError("dispatch claim is not consumable")
            record = self._require_execution(execution_id)
            # Re-verify secret versions in the same transaction (linearization point).
            if self._first_stale_version(version_ids) is not None or not self._heads_match(version_ids, heads):
                self._invalidate_claim(current, reason="secret version stale at consumption")
                self._transition_record(record, target="BLOCKED", reason="SECRET_VERSION_STALE", in_txn=True)
                return None
            consumed = finalize_object_digest(
                current.model_copy(
                    update={"claim_state": "consumed", "consumption_id": consumption_id, "consumed_at": now}
                ),
                digest_field="record_digest", digest_name="dispatch_claim_digest", digest_service=self._ds,
            )
            # OCC: only the caller whose unconsumed -> consumed update affects one
            # row wins; a concurrent consumer conflicts and never dispatches.
            self._claims.update_state(consumed, expected_state="unconsumed", guard=self._guard)
            self._record_claim_mutation(record.mission_id, consumed)
        # Read back the consumed claim and confirm the durable commit.
        readback = self._claims.get(claim.claim_id)
        if readback is None or readback.claim_state != "consumed" or readback.consumption_id != consumption_id:
            raise ExecutionRecordError("claim consumption read-back failed")
        return consumption_id

    def _inject_and_submit(
        self, *, execution_id: str, decision: PolicyDecision, tool: ToolDefinition, plan: ExecutionPlan,
        specs: tuple[SecretBindingSpec, ...], claim_id: str, consumption_id: str,
    ) -> DispatchOutcome:
        record = self._require_execution(execution_id)
        request = self._build_request(record=record, decision=decision, tool=tool, plan=plan)
        if request.result_delivery_mode == "local_result":
            return self._dispatch_local(
                execution_id=execution_id, record=record, request=request, specs=specs,
                claim_id=claim_id, consumption_id=consumption_id,
            )
        return self._dispatch_provider(
            execution_id=execution_id, record=record, request=request, specs=specs,
            claim_id=claim_id, consumption_id=consumption_id,
        )

    def _open_continuation(
        self, *, execution_id: str, claim_id: str, consumption_id: str, request: ExecutionRequest,
        capture: DispatchResultCapture, specs: tuple[SecretBindingSpec, ...],
    ) -> _SecretDispatchContinuation:
        # Repository-bound: the continuation is granted only if the durable claim
        # is consumed with this exact consumption id (the OCC winner); the secret
        # source and dispatch port are private to this executor.
        return _open_dispatch_continuation(
            source=self._secret_source, port=self._dispatch_port, digest_service=self._ds,
            claim_repository=self._claims, execution_repository=self._executions,
            execution_id=execution_id, claim_id=claim_id, expected_consumption_id=consumption_id,
            request=request, capture=capture, specs=specs,
        )

    def _dispatch_provider(
        self, *, execution_id: str, record: ExecutionRecord, request: ExecutionRequest,
        specs: tuple[SecretBindingSpec, ...], claim_id: str, consumption_id: str,
    ) -> DispatchOutcome:
        capture = DispatchResultCapture(mode="provider_task", capture_id=f"capture-{execution_id}", sink=None)
        try:
            continuation = self._open_continuation(
                execution_id=execution_id, claim_id=claim_id, consumption_id=consumption_id,
                request=request, capture=capture, specs=specs,
            )
            handle = continuation.run()
        except Exception:
            # Any post-consumption failure: never reuse the claim or resubmit; go
            # to reconciliation (uncertain -> OUTCOME_UNKNOWN).
            return self._reconcile_after_uncertain_submit(execution_id)
        return self._record_dispatched(execution_id=execution_id, handle=handle)

    def _dispatch_local(
        self, *, execution_id: str, record: ExecutionRecord, request: ExecutionRequest,
        specs: tuple[SecretBindingSpec, ...], claim_id: str, consumption_id: str,
    ) -> DispatchOutcome:
        identity = self._dispatch_port.adapter_identity(request.adapter_id)
        binding = finalize_local_result_binding(
            LocalResultBinding(
                task_id=record.task_id, execution_id=execution_id,
                adapter_identity_digest=identity.adapter_identity_digest,
                dispatch_claim_id=claim_id, capture_id=f"capture-{execution_id}", binding_digest="pending",
            ),
            self._ds,
        )
        _, sink = self._collection.prepare_local_collection(execution_id=execution_id, binding=binding)
        capture = DispatchResultCapture(
            mode="local_result", capture_id=binding.capture_id, sink=sink
        )
        try:
            continuation = self._open_continuation(
                execution_id=execution_id, claim_id=claim_id, consumption_id=consumption_id,
                request=request, capture=capture, specs=specs,
            )
            continuation.run()
            control = capture.control()
            if control is None:
                raise ExecutionRecordError("local adapter did not commit control metadata")
        except Exception:
            return self._reconcile_after_uncertain_submit(execution_id)
        self._collection.finalize_local_collection(execution_id=execution_id, sink=sink, control=control)
        final = self._require_execution(execution_id)
        return DispatchOutcome(
            execution_id=execution_id, provider_execution_state=final.provider_execution_state,
            pre_dispatch_block_reason=None, task_binding=binding, dispatch_attempts=1, reason_code="LOCAL_COMPLETE",
        )

    def _reconcile_after_uncertain_submit(self, execution_id: str) -> DispatchOutcome:
        record = self._require_execution(execution_id)
        if record.provider_execution_state == "DISPATCH_CLAIMED":
            self._transition_record(record, target="RECONCILING", reason=None)
        outcome = self._reconciliation.reconcile(execution_id=execution_id)
        final = self._require_execution(execution_id)
        return DispatchOutcome(
            execution_id=execution_id, provider_execution_state=final.provider_execution_state,
            pre_dispatch_block_reason=None, task_binding=None, dispatch_attempts=final.dispatch_attempts,
            reason_code=outcome.reason_code,
        )

    def _record_dispatched(self, *, execution_id: str, handle: TaskHandle) -> DispatchOutcome:
        record = self._require_execution(execution_id)
        if handle.provider_task_id is None:
            raise ExecutionRecordError("provider_task handle is missing a provider task id")
        binding: ResultTaskBinding = finalize_provider_task_binding(
            ProviderTaskBinding(
                task_id=record.task_id, execution_id=record.execution_id,
                adapter_identity_digest=handle.adapter_identity_digest,
                provider_identity_digest=handle.provider_identity_digest,
                provider_task_id=handle.provider_task_id, dispatch_claim_id=f"claim-{record.execution_id}",
                binding_digest="pending",
            ),
            self._ds,
        )
        now = self._clock.now()
        self._require_edge(record.provider_execution_state, "DISPATCHED")
        updated = self._finalize_execution(
            record.model_copy(
                update={
                    "provider_execution_state": "DISPATCHED",
                    "execution_state_version": record.execution_state_version + 1,
                    "result_task_binding_id": binding.task_id,
                    "updated_at": now,
                }
            )
        )
        with UnitOfWork(self._db):
            self._bindings.create(binding, guard=self._guard)
            self._executions.transition(updated, expected_version=record.execution_state_version, guard=self._guard)
            self._record_task_binding_mutation(record.mission_id, updated.execution_state_version, binding)
        return DispatchOutcome(
            execution_id=execution_id, provider_execution_state="DISPATCHED", pre_dispatch_block_reason=None,
            task_binding=binding, dispatch_attempts=1, reason_code="DISPATCHED",
        )

    # --- builders ---------------------------------------------------------

    def _build_request(
        self, *, record: ExecutionRecord, decision: PolicyDecision, tool: ToolDefinition, plan: ExecutionPlan
    ) -> ExecutionRequest:
        return ExecutionRequest(
            execution_id=record.execution_id,
            task_id=record.task_id,
            tool_ref=decision.tool_ref,
            adapter_id=decision.resolved_adapter_id,
            provider_tool_name=tool.provider_tool_name,
            result_delivery_mode="provider_task" if tool.adapter != "local" else "local_result",
            idempotency_key=record.idempotency_key,
            timeout_seconds=tool.default_timeout_seconds,
            arguments=plan.proposal.arguments,
        )

    def _new_record(
        self, *, execution_id: str, task_id: str, decision: PolicyDecision, tool: ToolDefinition,
        plan: ExecutionPlan, idempotency_key: str, state: ProviderExecutionState, version: int, attempts: int,
        now: datetime,
    ) -> ExecutionRecord:
        record = ExecutionRecord(
            execution_id=execution_id, task_id=task_id, execution_state_version=version, record_digest="pending",
            mission_id=decision.mission_id, mission_revision=decision.mission_revision,
            authorization_epoch=decision.authorization_epoch, plan_id=decision.plan_id,
            policy_decision_id=decision.decision_id, proposal_digest=decision.proposal_digest,
            authorization_digest=decision.authorization_digest, tool_ref=decision.tool_ref,
            resolved_adapter_id=decision.resolved_adapter_id, idempotency_key=idempotency_key,
            adapter_capabilities_digest=plan.adapter_capabilities_digest,
            sandbox_capabilities_digest=plan.sandbox_capabilities_digest,
            remote_mcp_trust_policy_digest=plan.remote_mcp_trust_policy_digest,
            provider_execution_state=state, pre_dispatch_block_reason=None, result_collection_state_id=None,
            result_ingestion_state="NOT_AVAILABLE", raw_result_quarantine_id=None, result_task_binding_id=None,
            dispatch_attempts=attempts, created_at=now, updated_at=now,
        )
        return self._finalize_execution(record)

    def _finalize_execution(self, record: ExecutionRecord) -> ExecutionRecord:
        return finalize_object_digest(
            record, digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds
        )

    def _require_edge(self, current: ProviderExecutionState, target: ProviderExecutionState) -> None:
        if not is_legal_provider_edge(current, target):
            raise ExecutionRecordError(f"illegal execution transition {current} -> {target}")

    def _transition_record(
        self, record: ExecutionRecord, *, target: ProviderExecutionState,
        reason: PreDispatchBlockReason | None, in_txn: bool = False,
    ) -> ExecutionRecord:
        now = self._clock.now()
        self._require_edge(record.provider_execution_state, target)
        updated = self._finalize_execution(
            record.model_copy(
                update={
                    "provider_execution_state": target,
                    "pre_dispatch_block_reason": reason,
                    "execution_state_version": record.execution_state_version + 1,
                    "updated_at": now,
                }
            )
        )
        if in_txn:
            self._executions.transition(updated, expected_version=record.execution_state_version, guard=self._guard)
        else:
            with UnitOfWork(self._db):
                self._executions.transition(
                    updated, expected_version=record.execution_state_version, guard=self._guard
                )
        return updated

    def _invalidate_claim(self, claim: DispatchClaim, *, reason: str) -> None:
        now = self._clock.now()
        invalidated = finalize_object_digest(
            claim.model_copy(
                update={"claim_state": "invalidated", "invalidated_at": now, "invalidation_reason": reason}
            ),
            digest_field="record_digest", digest_name="dispatch_claim_digest", digest_service=self._ds,
        )
        self._claims.update_state(invalidated, expected_state="unconsumed", guard=self._guard)
        record = self._require_execution(claim.execution_id)
        self._record_claim_mutation(record.mission_id, invalidated)

    def _record_claim_mutation(self, mission_id: str, claim: DispatchClaim) -> None:
        occurred_at = claim.consumed_at or claim.invalidated_at or claim.issued_at
        self._db.record_critical_mutation(
            CriticalMutation(
                mission_id=mission_id,
                event_type="DISPATCH_CLAIM_CHANGED",
                actor_id="executor",
                occurred_at_iso=occurred_at.isoformat(),
                record_type="dispatch_claim",
                record_id=claim.claim_id,
                state_version=claim.execution_state_version,
                security_projection_digest=claim.record_digest,
            )
        )

    def _record_task_binding_mutation(
        self, mission_id: str, state_version: int, binding: ResultTaskBinding
    ) -> None:
        self._db.record_critical_mutation(
            CriticalMutation(
                mission_id=mission_id,
                event_type="RESULT_TASK_BOUND",
                actor_id="executor",
                occurred_at_iso=self._clock.now().isoformat(),
                record_type="result_task_binding",
                record_id=binding.task_id,
                state_version=state_version,
                security_projection_digest=binding.binding_digest,
            )
        )

    # --- secret / lookup helpers ------------------------------------------

    def _secret_specs(self, *, plan: ExecutionPlan) -> tuple[SecretBindingSpec, ...]:
        arguments: Any = plan.proposal.arguments
        specs: list[SecretBindingSpec] = []
        for tokens in _discover_secret_reference_paths(arguments):
            leaf = resolve_pointer(tokens, arguments)
            pointer = "/" + "/".join(tokens)
            specs.append(
                SecretBindingSpec(secret_argument_path=pointer, secret_version_id=str(leaf["secret_version_id"]))
            )
        return tuple(specs)

    def _current_lifecycle_heads(self, version_ids: tuple[str, ...]) -> dict[str, str]:
        heads: dict[str, str] = {}
        for version_id in version_ids:
            meta = self._secret_metadata.get(version_id)
            if meta is not None:
                heads[version_id] = meta.lifecycle_head_digest
        return heads

    def _heads_match(self, version_ids: tuple[str, ...], heads: dict[str, str]) -> bool:
        return self._current_lifecycle_heads(version_ids) == heads

    def _first_stale_version(self, version_ids: tuple[str, ...]) -> str | None:
        now = self._clock.now()
        for version_id in version_ids:
            meta = self._secret_metadata.get(version_id)
            if meta is None or meta.state != "CONFIRMED":
                return version_id
            if meta.expires_at is not None and not (now < meta.expires_at):
                return version_id
        return None

    def _compute_idempotency_key(self, *, execution_id: str, decision: PolicyDecision) -> str:
        return self._ds.compute(
            "consumption_id_digest",
            {
                "kind": "idempotency",
                "mission_id": decision.mission_id,
                "mission_revision": decision.mission_revision,
                "execution_id": execution_id,
                "authorization_digest": decision.authorization_digest,
                "resolved_adapter_id": decision.resolved_adapter_id,
            },
        )

    def _require_decision(self, decision_id: str) -> PolicyDecision:
        decision = self._decisions.get(decision_id)
        if decision is None:
            raise ExecutionRecordError("policy decision not found")
        return decision

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self._executions.get(execution_id)
        if record is None:
            raise ExecutionRecordError("execution not found")
        return record

    def _require_tool(self, decision: PolicyDecision) -> ToolDefinition:
        registry = self._registry_repo.get(self._registry_revision)
        if registry is None:
            raise ExecutionRecordError("tool registry not found")
        tool = registry.by_ref(decision.tool_ref.tool_id, decision.tool_ref.registry_revision)
        if tool is None:
            raise ExecutionRecordError("tool not found in registry")
        return tool
