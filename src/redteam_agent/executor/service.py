"""Phase 0B executor with fail-closed pre-dispatch and crash reconciliation."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol

from redteam_agent.authorization_runtime import AuthorizationRuntimeContextResolver
from redteam_agent.canonical import digest_model, sha256_digest, stable_id
from redteam_agent.errors import (
    AdapterDispatchUncertainError,
    AdapterOperationError,
    AdapterResolutionError,
    CurrentAuthorizationStateError,
    DigestIntegrityError,
    ExecutionAuthorizationError,
    ExecutionStateTransitionError,
    ExternalDispatchOutcomeUnknownError,
    RawResultQuarantineError,
    RawResultStreamingError,
    ResultIngestionError,
    ResultIngestionLeaseError,
    TrustedDependencyUnavailableError,
)
from redteam_agent.models.execution import (
    AdapterRawResult,
    ExecutionRecord,
    ExecutionRequest,
    ExecutionResult,
    ExecutionRetryPolicy,
    PreDispatchBlockReason,
    ProviderExecutionState,
    ReconciliationResult,
    ResultIngestionRecord,
    SecureIngestionSummary,
    WorkflowRunBinding,
)
from redteam_agent.repositories.approval import (
    ApprovalRecordRepository,
    ApprovalRequestRepository,
)
from redteam_agent.repositories.context import ContextResourceIndexRepository
from redteam_agent.repositories.execution import (
    ExecutionRepository,
    ExecutionResultRepository,
    RawResultReceiptRepository,
    RawResultRecoveryRepository,
    ResultIngestionRepository,
    execution_record_digest,
    ingestion_record_digest,
)
from redteam_agent.repositories.plans import PlanRepository
from redteam_agent.repositories.policy import PolicyDecisionRepository

from .adapter import ExecutionAdapter, TrustedExecutionAdapterRegistry
from .authorization_gate import authorize_execution
from .finalization import FinalizationCoordinator
from .ingestion import SecureResultIngester
from .raw_results import MockRawResultSink, RawResultSink, RawResultSinkFactory


class PreDispatchCapabilityProbe(Protocol):
    """Trusted live capability observation used immediately before provider submit."""

    async def session_security_context_digest(self) -> str: ...

    async def sandbox_capabilities_digest(self, adapter_id: str) -> str: ...

    async def remote_mcp_trust_policy_digest(self, adapter_id: str) -> str: ...


class StaticPreDispatchCapabilityProbe:
    """Deterministic probe for the isolated Phase 0B runtime and tests."""

    def __init__(
        self,
        *,
        session_digest: str,
        sandbox_digest: str,
        remote_trust_digest: str,
    ) -> None:
        self._session_digest = session_digest
        self._sandbox_digest = sandbox_digest
        self._remote_trust_digest = remote_trust_digest

    async def session_security_context_digest(self) -> str:
        return self._session_digest

    async def sandbox_capabilities_digest(self, adapter_id: str) -> str:
        del adapter_id
        return self._sandbox_digest

    async def remote_mcp_trust_policy_digest(self, adapter_id: str) -> str:
        del adapter_id
        return self._remote_trust_digest


class Executor:
    """Coordinates trusted records; provider submit is deliberately never auto-retried."""

    def __init__(
        self,
        *,
        runtime_resolver: AuthorizationRuntimeContextResolver,
        plans: PlanRepository,
        decisions: PolicyDecisionRepository,
        resources: ContextResourceIndexRepository,
        approval_requests: ApprovalRequestRepository,
        approvals: ApprovalRecordRepository,
        executions: ExecutionRepository,
        receipts: RawResultReceiptRepository,
        recovery: RawResultRecoveryRepository,
        ingestions: ResultIngestionRepository,
        results: ExecutionResultRepository,
        sink_factory: RawResultSinkFactory,
        adapter_registry: TrustedExecutionAdapterRegistry,
        capability_probe: PreDispatchCapabilityProbe,
        finalization_requester: FinalizationCoordinator,
    ) -> None:
        if capability_probe is None or not isinstance(
            finalization_requester, FinalizationCoordinator
        ):
            raise TrustedDependencyUnavailableError(
                "live capability and finalization dependencies are mandatory"
            )
        self.runtime_resolver = runtime_resolver
        self.plans = plans
        self.decisions = decisions
        self.resources = resources
        self.approval_requests = approval_requests
        self.approvals = approvals
        self.executions = executions
        self.receipts = receipts
        self.recovery = recovery
        self.ingestions = ingestions
        self.results = results
        self.sink_factory = sink_factory
        self.adapter_registry = adapter_registry
        self.capability_probe = capability_probe
        self.finalization_requester = finalization_requester
        self.retry_policy = ExecutionRetryPolicy()

    def prepare(
        self,
        *,
        run: WorkflowRunBinding,
        plan_id: str,
        policy_decision_id: str,
        now: datetime,
        approval_request_id: str | None = None,
        approval_record_id: str | None = None,
    ) -> ExecutionRecord:
        gate = authorize_execution(
            plan_id=plan_id,
            policy_decision_id=policy_decision_id,
            runtime_resolver=self.runtime_resolver,
            plans=self.plans,
            decisions=self.decisions,
            resources=self.resources,
            approval_requests=self.approval_requests,
            approvals=self.approvals,
            approval_request_id=approval_request_id,
            approval_record_id=approval_record_id,
            now=now,
        )
        if gate.status != "AUTHORIZED":
            raise ExecutionAuthorizationError(
                f"execution authorization failed with status {gate.status}"
            )
        existing = self.executions.get_by_policy_decision(policy_decision_id)
        if existing is not None:
            return existing
        plan = self.plans.get(plan_id)
        decision = self.decisions.get(policy_decision_id)
        if plan is None or decision is None:
            raise ExecutionAuthorizationError("trusted execution envelope disappeared")
        runtime = self.runtime_resolver.resolve(plan.mission_id)
        if not (
            run.mission_id == plan.mission_id
            and run.mission_revision == plan.mission_revision
            and run.thread_id == f"{run.mission_id}:{run.mission_revision}:{run.run_id}"
        ):
            raise ExecutionAuthorizationError("workflow run is stale for the execution plan")
        execution_identity = {
            "schema_version": "execution-v1",
            "policy_decision_id": decision.decision_id,
            "run_id": run.run_id,
        }
        execution_id = stable_id("execution", execution_identity)
        idempotency_identity = {
            "schema_version": "execution-idempotency-v1",
            "mission_id": decision.mission_id,
            "mission_revision": decision.mission_revision,
            "execution_id": execution_id,
            "authorization_digest": decision.authorization_digest,
            "resolved_adapter_id": decision.resolved_adapter_id,
        }
        provisional = ExecutionRecord(
            execution_id=execution_id,
            record_digest="pending",
            state_version=0,
            mission_id=decision.mission_id,
            mission_revision=decision.mission_revision,
            authorization_epoch=decision.authorization_epoch,
            run_id=run.run_id,
            thread_id=run.thread_id,
            plan_id=plan.plan_id,
            policy_decision_id=decision.decision_id,
            proposal_digest=decision.proposal_digest,
            authorization_digest=decision.authorization_digest,
            tool_ref=decision.tool_ref,
            resolved_adapter_id=decision.resolved_adapter_id,
            idempotency_key=stable_id("idem", idempotency_identity),
            adapter_capabilities_digest=runtime.adapter_snapshot.snapshot_digest,
            sandbox_capabilities_digest=runtime.sandbox_snapshot.snapshot_digest,
            remote_mcp_trust_policy_digest=runtime.remote_trust_snapshot.snapshot_digest,
            provider_execution_state="PLANNED",
            result_ingestion_state="NOT_AVAILABLE",
            approval_request_id=approval_request_id,
            approval_record_id=approval_record_id,
            created_at=now,
            updated_at=now,
        )
        planned = provisional.model_copy(
            update={"record_digest": execution_record_digest(provisional)}
        )
        with self.executions.database.transaction(immediate=True):
            self.executions.add_planned(planned)
            return self.executions.transition_provider(
                planned.execution_id,
                expected_state_version=0,
                new_state="AUTHORIZED",
                now=now,
            )

    async def dispatch(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> ExecutionRecord:
        record = self._require_execution(execution_id)
        adapter = self._resolve_adapter(record)
        if record.provider_execution_state != "AUTHORIZED":
            if record.provider_execution_state in {
                "DISPATCHED",
                "RUNNING",
                "CANCEL_REQUESTED",
                "RECONCILING",
            }:
                return await self.resume_execution(execution_id, now=now)
            return record
        reason = await self._pre_dispatch_block_reason(record, adapter=adapter, now=now)
        if reason is None:
            try:
                self.sink_factory.for_execution(record.execution_id)
            except (RawResultQuarantineError, RawResultStreamingError):
                reason = "ENCRYPTION_KEY_UNAVAILABLE"
        if reason is not None:
            blocked = self.executions.transition_provider(
                record.execution_id,
                expected_state_version=record.state_version,
                new_state="BLOCKED",
                block_reason=reason,
                dispatch_attempts=0,
                now=now,
            )
            if reason == "MISSION_EXPIRED":
                self.finalization_requester.request_finalizing(record.mission_id, now=now)
            return blocked
        dispatched = self.executions.transition_provider(
            record.execution_id,
            expected_state_version=record.state_version,
            new_state="DISPATCHED",
            dispatch_attempts=1,
            now=now,
        )
        request = self._execution_request(dispatched)
        try:
            handle = await adapter.submit(request, dispatched.idempotency_key)
        except AdapterDispatchUncertainError:
            reconciling = self.executions.transition_provider(
                dispatched.execution_id,
                expected_state_version=dispatched.state_version,
                new_state="RECONCILING",
                now=now,
            )
            return await self._reconcile(reconciling, adapter=adapter, now=now)
        if handle.execution_id != dispatched.execution_id:
            return self.executions.transition_provider(
                dispatched.execution_id,
                expected_state_version=dispatched.state_version,
                new_state="OUTCOME_UNKNOWN",
                now=now,
            )
        return self.executions.transition_provider(
            dispatched.execution_id,
            expected_state_version=dispatched.state_version,
            new_state="RUNNING",
            provider_task_id=handle.provider_task_id,
            now=now,
        )

    async def resume_execution(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> ExecutionRecord:
        record = self._require_execution(execution_id)
        if record.provider_execution_state not in {
            "DISPATCHED",
            "RUNNING",
            "CANCEL_REQUESTED",
            "RECONCILING",
        }:
            return record
        adapter = self._resolve_adapter(record)
        if record.provider_execution_state in {"DISPATCHED", "RUNNING"}:
            record = self.executions.transition_provider(
                record.execution_id,
                expected_state_version=record.state_version,
                new_state="RECONCILING",
                now=now,
            )
        return await self._reconcile(record, adapter=adapter, now=now)

    async def request_cancel(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> ExecutionRecord:
        record = self._require_execution(execution_id)
        adapter = self._resolve_adapter(record)
        if record.provider_execution_state not in {"DISPATCHED", "RUNNING"}:
            raise ExecutionStateTransitionError("execution is not cancellable")
        if record.provider_task_id is None:
            reconciling = self.executions.transition_provider(
                record.execution_id,
                expected_state_version=record.state_version,
                new_state="RECONCILING",
                now=now,
            )
            return await self._reconcile(reconciling, adapter=adapter, now=now)
        cancelling = self.executions.transition_provider(
            record.execution_id,
            expected_state_version=record.state_version,
            new_state="CANCEL_REQUESTED",
            now=now,
        )
        cancellation = await adapter.cancel_task(record.provider_task_id)
        if cancellation.task_id != record.provider_task_id:
            return self.executions.transition_provider(
                cancelling.execution_id,
                expected_state_version=cancelling.state_version,
                new_state="OUTCOME_UNKNOWN",
                now=now,
            )
        if cancellation.confirmed:
            return self.executions.transition_provider(
                cancelling.execution_id,
                expected_state_version=cancelling.state_version,
                new_state="CANCELLED",
                provider_task_id=record.provider_task_id,
                now=now,
            )
        return await self._reconcile(cancelling, adapter=adapter, now=now)

    async def _reconcile(
        self,
        record: ExecutionRecord,
        *,
        adapter: ExecutionAdapter,
        now: datetime,
    ) -> ExecutionRecord:
        outcome = await adapter.reconcile(record.execution_id, record.idempotency_key)
        if outcome.execution_id != record.execution_id:
            outcome = ReconciliationResult(
                execution_id=record.execution_id,
                status="UNKNOWN",
                checked_at=now,
            )
        targets: dict[str, ProviderExecutionState] = {
            "QUEUED": "DISPATCHED",
            "RUNNING": "RUNNING",
            "SUCCEEDED": "SUCCEEDED",
            "FAILED": "FAILED",
            "CANCELLED": "CANCELLED",
            "NOT_FOUND": "OUTCOME_UNKNOWN",
            "UNKNOWN": "OUTCOME_UNKNOWN",
            "UNSUPPORTED": "OUTCOME_UNKNOWN",
        }
        target = targets[outcome.status]
        task_id_mismatch = (
            record.provider_task_id is not None
            and outcome.provider_task_id is not None
            and outcome.provider_task_id != record.provider_task_id
        )
        if task_id_mismatch:
            target = "OUTCOME_UNKNOWN"
        if record.provider_execution_state == "CANCEL_REQUESTED" and target not in {
            "RUNNING",
            "CANCELLED",
            "OUTCOME_UNKNOWN",
        }:
            target = "OUTCOME_UNKNOWN"
        return self.executions.transition_provider(
            record.execution_id,
            expected_state_version=record.state_version,
            new_state=target,
            provider_task_id=(None if task_id_mismatch else outcome.provider_task_id),
            now=now,
        )

    async def collect_result(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> AdapterRawResult:
        record = self._require_execution(execution_id)
        adapter = self._resolve_adapter(record)
        if record.provider_execution_state not in {
            "RUNNING",
            "SUCCEEDED",
            "FAILED",
            "CANCELLED",
        } or record.provider_task_id is None:
            raise ExecutionStateTransitionError("execution has no confirmed provider result task")
        sink = self.sink_factory.for_execution(record.execution_id)
        try:
            metadata = await adapter.collect_result(record.provider_task_id, sink)
        except (
            AdapterOperationError,
            RawResultQuarantineError,
            RawResultStreamingError,
        ) as exc:
            self._record_raw_result_failure(record, sink=sink, now=now)
            if isinstance(exc, (RawResultQuarantineError, RawResultStreamingError)):
                raise
            raise RawResultStreamingError("provider result streaming did not complete") from exc
        if not (
            metadata.execution_id == record.execution_id
            and metadata.provider_task_id == record.provider_task_id
        ):
            raise RawResultStreamingError("adapter result metadata binding mismatch")
        self.receipts.add(metadata.receipt)
        if isinstance(sink, MockRawResultSink):
            self.recovery.set_current(sink.recovery_metadata(updated_at=now))
        ingestion = self.ingestions.get_by_execution(record.execution_id)
        current = self._require_execution(execution_id)
        if ingestion is None:
            provisional = ResultIngestionRecord(
                ingestion_id=stable_id(
                    "ingestion",
                    {
                        "schema_version": "result-ingestion-v1",
                        "execution_id": record.execution_id,
                        "receipt_id": metadata.receipt.receipt_id,
                    },
                ),
                ingestion_digest="pending",
                execution_id=record.execution_id,
                state_version=0,
                status="PENDING",
                receipt_id=metadata.receipt.receipt_id,
                quarantine_id=metadata.receipt.quarantine_id,
                adapter_metadata_digest=sha256_digest(
                    metadata.model_dump(mode="python", exclude={"receipt"})
                ),
                created_at=now,
                updated_at=now,
            )
            ingestion = provisional.model_copy(
                update={"ingestion_digest": ingestion_record_digest(provisional)}
            )
            self.ingestions.add_pending(ingestion)
        if current.provider_execution_state in {"RUNNING"}:
            current = self.executions.transition_provider(
                current.execution_id,
                expected_state_version=current.state_version,
                new_state=metadata.provider_status,
                provider_task_id=metadata.provider_task_id,
                now=now,
            )
        if current.result_ingestion_state == "NOT_AVAILABLE":
            self.executions.transition_ingestion(
                current.execution_id,
                expected_state_version=current.state_version,
                new_state="PENDING",
                quarantine_id=metadata.receipt.quarantine_id,
                now=now,
            )
        return metadata

    def _record_raw_result_failure(
        self,
        record: ExecutionRecord,
        *,
        sink: RawResultSink,
        now: datetime,
    ) -> None:
        self.finalization_requester.pause_for_raw_result_failure(
            record.mission_id, now=now
        )
        if isinstance(sink, MockRawResultSink):
            sink.mark_recovery_required()
            self.recovery.set_current(sink.recovery_metadata(updated_at=now))

    async def ingest_result(
        self,
        execution_id: str,
        *,
        ingester: SecureResultIngester,
        now: datetime,
    ) -> ExecutionResult:
        adapter_result = await self.collect_result(execution_id, now=now)
        record = self._require_execution(execution_id)
        ingestion = self.ingestions.get_by_execution(execution_id)
        if ingestion is None:
            raise ExecutionStateTransitionError("result ingestion does not exist")
        existing = self.results.get_by_execution(execution_id)
        if existing is not None:
            if ingestion.status not in {"INGESTING", "SUCCEEDED"} or (
                record.result_ingestion_state not in {"INGESTING", "SUCCEEDED"}
            ):
                raise ExecutionStateTransitionError(
                    "existing result has inconsistent ingestion state"
                )
            if ingestion.status == "INGESTING":
                ingestion = self.ingestions.transition(
                    ingestion.ingestion_id,
                    expected_state_version=ingestion.state_version,
                    status="SUCCEEDED",
                    now=now,
                )
            if record.result_ingestion_state == "INGESTING":
                self.executions.transition_ingestion(
                    record.execution_id,
                    expected_state_version=record.state_version,
                    new_state="SUCCEEDED",
                    now=now,
                )
            return existing
        if ingestion.status not in {"PENDING", "FAILED", "INGESTING"}:
            raise ExecutionStateTransitionError("result ingestion is not resumable")
        lease_id = stable_id(
            "lease",
            {
                "schema_version": "ingestion-lease-v1",
                "ingestion_id": ingestion.ingestion_id,
                "attempt": ingestion.attempt_count + 1,
            },
        )
        lease_expires_at = now + timedelta(minutes=1)
        if ingestion.status == "INGESTING":
            if ingestion.lease_expires_at is None or now < ingestion.lease_expires_at:
                raise ResultIngestionLeaseError("result-ingestion lease is still active")
            active = self.ingestions.take_over_expired_lease(
                ingestion.ingestion_id,
                expected_state_version=ingestion.state_version,
                lease_id=lease_id,
                lease_expires_at=lease_expires_at,
                now=now,
            )
            if record.result_ingestion_state != "INGESTING":
                record = self.executions.transition_ingestion(
                    record.execution_id,
                    expected_state_version=record.state_version,
                    new_state="INGESTING",
                    now=now,
                )
        else:
            active = self.ingestions.transition(
                ingestion.ingestion_id,
                expected_state_version=ingestion.state_version,
                status="INGESTING",
                lease_id=lease_id,
                lease_expires_at=lease_expires_at,
                now=now,
            )
            record = self.executions.transition_ingestion(
                record.execution_id,
                expected_state_version=record.state_version,
                new_state="INGESTING",
                now=now,
            )
        try:
            summary = await ingester.ingest(adapter_result.receipt)
        except ResultIngestionError:
            self.finalization_requester.pause_for_result_ingestion_failure(
                record.mission_id, now=now
            )
            self.ingestions.transition(
                active.ingestion_id,
                expected_state_version=active.state_version,
                status="FAILED",
                failure_code="SECURE_INGESTION_FAILED",
                now=now,
            )
            self.executions.transition_ingestion(
                record.execution_id,
                expected_state_version=record.state_version,
                new_state="FAILED",
                now=now,
            )
            raise
        result = self._normalize_result(record, adapter_result, summary)
        self.results.add(result)
        completed = self.ingestions.transition(
            active.ingestion_id,
            expected_state_version=active.state_version,
            status="SUCCEEDED",
            now=now,
        )
        del completed
        self.executions.transition_ingestion(
            record.execution_id,
            expected_state_version=record.state_version,
            new_state="SUCCEEDED",
            now=now,
        )
        return result

    async def resume_result_ingestion(
        self,
        execution_id: str,
        *,
        ingester: SecureResultIngester,
        now: datetime,
    ) -> ExecutionResult:
        return await self.ingest_result(
            execution_id,
            ingester=ingester,
            now=now,
        )

    def quarantine_failed_ingestion(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> ExecutionRecord:
        record = self._require_execution(execution_id)
        ingestion = self.ingestions.get_by_execution(execution_id)
        if (
            ingestion is None
            or ingestion.status != "FAILED"
            or record.result_ingestion_state != "FAILED"
        ):
            raise ExecutionStateTransitionError("result ingestion is not failed")
        self.ingestions.transition(
            ingestion.ingestion_id,
            expected_state_version=ingestion.state_version,
            status="QUARANTINED",
            failure_code=ingestion.failure_code,
            now=now,
        )
        return self.executions.transition_ingestion(
            execution_id,
            expected_state_version=record.state_version,
            new_state="QUARANTINED",
            now=now,
        )

    async def _pre_dispatch_block_reason(
        self,
        record: ExecutionRecord,
        *,
        adapter: ExecutionAdapter,
        now: datetime,
    ) -> PreDispatchBlockReason | None:
        try:
            current_state = self.runtime_resolver.states.get(record.mission_id)
            current_revision = self.runtime_resolver.revisions.latest(record.mission_id)
            current_binding = self.runtime_resolver.bindings.get(record.mission_id)
        except DigestIntegrityError:
            return "DIGEST_INTEGRITY_FAILURE"
        if current_state is None or current_revision is None or current_binding is None:
            return "POLICY_STALE"
        if current_state.authorization_epoch != record.authorization_epoch:
            return "AUTHORIZATION_EPOCH_MISMATCH"
        if current_state.state != "RUNNING":
            return "MISSION_NOT_RUNNING"
        if not (current_revision.valid_from <= now < current_revision.valid_until):
            return "MISSION_EXPIRED"
        plan_before_resolution = self.plans.get(record.plan_id)
        if plan_before_resolution is None:
            return "POLICY_STALE"
        if (
            current_binding.available_tool_snapshot_id
            != plan_before_resolution.available_tool_snapshot_id
        ):
            return "SNAPSHOT_STALE"
        try:
            runtime = self.runtime_resolver.resolve(record.mission_id)
            decision = self.decisions.get(record.policy_decision_id)
            plan = self.plans.get(record.plan_id)
        except DigestIntegrityError:
            return "DIGEST_INTEGRITY_FAILURE"
        except CurrentAuthorizationStateError:
            return "POLICY_STALE"
        if decision is None or plan is None:
            return "POLICY_STALE"
        mission = runtime.mission
        if mission.state != "RUNNING":
            return "MISSION_NOT_RUNNING"
        if not (mission.valid_from <= now < mission.valid_until):
            return "MISSION_EXPIRED"
        if record.authorization_epoch != mission.authorization_epoch:
            return "AUTHORIZATION_EPOCH_MISMATCH"
        if now >= decision.expires_at or now >= runtime.snapshot.expires_at:
            return "AUTHORIZATION_TTL_EXPIRED"
        if not (
            record.mission_revision == mission.mission_revision
            and record.authorization_digest == decision.authorization_digest
            and record.proposal_digest == decision.proposal_digest
        ):
            return "POLICY_STALE"
        if record.adapter_capabilities_digest != runtime.adapter_snapshot.snapshot_digest:
            return "ADAPTER_CAPABILITY_MISMATCH"
        if record.sandbox_capabilities_digest != runtime.sandbox_snapshot.snapshot_digest:
            return "SANDBOX_CAPABILITY_MISMATCH"
        if (
            record.remote_mcp_trust_policy_digest
            != runtime.remote_trust_snapshot.snapshot_digest
        ):
            return "REMOTE_MCP_TRUST_MISMATCH"
        if (
            await self.capability_probe.session_security_context_digest()
            != runtime.session_snapshot.snapshot_digest
        ):
            return "SESSION_STALE"
        if (
            await self.capability_probe.sandbox_capabilities_digest(
                record.resolved_adapter_id
            )
            != record.sandbox_capabilities_digest
        ):
            return "SANDBOX_CAPABILITY_MISMATCH"
        if (
            await self.capability_probe.remote_mcp_trust_policy_digest(
                record.resolved_adapter_id
            )
            != record.remote_mcp_trust_policy_digest
        ):
            return "REMOTE_MCP_TRUST_MISMATCH"
        expected_adapter = next(
            (
                item
                for item in runtime.adapter_snapshot.adapters
                if item.adapter_type == decision.resolved_adapter
                and item.adapter_id == record.resolved_adapter_id
            ),
            None,
        )
        if expected_adapter is None or await adapter.get_capabilities() != expected_adapter:
            return "ADAPTER_CAPABILITY_MISMATCH"
        gate = authorize_execution(
            plan_id=record.plan_id,
            policy_decision_id=record.policy_decision_id,
            runtime_resolver=self.runtime_resolver,
            plans=self.plans,
            decisions=self.decisions,
            resources=self.resources,
            approval_requests=self.approval_requests,
            approvals=self.approvals,
            approval_request_id=record.approval_request_id,
            approval_record_id=record.approval_record_id,
            now=now,
        )
        if gate.status == "AUTHORIZED":
            return None
        if gate.status == "WAITING_APPROVAL" or any(
            "APPROVAL" in reason for reason in gate.reason_codes
        ):
            return "APPROVAL_INVALID"
        if any("SNAPSHOT" in reason for reason in gate.reason_codes):
            return "SNAPSHOT_STALE"
        if any("EPOCH" in reason for reason in gate.reason_codes):
            return "AUTHORIZATION_EPOCH_MISMATCH"
        if any("EXPIRED" in reason for reason in gate.reason_codes):
            return "AUTHORIZATION_TTL_EXPIRED"
        if any("INTEGRITY" in reason for reason in gate.reason_codes):
            return "DIGEST_INTEGRITY_FAILURE"
        return "POLICY_STALE"

    def _execution_request(self, record: ExecutionRecord) -> ExecutionRequest:
        plan = self.plans.get(record.plan_id)
        decision = self.decisions.get(record.policy_decision_id)
        runtime = self.runtime_resolver.resolve(record.mission_id)
        if plan is None or decision is None:
            raise ExecutionAuthorizationError("execution source envelope is missing")
        tool = next(
            (item for item in runtime.registry.tools if item.tool_ref == decision.tool_ref), None
        )
        if tool is None or not (
            tool.adapter_id == record.resolved_adapter_id
            and tool.adapter == decision.resolved_adapter
        ):
            raise ExecutionAuthorizationError("trusted adapter resolution changed")
        return ExecutionRequest(
            execution_id=record.execution_id,
            mission_id=record.mission_id,
            mission_revision=record.mission_revision,
            authorization_epoch=record.authorization_epoch,
            policy_decision_id=record.policy_decision_id,
            authorization_digest=record.authorization_digest,
            proposal_digest=record.proposal_digest,
            validated_arguments_digest=decision.validated_arguments_digest,
            tool_ref=record.tool_ref,
            adapter_id=record.resolved_adapter_id,
            provider_operation=tool.provider_tool_name,
            session_id=plan.proposal.session_id,
            normalized_targets=decision.normalized_targets,
            authorized_data_access=decision.authorized_data_access,
            effective_risk=decision.effective_risk,
            side_effect=decision.side_effect,
            arguments=plan.proposal.arguments,
            approval_request_id=record.approval_request_id,
            approval_record_id=record.approval_record_id,
        )

    def _normalize_result(
        self,
        record: ExecutionRecord,
        adapter_result: AdapterRawResult,
        summary: SecureIngestionSummary,
    ) -> ExecutionResult:
        decision = self.decisions.get(record.policy_decision_id)
        plan = self.plans.get(record.plan_id)
        if decision is None or plan is None:
            raise ExecutionAuthorizationError("normalization source envelope is missing")
        identity = {
            "schema_version": "execution-result-v1",
            "execution_id": record.execution_id,
            "receipt_id": adapter_result.receipt.receipt_id,
            "secure_ingestion_id": summary.secure_ingestion_id,
        }
        provisional = ExecutionResult(
            result_id=stable_id("result", identity),
            result_digest="pending",
            execution_id=record.execution_id,
            provider_task_id=adapter_result.provider_task_id,
            adapter_id=record.resolved_adapter_id,
            tool_ref=decision.tool_ref,
            policy_decision_id=decision.decision_id,
            secure_ingestion_id=summary.secure_ingestion_id,
            normalized_targets=decision.normalized_targets,
            session_id=plan.proposal.session_id,
            status=adapter_result.provider_status,
            timed_out=False,
            started_at=adapter_result.started_at,
            finished_at=adapter_result.finished_at,
            stdout_preview=summary.stdout_preview,
            stderr_preview=summary.stderr_preview,
            redacted_artifact_references=summary.redacted_artifact_references,
            exit_code=adapter_result.exit_code,
        )
        return provisional.model_copy(
            update={"result_digest": digest_model(provisional, exclude={"result_digest"})}
        )

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self.executions.get(execution_id)
        if record is None:
            raise ExecutionStateTransitionError("execution does not exist")
        return record

    def _resolve_adapter(self, record: ExecutionRecord) -> ExecutionAdapter:
        decision = self.decisions.get(record.policy_decision_id)
        if decision is None or decision.resolved_adapter_id != record.resolved_adapter_id:
            raise AdapterResolutionError("execution adapter authorization is unavailable")
        return self.adapter_registry.resolve(
            decision.resolved_adapter,
            decision.resolved_adapter_id,
        )


def require_known_outcome(record: ExecutionRecord) -> None:
    if record.provider_execution_state == "OUTCOME_UNKNOWN":
        raise ExternalDispatchOutcomeUnknownError(
            "external outcome is unknown; explicit human review is required"
        )
