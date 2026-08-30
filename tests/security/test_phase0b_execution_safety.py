from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from redteam_agent.canonical import stable_id
from redteam_agent.errors import (
    AdapterOperationError,
    DigestIntegrityError,
    ExecutionAuthorizationError,
    ExternalDispatchOutcomeUnknownError,
    MissionStateVersionConflictError,
    ResultIngestionLeaseError,
    TrustedDependencyUnavailableError,
)
from redteam_agent.executor import (
    Executor,
    FinalizationCoordinator,
    MockExecutionAdapter,
    MockSecureResultIngester,
    StaticPreDispatchCapabilityProbe,
    require_known_outcome,
)
from redteam_agent.mission import MissionManager
from redteam_agent.models.capabilities import AdapterCapabilities
from redteam_agent.models.execution import SecureIngestionSummary
from redteam_agent.policy.approval import ApprovalService
from redteam_agent.repositories import (
    ExecutionRepository,
    LLMProfileRepository,
    MissionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
)
from redteam_agent.repositories.base import model_json
from redteam_agent.repositories.execution import execution_record_digest
from redteam_agent.seeds import FIXED_TIME
from tests.phase0b_helpers import (
    build_execution_harness,
    executor_with_adapter,
    prepare_execution,
)


@pytest.mark.parametrize("reconcile_status", ["UNKNOWN", "UNSUPPORTED", "NOT_FOUND"])
def test_uncertain_reconciliation_stops_without_duplicate_dispatch(reconcile_status: str) -> None:
    harness = build_execution_harness()
    adapter = MockExecutionAdapter(
        capabilities=harness.environment.adapter_snapshot.adapters[0],
        now=FIXED_TIME + timedelta(minutes=3),
        submit_uncertain=True,
        reconcile_status=reconcile_status,  # type: ignore[arg-type]
    )
    harness.executor = executor_with_adapter(harness, adapter)
    prepared = prepare_execution(harness)
    unknown = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    assert unknown.provider_execution_state == "OUTCOME_UNKNOWN"
    assert adapter.submit_calls == 1
    resumed = asyncio.run(
        harness.executor.dispatch(
            unknown.execution_id,
            now=FIXED_TIME + timedelta(minutes=4),
        )
    )
    assert resumed == unknown
    assert adapter.submit_calls == 1
    with pytest.raises(ExternalDispatchOutcomeUnknownError):
        require_known_outcome(unknown)


def test_resume_after_provider_task_id_reconciles_without_submit() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    assert harness.adapter.submit_calls == 1
    reconciled = asyncio.run(
        harness.executor.resume_execution(
            running.execution_id,
            now=FIXED_TIME + timedelta(minutes=4),
        )
    )
    assert reconciled.provider_execution_state == "RUNNING"
    assert reconciled.provider_task_id == running.provider_task_id
    assert harness.adapter.submit_calls == 1
    assert harness.adapter.reconcile_calls == 1


def test_reconciliation_rejects_provider_task_id_replacement() -> None:
    harness = build_execution_harness()
    adapter = MockExecutionAdapter(
        capabilities=harness.environment.adapter_snapshot.adapters[0],
        now=FIXED_TIME + timedelta(minutes=3),
        reconcile_provider_task_id="provider-task-from-another-execution",
    )
    harness.executor = executor_with_adapter(harness, adapter)
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    unknown = asyncio.run(
        harness.executor.resume_execution(
            running.execution_id,
            now=FIXED_TIME + timedelta(minutes=4),
        )
    )
    assert unknown.provider_execution_state == "OUTCOME_UNKNOWN"
    assert unknown.provider_task_id == running.provider_task_id
    assert adapter.submit_calls == 1


def test_confirmed_cancel_uses_existing_task_without_resubmit() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    cancelled = asyncio.run(
        harness.executor.request_cancel(
            running.execution_id,
            now=FIXED_TIME + timedelta(minutes=4),
        )
    )
    assert cancelled.provider_execution_state == "CANCELLED"
    assert cancelled.provider_task_id == running.provider_task_id
    assert harness.adapter.submit_calls == 1


def test_cancel_requested_restart_reconciles_after_adapter_interruption() -> None:
    harness = build_execution_harness()
    adapter = MockExecutionAdapter(
        capabilities=harness.environment.adapter_snapshot.adapters[0],
        now=FIXED_TIME + timedelta(minutes=3),
        cancel_error=True,
    )
    harness.executor = executor_with_adapter(harness, adapter)
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    with pytest.raises(AdapterOperationError):
        asyncio.run(
            harness.executor.request_cancel(
                running.execution_id,
                now=FIXED_TIME + timedelta(minutes=4),
            )
        )
    interrupted = harness.executions.get(running.execution_id)
    assert interrupted is not None
    assert interrupted.provider_execution_state == "CANCEL_REQUESTED"

    recovered = asyncio.run(
        harness.executor.resume_execution(
            running.execution_id,
            now=FIXED_TIME + timedelta(minutes=5),
        )
    )
    assert recovered.provider_execution_state == "RUNNING"
    assert recovered.provider_task_id == running.provider_task_id
    assert adapter.submit_calls == 1


def test_expired_authorization_blocks_before_provider_and_creates_no_result() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    blocked = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=31),
        )
    )
    assert blocked.provider_execution_state == "BLOCKED"
    assert blocked.pre_dispatch_block_reason == "AUTHORIZATION_TTL_EXPIRED"
    assert blocked.dispatch_attempts == 0
    assert blocked.provider_task_id is None
    assert harness.adapter.submit_calls == 0
    assert harness.results.get_by_execution(blocked.execution_id) is None


def test_expired_mission_blocks_and_requests_finalizing() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    manager = harness.finalization.missions
    blocked = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(hours=4),
        )
    )
    assert blocked.provider_execution_state == "BLOCKED"
    assert blocked.pre_dispatch_block_reason == "MISSION_EXPIRED"
    assert manager.current(blocked.mission_id).state == "FINALIZING"
    assert harness.adapter.submit_calls == 0


def test_epoch_change_blocks_before_provider() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    state = MissionStateRepository(harness.database).get(prepared.mission_id)
    assert state is not None
    MissionStateRepository(harness.database)._transition(
        prepared.mission_id,
        expected_mission_state_version=state.mission_state_version,
        expected_authorization_epoch=state.authorization_epoch,
        new_state="PAUSED",
        updated_at=FIXED_TIME + timedelta(minutes=3),
    )
    blocked = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    assert blocked.provider_execution_state == "BLOCKED"
    assert blocked.pre_dispatch_block_reason == "AUTHORIZATION_EPOCH_MISMATCH"
    assert harness.adapter.submit_calls == 0


def test_live_adapter_capability_mismatch_blocks_before_provider() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    expected = harness.environment.adapter_snapshot.adapters[0]
    mismatched = AdapterCapabilities(
        **{
            **expected.model_dump(mode="python"),
            "provider_tool_catalog_digest": "sha256:changed-catalog",
        }
    )
    adapter = MockExecutionAdapter(
        capabilities=mismatched,
        now=FIXED_TIME + timedelta(minutes=3),
    )
    harness.executor = executor_with_adapter(harness, adapter)
    blocked = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    assert blocked.pre_dispatch_block_reason == "ADAPTER_CAPABILITY_MISMATCH"
    assert adapter.submit_calls == 0


def test_dispatch_adapter_cannot_be_replaced_by_the_caller() -> None:
    harness = build_execution_harness()
    replacement = MockExecutionAdapter(
        capabilities=harness.environment.adapter_snapshot.adapters[0],
        now=FIXED_TIME + timedelta(minutes=3),
    )
    prepared = prepare_execution(harness)
    with pytest.raises(TypeError):
        harness.executor.dispatch(  # type: ignore[call-arg]
            prepared.execution_id,
            adapter=replacement,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    assert running.provider_execution_state == "RUNNING"
    assert harness.adapter.submit_calls == 1
    assert replacement.submit_calls == 0


@pytest.mark.parametrize("missing", ["capability_probe", "finalization_requester"])
def test_executor_rejects_missing_trusted_runtime_dependency(missing: str) -> None:
    harness = build_execution_harness()
    dependencies: dict[str, object] = {
        "runtime_resolver": harness.kernel.runtime_resolver,
        "plans": harness.kernel.plans,
        "decisions": harness.kernel.decisions,
        "resources": harness.kernel.resources,
        "approval_requests": harness.kernel.approval_requests,
        "approvals": harness.kernel.approvals,
        "executions": harness.executions,
        "receipts": harness.receipts,
        "recovery": harness.recovery,
        "ingestions": harness.ingestions,
        "results": harness.results,
        "sink_factory": harness.sink_factory,
        "adapter_registry": harness.adapter_registry,
        "capability_probe": harness.capability_probe,
        "finalization_requester": harness.finalization,
    }
    dependencies[missing] = None
    with pytest.raises(TrustedDependencyUnavailableError):
        Executor(**dependencies)  # type: ignore[arg-type]


def test_live_sandbox_capability_mismatch_blocks_before_provider() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    harness.executor.capability_probe = StaticPreDispatchCapabilityProbe(
        session_digest=harness.environment.session_snapshot.snapshot_digest,
        sandbox_digest="sha256:stale-live-sandbox",
        remote_trust_digest=harness.environment.remote_snapshot.snapshot_digest,
    )
    blocked = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    assert blocked.pre_dispatch_block_reason == "SANDBOX_CAPABILITY_MISMATCH"
    assert harness.adapter.submit_calls == 0


def test_execution_read_rejects_recomputed_digest_with_reduced_parent_binding() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    changed_authorization = "sha256:caller-reduced-authorization"
    changed_key = stable_id(
        "idem",
        {
            "schema_version": "execution-idempotency-v1",
            "mission_id": prepared.mission_id,
            "mission_revision": prepared.mission_revision,
            "execution_id": prepared.execution_id,
            "authorization_digest": changed_authorization,
            "resolved_adapter_id": prepared.resolved_adapter_id,
        },
    )
    tampered = prepared.model_copy(
        update={
            "authorization_digest": changed_authorization,
            "idempotency_key": changed_key,
            "record_digest": "pending",
        }
    )
    tampered = tampered.model_copy(
        update={"record_digest": execution_record_digest(tampered)}
    )
    harness.database.connection.execute(
        "UPDATE execution_records SET record_digest = ?, idempotency_key = ?, payload_json = ? "
        "WHERE execution_id = ?",
        (
            tampered.record_digest,
            tampered.idempotency_key,
            model_json(tampered),
            tampered.execution_id,
        ),
    )
    with pytest.raises(DigestIntegrityError):
        harness.executions.get(prepared.execution_id)


def test_result_repository_rejects_result_before_secure_ingestion_starts() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    metadata = asyncio.run(
        harness.executor.collect_result(
            running.execution_id,
            now=FIXED_TIME + timedelta(minutes=4),
        )
    )
    current = harness.executions.get(running.execution_id)
    assert current is not None
    forged = harness.executor._normalize_result(
        current,
        metadata,
        SecureIngestionSummary(secure_ingestion_id="not-actually-ingested"),
    )
    with pytest.raises(DigestIntegrityError):
        harness.results.add(forged)


def test_expired_ingestion_lease_is_taken_over_without_action_resubmit() -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    asyncio.run(
        harness.executor.collect_result(
            running.execution_id,
            now=FIXED_TIME + timedelta(minutes=4),
        )
    )
    ingestion = harness.ingestions.get_by_execution(running.execution_id)
    record = harness.executions.get(running.execution_id)
    assert ingestion is not None and record is not None
    leased = harness.ingestions.transition(
        ingestion.ingestion_id,
        expected_state_version=ingestion.state_version,
        status="INGESTING",
        lease_id="lease-before-process-crash",
        lease_expires_at=FIXED_TIME + timedelta(minutes=5),
        now=FIXED_TIME + timedelta(minutes=4),
    )
    harness.executions.transition_ingestion(
        record.execution_id,
        expected_state_version=record.state_version,
        new_state="INGESTING",
        now=FIXED_TIME + timedelta(minutes=4),
    )
    ingester = MockSecureResultIngester(
        summary=SecureIngestionSummary(secure_ingestion_id="lease-recovered")
    )
    with pytest.raises(ResultIngestionLeaseError):
        asyncio.run(
            harness.executor.ingest_result(
                running.execution_id,
                ingester=ingester,
                now=FIXED_TIME + timedelta(minutes=4, seconds=30),
            )
        )
    result = asyncio.run(
        harness.executor.ingest_result(
            running.execution_id,
            ingester=ingester,
            now=FIXED_TIME + timedelta(minutes=6),
        )
    )
    recovered = harness.ingestions.get(leased.ingestion_id)
    assert recovered is not None
    assert recovered.status == "SUCCEEDED"
    assert recovered.attempt_count == 2
    assert result.secure_ingestion_id == "lease-recovered"
    assert harness.adapter.submit_calls == 1


def test_require_approval_has_no_execution_until_exact_approval_exists() -> None:
    harness = build_execution_harness(approval_rule="always")
    with pytest.raises(ExecutionAuthorizationError):
        prepare_execution(harness)
    assert harness.database.connection.execute(
        "SELECT COUNT(*) FROM execution_records"
    ).fetchone()[0] == 0

    service = ApprovalService(
        runtime_resolver=harness.kernel.runtime_resolver,
        plans=harness.kernel.plans,
        decisions=harness.kernel.decisions,
        requests=harness.kernel.approval_requests,
        records=harness.kernel.approvals,
    )
    request = service.request(
        plan_id=harness.environment.plan.plan_id,
        policy_decision_id=harness.kernel.decision.decision_id,
        issued_at=FIXED_TIME + timedelta(minutes=2),
        expires_at=FIXED_TIME + timedelta(minutes=5),
    )
    approval = service.record(
        approval_request_id=request.approval_request_id,
        human_decision="APPROVED",
        approver_id="operator-1",
        approver_role="redteam-lead",
        issued_at=FIXED_TIME + timedelta(minutes=3),
        expires_at=FIXED_TIME + timedelta(minutes=5),
    )
    prepared = harness.executor.prepare(
        run=harness.run,
        plan_id=harness.environment.plan.plan_id,
        policy_decision_id=harness.kernel.decision.decision_id,
        approval_request_id=request.approval_request_id,
        approval_record_id=approval.approval_id,
        now=FIXED_TIME + timedelta(minutes=4),
    )
    assert prepared.provider_execution_state == "AUTHORIZED"


def test_approved_execution_is_blocked_if_approval_expires_before_dispatch() -> None:
    harness = build_execution_harness(approval_rule="always")
    service = ApprovalService(
        runtime_resolver=harness.kernel.runtime_resolver,
        plans=harness.kernel.plans,
        decisions=harness.kernel.decisions,
        requests=harness.kernel.approval_requests,
        records=harness.kernel.approvals,
    )
    request = service.request(
        plan_id=harness.environment.plan.plan_id,
        policy_decision_id=harness.kernel.decision.decision_id,
        issued_at=FIXED_TIME + timedelta(minutes=2),
        expires_at=FIXED_TIME + timedelta(minutes=5),
    )
    approval = service.record(
        approval_request_id=request.approval_request_id,
        human_decision="APPROVED",
        approver_id="operator-1",
        approver_role="redteam-lead",
        issued_at=FIXED_TIME + timedelta(minutes=3),
        expires_at=FIXED_TIME + timedelta(minutes=5),
    )
    prepared = harness.executor.prepare(
        run=harness.run,
        plan_id=harness.environment.plan.plan_id,
        policy_decision_id=harness.kernel.decision.decision_id,
        approval_request_id=request.approval_request_id,
        approval_record_id=approval.approval_id,
        now=FIXED_TIME + timedelta(minutes=4),
    )
    blocked = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=FIXED_TIME + timedelta(minutes=6),
        )
    )
    assert blocked.provider_execution_state == "BLOCKED"
    assert blocked.pre_dispatch_block_reason == "APPROVAL_INVALID"
    assert harness.adapter.submit_calls == 0
    assert harness.results.get_by_execution(blocked.execution_id) is None


def test_goal_completion_enters_finalizing_and_cannot_jump_to_completed() -> None:
    harness = build_execution_harness()
    states = MissionStateRepository(harness.database)
    running = states.get(harness.environment.plan.mission_id)
    assert running is not None
    with pytest.raises(MissionStateVersionConflictError):
        states._transition(
            running.mission_id,
            expected_mission_state_version=running.mission_state_version,
            expected_authorization_epoch=running.authorization_epoch,
            new_state="COMPLETED",
            updated_at=FIXED_TIME + timedelta(minutes=3),
        )

    manager = MissionManager(
        MissionRepository(harness.database),
        MissionRevisionRepository(harness.database),
        MissionStateRepository(harness.database),
        LLMProfileRepository(harness.database),
    )
    coordinator = FinalizationCoordinator(
        missions=manager,
        executions=ExecutionRepository(harness.database),
    )
    finalized = coordinator.begin_for_goal(
        harness.environment.plan.mission_id,
        now=FIXED_TIME + timedelta(minutes=3),
    )
    assert finalized.state == "FINALIZING"
