"""Executor dispatch: single claim, one-decision-one-execution, pre-dispatch BLOCKED."""

from __future__ import annotations

import pytest

import support
import support_phase0b as p0b
from redteam_agent.errors import ExecutionRecordError, ExecutorAuthorizationError


def test_create_then_dispatch_provider_task() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel)
    rec = kernel.executor.create_execution(
        execution_id="exec-1", task_id="task-1", decision_id=seeded.decision.decision_id, plan=seeded.plan
    )
    assert rec.provider_execution_state == "AUTHORIZED"
    assert rec.dispatch_attempts == 0

    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    assert out.provider_execution_state == "DISPATCHED"
    assert out.dispatch_attempts == 1
    assert kernel.mock_adapter.submit_calls == 1
    claim = kernel.claim_repository.get("claim-exec-1")
    assert claim is not None and claim.claim_state == "consumed"
    binding = kernel.task_binding_repository.find_by_execution("exec-1")
    assert binding is not None and binding.binding_type == "provider_task"


def test_one_decision_yields_one_execution() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel)
    p0b.authorize(seeded)
    # A second execution referencing the same policy decision is rejected.
    with pytest.raises(ExecutionRecordError):
        kernel.executor.create_execution(
            execution_id="exec-2", task_id="task-2", decision_id=seeded.decision.decision_id, plan=seeded.plan
        )
    assert kernel.execution_repository.get("exec-2") is None


def test_pre_dispatch_mismatch_blocks_without_provider_call() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel)
    p0b.authorize(seeded)
    # Pause the mission after AUTHORIZED; pre-dispatch revalidation must fail closed.
    kernel.phase0a.mission_manager.pause_mission(
        support.MISSION_ID, expected_version=seeded.seeded.running_state.mission_state_version,
        actor_token=support.OPERATOR_ACTOR_TOKEN,
    )
    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    assert out.provider_execution_state == "BLOCKED"
    assert out.dispatch_attempts == 0
    assert out.pre_dispatch_block_reason == "MISSION_NOT_RUNNING"
    assert kernel.mock_adapter.submit_calls == 0
    assert kernel.claim_repository.find_unconsumed("exec-1") is None
    assert kernel.claim_repository.get("claim-exec-1") is None
    assert kernel.result_repository.get("exec-1") is None


def test_stale_authorization_epoch_blocks_dispatch() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel)
    p0b.authorize(seeded)
    # Rotate the authorization epoch (a revocation boundary) after AUTHORIZED.
    kernel.phase0a.mission_manager.invalidate_authorization(
        support.MISSION_ID, expected_version=seeded.seeded.running_state.mission_state_version,
        actor_token=support.OPERATOR_ACTOR_TOKEN,
    )
    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    assert out.provider_execution_state == "BLOCKED"
    assert out.pre_dispatch_block_reason == "AUTHORIZATION_EPOCH_MISMATCH"
    assert kernel.mock_adapter.submit_calls == 0


def test_blocked_execution_cannot_be_redispatched() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel)
    p0b.authorize(seeded)
    kernel.phase0a.mission_manager.pause_mission(
        support.MISSION_ID, expected_version=seeded.seeded.running_state.mission_state_version,
        actor_token=support.OPERATOR_ACTOR_TOKEN,
    )
    kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)  # -> BLOCKED
    with pytest.raises(ExecutionRecordError):
        kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)


def test_require_approval_without_record_is_not_authorized() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(
        kernel, side_effect="destructive", minimum_risk="high",
        require_for_side_effect=frozenset({"destructive"}),
    )
    assert seeded.decision.decision == "REQUIRE_APPROVAL"
    # No approval request/record exists yet: not executable, so no execution created.
    with pytest.raises(ExecutorAuthorizationError):
        p0b.authorize(seeded)
    assert kernel.execution_repository.get("exec-1") is None


def test_require_approval_with_record_dispatches() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(
        kernel, side_effect="destructive", minimum_risk="high",
        require_for_side_effect=frozenset({"destructive"}),
    )
    approvals = kernel.phase0a.approval_service
    approvals.issue_request(
        approval_request_id="req-1", decision_id=seeded.decision.decision_id, plan=seeded.plan
    )
    support.register_approver(kernel.phase0a)
    approvals.submit_decision(
        approval_id="appr-1", approval_request_id="req-1", actor_token="tok-approver", verdict="APPROVED"
    )
    p0b.authorize(seeded)
    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    assert out.provider_execution_state == "DISPATCHED"
    claim = kernel.claim_repository.get("claim-exec-1")
    assert claim is not None and claim.approval_record_id == "appr-1"


def test_idempotency_key_is_deterministic_and_bound() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel)
    rec = kernel.executor.create_execution(
        execution_id="exec-1", task_id="task-1", decision_id=seeded.decision.decision_id, plan=seeded.plan
    )
    # Recomputing over the same identity yields the same key (no new key on retry).
    expected = kernel.executor._compute_idempotency_key(execution_id="exec-1", decision=seeded.decision)
    assert rec.idempotency_key == expected
