"""Execution recovery authority + single-consume cancel + recovery-window continuation."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
import support_phase0b as p0b
from redteam_agent.errors import (
    CancelAttemptError,
    ExecutionRecordError,
    ExecutionRecoveryAuthorityError,
    PolicyEvaluationIndeterminateError,
)


def _dispatched(kernel: object):  # type: ignore[no-untyped-def]
    seeded = p0b.seed_authorized(kernel)  # type: ignore[arg-type]
    p0b.authorize(seeded)
    kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)  # type: ignore[attr-defined]
    return seeded


def test_issue_recovery_authority_for_dispatched_execution() -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    authority = kernel.recovery_service.issue_authority(
        authority_id="ra-1", execution_id="exec-1", allowed_operation="reconcile", reason="monitor"
    )
    assert authority.allowed_operation == "reconcile"
    assert authority.execution_id == "exec-1"
    assert authority.issued_at < authority.expires_at


def test_cancel_authority_denied_before_dispatch() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel)
    p0b.authorize(seeded)  # AUTHORIZED, not dispatched
    with pytest.raises(ExecutionRecoveryAuthorityError):
        kernel.recovery_service.issue_authority(
            authority_id="ra-1", execution_id="exec-1", allowed_operation="cancel", reason="stop"
        )


def test_cancel_requires_bound_recovery_authority() -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    with pytest.raises(CancelAttemptError):
        kernel.recovery_service.request_cancel(
            cancel_attempt_id="ca-1", execution_id="exec-1", recovery_authority_id="missing", reason="stop"
        )
    assert kernel.mock_adapter.cancel_calls == 0


def test_single_consume_cancel_attempt() -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    kernel.recovery_service.issue_authority(
        authority_id="ra-1", execution_id="exec-1", allowed_operation="cancel", reason="stop"
    )
    result = kernel.recovery_service.request_cancel(
        cancel_attempt_id="ca-1", execution_id="exec-1", recovery_authority_id="ra-1", reason="stop"
    )
    assert result.reached_adapter is True
    assert kernel.mock_adapter.cancel_calls == 1
    record = kernel.execution_repository.get("exec-1")
    assert record is not None and record.provider_execution_state == "CANCEL_REQUESTED"
    # A second cancel on the already-cancel-requested execution is refused
    # (single-consume): a new cancel authority cannot even be issued for it.
    with pytest.raises(ExecutionRecoveryAuthorityError):
        kernel.recovery_service.issue_authority(
            authority_id="ra-2", execution_id="exec-1", allowed_operation="cancel", reason="stop again"
        )
    # And re-using the original authority is refused too.
    with pytest.raises(CancelAttemptError):
        kernel.recovery_service.request_cancel(
            cancel_attempt_id="ca-2", execution_id="exec-1", recovery_authority_id="ra-1", reason="stop again"
        )
    assert kernel.mock_adapter.cancel_calls == 1  # no second adapter call


def test_recovery_window_allows_continuation_but_not_new_dispatch() -> None:
    kernel = p0b.make_kernel()
    seeded = _dispatched(kernel)  # dispatched while valid
    mission = seeded.seeded.revision
    # Advance the trusted clock past valid_until but before recovery_until.
    after_valid = mission.valid_until + timedelta(minutes=1)
    assert after_valid < mission.recovery_until
    kernel.phase0a.clock.set(after_valid)

    # Continuation of the existing execution is allowed (recovery authority issues).
    authority = kernel.recovery_service.issue_authority(
        authority_id="ra-1", execution_id="exec-1", allowed_operation="reconcile", reason="recover"
    )
    assert authority.allowed_operation == "reconcile"

    # A brand-new execution/dispatch is refused: the mission is outside its
    # validity window (new authorization/dispatch is not permitted after valid_until).
    proposal = support.make_proposal(
        tool=seeded.seeded.tool, arguments={"destinations": ["10.9.9.9"], "port": 443, "protocol": "tcp"}
    )
    plan2 = support.make_plan(kernel.phase0a, seeded=seeded.seeded, proposal=proposal, plan_id="plan-2")
    with pytest.raises(PolicyEvaluationIndeterminateError):
        support.issue_decision(kernel.phase0a, plan=plan2, decision_id="decision-2")


def test_reconcile_at_valid_until_requires_exact_recovery_authority() -> None:
    kernel = p0b.make_kernel(reconcile_status="UNKNOWN")
    seeded = _dispatched(kernel)
    kernel.phase0a.clock.set(seeded.seeded.revision.valid_until)
    with pytest.raises(ExecutionRecordError):
        kernel.reconciliation.reconcile(execution_id="exec-1")
    authority = kernel.recovery_service.issue_authority(
        authority_id="ra-reconcile", execution_id="exec-1",
        allowed_operation="reconcile", reason="recover",
    )
    result = kernel.reconciliation.reconcile(
        execution_id="exec-1", recovery_authority_id=authority.authority_id
    )
    assert result.provider_execution_state == "OUTCOME_UNKNOWN"


def test_reconcile_at_recovery_until_never_reads_provider() -> None:
    kernel = p0b.make_kernel(reconcile_status="UNKNOWN")
    seeded = _dispatched(kernel)
    kernel.phase0a.clock.set(seeded.seeded.revision.recovery_until)
    with pytest.raises(ExecutionRecordError):
        kernel.reconciliation.reconcile(execution_id="exec-1")
    assert kernel.mock_adapter.reconcile_calls == 0
