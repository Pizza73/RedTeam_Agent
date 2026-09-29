"""Reconciliation: uncertain outcome -> OUTCOME_UNKNOWN, never resubmit."""

from __future__ import annotations

import pytest

import support_phase0b as p0b
from redteam_agent.errors import ExecutionRecordError
from redteam_agent.execution.adapter import ReconciliationResult


def _dispatch(kernel: object):  # type: ignore[no-untyped-def]
    seeded = p0b.seed_authorized(kernel)  # type: ignore[arg-type]
    p0b.authorize(seeded)
    return kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)  # type: ignore[attr-defined]


@pytest.mark.parametrize("status", ["UNKNOWN", "UNSUPPORTED", "NOT_FOUND_UNCERTAIN", "NOT_FOUND_CONFIRMED"])
def test_uncertain_reconcile_maps_to_outcome_unknown(status: str) -> None:
    kernel = p0b.make_kernel(reconcile_status=status)
    _dispatch(kernel)  # -> DISPATCHED
    outcome = kernel.reconciliation.reconcile(execution_id="exec-1")
    assert outcome.provider_execution_state == "OUTCOME_UNKNOWN"
    # Reconciliation never resubmits.
    assert kernel.mock_adapter.submit_calls == 1


def test_found_terminal_advances_to_succeeded() -> None:
    kernel = p0b.make_kernel(reconcile_status="FOUND_TERMINAL", reconcile_provider_status="succeeded")
    _dispatch(kernel)
    outcome = kernel.reconciliation.reconcile(execution_id="exec-1")
    assert outcome.provider_execution_state == "SUCCEEDED"
    assert kernel.mock_adapter.submit_calls == 1


def test_found_running_advances_to_running() -> None:
    kernel = p0b.make_kernel(reconcile_status="FOUND_RUNNING")
    _dispatch(kernel)
    outcome = kernel.reconciliation.reconcile(execution_id="exec-1")
    assert outcome.provider_execution_state == "RUNNING"


def test_uncertain_submit_goes_to_reconciliation_without_resubmit() -> None:
    # The adapter accepts the (single) submit call but then raises: the claim is
    # already consumed, so the executor does not reuse it or resubmit; it
    # reconciles to OUTCOME_UNKNOWN.
    kernel = p0b.make_kernel(fail_on_submit=True, reconcile_status="UNKNOWN")
    out = _dispatch(kernel)
    assert out.provider_execution_state == "OUTCOME_UNKNOWN"
    assert out.dispatch_attempts == 1
    assert kernel.mock_adapter.submit_calls == 1
    # The claim was consumed exactly once; it is not reused.
    claim = kernel.claim_repository.get("claim-exec-1")
    assert claim is not None and claim.claim_state == "consumed"
    record = kernel.execution_repository.get("exec-1")
    assert record is not None and record.provider_execution_state == "OUTCOME_UNKNOWN"
    assert kernel.result_repository.get("exec-1") is None  # no fabricated ExecutionResult


def test_reconcile_rejects_result_for_another_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = p0b.make_kernel()
    _dispatch(kernel)

    def wrong_execution(execution_id, task_binding):  # type: ignore[no-untyped-def]
        return ReconciliationResult(
            execution_id="exec-other", status="FOUND_TERMINAL", task_binding=task_binding,
            provider_status="succeeded", provider_task_id=task_binding.provider_task_id,
            observed_at=kernel.phase0a.clock.now(),
        )

    monkeypatch.setattr(kernel.mock_adapter, "reconcile", wrong_execution)
    with pytest.raises(ExecutionRecordError):
        kernel.reconciliation.reconcile(execution_id="exec-1")
