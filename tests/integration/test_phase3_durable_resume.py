"""Phase 3 Durable Resume: reconcile a stopped/review mission without resuming it.

These tests exercise SystemDesign §17.3 / §21.1.1 / §21.1.3: a PAUSED or
WAITING_HUMAN_REVIEW mission is reconciled using only the existing RECONCILING
recovery path and Current Recovery Authority. No dispatch and no Planner/Analyzer
call occurs, the mission never returns to RUNNING, reconciliation consults the
durable checkpoint, then the Application DB, then the Adapter, an uncertain
outcome stays OUTCOME_UNKNOWN, and the only permitted progression is the
documented WAITING_HUMAN_REVIEW -> FINALIZING edge once every item is RESOLVED.
"""

from __future__ import annotations

import pytest

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.composition.phase1 import build_phase1_kernel
from redteam_agent.errors import AgentLoopError

OPERATOR = support.OPERATOR_ACTOR_TOKEN


def _running_dispatched():
    """A RUNNING mission with one DISPATCHED (provider-task) execution."""
    kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
    phase0b = kernel.phase0c.phase0b
    seeded = p0b.seed_authorized(phase0b)
    mission_id = seeded.seeded.revision.mission_id
    p0b.authorize(seeded)
    outcome = phase0b.executor.dispatch(execution_id=seeded.execution_id, plan=seeded.plan)
    assert outcome.provider_execution_state == "DISPATCHED"
    assert phase0b.mock_adapter.submit_calls == 1
    return kernel, phase0b, seeded, mission_id


def _pause(phase0b, mission_id: str) -> None:
    phase0b.phase0a.mission_manager.pause_mission(
        mission_id, expected_version=2, actor_token=OPERATOR
    )


def _state(phase0b, mission_id: str):
    return phase0b.phase0a.state_repository.get(mission_id)


def test_durable_resume_reconciles_paused_mission_without_dispatch_or_llm() -> None:
    kernel, phase0b, seeded, mission_id = _running_dispatched()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    _pause(phase0b, mission_id)
    paused = _state(phase0b, mission_id)
    assert paused is not None and paused.state == "PAUSED"
    assert paused.authorization_epoch == 1  # RUNNING -> PAUSED rotates the epoch

    result = kernel.workflow.durable_resume(mission_id=mission_id)

    # Mission stays PAUSED; the graph state maps to the *current* mission (§17.3).
    assert result.mission_state == "PAUSED"
    assert result.graph_state == "PAUSED"
    assert result.entry_mission_state == "PAUSED"
    assert result.advanced_to_finalizing is False
    # The uncertain provider outcome is OUTCOME_UNKNOWN, never re-dispatched.
    record = phase0b.execution_repository.get(seeded.execution_id)
    assert record is not None and record.provider_execution_state == "OUTCOME_UNKNOWN"
    assert (seeded.execution_id, "RECONCILE_UNKNOWN") in result.reconciled
    # Zero new dispatch, zero Planner/Analyzer calls.
    assert adapter.submit_calls == 1
    assert adapter.reconcile_calls == 1
    # Mission lifecycle preserved: still PAUSED, revision unchanged, not RUNNING.
    still = _state(phase0b, mission_id)
    assert still is not None and still.state == "PAUSED"
    assert still.mission_revision == paused.mission_revision


def test_durable_resume_consults_checkpoint_then_appdb_then_adapter() -> None:
    kernel, phase0b, seeded, mission_id = _running_dispatched()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    _pause(phase0b, mission_id)

    order: list[str] = []
    original_checkpoint = kernel.controller.checkpoint
    original_reconcile = adapter.reconcile

    def spy_checkpoint(mid: str):
        order.append("checkpoint")
        return original_checkpoint(mid)

    def spy_reconcile(execution_id, task_binding):
        # By the time the adapter is read, the Application DB record has already
        # been advanced to RECONCILING inside the same recovery step.
        current = phase0b.execution_repository.get(execution_id)
        assert current is not None
        order.append(f"appdb:{current.provider_execution_state}")
        order.append("adapter")
        return original_reconcile(execution_id, task_binding)

    kernel.controller.checkpoint = spy_checkpoint  # type: ignore[method-assign]
    adapter.reconcile = spy_reconcile  # type: ignore[method-assign]
    try:
        kernel.workflow.durable_resume(mission_id=mission_id)
    finally:
        kernel.controller.checkpoint = original_checkpoint  # type: ignore[method-assign]
        adapter.reconcile = original_reconcile  # type: ignore[method-assign]

    assert order == ["checkpoint", "appdb:RECONCILING", "adapter"]


def test_durable_resume_rejects_a_running_mission() -> None:
    kernel, phase0b, seeded, mission_id = _running_dispatched()
    running = _state(phase0b, mission_id)
    assert running is not None and running.state == "RUNNING"
    with pytest.raises(AgentLoopError):
        kernel.workflow.durable_resume(mission_id=mission_id)


def test_durable_resume_after_recovery_window_makes_no_provider_read() -> None:
    kernel, phase0b, seeded, mission_id = _running_dispatched()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    _pause(phase0b, mission_id)
    reconcile_before = adapter.reconcile_calls
    # Advance past recovery_until (valid_until + 1 day); no provider recovery read.
    kernel.phase0c.monotonic_clock.advance(seconds=3 * 24 * 3600 + 3600)
    kernel.phase0c.phase0b.phase0a.clock.set(kernel.phase0c.monotonic_clock.now())  # type: ignore[attr-defined]

    result = kernel.workflow.durable_resume(mission_id=mission_id)

    assert result.mission_state == "PAUSED"
    assert (seeded.execution_id, "RECOVERY_WINDOW_CLOSED") in result.reconciled
    assert adapter.reconcile_calls == reconcile_before  # adapter never consulted
    record = phase0b.execution_repository.get(seeded.execution_id)
    assert record is not None and record.provider_execution_state == "DISPATCHED"


def test_pre_pause_decision_and_approval_are_not_reused_after_resume() -> None:
    """PAUSED/Resume rotates the epoch, so a pre-pause decision fails closed (§21)."""
    kernel, phase0b, seeded, mission_id = _running_dispatched()
    gate = phase0b.phase0a.authorization_gate
    # The pre-pause decision authorized the running mission at epoch 0.
    pre_pause = gate.authorize_execution(decision_id=seeded.decision.decision_id, plan=seeded.plan)
    assert pre_pause.authorized

    _pause(phase0b, mission_id)
    kernel.phase0c.phase0b.phase0a.mission_manager.resume_mission(
        mission_id, expected_version=3, actor_token=OPERATOR
    )
    resumed = _state(phase0b, mission_id)
    assert resumed is not None and resumed.state == "RUNNING"
    assert resumed.authorization_epoch == 2  # pause(0->1) + resume(1->2)

    # The pre-pause PolicyDecision/plan carry the stale epoch and are rejected.
    after = gate.authorize_execution(decision_id=seeded.decision.decision_id, plan=seeded.plan)
    assert not after.authorized
    assert after.reason_code in ("AUTHORIZATION_EPOCH_STALE", "PLAN_EPOCH_STALE")


def _waiting_human_review():
    """A WAITING_HUMAN_REVIEW mission (abort intent) with one OPEN item."""
    kernel, phase0b, seeded, mission_id = _running_dispatched()
    kernel.knowledge_service.initialize_mission(
        mission_id=mission_id,
        mission_revision=seeded.seeded.revision.mission_revision,
        recorded_at=support.T0,
    )
    # Enter the common FINALIZING workflow with the ABORTED terminal reason.
    kernel.finalization_service.begin_abort(mission_id)
    # A provider outcome is not yet reconciled -> an OPEN unresolved item, then
    # the mission waits for a human decision.
    kernel.unresolved_items.open(
        unresolved_id=f"unresolved-execution_reconciled-{seeded.execution_id}",
        mission_id=mission_id,
        source_execution_id=seeded.execution_id,
        reason_code="EXECUTION_RECONCILED",
    )
    kernel.finalization_service.wait_for_human_review(mission_id)
    state = _state(phase0b, mission_id)
    assert state is not None and state.state == "WAITING_HUMAN_REVIEW"
    return kernel, phase0b, seeded, mission_id


def test_durable_resume_holds_waiting_review_while_items_are_open() -> None:
    kernel, phase0b, seeded, mission_id = _waiting_human_review()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "FOUND_TERMINAL"  # type: ignore[attr-defined]
    adapter._reconcile_provider_status = "succeeded"  # type: ignore[attr-defined]

    result = kernel.workflow.durable_resume(mission_id=mission_id)

    # The item is still OPEN, so the mission stays in WAITING_HUMAN_REVIEW and is
    # never implicitly resumed to RUNNING or advanced.
    assert result.mission_state == "WAITING_HUMAN_REVIEW"
    assert result.graph_state == "WAITING_HUMAN_REVIEW"
    assert result.advanced_to_finalizing is False
    # Reconciliation still ran read-only: the execution is now SUCCEEDED.
    record = phase0b.execution_repository.get(seeded.execution_id)
    assert record is not None and record.provider_execution_state == "SUCCEEDED"
    assert adapter.submit_calls == 1
    item = kernel.unresolved_items.current(mission_id)[0]
    assert item.status == "OPEN"


def test_durable_resume_advances_to_finalizing_once_all_items_resolved() -> None:
    kernel, phase0b, seeded, mission_id = _waiting_human_review()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "FOUND_TERMINAL"  # type: ignore[attr-defined]
    adapter._reconcile_provider_status = "succeeded"  # type: ignore[attr-defined]

    # First resume reconciles the provider outcome (read-only) to SUCCEEDED.
    kernel.workflow.durable_resume(mission_id=mission_id)
    # The responsible service resolves the item against the settled source (§21.1.3).
    kernel.unresolved_items.resolve_from_execution(
        unresolved_id=f"unresolved-execution_reconciled-{seeded.execution_id}"
    )
    assert kernel.unresolved_items.current(mission_id)[0].status == "RESOLVED"

    # Second resume: every item RESOLVED -> the Mission Manager takes the existing
    # WAITING_HUMAN_REVIEW -> FINALIZING edge (§21.1.3). Durable resume hands off to
    # the ordinary FINALIZING workflow and never implies a normal resume itself.
    result = kernel.workflow.durable_resume(mission_id=mission_id)

    assert result.entry_mission_state == "WAITING_HUMAN_REVIEW"
    assert result.advanced_to_finalizing is True
    assert result.mission_state == "FINALIZING"
    assert result.graph_state == "FINALIZING"
    final = _state(phase0b, mission_id)
    assert final is not None and final.state == "FINALIZING"
    assert adapter.submit_calls == 1  # never re-dispatched


def test_durable_resume_handoff_preserves_the_original_terminal_reason() -> None:
    kernel, phase0b, seeded, mission_id = _waiting_human_review()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "FOUND_TERMINAL"  # type: ignore[attr-defined]
    adapter._reconcile_provider_status = "succeeded"  # type: ignore[attr-defined]

    kernel.workflow.durable_resume(mission_id=mission_id)
    kernel.unresolved_items.resolve_from_execution(
        unresolved_id=f"unresolved-execution_reconciled-{seeded.execution_id}"
    )
    handoff = kernel.workflow.durable_resume(mission_id=mission_id)

    # The handoff enters the existing FINALIZING state with the ORIGINAL terminal
    # reason (ABORTED); it never rewrites it to a normal completion, and adds no
    # new graph/state/record. The remaining collection/ingestion/audit is the
    # ordinary FINALIZING workflow's responsibility.
    assert handoff.mission_state == "FINALIZING"
    assert kernel.finalization_service.is_finalizing(mission_id)
    intent_row = kernel.phase0c.phase0b.phase0a.database.occ_get(
        "mission_finalization_intent", mission_id
    )
    assert intent_row is not None and '"target_state": "ABORTED"' in intent_row[1]
    assert adapter.submit_calls == 1


def test_advance_from_human_review_fails_closed_while_items_unresolved() -> None:
    kernel, phase0b, seeded, mission_id = _waiting_human_review()
    with pytest.raises(AgentLoopError):
        kernel.finalization_service.advance_from_human_review(mission_id)
    # Wrong state: a RUNNING/PAUSED mission cannot take the review-exit edge.
    kernel2, phase0b2, _seeded2, mission_id2 = _running_dispatched()
    with pytest.raises(AgentLoopError):
        kernel2.finalization_service.advance_from_human_review(mission_id2)


def test_durable_resume_recovers_from_a_crash_between_reconciling_and_adapter() -> None:
    """Crash point: RECONCILING is committed durably before the adapter read."""
    kernel, phase0b, seeded, mission_id = _running_dispatched()
    adapter = phase0b.mock_adapter
    _pause(phase0b, mission_id)

    original = adapter.reconcile

    def crashing(execution_id, task_binding):
        # Model a process crash after the durable RECONCILING transition but
        # before the provider read completes.
        raise RuntimeError("crash after RECONCILING commit, before adapter result")

    adapter.reconcile = crashing  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        kernel.workflow.durable_resume(mission_id=mission_id)
    crashed = phase0b.execution_repository.get(seeded.execution_id)
    assert crashed is not None and crashed.provider_execution_state == "RECONCILING"

    # Restart: the adapter now confirms a terminal outcome. Durable resume picks
    # up the RECONCILING execution and settles it without any re-dispatch.
    adapter.reconcile = original  # type: ignore[method-assign]
    adapter._reconcile_status = "FOUND_TERMINAL"  # type: ignore[attr-defined]
    adapter._reconcile_provider_status = "succeeded"  # type: ignore[attr-defined]
    result = kernel.workflow.durable_resume(mission_id=mission_id)

    assert result.mission_state == "PAUSED"
    settled = phase0b.execution_repository.get(seeded.execution_id)
    assert settled is not None and settled.provider_execution_state == "SUCCEEDED"
    assert adapter.submit_calls == 1  # never re-dispatched across the crash


def test_review_exit_edge_is_occ_guarded() -> None:
    """WAITING_HUMAN_REVIEW -> FINALIZING is an OCC transition (§21.1)."""
    from redteam_agent.errors import MissionStateVersionConflictError

    kernel, phase0b, seeded, mission_id = _waiting_human_review()
    state = _state(phase0b, mission_id)
    assert state is not None and state.state == "WAITING_HUMAN_REVIEW"
    manager = phase0b.phase0a.mission_manager
    # A stale expected version is rejected rather than silently retried/merged.
    with pytest.raises(MissionStateVersionConflictError):
        manager.begin_finalization(
            mission_id,
            expected_version=state.mission_state_version + 5,
            actor_token=OPERATOR,
        )
