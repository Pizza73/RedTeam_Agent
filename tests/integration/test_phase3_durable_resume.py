"""Phase 3 Durable Resume driven by the real LangGraph checkpoint (SystemDesign §17.1/§17.2/§17.3/§21.1.1/§21.1.3).

Resume is owned by the compiled planning graph and its LangGraph SqliteSaver: the
graph is re-invoked on the canonical ``thread_id`` so the actual checkpoint is
restored, its controller routes a PAUSED / WAITING_HUMAN_REVIEW mission with an
incomplete execution to the existing RECONCILING node, and reconciliation reads
the Application DB (authoritative) then the Adapter. No dispatch, no Planner /
Analyzer call, never RUNNING, uncertain outcome stays OUTCOME_UNKNOWN, and the
only progression is the documented WAITING_HUMAN_REVIEW -> FINALIZING edge.
"""

from __future__ import annotations

import pytest
from test_phase1_planner_context import _inputs

import support
from redteam_agent.agent.mock_agents import MockPlanner
from redteam_agent.agent.workflow import PlanningOperationIds
from redteam_agent.composition.execution_testing import build_phase0b_kernel
from redteam_agent.composition.phase0c import build_phase0c_kernel
from redteam_agent.composition.phase1 import build_phase1_kernel
from redteam_agent.errors import (
    AgentLoopError,
    ExecutionRecoveryAuthorityError,
    MissionAuthorizationError,
    MissionRevisionConflictError,
    MissionStateVersionConflictError,
)
from redteam_agent.execution.thread import compute_thread_id
from redteam_agent.plan.models import PlannerActionOutput
from redteam_agent.policy.scope_models import IpTargetReference
from redteam_agent.runtime.clock import ManualClock, ManualMonotonicClock

OPERATOR = support.OPERATOR_ACTOR_TOKEN
RUN_ID = "dr-run"
EXECUTION_ID = "dr-execution"


def _thread(mission_id: str, run_id: str = RUN_ID) -> str:
    return compute_thread_id(mission_id=mission_id, mission_revision=1, run_id=run_id)


def _dispatch_via_graph(kernel, seeded, goal, grant, projection, *, run_id: str = RUN_ID):
    """Run one RUNNING planning iteration that dispatches and writes a checkpoint."""
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id=f"dr-context-{run_id}", mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id, projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id, iteration=0,
    )
    planner = MockPlanner(PlannerActionOutput(
        proposal=support.make_proposal(
            tool=seeded.seeded.tool,
            arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
            requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
        ),
        working_state_update=None, next_iteration_hints=(),
    ))
    step = kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id=f"dr-plan-{run_id}", plan_id=f"dr-plan-{run_id}", run_id=run_id,
            thread_id=_thread(mission_id, run_id), decision_id=f"dr-decision-{run_id}",
            execution_id=EXECUTION_ID, task_id=f"dr-task-{run_id}",
        ),
        invoke_planner=planner.invoke,
    )
    assert step.action_transition is not None and step.action_transition.dispatch is not None
    return mission_id


def _running_dispatched(*, phase0c=None):
    kernel, seeded, goal, grant, projection = _inputs(phase0c=phase0c)
    mission_id = _dispatch_via_graph(kernel, seeded, goal, grant, projection)
    phase0b = kernel.phase0c.phase0b
    assert phase0b.mock_adapter.submit_calls == 1
    record = phase0b.execution_repository.get(EXECUTION_ID)
    assert record is not None and record.provider_execution_state == "DISPATCHED"
    return kernel, phase0b, mission_id, (seeded, goal, grant, projection)


def _pause(phase0b, mission_id: str, *, expected_version: int = 2) -> None:
    phase0b.phase0a.mission_manager.pause_mission(
        mission_id, expected_version=expected_version, actor_token=OPERATOR
    )


def _state(phase0b, mission_id: str):
    return phase0b.phase0a.state_repository.get(mission_id)


def _resume(kernel, mission_id: str, *, run_id: str = RUN_ID, operation_id: str = "dr-resume-op"):
    return kernel.workflow.durable_resume(
        mission_id=mission_id, run_id=run_id, operation_id=operation_id, actor_token=OPERATOR
    )


def test_durable_resume_reconciles_paused_via_langgraph_checkpoint() -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    _pause(phase0b, mission_id)
    paused = _state(phase0b, mission_id)
    assert paused is not None and paused.state == "PAUSED"
    assert paused.authorization_epoch == 1  # RUNNING -> PAUSED rotates the epoch

    # The actual LangGraph checkpoint exists for this canonical thread.
    assert kernel.workflow.graph.checkpointer is not None
    assert kernel.workflow.graph.checkpointer.get(
        {"configurable": {"thread_id": _thread(mission_id)}}
    ) is not None

    result = _resume(kernel, mission_id)

    assert result.mission_state == "PAUSED" and result.graph_state == "PAUSED"
    assert result.entry_mission_state == "PAUSED"
    assert result.advanced_to_finalizing is False
    assert (EXECUTION_ID, "RECONCILE_UNKNOWN") in result.reconciled
    record = phase0b.execution_repository.get(EXECUTION_ID)
    assert record is not None and record.provider_execution_state == "OUTCOME_UNKNOWN"
    assert adapter.submit_calls == 1  # no re-dispatch
    assert adapter.reconcile_calls == 1  # Application DB -> Adapter, exactly once
    still = _state(phase0b, mission_id)
    assert still is not None and still.state == "PAUSED"  # never RUNNING


def test_durable_resume_reads_checkpoint_then_appdb_then_adapter() -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    _pause(phase0b, mission_id)

    order: list[str] = []
    original_get = kernel.workflow._checkpointer.get
    original_reconcile = adapter.reconcile

    def spy_get(config):
        got = original_get(config)
        order.append("langgraph_checkpoint" if got is not None else "checkpoint_missing")
        return got

    def spy_reconcile(execution_id, task_binding):
        current = phase0b.execution_repository.get(execution_id)
        assert current is not None
        order.append(f"appdb:{current.provider_execution_state}")
        order.append("adapter")
        return original_reconcile(execution_id, task_binding)

    kernel.workflow._checkpointer.get = spy_get  # type: ignore[method-assign]
    adapter.reconcile = spy_reconcile  # type: ignore[method-assign]
    try:
        _resume(kernel, mission_id)
    finally:
        kernel.workflow._checkpointer.get = original_get  # type: ignore[method-assign]
        adapter.reconcile = original_reconcile  # type: ignore[method-assign]

    # LangGraph checkpoint is consulted first; by the time the adapter is read the
    # Application DB record is already RECONCILING (DB authoritative, adapter third).
    assert order == ["langgraph_checkpoint", "appdb:RECONCILING", "adapter"]


def test_durable_resume_requires_an_actual_langgraph_checkpoint() -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    _pause(phase0b, mission_id)
    # A different run_id addresses a thread with no checkpoint: no replay, fail closed.
    with pytest.raises(AgentLoopError, match="no LangGraph checkpoint"):
        _resume(kernel, mission_id, run_id="a-thread-that-never-ran")


def test_durable_resume_rejects_a_malformed_or_foreign_thread() -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    _pause(phase0b, mission_id)
    # A run id that would not form the canonical thread binding is rejected.
    with pytest.raises((AgentLoopError, MissionRevisionConflictError)):
        _resume(kernel, mission_id, run_id="bad:run:id")
    # A foreign mission id has no operator authority / checkpoint for this caller.
    with pytest.raises(MissionAuthorizationError):
        _resume(kernel, "mission-does-not-exist")


def test_durable_resume_requires_an_authenticated_operator() -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    _pause(phase0b, mission_id)
    with pytest.raises(MissionAuthorizationError):
        kernel.workflow.durable_resume(
            mission_id=mission_id, run_id=RUN_ID, operation_id="dr",
            actor_token="token:not-an-operator",
        )


def test_durable_resume_rejects_a_running_mission() -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    running = _state(phase0b, mission_id)
    assert running is not None and running.state == "RUNNING"
    with pytest.raises(AgentLoopError):
        _resume(kernel, mission_id)


def test_durable_resume_after_recovery_window_makes_no_provider_read() -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    adapter = phase0b.mock_adapter
    _pause(phase0b, mission_id)
    before = adapter.reconcile_calls
    # Advance past recovery_until (valid_until + 1 day); no provider recovery read.
    kernel.phase0c.monotonic_clock.advance(seconds=3 * 24 * 3600 + 3600)
    kernel.phase0c.phase0b.phase0a.clock.set(kernel.phase0c.monotonic_clock.now())  # type: ignore[attr-defined]

    # Recovery authority cannot be issued past recovery_until, so no RECONCILING
    # transition and no provider read occurs; the mission stays PAUSED.
    with pytest.raises(ExecutionRecoveryAuthorityError):
        _resume(kernel, mission_id)
    assert adapter.reconcile_calls == before  # adapter never consulted
    record = phase0b.execution_repository.get(EXECUTION_ID)
    assert record is not None and record.provider_execution_state == "DISPATCHED"
    assert _state(phase0b, mission_id).state == "PAUSED"  # lifecycle preserved


def test_pre_pause_decision_is_not_reused_after_resume() -> None:
    """PAUSE/Resume rotates the epoch, so a pre-pause decision fails closed (§21)."""
    kernel, phase0b, mission_id, ctx = _running_dispatched()
    gate = phase0b.phase0a.authorization_gate
    # Build a fresh decision/plan bound to the current (running) epoch.
    seeded, goal, grant, projection = ctx
    proposal = support.make_proposal(
        tool=seeded.seeded.tool,
        arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
        requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
    )
    plan = support.make_plan(phase0b.phase0a, seeded=seeded.seeded, proposal=proposal, plan_id="pre-pause-plan")
    decision = support.issue_decision(phase0b.phase0a, plan=plan, decision_id="pre-pause-decision")
    assert gate.authorize_execution(decision_id=decision.decision_id, plan=plan).authorized

    _pause(phase0b, mission_id)
    phase0b.phase0a.mission_manager.resume_mission(mission_id, expected_version=3, actor_token=OPERATOR)
    resumed = _state(phase0b, mission_id)
    assert resumed is not None and resumed.state == "RUNNING" and resumed.authorization_epoch == 2

    after = gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert not after.authorized
    assert after.reason_code in ("AUTHORIZATION_EPOCH_STALE", "PLAN_EPOCH_STALE")


def test_durable_resume_maps_a_concurrent_resume_without_rejecting_it() -> None:
    """BLOCKER 2: a concurrent legitimate operator Resume is mapped, not rejected.

    Durable resume itself never transitions to RUNNING; a state that changed under
    a legitimate concurrent operator action is reported from the current mission
    repository, not overwritten with the entry snapshot and not rejected.
    """
    kernel, phase0b, mission_id, _ = _running_dispatched()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    _pause(phase0b, mission_id)
    manager = phase0b.phase0a.mission_manager
    original_reconcile = adapter.reconcile
    fired: list[str] = []

    def concurrent_resume(execution_id, task_binding):
        # A different operator legitimately resumes the mission mid-reconcile.
        if not fired:
            fired.append("resumed")
            paused = _state(phase0b, mission_id)
            manager.resume_mission(mission_id, expected_version=paused.mission_state_version, actor_token=OPERATOR)
        return original_reconcile(execution_id, task_binding)

    adapter.reconcile = concurrent_resume  # type: ignore[method-assign]
    try:
        result = _resume(kernel, mission_id)
    finally:
        adapter.reconcile = original_reconcile  # type: ignore[method-assign]

    assert fired == ["resumed"]
    # The current repository state (RUNNING, set by the concurrent operator) is
    # mapped and returned; durable resume did not raise and did not itself resume.
    assert result.mission_state == "RUNNING" and result.graph_state == "RUNNING"
    assert result.entry_mission_state == "PAUSED"
    current = _state(phase0b, mission_id)
    assert current is not None and current.state == "RUNNING" and current.authorization_epoch == 2


def test_durable_resume_recovers_from_a_crash_between_reconciling_and_adapter() -> None:
    """Crash point: RECONCILING is committed durably before the adapter read."""
    kernel, phase0b, mission_id, _ = _running_dispatched()
    adapter = phase0b.mock_adapter
    _pause(phase0b, mission_id)
    original = adapter.reconcile

    def crashing(execution_id, task_binding):
        raise RuntimeError("crash after RECONCILING commit, before adapter result")

    adapter.reconcile = crashing  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        _resume(kernel, mission_id, operation_id="dr-crash")
    crashed = phase0b.execution_repository.get(EXECUTION_ID)
    assert crashed is not None and crashed.provider_execution_state == "RECONCILING"

    adapter.reconcile = original  # type: ignore[method-assign]
    adapter._reconcile_status = "FOUND_TERMINAL"  # type: ignore[attr-defined]
    adapter._reconcile_provider_status = "succeeded"  # type: ignore[attr-defined]
    result = _resume(kernel, mission_id, operation_id="dr-restart")

    assert result.mission_state == "PAUSED"
    settled = phase0b.execution_repository.get(EXECUTION_ID)
    assert settled is not None and settled.provider_execution_state == "SUCCEEDED"
    assert adapter.submit_calls == 1  # never re-dispatched across the crash


def test_durable_resume_restores_a_persisted_checkpoint_in_a_new_kernel(tmp_path) -> None:
    """Restart: a newly constructed workflow + SqliteSaver over the same file DB
    restores the persisted LangGraph checkpoint and reconciles it."""
    db_path = str(tmp_path / "app.db")
    k0b = build_phase0b_kernel(db_path=db_path, clock=ManualClock(support.T0))
    phase0c = build_phase0c_kernel(phase0b=k0b, monotonic_clock=ManualMonotonicClock(support.T0))
    kernel1, seeded, goal, grant, projection = _inputs(phase0c=phase0c)
    mission_id = _dispatch_via_graph(kernel1, seeded, goal, grant, projection)
    phase0b = kernel1.phase0c.phase0b
    phase0b.mock_adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    _pause(phase0b, mission_id)

    # Process-equivalent restart: a fresh Phase 1 workflow + a fresh SqliteSaver
    # connection over the same durable SQLite file.
    kernel2 = build_phase1_kernel(phase0c=phase0c)
    thread_id = _thread(mission_id)
    assert kernel2.workflow._checkpointer.get({"configurable": {"thread_id": thread_id}}) is not None

    result = kernel2.workflow.durable_resume(
        mission_id=mission_id, run_id=RUN_ID, operation_id="dr-restart", actor_token=OPERATOR
    )
    assert result.mission_state == "PAUSED"
    assert (EXECUTION_ID, "RECONCILE_UNKNOWN") in result.reconciled
    record = phase0b.execution_repository.get(EXECUTION_ID)
    assert record is not None and record.provider_execution_state == "OUTCOME_UNKNOWN"
    assert phase0b.mock_adapter.submit_calls == 1  # restart performed no dispatch


# --- WAITING_HUMAN_REVIEW progression (§21.1.3) ---------------------------


def _waiting_human_review():
    kernel, phase0b, mission_id, _ = _running_dispatched()
    kernel.finalization_service.begin_abort(mission_id)  # RUNNING -> FINALIZING (ABORTED intent)
    kernel.unresolved_items.open(
        unresolved_id=f"unresolved-execution_reconciled-{EXECUTION_ID}",
        mission_id=mission_id, source_execution_id=EXECUTION_ID,
        reason_code="EXECUTION_RECONCILED",
    )
    kernel.finalization_service.wait_for_human_review(mission_id)
    assert _state(phase0b, mission_id).state == "WAITING_HUMAN_REVIEW"
    return kernel, phase0b, mission_id


def test_durable_resume_holds_waiting_review_while_items_are_open() -> None:
    kernel, phase0b, mission_id = _waiting_human_review()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "FOUND_TERMINAL"  # type: ignore[attr-defined]
    adapter._reconcile_provider_status = "succeeded"  # type: ignore[attr-defined]

    result = _resume(kernel, mission_id)

    assert result.mission_state == "WAITING_HUMAN_REVIEW"
    assert result.graph_state == "WAITING_HUMAN_REVIEW"
    assert result.advanced_to_finalizing is False
    record = phase0b.execution_repository.get(EXECUTION_ID)
    assert record is not None and record.provider_execution_state == "SUCCEEDED"
    assert kernel.unresolved_items.current(mission_id)[0].status == "OPEN"
    assert adapter.submit_calls == 1


def test_durable_resume_advances_to_finalizing_once_all_items_resolved() -> None:
    kernel, phase0b, mission_id = _waiting_human_review()
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "FOUND_TERMINAL"  # type: ignore[attr-defined]
    adapter._reconcile_provider_status = "succeeded"  # type: ignore[attr-defined]
    # A collectible JSON result so the graph-owned FINALIZING path can complete.
    adapter._stdout_chunks = (b'{"host":"10.1.2.3","status":"open","port":443}\n',)  # type: ignore[attr-defined]

    _resume(kernel, mission_id, operation_id="dr-1")  # settle the provider outcome
    kernel.unresolved_items.resolve_from_execution(
        unresolved_id=f"unresolved-execution_reconciled-{EXECUTION_ID}"
    )
    assert kernel.unresolved_items.current(mission_id)[0].status == "RESOLVED"

    # The graph finalization node itself takes the WAITING_HUMAN_REVIEW ->
    # FINALIZING edge (Mission Manager, original ABORTED intent) and drives the
    # existing FINALIZING workflow to its terminal — LangGraph stays the sole owner.
    result = _resume(kernel, mission_id, operation_id="dr-2")

    assert result.entry_mission_state == "WAITING_HUMAN_REVIEW"
    assert result.advanced_to_finalizing is True
    assert result.mission_state == "ABORTED"
    assert _state(phase0b, mission_id).state == "ABORTED"
    intent = kernel.phase0c.phase0b.phase0a.database.occ_get("mission_finalization_intent", mission_id)
    assert intent is not None and '"target_state": "ABORTED"' in intent[1]  # original reason preserved
    assert adapter.submit_calls == 1  # never re-dispatched


def test_advance_from_human_review_fails_closed_while_items_unresolved() -> None:
    kernel, phase0b, mission_id = _waiting_human_review()
    with pytest.raises(AgentLoopError):
        kernel.finalization_service.advance_from_human_review(mission_id)
    kernel2, _p2, mission_id2, _ = _running_dispatched()
    with pytest.raises(AgentLoopError):
        kernel2.finalization_service.advance_from_human_review(mission_id2)


def test_review_exit_edge_is_occ_guarded() -> None:
    kernel, phase0b, mission_id = _waiting_human_review()
    state = _state(phase0b, mission_id)
    manager = phase0b.phase0a.mission_manager
    with pytest.raises(MissionStateVersionConflictError):
        manager.begin_finalization(
            mission_id, expected_version=state.mission_state_version + 5, actor_token=OPERATOR
        )


# --- HIGH 1: every incomplete execution reconciled exactly once ------------


def _dispatch_second(kernel, ctx, *, execution_id: str = "dr-execution-2") -> None:
    """Dispatch a second provider-task execution on the still-RUNNING mission."""
    seeded = ctx[0]
    phase0a = kernel.phase0c.phase0b.phase0a
    proposal = support.make_proposal(
        tool=seeded.seeded.tool,
        arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
        requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
    )
    plan = support.make_plan(phase0a, seeded=seeded.seeded, proposal=proposal, plan_id="dr-plan-2")
    decision = support.issue_decision(phase0a, plan=plan, decision_id="dr-decision-2")
    kernel.phase0c.phase0b.executor.create_execution(
        execution_id=execution_id, task_id="dr-task-2", decision_id=decision.decision_id, plan=plan
    )
    out = kernel.phase0c.phase0b.executor.dispatch(execution_id=execution_id, plan=plan)
    assert out.provider_execution_state == "DISPATCHED"


def test_durable_resume_reconciles_every_incomplete_execution_exactly_once() -> None:
    kernel, phase0b, mission_id, ctx = _running_dispatched()
    _dispatch_second(kernel, ctx, execution_id="dr-execution-2")
    adapter = phase0b.mock_adapter
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    assert adapter.submit_calls == 2  # two dispatches during setup
    _pause(phase0b, mission_id)

    # Record the exact (execution, provider task) the adapter is asked about, to
    # prove each reconcile is bound to its own task binding.
    reads: list[tuple[str, str | None]] = []
    original = adapter.reconcile

    def spy(execution_id, task_binding):
        provider_task_id = getattr(task_binding, "provider_task_id", None)
        reads.append((execution_id, provider_task_id))
        return original(execution_id, task_binding)

    adapter.reconcile = spy  # type: ignore[method-assign]
    try:
        result = _resume(kernel, mission_id)
    finally:
        adapter.reconcile = original  # type: ignore[method-assign]

    # Every incomplete execution reconciled exactly once, in deterministic order,
    # each bound to its own provider task; no execution reported prematurely.
    assert sorted(e for e, _ in result.reconciled) == ["dr-execution", "dr-execution-2"]
    assert all(reason == "RECONCILE_UNKNOWN" for _, reason in result.reconciled)
    assert [e for e, _ in reads] == ["dr-execution", "dr-execution-2"]
    assert reads == [("dr-execution", "provider-dr-task-dr-run"), ("dr-execution-2", "provider-dr-task-2")]
    assert adapter.reconcile_calls == 2
    assert adapter.submit_calls == 2  # no new dispatch during resume
    for eid in ("dr-execution", "dr-execution-2"):
        rec = phase0b.execution_repository.get(eid)
        assert rec is not None and rec.provider_execution_state == "OUTCOME_UNKNOWN"
    assert _state(phase0b, mission_id).state == "PAUSED"


# --- HIGH 2: the actual persisted checkpoint contents are validated --------


def _tamper_checkpoint(kernel, mission_id: str, overrides: dict) -> None:
    saver = kernel.workflow._checkpointer
    config = {"configurable": {"thread_id": _thread(mission_id)}}
    tup = saver.get_tuple(config)
    checkpoint = dict(tup.checkpoint)
    channel_values = dict(checkpoint["channel_values"])
    channel_values.update(overrides)
    checkpoint["channel_values"] = channel_values
    saver.put(tup.config, checkpoint, tup.metadata, {})


@pytest.mark.parametrize(
    "overrides",
    [
        {"mission_id": "foreign-mission"},
        {"mission_revision": 2},
        {"run_id": "another-run"},
    ],
)
def test_durable_resume_rejects_a_checkpoint_bound_to_another_mission(overrides) -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    adapter = phase0b.mock_adapter
    _pause(phase0b, mission_id)
    # The checkpoint exists under the correct thread key but its persisted
    # channel_values are bound to a different mission / revision / run.
    _tamper_checkpoint(kernel, mission_id, overrides)
    reconcile_before = adapter.reconcile_calls

    with pytest.raises(MissionRevisionConflictError):
        _resume(kernel, mission_id)

    # Fail closed before any execution mutation or adapter read.
    assert adapter.reconcile_calls == reconcile_before
    record = phase0b.execution_repository.get(EXECUTION_ID)
    assert record is not None and record.provider_execution_state == "DISPATCHED"
    assert _state(phase0b, mission_id).state == "PAUSED"


def test_durable_resume_makes_zero_planner_and_analyzer_calls() -> None:
    kernel, phase0b, mission_id, _ = _running_dispatched()
    phase0b.mock_adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    _pause(phase0b, mission_id)

    planner_calls: list[int] = []
    analyzer_calls: list[int] = []
    orig_planner = kernel.llm_gateway.invoke_planner
    orig_analyzer = kernel.llm_gateway.invoke_analyzer

    def spy_planner(*a, **k):
        planner_calls.append(1)
        return orig_planner(*a, **k)

    def spy_analyzer(*a, **k):
        analyzer_calls.append(1)
        return orig_analyzer(*a, **k)

    kernel.llm_gateway.invoke_planner = spy_planner  # type: ignore[method-assign]
    kernel.llm_gateway.invoke_analyzer = spy_analyzer  # type: ignore[method-assign]
    try:
        result = _resume(kernel, mission_id)
    finally:
        kernel.llm_gateway.invoke_planner = orig_planner  # type: ignore[method-assign]
        kernel.llm_gateway.invoke_analyzer = orig_analyzer  # type: ignore[method-assign]

    assert planner_calls == [] and analyzer_calls == []
    assert result.mission_state == "PAUSED"
