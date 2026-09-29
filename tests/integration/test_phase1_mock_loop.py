"""Phase 1 Mock Planner -> gates -> Executor -> Analyzer -> Goal integration."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from test_phase1_planner_context import _inputs

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.agent.mock_agents import MockAnalyzer, MockPlanner
from redteam_agent.agent.workflow import PlanningOperationIds
from redteam_agent.errors import AgentLoopError, MissionRevisionConflictError
from redteam_agent.execution.models import AdapterCollectionControl
from redteam_agent.execution.thread import compute_thread_id
from redteam_agent.knowledge.models import AnalyzerCandidateObservation
from redteam_agent.plan.models import PlannerActionOutput
from redteam_agent.policy.scope_models import IpTargetReference
from redteam_agent.runtime.clock import ManualClock, ManualMonotonicClock


def _thread_id(mission_id: str, run_id: str) -> str:
    return compute_thread_id(mission_id=mission_id, mission_revision=1, run_id=run_id)


def test_phase1_uses_compiled_coarse_graphs_without_automatic_retry() -> None:
    kernel, *_ = _inputs()
    planning_nodes = set(kernel.workflow.graph.get_graph().nodes)
    analysis_nodes = set(kernel.workflow.analysis_graph.get_graph().nodes)
    assert {
        "session_refresh",
        "controller",
        "context_rebuild",
        "context_selector",
        "context_authorization",
        "context_builder",
        "tool_availability",
        "planner",
        "context_request",
        "action_application",
        "reconciliation",
        "finalization",
    } <= planning_nodes
    assert {
        "analysis_source_binding",
        "analyzer_context_selector",
        "analyzer_context_authorization",
        "analyzer_context_builder",
        "analyzer",
        "knowledge_reducer",
        "post_analysis_session_refresh",
        "goal_evaluation",
    } <= analysis_nodes
    assert kernel.workflow.graph.checkpointer is not None
    assert kernel.workflow.analysis_graph.checkpointer is not None
    assert all(node.retry_policy is None for node in kernel.workflow.graph.nodes.values())
    assert all(node.retry_policy is None for node in kernel.workflow.analysis_graph.nodes.values())


def test_stale_planner_context_is_rebuilt_before_the_model_call() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    stale = kernel.planner_context_service.build(
        planner_context_id="stale-workflow-context",
        mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    output = PlannerActionOutput(
        proposal=support.make_proposal(
            tool=seeded.seeded.tool,
            arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
            requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
        ),
        working_state_update=None,
        next_iteration_hints=(),
    )
    model_inputs = []
    kernel.phase0c.monotonic_clock.advance(seconds=121)
    kernel.phase0c.phase0b.phase0a.clock.set(kernel.phase0c.monotonic_clock.now())  # type: ignore[attr-defined]

    step = kernel.workflow.run_planning_iteration(
        envelope=stale,
        ids=PlanningOperationIds(
            operation_id="stale-workflow-plan",
            plan_id="stale-workflow-plan",
            run_id="stale-workflow-run",
            thread_id=_thread_id(mission_id, "stale-workflow-run"),
            decision_id="stale-workflow-decision",
            execution_id="stale-workflow-execution",
            task_id="stale-workflow-task",
        ),
        invoke_planner=lambda current: model_inputs.append(current) or output,
    )

    assert step.action_transition is not None
    assert len(model_inputs) == 1
    rebuilt = model_inputs[0]
    assert rebuilt.parent_context_id == stale.planner_context_id
    assert rebuilt.context_rebuild_count == 1
    assert rebuilt.planner_context_id != stale.planner_context_id
    retry_rows = kernel.phase0c.phase0b.phase0a.database.occ_get_all("agent_retry_budget")
    assert len(retry_rows) == 1

    checkpointer = kernel.workflow.graph.checkpointer
    assert checkpointer is not None
    checkpoint = checkpointer.get({
        "configurable": {
            "thread_id": _thread_id(mission_id, "stale-workflow-run"),
        }
    })
    assert checkpoint is not None
    values = checkpoint["channel_values"]
    assert set(values) <= {
        "mission_id",
        "mission_revision",
        "run_id",
        "operation_id",
        "planner_context_id",
        "goal_evaluation_id",
        "controller_action",
        "controller_reason",
        "planner_output_kind",
    }
    # Only application-issued record-identity / routing fields; the sole non-string
    # is the integer mission_revision (a repository record identity, not free text).
    assert all(
        isinstance(value, str) or (key == "mission_revision" and isinstance(value, int))
        for key, value in values.items()
    )


def test_workflow_rejects_malformed_wrong_revision_and_reused_run_threads() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="invalid-workflow-thread-context",
        mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    invoked = False

    def invoke(_current: object) -> object:
        nonlocal invoked
        invoked = True
        return {}

    invalid_threads = (
        "attacker-selected-noncanonical-thread",
        f"{mission_id}:2:bound-run",
        f"{mission_id}:1:another-run",
    )
    for index, invalid_thread in enumerate(invalid_threads):
        with pytest.raises(MissionRevisionConflictError):
            kernel.workflow.run_planning_iteration(
                envelope=envelope,
                ids=PlanningOperationIds(
                    operation_id=f"invalid-workflow-thread-{index}",
                    plan_id="invalid-workflow-plan",
                    run_id="bound-run",
                    thread_id=invalid_thread,
                    decision_id="invalid-workflow-decision",
                    execution_id="invalid-workflow-execution",
                    task_id="invalid-workflow-task",
                ),
                invoke_planner=invoke,
            )
        checkpointer = kernel.workflow.graph.checkpointer
        assert checkpointer is not None
        snapshot = checkpointer.get({
            "configurable": {"thread_id": invalid_thread}
        })
        assert snapshot is None
    assert not invoked


def test_graph_checkpoints_are_written_to_the_application_sqlite_file(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase1.sqlite3"
    phase0b = p0b.build_phase0b_kernel(
        db_path=str(database_path),
        clock=ManualClock(support.T0),
    )
    phase0c = p0c.build_phase0c_kernel(
        phase0b=phase0b,
        monotonic_clock=ManualMonotonicClock(support.T0),
    )
    kernel, seeded, goal, grant, projection = _inputs(phase0c=phase0c)
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="durable-checkpoint-context",
        mission_id=seeded.seeded.revision.mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    output = PlannerActionOutput(
        proposal=support.make_proposal(
            tool=seeded.seeded.tool,
            arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
            requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
        ),
        working_state_update=None,
        next_iteration_hints=(),
    )
    kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="durable-checkpoint-plan",
            plan_id="durable-checkpoint-plan",
            run_id="durable-checkpoint-run",
            thread_id=_thread_id(mission_id, "durable-checkpoint-run"),
            decision_id="durable-checkpoint-decision",
            execution_id="durable-checkpoint-execution",
            task_id="durable-checkpoint-task",
        ),
        invoke_planner=lambda _current: output,
    )

    with sqlite3.connect(database_path) as observer:
        tables = {
            row[0]
            for row in observer.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {"checkpoints", "writes"} <= tables
        assert observer.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0] > 0


def test_mock_agent_loop_reaches_goal_through_real_policy_and_executor() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="mock-loop-context", mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id, projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id, iteration=0,
    )
    output = PlannerActionOutput(
        proposal=support.make_proposal(
            tool=seeded.seeded.tool,
            arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
            requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
        ),
        working_state_update=None, next_iteration_hints=(),
    )
    planner = MockPlanner(output)
    step = kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="mock-loop-planner", plan_id="mock-loop-plan",
            run_id="mock-loop-run", thread_id=_thread_id(mission_id, "mock-loop-run"),
            decision_id="mock-loop-decision", execution_id="mock-loop-execution",
            task_id="mock-loop-task",
        ),
        invoke_planner=planner.invoke,
    )
    planned = step.planner_output
    assert isinstance(planned, PlannerActionOutput)
    replayed = kernel.llm_gateway.invoke_planner(
        operation_id="mock-loop-planner", envelope=envelope,
        invoke=lambda _envelope: (_ for _ in ()).throw(AssertionError("must not reinvoke")),
    )
    assert replayed == planned and planner.call_count == 1
    with pytest.raises(AgentLoopError):
        kernel.llm_gateway.invoke_planner(
            operation_id="budget-reset", envelope=envelope,
            invoke=planner.invoke,
        )
    transition = step.action_transition
    assert transition is not None
    assert transition.dispatch is not None and planner.call_count == 1

    adapter = kernel.phase0c.phase0b.mock_adapter
    adapter._reconcile_status = "FOUND_RUNNING"  # type: ignore[attr-defined]
    recovery = kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="mock-loop-recover", plan_id="unused-plan",
            run_id="unused-run", thread_id=_thread_id(mission_id, "unused-run"),
            decision_id="unused-decision", execution_id="unused-execution",
            task_id="unused-task",
        ),
        invoke_planner=lambda _envelope: (_ for _ in ()).throw(
            AssertionError("recovery must not invoke the Planner")
        ),
    )
    assert recovery.controller_decision.action == "RECOVER"
    assert adapter.reconcile_calls == 1

    collected = kernel.phase0c.collection_service.collect(
        execution_id="mock-loop-execution",
        stdout=b'{"host":"10.1.2.3","status":"open","port":443}', stderr=b"",
        control=AdapterCollectionControl(
            provider_status="succeeded", exit_code=0, timed_out=False,
            started_at=support.T0, finished_at=support.T0,
            status_normalization_rule_id="status-normalization-v1",
        ),
    )
    kernel.unresolved_items.open(
        unresolved_id="item-1",
        mission_id=mission_id,
        source_execution_id="mock-loop-execution",
        reason_code="INGESTION_COMPLETE",
    )
    with pytest.raises(AgentLoopError):
        kernel.unresolved_items.open(
            unresolved_id="item-1",
            mission_id="another-mission",
            source_execution_id="mock-loop-execution",
            reason_code="INGESTION_COMPLETE",
        )
    published = kernel.phase0c.ingestion_service.ingest(ingestion_id=collected.ingestion_id)
    assert published.deletion_intent_id is not None
    kernel.phase0c.eraser.run(deletion_intent_id=published.deletion_intent_id)
    result = kernel.phase0c.phase0b.result_repository.get("mock-loop-execution")
    assert result is not None and result.status == "SUCCEEDED"
    verified = kernel.workflow.project_verified_execution("mock-loop-execution")
    assert verified.verification_state == "confirmed"
    assert kernel.workflow.project_verified_execution("mock-loop-execution") == verified

    analyzer = MockAnalyzer(AnalyzerCandidateObservation(
        observation_id="mock-loop-observation", condition_id="c1",
        source_execution_id="mock-loop-execution", observation_type="finding",
        subject_ref="host-1", predicate="session_candidate", object_ref="sess-1",
        attributes={"status": "candidate"}, source_artifact_ids=result.redacted_artifact_ids,
        llm_confidence=1.0,
    ))
    analyzer_grant = (
        kernel.phase0c.phase0b.phase0a.context_authorization_service.issue_grant(
            grant_id="mock-loop-analyzer-grant",
            mission_id=mission_id,
            service_identity="analyzer_context",
            candidate_resource_ids=(),
            session_ids=(),
            ttl_seconds=120,
        )
    )
    result_digest = kernel.phase0c.phase0b.phase0a.digest_service.compute(
        "execution_outcome_source_digest", result.model_dump(mode="python")
    )
    with pytest.raises(MissionRevisionConflictError):
        kernel.workflow.run_analysis(
            mission_id=mission_id,
            mission_revision=envelope.mission_revision,
            operation_id="invalid-analyzer-thread",
            execution_id="mock-loop-execution",
            result_digest=result_digest,
            context_grant_id=analyzer_grant.grant_id,
            run_id="mock-loop-run",
            thread_id="attacker-selected-noncanonical-thread",
            invoke_analyzer=lambda: analyzer.invoke(execution_id="mock-loop-execution"),
        )
    assert analyzer.call_count == 0
    with pytest.raises(AgentLoopError):
        kernel.workflow.run_analysis(
            mission_id=mission_id,
            mission_revision=envelope.mission_revision,
            operation_id="mock-loop-analyzer",
            execution_id="mock-loop-execution",
            result_digest="forged-result-digest",
            context_grant_id=analyzer_grant.grant_id,
            run_id="mock-loop-run",
            thread_id=_thread_id(mission_id, "mock-loop-run"),
            invoke_analyzer=lambda: analyzer.invoke(execution_id="mock-loop-execution"),
        )
    assert analyzer.call_count == 0
    with pytest.raises(AgentLoopError):
        kernel.workflow.run_analysis(
            mission_id=mission_id,
            mission_revision=envelope.mission_revision,
            operation_id="mock-loop-analyzer",
            execution_id="mock-loop-execution",
            result_digest=result_digest,
            context_grant_id=grant.grant_id,
            run_id="mock-loop-run",
            thread_id=_thread_id(mission_id, "mock-loop-run"),
            invoke_analyzer=lambda: analyzer.invoke(execution_id="mock-loop-execution"),
        )
    assert analyzer.call_count == 0
    observation = kernel.workflow.run_analysis(
        mission_id=mission_id, mission_revision=envelope.mission_revision,
        operation_id="mock-loop-analyzer", execution_id="mock-loop-execution",
        result_digest=result_digest,
        context_grant_id=analyzer_grant.grant_id,
        run_id="mock-loop-run",
        thread_id=_thread_id(mission_id, "mock-loop-run"),
        invoke_analyzer=lambda: analyzer.invoke(execution_id="mock-loop-execution"),
    )
    assert observation.object_ref == "sess-1" and analyzer.call_count == 1
    kernel.phase0c.phase0b.phase0a.session_repository.save(support.session_snapshot())
    with pytest.raises(AgentLoopError):
        kernel.workflow.run_planning_iteration(
            envelope=envelope,
            ids=PlanningOperationIds(
                operation_id="mock-loop-enter-finalization", plan_id="unused-plan",
                run_id="unused-run", thread_id=_thread_id(mission_id, "unused-run"),
                decision_id="unused-decision", execution_id="unused-execution",
                task_id="unused-task",
            ),
            invoke_planner=lambda _envelope: (_ for _ in ()).throw(
                AssertionError("finalization must not invoke the Planner")
            ),
        )
    finalizing = kernel.phase0c.phase0b.phase0a.state_repository.get(mission_id)
    assert finalizing is not None and finalizing.state == "FINALIZING"
    assert kernel.goal_service.evaluate(mission_id=mission_id).status.status == "achieved"

    # Runtime state changes only through the trusted Session Manager repository,
    # never from the Analyzer candidate itself.
    final = kernel.controller.step(mission_id=mission_id, operation_id="mock-loop-final")
    assert final.action == "STOP" and final.reason_code == "MISSION_NOT_RUNNING"
    with pytest.raises(AgentLoopError):
        kernel.workflow.finalize(mission_id)
    kernel.unresolved_items.resolve_from_execution(unresolved_id="item-1")
    resolved = kernel.unresolved_items.current(mission_id)
    assert len(resolved) == 1
    assert resolved[0].source_execution_id == "mock-loop-execution"
    assert resolved[0].status == "RESOLVED"
    item_events = kernel.phase0c.phase0b.phase0a.database.occ_get_all(
        "unresolved_item_event"
    )
    assert len(item_events) == 2
    audit_events = kernel.phase0c.audit_store.events(mission_id)
    assert sum(event.event_type == "UNRESOLVED_ITEM_CHANGED" for event in audit_events) == 2
    completed_step = kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="mock-loop-finalize", plan_id="unused-plan",
            run_id="unused-run", thread_id=_thread_id(mission_id, "unused-run"),
            decision_id="unused-decision", execution_id="unused-execution",
            task_id="unused-task",
        ),
        invoke_planner=lambda _envelope: (_ for _ in ()).throw(
            AssertionError("finalization must not invoke the Planner")
        ),
    )
    assert completed_step.controller_decision.action == "STOP"
    completed = kernel.phase0c.phase0b.phase0a.state_repository.get(mission_id)
    assert completed is not None
    assert completed.state == "COMPLETED"
    outcomes = kernel.phase0c.phase0b.phase0a.database.connection.execute(
        "SELECT COUNT(*) FROM occ_store WHERE namespace = 'execution_budget_outcome'"
    ).fetchone()[0]
    assert outcomes == 1


def test_hard_limit_aborts_without_planner_or_goal_rewrite() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="hard-limit-context",
        mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    kernel.phase0c.monotonic_clock.advance(seconds=2 * 24 * 3600 + 1)
    step = kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="hard-limit", plan_id="unused-plan", run_id="unused-run",
            thread_id=_thread_id(mission_id, "unused-run"), decision_id="unused-decision",
            execution_id="unused-execution", task_id="unused-task",
        ),
        invoke_planner=lambda _envelope: (_ for _ in ()).throw(
            AssertionError("hard limit must not invoke the Planner")
        ),
    )
    assert step.controller_decision.reason_code == "HARD_LIMIT"
    state = kernel.phase0c.phase0b.phase0a.state_repository.get(mission_id)
    assert state is not None and state.state == "ABORTED"


def test_finalizing_resume_uses_bounded_reconciliation_and_cancel() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="finalizing-recovery-context",
        mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    planner = MockPlanner(PlannerActionOutput(
        proposal=support.make_proposal(
            tool=seeded.seeded.tool,
            arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
            requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
        ),
        working_state_update=None,
        next_iteration_hints=(),
    ))
    kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="finalizing-plan", plan_id="finalizing-plan", run_id="finalizing-run",
            thread_id=_thread_id(mission_id, "finalizing-run"), decision_id="finalizing-decision",
            execution_id="finalizing-execution", task_id="finalizing-task",
        ),
        invoke_planner=planner.invoke,
    )
    kernel.phase0c.phase0b.phase0a.session_repository.save(support.session_snapshot())
    kernel.finalization_service.begin_completion(mission_id)
    adapter = kernel.phase0c.phase0b.mock_adapter
    adapter._reconcile_status = "FOUND_RUNNING"  # type: ignore[attr-defined]
    adapter._cancel_result = "CONFIRMED"  # type: ignore[attr-defined]
    resumed = kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="finalizing-resume", plan_id="unused-plan", run_id="unused-run",
            thread_id=_thread_id(mission_id, "unused-run"), decision_id="unused-decision",
            execution_id="unused-execution", task_id="unused-task",
        ),
        invoke_planner=lambda _envelope: (_ for _ in ()).throw(
            AssertionError("FINALIZING recovery must not invoke the Planner")
        ),
    )
    assert resumed.controller_decision.action == "STOP"
    assert adapter.reconcile_calls == 1 and adapter.cancel_calls == 1
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    for attempt in (2, 3):
        kernel.workflow.run_planning_iteration(
            envelope=envelope,
            ids=PlanningOperationIds(
                operation_id=f"finalizing-resume-{attempt}", plan_id="unused-plan",
                run_id="unused-run", thread_id=_thread_id(mission_id, "unused-run"),
                decision_id="unused-decision", execution_id="unused-execution",
                task_id="unused-task",
            ),
            invoke_planner=lambda _envelope: (_ for _ in ()).throw(
                AssertionError("FINALIZING recovery must not invoke the Planner")
            ),
        )
    exhausted = kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="finalizing-resume-exhausted", plan_id="unused-plan",
            run_id="unused-run", thread_id=_thread_id(mission_id, "unused-run"),
            decision_id="unused-decision", execution_id="unused-execution",
            task_id="unused-task",
        ),
        invoke_planner=lambda _envelope: (_ for _ in ()).throw(
            AssertionError("FINALIZING recovery must not invoke the Planner")
        ),
    )
    assert exhausted.controller_decision.action == "STOP"
    assert adapter.reconcile_calls == 3 and adapter.cancel_calls == 1
    retry_rows = kernel.phase0c.phase0b.phase0a.database.occ_get_all("agent_retry_budget")
    assert len(retry_rows) == 1
    state = kernel.phase0c.phase0b.phase0a.state_repository.get(mission_id)
    assert state is not None and state.state == "WAITING_HUMAN_REVIEW"
    unresolved = kernel.unresolved_items.current(mission_id)
    assert len(unresolved) == 1
    assert unresolved[0].reason_code == "EXECUTION_RECONCILED"
    assert unresolved[0].status == "OPEN"


def test_running_recovery_budget_exhaustion_converges_to_human_review() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="running-recovery-context",
        mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    planner = MockPlanner(PlannerActionOutput(
        proposal=support.make_proposal(
            tool=seeded.seeded.tool,
            arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
            requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
        ),
        working_state_update=None,
        next_iteration_hints=(),
    ))
    kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="running-plan", plan_id="running-plan", run_id="running-run",
            thread_id=_thread_id(mission_id, "running-run"), decision_id="running-decision",
            execution_id="running-execution", task_id="running-task",
        ),
        invoke_planner=planner.invoke,
    )
    adapter = kernel.phase0c.phase0b.mock_adapter
    adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
    for attempt in range(4):
        kernel.workflow.run_planning_iteration(
            envelope=envelope,
            ids=PlanningOperationIds(
                operation_id=f"running-recovery-{attempt}", plan_id="unused-plan",
                run_id="unused-run", thread_id=_thread_id(mission_id, "unused-run"),
                decision_id="unused-decision", execution_id="unused-execution",
                task_id="unused-task",
            ),
            invoke_planner=lambda _envelope: (_ for _ in ()).throw(AssertionError("no Planner")),
        )
    state = kernel.phase0c.phase0b.phase0a.state_repository.get(mission_id)
    assert state is not None and state.state == "WAITING_HUMAN_REVIEW"
    unresolved = kernel.unresolved_items.current(mission_id)
    assert len(unresolved) == 1
    assert unresolved[0].source_execution_id == "running-execution"
    assert unresolved[0].reason_code == "EXECUTION_RECONCILED"
    assert adapter.reconcile_calls == 3


def test_finalizing_cancelled_execution_collects_ingests_and_completes() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="finalizing-cancel-context",
        mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    planner = MockPlanner(PlannerActionOutput(
        proposal=support.make_proposal(
            tool=seeded.seeded.tool,
            arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
            requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
        ),
        working_state_update=None,
        next_iteration_hints=(),
    ))
    kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="cancel-plan", plan_id="cancel-plan", run_id="cancel-run",
            thread_id=_thread_id(mission_id, "cancel-run"), decision_id="cancel-decision",
            execution_id="cancel-execution", task_id="cancel-task",
        ),
        invoke_planner=planner.invoke,
    )
    kernel.phase0c.phase0b.phase0a.session_repository.save(support.session_snapshot())
    kernel.finalization_service.begin_completion(mission_id)
    adapter = kernel.phase0c.phase0b.mock_adapter
    adapter._reconcile_status = "FOUND_RUNNING"  # type: ignore[attr-defined]
    adapter._cancel_result = "CONFIRMED"  # type: ignore[attr-defined]
    kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="cancel-start", plan_id="unused-plan", run_id="unused-run",
            thread_id=_thread_id(mission_id, "unused-run"), decision_id="unused-decision",
            execution_id="unused-execution", task_id="unused-task",
        ),
        invoke_planner=lambda _envelope: (_ for _ in ()).throw(AssertionError("no Planner")),
    )
    adapter._reconcile_status = "FOUND_TERMINAL"  # type: ignore[attr-defined]
    adapter._reconcile_provider_status = "cancelled"  # type: ignore[attr-defined]
    adapter._collect_status = "cancelled"  # type: ignore[attr-defined]
    adapter._collect_exit_code = None  # type: ignore[attr-defined]
    adapter._stdout_chunks = (  # type: ignore[attr-defined]
        b'{"host":"10.1.2.3","status":"cancelled","port":443}',
    )
    kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="cancel-finish", plan_id="unused-plan", run_id="unused-run",
            thread_id=_thread_id(mission_id, "unused-run"), decision_id="unused-decision",
            execution_id="unused-execution", task_id="unused-task",
        ),
        invoke_planner=lambda _envelope: (_ for _ in ()).throw(AssertionError("no Planner")),
    )
    state = kernel.phase0c.phase0b.phase0a.state_repository.get(mission_id)
    assert state is not None and state.state == "COMPLETED"
    result = kernel.phase0c.phase0b.result_repository.get("cancel-execution")
    assert result is not None and result.status == "CANCELLED"
