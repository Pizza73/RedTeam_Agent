"""Phase 1 Mock Planner -> gates -> Executor -> Analyzer -> Goal integration."""

from __future__ import annotations

import pytest
from test_phase1_planner_context import _inputs

import support
from redteam_agent.agent.mock_agents import MockAnalyzer, MockPlanner
from redteam_agent.agent.workflow import PlanningOperationIds
from redteam_agent.errors import AgentLoopError
from redteam_agent.execution.models import AdapterCollectionControl
from redteam_agent.knowledge.models import AnalyzerCandidateObservation
from redteam_agent.plan.models import PlannerActionOutput
from redteam_agent.policy.scope_models import IpTargetReference


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
            run_id="mock-loop-run", thread_id="mock-loop-thread",
            decision_id="mock-loop-decision", execution_id="mock-loop-execution",
            task_id="mock-loop-task",
        ),
        invoke_planner=lambda: planner.invoke(envelope),
    )
    planned = step.planner_output
    assert isinstance(planned, PlannerActionOutput)
    replayed = kernel.llm_gateway.invoke_planner(
        operation_id="mock-loop-planner", envelope=envelope,
        invoke=lambda: (_ for _ in ()).throw(AssertionError("must not reinvoke")),
    )
    assert replayed == planned and planner.call_count == 1
    with pytest.raises(AgentLoopError):
        kernel.llm_gateway.invoke_planner(
            operation_id="budget-reset", envelope=envelope,
            invoke=lambda: planner.invoke(envelope),
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
            run_id="unused-run", thread_id="unused-thread",
            decision_id="unused-decision", execution_id="unused-execution",
            task_id="unused-task",
        ),
        invoke_planner=lambda: (_ for _ in ()).throw(
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
    kernel.phase0c.phase0b.phase0a.session_repository.save(support.session_snapshot())
    with pytest.raises(AgentLoopError):
        kernel.workflow.run_planning_iteration(
            envelope=envelope,
            ids=PlanningOperationIds(
                operation_id="mock-loop-enter-finalization", plan_id="unused-plan",
                run_id="unused-run", thread_id="unused-thread",
                decision_id="unused-decision", execution_id="unused-execution",
                task_id="unused-task",
            ),
            invoke_planner=lambda: (_ for _ in ()).throw(
                AssertionError("finalization must not invoke the Planner")
            ),
        )
    finalizing = kernel.phase0c.phase0b.phase0a.state_repository.get(mission_id)
    assert finalizing is not None and finalizing.state == "FINALIZING"
    published = kernel.phase0c.ingestion_service.ingest(ingestion_id=collected.ingestion_id)
    assert published.deletion_intent_id is not None
    with pytest.raises(AgentLoopError):
        kernel.finalization_service.finalize(mission_id)
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
    observation = kernel.workflow.run_analysis(
        mission_id=mission_id, mission_revision=envelope.mission_revision,
        operation_id="mock-loop-analyzer", execution_id="mock-loop-execution",
        result_digest=kernel.phase0c.phase0b.phase0a.digest_service.compute(
            "execution_outcome_source_digest", result.model_dump(mode="python")
        ),
        invoke_analyzer=lambda: analyzer.invoke(execution_id="mock-loop-execution"),
    )
    assert observation.object_ref == "sess-1" and analyzer.call_count == 1
    assert kernel.goal_service.evaluate(mission_id=mission_id).status.status == "achieved"

    # Runtime state changes only through the trusted Session Manager repository,
    # never from the Analyzer candidate itself.
    final = kernel.controller.step(mission_id=mission_id, operation_id="mock-loop-final")
    assert final.action == "STOP" and final.reason_code == "MISSION_NOT_RUNNING"
    kernel.unresolved_items.open(
        unresolved_id="item-1", mission_id=mission_id,
        reason_code="INGESTION_COMPLETE", evidence_digest="pending-evidence",
    )
    with pytest.raises(AgentLoopError):
        kernel.unresolved_items.open(
            unresolved_id="item-1", mission_id="another-mission",
            reason_code="INGESTION_COMPLETE", evidence_digest="replacement-evidence",
        )
    with pytest.raises(AgentLoopError):
        kernel.workflow.finalize(mission_id)
    kernel.unresolved_items.resolve_from_execution(
        unresolved_id="item-1", execution_id="mock-loop-execution"
    )
    completed_step = kernel.workflow.run_planning_iteration(
        envelope=envelope,
        ids=PlanningOperationIds(
            operation_id="mock-loop-finalize", plan_id="unused-plan",
            run_id="unused-run", thread_id="unused-thread",
            decision_id="unused-decision", execution_id="unused-execution",
            task_id="unused-task",
        ),
        invoke_planner=lambda: (_ for _ in ()).throw(
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
