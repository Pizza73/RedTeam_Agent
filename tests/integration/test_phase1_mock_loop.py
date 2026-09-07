"""Phase 1 Mock Planner -> gates -> Executor -> Analyzer -> Goal integration."""

from __future__ import annotations

import pytest
from test_phase1_planner_context import _inputs

import support
from redteam_agent.agent.mock_agents import MockAnalyzer, MockPlanner
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
    planned = kernel.llm_gateway.invoke_planner(
        operation_id="mock-loop-planner", envelope=envelope,
        invoke=lambda: planner.invoke(envelope),
    )
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
    transition = kernel.action_service.execute(
        planner_context_id=envelope.planner_context_id, output=planned,
        plan_id="mock-loop-plan", run_id="mock-loop-run", thread_id="mock-loop-thread",
        decision_id="mock-loop-decision", execution_id="mock-loop-execution",
        task_id="mock-loop-task",
    )
    assert transition.dispatch is not None and planner.call_count == 1

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
        kernel.finalization_service.finalize(mission_id)
    published = kernel.phase0c.ingestion_service.ingest(ingestion_id=collected.ingestion_id)
    assert published.deletion_intent_id is not None
    with pytest.raises(AgentLoopError):
        kernel.finalization_service.finalize(mission_id)
    kernel.phase0c.eraser.run(deletion_intent_id=published.deletion_intent_id)
    result = kernel.phase0c.phase0b.result_repository.get("mock-loop-execution")
    assert result is not None and result.status == "SUCCEEDED"

    analyzer = MockAnalyzer(AnalyzerCandidateObservation(
        observation_id="mock-loop-observation", condition_id="c1",
        source_execution_id="mock-loop-execution", observation_type="finding",
        subject_ref="host-1", predicate="session_candidate", object_ref="sess-1",
        attributes={"status": "candidate"}, source_artifact_ids=result.redacted_artifact_ids,
        llm_confidence=1.0,
    ))
    analyzed = kernel.llm_gateway.invoke_analyzer(
        mission_id=mission_id, mission_revision=envelope.mission_revision,
        operation_id="mock-loop-analyzer", execution_id="mock-loop-execution",
        result_digest=kernel.phase0c.phase0b.phase0a.digest_service.compute(
            "execution_outcome_source_digest", result.model_dump(mode="python")
        ),
        invoke=lambda: analyzer.invoke(execution_id="mock-loop-execution"),
    )
    observation = kernel.knowledge_reducer.reduce(analyzed)
    assert observation.object_ref == "sess-1" and analyzer.call_count == 1
    assert kernel.goal_service.evaluate(mission_id=mission_id).status.status == "achieved"

    # Runtime state changes only through the trusted Session Manager repository,
    # never from the Analyzer candidate itself.
    final = kernel.controller.step(mission_id=mission_id, operation_id="mock-loop-final")
    assert final.action == "FINALIZE" and final.reason_code == "GOAL_ACHIEVED"
    completed = kernel.finalization_service.finalize(mission_id)
    assert completed.state == "COMPLETED"
    outcomes = kernel.phase0c.phase0b.phase0a.database.connection.execute(
        "SELECT COUNT(*) FROM occ_store WHERE namespace = 'execution_budget_outcome'"
    ).fetchone()[0]
    assert outcomes == 1
