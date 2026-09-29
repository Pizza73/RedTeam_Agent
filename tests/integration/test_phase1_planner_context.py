"""Phase 1 Planner input is finite and bound to current trusted sources."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.agent.models import ActionCandidateSeed
from redteam_agent.composition.phase1 import build_phase1_kernel
from redteam_agent.errors import (
    GoalEvaluationConflictError,
    MissionRevisionConflictError,
    PlannerCandidateError,
    PlannerContextError,
)
from redteam_agent.execution.thread import compute_thread_id
from redteam_agent.plan.models import PlannerActionOutput, PlannerContextRequest, RetrievalHint
from redteam_agent.policy.scope_models import IpTargetReference


def _inputs(*, phase0c=None):
    kernel = build_phase1_kernel(
        phase0c=p0c.make_phase0c() if phase0c is None else phase0c
    )
    seeded = p0b.seed_authorized(kernel.phase0c.phase0b)
    mission_id = seeded.seeded.revision.mission_id
    head = kernel.knowledge_service.initialize_mission(
        mission_id=mission_id,
        mission_revision=seeded.seeded.revision.mission_revision,
        recorded_at=support.T0,
    )
    goal = kernel.goal_service.evaluate(mission_id=mission_id)
    grant = kernel.phase0c.phase0b.phase0a.context_authorization_service.issue_grant(
        grant_id="planner-grant-1", mission_id=mission_id,
        service_identity="planner_context", candidate_resource_ids=(), session_ids=(),
        ttl_seconds=120,
    )
    seed = ActionCandidateSeed(
        tool_ref=seeded.seeded.tool.tool_ref,
        canonical_target_binding=(IpTargetReference(type="ip", address="10.1.2.3"),),
        satisfied_precondition_refs=(), objective_dependency_ids=("mission-objective-0",),
    )
    projection = kernel.candidate_projector.build(
        snapshot_id=seeded.seeded.snapshot.snapshot_id, seeds=(seed,),
        source_version_digests=(goal.evaluation_digest, head.head_digest),
    )
    return kernel, seeded, goal, grant, projection


def test_planner_context_and_action_are_exactly_bound_to_current_candidate() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    envelope = kernel.planner_context_service.build(
        planner_context_id="planner-context-1",
        mission_id=seeded.seeded.revision.mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
        operational_phase="DISCOVERY",
    )
    assert kernel.planner_context_service.revalidate(envelope.planner_context_id) == envelope

    proposal = support.make_proposal(
        tool=seeded.seeded.tool,
        arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
        requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
    )
    output = PlannerActionOutput(
        proposal=proposal, working_state_update=None, next_iteration_hints=(),
    )
    transition = kernel.action_service.execute(
        planner_context_id=envelope.planner_context_id, output=output,
        plan_id="phase1-plan-1", run_id="phase1-run-1",
        thread_id=compute_thread_id(
            mission_id=envelope.mission_id,
            mission_revision=envelope.mission_revision,
            run_id="phase1-run-1",
        ),
        decision_id="phase1-decision-1", execution_id="phase1-execution-1",
        task_id="phase1-task-1",
    )
    assert transition.decision.decision == "ALLOW"
    assert transition.plan.action_contract_ref == projection.candidates[0].action_contract_ref
    assert transition.dispatch is not None
    assert kernel.phase0c.phase0b.mock_adapter.submit_calls == 1
    with pytest.raises(PlannerContextError):
        kernel.action_service.execute(
            planner_context_id=envelope.planner_context_id, output=output,
            plan_id="phase1-plan-replay", run_id="phase1-run-replay",
            thread_id=compute_thread_id(
                mission_id=envelope.mission_id,
                mission_revision=envelope.mission_revision,
                run_id="phase1-run-replay",
            ),
            decision_id="phase1-decision-replay",
            execution_id="phase1-execution-replay", task_id="phase1-task-replay",
        )
    assert kernel.phase0c.phase0b.mock_adapter.submit_calls == 1


def test_planner_action_cannot_select_another_target() -> None:
    kernel, seeded, _goal, _grant, projection = _inputs()
    proposal = support.make_proposal(
        tool=seeded.seeded.tool,
        arguments={"destinations": ["10.9.9.9"], "port": 443, "protocol": "tcp"},
        requested_targets=(IpTargetReference(type="ip", address="10.9.9.9"),),
    )
    output = PlannerActionOutput(
        proposal=proposal, working_state_update=None, next_iteration_hints=(),
    )
    with pytest.raises(PlannerCandidateError):
        kernel.candidate_projector.match_action(output=output, projection=projection)


def test_action_rejects_noncanonical_thread_before_consuming_context() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="planner-context-thread-binding",
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
    with pytest.raises(MissionRevisionConflictError):
        kernel.action_service.execute(
            planner_context_id=envelope.planner_context_id,
            output=output,
            plan_id="invalid-thread-plan",
            run_id="bound-run",
            thread_id="attacker-selected-noncanonical-thread",
            decision_id="invalid-thread-decision",
            execution_id="invalid-thread-execution",
            task_id="invalid-thread-task",
        )
    assert kernel.phase0c.phase0b.mock_adapter.submit_calls == 0

    transition = kernel.action_service.execute(
        planner_context_id=envelope.planner_context_id,
        output=output,
        plan_id="valid-thread-plan",
        run_id="bound-run",
        thread_id=compute_thread_id(
            mission_id=mission_id,
            mission_revision=envelope.mission_revision,
            run_id="bound-run",
        ),
        decision_id="valid-thread-decision",
        execution_id="valid-thread-execution",
        task_id="valid-thread-task",
    )
    assert transition.dispatch is not None


def test_scope_false_action_never_reaches_mock_adapter() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    envelope = kernel.planner_context_service.build(
        planner_context_id="planner-context-denied",
        mission_id=seeded.seeded.revision.mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    proposal = support.make_proposal(
        tool=seeded.seeded.tool,
        arguments={"destinations": ["192.168.1.1"], "port": 443, "protocol": "tcp"},
        requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
    )
    output = PlannerActionOutput(
        proposal=proposal, working_state_update=None, next_iteration_hints=(),
    )
    transition = kernel.action_service.execute(
        planner_context_id=envelope.planner_context_id, output=output,
        plan_id="phase1-plan-denied", run_id="phase1-run-denied",
        thread_id=compute_thread_id(
            mission_id=envelope.mission_id,
            mission_revision=envelope.mission_revision,
            run_id="phase1-run-denied",
        ),
        decision_id="phase1-decision-denied",
        execution_id="phase1-execution-denied", task_id="phase1-task-denied",
    )
    assert transition.decision.decision == "DENY"
    assert transition.dispatch is None
    assert kernel.phase0c.phase0b.mock_adapter.submit_calls == 0


def test_epoch_change_invalidates_planner_context_before_model_use() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    envelope = kernel.planner_context_service.build(
        planner_context_id="planner-context-epoch",
        mission_id=seeded.seeded.revision.mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    kernel.phase0c.phase0b.phase0a.mission_manager.invalidate_authorization(
        support.MISSION_ID, expected_version=2, actor_token=support.OPERATOR_ACTOR_TOKEN
    )
    with pytest.raises(GoalEvaluationConflictError):
        kernel.planner_context_service.revalidate(envelope.planner_context_id)
    invoked = False

    def invoke(_envelope: object) -> object:
        nonlocal invoked
        invoked = True
        return {}

    with pytest.raises(GoalEvaluationConflictError):
        kernel.llm_gateway.invoke_planner(
            operation_id="stale-planner", envelope=envelope, invoke=invoke
        )
    assert not invoked


def test_context_request_is_bounded_by_lineage_and_durable_retry_budget() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    values = {
        "mission_id": seeded.seeded.revision.mission_id,
        "goal_evaluation_id": goal.evaluation_id,
        "projection": projection,
        "context_grant_id": grant.grant_id,
        "available_tool_snapshot_id": seeded.seeded.snapshot.snapshot_id,
        "iteration": 0,
    }
    first = kernel.planner_context_service.build(planner_context_id="ctx-0", **values)
    request = PlannerContextRequest(
        objective="get current evidence",
        retrieval_hints=(RetrievalHint(
            resource_types=("artifact",), related_entity_refs=("host-1",),
            requested_fact_types=("service",), recency_class="current",
            purpose_code="verify_hypothesis",
        ),),
        working_state_update=None,
    )
    db = kernel.phase0c.phase0b.phase0a.database.connection
    before_executions = db.execute("SELECT COUNT(*) FROM executions").fetchone()[0]
    before_decisions = db.execute(
        "SELECT COUNT(*) FROM kv_store WHERE namespace = 'policy_decisions'"
    ).fetchone()[0]
    kernel.planner_context_service.accept_context_request(
        planner_context_id=first.planner_context_id, output=request
    )
    assert db.execute("SELECT COUNT(*) FROM executions").fetchone()[0] == before_executions
    assert db.execute(
        "SELECT COUNT(*) FROM kv_store WHERE namespace = 'policy_decisions'"
    ).fetchone()[0] == before_decisions
    with pytest.raises(PlannerContextError):
        kernel.planner_context_service.accept_context_request(
            planner_context_id=first.planner_context_id, output=request
        )
    second = kernel.planner_context_service.build(
        planner_context_id="ctx-1", parent_context_id=first.planner_context_id, **values
    )
    with pytest.raises(PlannerContextError):
        kernel.planner_context_service.build(
            planner_context_id="ctx-sibling", parent_context_id=first.planner_context_id,
            **values,
        )
    kernel.planner_context_service.accept_context_request(
        planner_context_id=second.planner_context_id, output=request
    )
    budget_rows = db.execute(
        "SELECT COUNT(*) FROM occ_store WHERE namespace = 'agent_retry_budget'"
    ).fetchone()[0]
    assert budget_rows == 1
    third = kernel.planner_context_service.build(
        planner_context_id="ctx-2", parent_context_id=second.planner_context_id, **values
    )
    with pytest.raises(PlannerContextError):
        kernel.planner_context_service.accept_context_request(
            planner_context_id=third.planner_context_id, output=request
        )


def test_automatic_stale_rebuild_shares_the_lineage_retry_budget() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    first = kernel.planner_context_service.build(
        planner_context_id="stale-budget-context",
        mission_id=seeded.seeded.revision.mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )

    def advance() -> None:
        kernel.phase0c.monotonic_clock.advance(seconds=121)
        kernel.phase0c.phase0b.phase0a.clock.set(  # type: ignore[attr-defined]
            kernel.phase0c.monotonic_clock.now()
        )

    advance()
    second = kernel.planner_context_service.rebuild_stale(first.planner_context_id)
    advance()
    third = kernel.planner_context_service.rebuild_stale(second.planner_context_id)
    advance()
    with pytest.raises(PlannerContextError, match="context rebuild limit reached"):
        kernel.planner_context_service.rebuild_stale(third.planner_context_id)

    rows = kernel.phase0c.phase0b.phase0a.database.occ_get_all("agent_retry_budget")
    assert len(rows) == 1
    assert json.loads(rows[0][2])["consumed_attempts"] == 2


def test_old_revision_rebuild_is_rejected_before_retry_budget_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    envelope = kernel.planner_context_service.build(
        planner_context_id="old-revision-rebuild-context",
        mission_id=seeded.seeded.revision.mission_id,
        goal_evaluation_id=goal.evaluation_id,
        projection=projection,
        context_grant_id=grant.grant_id,
        available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    monkeypatch.setattr(
        kernel.planner_context_service._resolver,  # type: ignore[attr-defined]
        "resolve",
        lambda _mission_id, *, now: SimpleNamespace(
            mission=SimpleNamespace(mission_revision=envelope.mission_revision + 1)
        ),
    )

    database = kernel.phase0c.phase0b.phase0a.database
    before = database.occ_get_all("agent_retry_budget")
    with pytest.raises(MissionRevisionConflictError, match="cannot cross"):
        kernel.planner_context_service.rebuild_stale(envelope.planner_context_id)
    assert database.occ_get_all("agent_retry_budget") == before
