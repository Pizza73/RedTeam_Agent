"""Phase 1 Planner input is finite and bound to current trusted sources."""

from __future__ import annotations

import pytest

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.agent.models import ActionCandidateSeed
from redteam_agent.composition.phase1 import build_phase1_kernel
from redteam_agent.errors import (
    GoalEvaluationConflictError,
    PlannerCandidateError,
    PlannerContextError,
)
from redteam_agent.plan.models import PlannerActionOutput, PlannerContextRequest, RetrievalHint
from redteam_agent.policy.scope_models import IpTargetReference


def _inputs():
    kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
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
        authorized_context={"verified_facts": [], "observations": [], "hypotheses": []},
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
    matched = kernel.planner_context_service.accept_action(
        planner_context_id=envelope.planner_context_id, output=output
    )
    assert matched.candidate_id == projection.candidates[0].candidate_id


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
        authorized_context={},
    )
    kernel.phase0c.phase0b.phase0a.mission_manager.invalidate_authorization(
        support.MISSION_ID, expected_version=2, actor_token=support.OPERATOR_ACTOR_TOKEN
    )
    with pytest.raises(GoalEvaluationConflictError):
        kernel.planner_context_service.revalidate(envelope.planner_context_id)


def test_context_request_is_bounded_by_envelope_lineage_without_new_counter_state() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    values = {
        "mission_id": seeded.seeded.revision.mission_id,
        "goal_evaluation_id": goal.evaluation_id,
        "projection": projection,
        "context_grant_id": grant.grant_id,
        "available_tool_snapshot_id": seeded.seeded.snapshot.snapshot_id,
        "iteration": 0,
        "authorized_context": {},
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
    second = kernel.planner_context_service.build(
        planner_context_id="ctx-1", parent_context_id=first.planner_context_id, **values
    )
    third = kernel.planner_context_service.build(
        planner_context_id="ctx-2", parent_context_id=second.planner_context_id, **values
    )
    with pytest.raises(PlannerContextError):
        kernel.planner_context_service.accept_context_request(
            planner_context_id=third.planner_context_id, output=request
        )
