import pytest
from test_phase1_planner_context import _inputs

from redteam_agent.errors import AgentLoopError


def test_invalid_proposal_counts_as_planner_call_and_replay_does_not_charge_twice() -> None:
    kernel, seeded, goal, grant, projection = _inputs()
    mission_id = seeded.seeded.revision.mission_id
    envelope = kernel.planner_context_service.build(
        planner_context_id="budget-context", mission_id=mission_id,
        goal_evaluation_id=goal.evaluation_id, projection=projection,
        context_grant_id=grant.grant_id, available_tool_snapshot_id=seeded.seeded.snapshot.snapshot_id,
        iteration=0,
    )
    # Invalid outputs also consume one logical invocation and bounded attempts.
    calls = []

    def invalid(_envelope):
        calls.append(1)
        return {}

    with pytest.raises(AgentLoopError, match="output retry budget exhausted"):
        kernel.llm_gateway.invoke_planner(operation_id="budget-plan", envelope=envelope, invoke=invalid)
    budget = kernel.phase0c.phase0b.budget_service.get(mission_id, 1)
    assert budget.consumed_planner_invocations == 1
    assert budget.consumed_dispatch_claims == 0
    with pytest.raises(AgentLoopError):
        kernel.llm_gateway.invoke_planner(operation_id="budget-plan", envelope=envelope, invoke=invalid)
    assert len(calls) == 4
    assert kernel.phase0c.phase0b.budget_service.get(mission_id, 1).consumed_planner_invocations == 1
