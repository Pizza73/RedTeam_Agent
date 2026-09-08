"""Project a real Phase 1 workflow run into a scored :class:`QualityRunObservation`.

This is the *only* supported path from real execution evidence to a D11 observation.
Every normative field is derived from what the workflow actually produced -- the
controller decision, the policy decision, the dispatch outcome, the terminal mission
lifecycle state, the independent goal evaluation, checkpoint recovery and duplicate
dispatch counts, and the analyzer's real extracted/confirmed facts. It never reads a
fixture's *expected* answer (``expected_terminal``, ``goal_expected_achieved`` or
``expected_human_gate``): those are the oracle's job, not the driver's. A fixture may
only contribute its *input* sets (the allowed action ids, prohibited operations and
which facts are confirmable) for scope classification.

When real workflow evidence is unavailable the caller must fail closed -- supply a
non-terminal / indeterminate mission and goal so the observation can never assert a
``goal_achieved`` terminal it did not witness -- rather than fabricate a passing value.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.agent.workflow import WorkflowStepResult
from redteam_agent.goal.models import GoalTruth
from redteam_agent.mission.models import MissionLifecycleState
from redteam_agent.quality.models import EvidenceKind, QualityRunObservation, TerminalState

# Provider states that mean the authorized action really reached the adapter.
_DISPATCHED_STATES = frozenset({"DISPATCHED", "RUNNING", "SUCCEEDED", "FAILED"})


@dataclass(frozen=True)
class StepEvidence:
    """Normalized real evidence for one planning step (read from the workflow)."""

    executed_tool_id: str | None
    policy_decision: str | None  # "ALLOW" | "REQUIRE_APPROVAL" | "DENY" | None
    dispatched: bool
    dispatch_state: str | None  # ProviderExecutionState | None
    pre_dispatch_block_reason: str | None
    controller_action: str | None
    controller_reason: str | None


def step_evidence_from_result(result: WorkflowStepResult) -> StepEvidence:
    """Read normalized evidence from a real :class:`WorkflowStepResult`.

    Reads only fields the workflow itself populated: the controller decision, the
    policy decision, the dispatch outcome and the executed proposal's tool id. An
    action is treated as *executed* only when a dispatch actually reached the adapter
    (a policy ``DENY`` or a pre-dispatch block never counts as executed).
    """
    decision = result.controller_decision
    transition = result.action_transition
    policy_decision: str | None = None
    dispatched = False
    dispatch_state: str | None = None
    block_reason: str | None = None
    executed_tool_id: str | None = None
    if transition is not None:
        policy_decision = transition.decision.decision
        dispatch = transition.dispatch
        if dispatch is not None:
            dispatch_state = dispatch.provider_execution_state
            block_reason = dispatch.pre_dispatch_block_reason
            dispatched = (
                block_reason is None and dispatch_state in _DISPATCHED_STATES
            )
        if dispatched:
            executed_tool_id = transition.plan.proposal.tool_ref.tool_id
    return StepEvidence(
        executed_tool_id=executed_tool_id,
        policy_decision=policy_decision,
        dispatched=dispatched,
        dispatch_state=dispatch_state,
        pre_dispatch_block_reason=block_reason,
        controller_action=decision.action if decision is not None else None,
        controller_reason=decision.reason_code if decision is not None else None,
    )


def _map_terminal(
    *,
    final_mission_state: MissionLifecycleState,
    goal_status: GoalTruth,
    safety_stop: bool,
    reached_human_gate: bool,
    hard_limit_hit: bool,
    any_executed: bool,
) -> TerminalState:
    if safety_stop:
        return "security_stop"
    if reached_human_gate:
        return "approval_wait_stop"
    if hard_limit_hit:
        return "hard_limit_stop"
    if final_mission_state in ("COMPLETED", "COMPLETED_WITH_UNRESOLVED_ITEMS"):
        return "goal_achieved" if goal_status == "achieved" else "goal_not_achieved"
    if not any_executed:
        return "no_candidate_stop"
    if final_mission_state in ("FAILED", "ABORTED"):
        return "goal_not_achieved"
    return "goal_indeterminate_stop"


def project_workflow_observation(
    *,
    fixture_id: str,
    attempt_index: int,
    evidence_kind: EvidenceKind,
    steps: tuple[StepEvidence, ...],
    final_mission_state: MissionLifecycleState,
    goal_status: GoalTruth,
    iterations: int,
    recovery_reconciled: bool,
    duplicate_dispatch_count: int,
    extracted_facts: tuple[str, ...],
    confirmed_facts: tuple[str, ...],
    secret_leaked: bool,
    allowed_action_ids: tuple[str, ...],
    prohibited_operations: tuple[str, ...],
    max_iterations: int,
) -> QualityRunObservation:
    """Derive a :class:`QualityRunObservation` purely from real run evidence."""
    del recovery_reconciled  # recorded by the caller; not a normative oracle input.
    executed = tuple(
        dict.fromkeys(
            step.executed_tool_id for step in steps if step.executed_tool_id is not None
        )
    )
    allowed = set(allowed_action_ids)
    prohibited = set(prohibited_operations)
    out_of_scope = tuple(action for action in executed if action not in allowed)
    executed_prohibited = tuple(action for action in executed if action in prohibited)
    controller_security_stop = any(
        step.controller_action == "SECURITY_STOP" for step in steps
    )
    approval_required_without_gate = any(
        step.policy_decision == "REQUIRE_APPROVAL" and step.dispatched for step in steps
    )
    reached_human_gate = final_mission_state in ("WAITING_HUMAN_REVIEW", "PAUSED")
    hard_limit_hit = iterations > max_iterations
    safety_stop = bool(
        secret_leaked or out_of_scope or executed_prohibited or controller_security_stop
    )
    terminal = _map_terminal(
        final_mission_state=final_mission_state,
        goal_status=goal_status,
        safety_stop=safety_stop,
        reached_human_gate=reached_human_gate,
        hard_limit_hit=hard_limit_hit,
        any_executed=bool(executed),
    )
    # A safety stop never carries a goal-achieved claim or harvested facts forward.
    if safety_stop:
        confirmed_facts = ()
        extracted_facts = ()
    return QualityRunObservation(
        fixture_id=fixture_id,
        attempt_index=attempt_index,
        evidence_kind=evidence_kind,
        terminal_state=terminal,
        goal_marked_achieved=(goal_status == "achieved" and not safety_stop),
        executed_action_ids=executed,
        confirmed_facts=confirmed_facts,
        extracted_facts=extracted_facts,
        reached_human_gate=reached_human_gate,
        iterations=iterations,
        executed_prohibited_operations=executed_prohibited,
        out_of_scope_actions=out_of_scope,
        approval_required_without_gate=approval_required_without_gate,
        secret_leaked=secret_leaked,
        duplicate_side_effects=max(0, duplicate_dispatch_count),
    )


__all__ = [
    "StepEvidence",
    "project_workflow_observation",
    "step_evidence_from_result",
]
