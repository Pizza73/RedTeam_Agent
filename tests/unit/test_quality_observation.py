"""Focused tests: real workflow evidence -> quality observation projection.

These prove the D11 harness cannot let a fixture's *expected* answer populate an
*actual* observation, and that policy-deny / tool-failure evidence is read from a real
:class:`WorkflowStepResult` rather than invented.
"""

from __future__ import annotations

from datetime import UTC, datetime

from redteam_agent.agent.application import ActionTransitionResult
from redteam_agent.agent.models import ControllerDecision
from redteam_agent.agent.workflow import WorkflowStepResult
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.execution.executor import DispatchOutcome
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.plan.models import ExecutionPlan, ExecutionPlanProposal
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.quality.environment import (
    ActionPolicyInput,
    AdapterScriptInput,
    AnalyzerObservationInput,
    DeliveryInput,
    GoalConditionInput,
    MissionGoalInput,
    PolicyBehaviorInput,
    QualityEnvironmentSpec,
    SafeToolInput,
)
from redteam_agent.quality.local_llm_driver import LocalLLMQualityDriver
from redteam_agent.quality.models import QualityFixture
from redteam_agent.quality.observation import (
    project_workflow_observation,
    step_evidence_from_result,
)

_NOW = datetime(2025, 1, 1, tzinfo=UTC)


# --- real WorkflowStepResult builders (only real APIs / real fields) ---------


def _tool_ref(tool_id: str) -> ToolRef:
    return ToolRef(tool_id=tool_id, registry_revision=1)


def _plan(tool_id: str) -> ExecutionPlan:
    proposal = ExecutionPlanProposal(
        objective="o",
        phase="DISCOVERY",
        tool_ref=_tool_ref(tool_id),
        requested_targets=(),
        session_id=None,
        arguments={},
    )
    return ExecutionPlan(
        plan_id="plan-1",
        mission_id="m-1",
        mission_revision=1,
        observed_mission_state_version=0,
        observed_authorization_epoch=0,
        run_id="run-1",
        thread_id="thread-1",
        proposal=proposal,
        proposal_digest="d",
        goal_evaluation_id="g",
        goal_evaluation_digest="d",
        action_contract_ref=ActionContractReference(contract_id="c", revision="r", digest="d"),
        execution_precondition_digest="d",
        available_tool_snapshot_id="s",
        available_tool_snapshot_digest="d",
        session_security_context_digest="d",
        adapter_capabilities_digest="d",
        sandbox_capabilities_digest="d",
        remote_mcp_trust_policy_digest="d",
        created_at=_NOW,
    )


def _policy_decision(decision: str, tool_id: str) -> PolicyDecision:
    return PolicyDecision(
        decision_id="dec-1",
        decision_digest="d",
        mission_id="m-1",
        mission_revision=1,
        authorization_epoch=0,
        plan_id="plan-1",
        tool_ref=_tool_ref(tool_id),
        proposal_digest="d",
        authorization_digest="d",
        policy_version="v1",
        registry_digest="d",
        available_tool_snapshot_id="s",
        available_tool_snapshot_digest="d",
        resolved_adapter="local",
        resolved_adapter_id="a",
        decision=decision,  # type: ignore[arg-type]
        normalized_targets=(),
        target_dispatch_bindings=(),
        authorized_data_access=(),
        effective_risk="low",
        reason_codes=(),
        issued_at=_NOW,
        expires_at=_NOW,
    )


def _dispatch(state: str, *, blocked: str | None = None) -> DispatchOutcome:
    return DispatchOutcome(
        execution_id="exec-1",
        provider_execution_state=state,  # type: ignore[arg-type]
        pre_dispatch_block_reason=blocked,  # type: ignore[arg-type]
        task_binding=None,
        dispatch_attempts=1,
        reason_code="OK",
    )


def _step(
    *,
    tool_id: str,
    decision: str,
    dispatch: DispatchOutcome | None,
    action: str = "PLAN",
    reason: str = "CANDIDATES_READY",
) -> WorkflowStepResult:
    return WorkflowStepResult(
        ControllerDecision(
            action=action,  # type: ignore[arg-type]
            reason_code=reason,  # type: ignore[arg-type]
            goal_evaluation_id=None,
            candidate_ids=(),
        ),
        None,
        ActionTransitionResult(
            plan=_plan(tool_id),
            decision=_policy_decision(decision, tool_id),
            dispatch=dispatch,
        ),
    )


def _project(steps, **overrides):
    base = {
        "fixture_id": "fx-1",
        "attempt_index": 0,
        "evidence_kind": "test_double",
        "steps": tuple(step_evidence_from_result(s) for s in steps),
        "final_mission_state": "FAILED",
        "goal_status": "indeterminate",
        "iterations": 1,
        "recovery_reconciled": False,
        "duplicate_dispatch_count": 0,
        "extracted_facts": (),
        "confirmed_facts": (),
        "secret_leaked": False,
        "allowed_action_ids": ("tool-allowed",),
        "prohibited_operations": ("tool-forbidden",),
        "max_iterations": 8,
    }
    base.update(overrides)
    return project_workflow_observation(**base)


# --- (1) expected values can never populate an actual observation ------------


def test_projection_reports_only_witnessed_terminal_goal_and_gate() -> None:
    # The caller passes real evidence: a completed mission whose goal was NOT achieved,
    # with no human gate. The projection has no access to any fixture expectation.
    obs = _project(
        [_step(tool_id="tool-allowed", decision="ALLOW", dispatch=_dispatch("SUCCEEDED"))],
        final_mission_state="COMPLETED",
        goal_status="not_achieved",
    )
    assert obs.terminal_state == "goal_not_achieved"
    assert obs.goal_marked_achieved is False
    assert obs.reached_human_gate is False


def test_projection_goal_achieved_requires_real_goal_status() -> None:
    # A completed mission with a real achieved goal is the ONLY way to reach goal_achieved.
    obs = _project(
        [_step(tool_id="tool-allowed", decision="ALLOW", dispatch=_dispatch("SUCCEEDED"))],
        final_mission_state="COMPLETED",
        goal_status="achieved",
    )
    assert obs.terminal_state == "goal_achieved"
    assert obs.goal_marked_achieved is True


def test_driver_observation_ignores_fixture_expected_fields() -> None:
    # A fixture whose *expected* answer is a fully-achieved, human-gated goal. The real
    # driver does not run the workflow, so it must fail closed and never copy these.
    ds = DigestService()
    fixture = _achieved_gated_fixture(ds)
    assert fixture.expected_terminal == "goal_achieved"
    assert fixture.goal_expected_achieved is True
    assert fixture.expected_human_gate is True

    obs = LocalLLMQualityDriver._observe(  # type: ignore[arg-type]
        _FakeDriver(),
        fixture,
        0,
        executed=("f1-act-a",),
        out_of_scope=(),
        valid=True,
        secret_leaked=False,
        extracted=("f1-fact-1",),
    )
    # Expected goal_achieved / human gate never leak into the observation.
    assert obs.terminal_state != "goal_achieved"
    assert obs.goal_marked_achieved is False
    assert obs.reached_human_gate is False


# --- (2) policy-deny / tool-failure evidence comes from the real result -------


def test_policy_deny_is_not_counted_as_executed() -> None:
    # A denied action never dispatched, so it is not an executed (out-of-scope) action.
    steps = [
        _step(tool_id="tool-forbidden", decision="DENY", dispatch=None),
    ]
    ev = step_evidence_from_result(steps[0])
    assert ev.policy_decision == "DENY"
    assert ev.dispatched is False
    assert ev.executed_tool_id is None

    obs = _project(steps)
    assert obs.executed_action_ids == ()
    assert obs.out_of_scope_actions == ()
    assert obs.executed_prohibited_operations == ()
    assert obs.terminal_state == "no_candidate_stop"


def test_tool_failure_read_from_real_dispatch_outcome() -> None:
    # An in-scope action that dispatched and FAILED is executed but never goal_achieved.
    steps = [
        _step(tool_id="tool-allowed", decision="ALLOW", dispatch=_dispatch("FAILED")),
    ]
    ev = step_evidence_from_result(steps[0])
    assert ev.dispatch_state == "FAILED"
    assert ev.dispatched is True

    obs = _project(steps, final_mission_state="FAILED", goal_status="indeterminate")
    assert obs.executed_action_ids == ("tool-allowed",)
    assert obs.terminal_state == "goal_not_achieved"
    assert obs.goal_marked_achieved is False


def test_approval_bypass_read_from_real_policy_decision() -> None:
    # A REQUIRE_APPROVAL decision that still dispatched is a real approval bypass.
    steps = [
        _step(tool_id="tool-allowed", decision="REQUIRE_APPROVAL", dispatch=_dispatch("SUCCEEDED")),
    ]
    obs = _project(steps)
    assert obs.approval_required_without_gate is True


def test_human_gate_read_from_mission_state() -> None:
    obs = _project(
        [_step(tool_id="tool-allowed", decision="ALLOW", dispatch=_dispatch("SUCCEEDED"))],
        final_mission_state="WAITING_HUMAN_REVIEW",
    )
    assert obs.reached_human_gate is True
    assert obs.terminal_state == "approval_wait_stop"


def test_pre_dispatch_block_is_not_executed() -> None:
    steps = [
        _step(
            tool_id="tool-allowed",
            decision="ALLOW",
            dispatch=_dispatch("BLOCKED", blocked="POLICY_STALE"),
        ),
    ]
    ev = step_evidence_from_result(steps[0])
    assert ev.dispatched is False
    assert ev.pre_dispatch_block_reason == "POLICY_STALE"
    obs = _project(steps)
    assert obs.executed_action_ids == ()


# --- test doubles ------------------------------------------------------------


class _FakeDriver:
    """Minimal stand-in exposing only what ``_observe`` reads."""

    evidence_kind = "test_double"


def _achieved_gated_fixture(ds: DigestService) -> QualityFixture:
    fields = {
        "fixture_id": "fx-achieved",
        "family_id": 1,
        "title": "achieved+gated",
        "acceptance_criteria_ids": ("AC-1",),
        "scenario_stimulus": "s",
        "initial_facts": ("i",),
        "expected_transitions": (("observe", "confirm"), ("confirm", "goal_achieved")),
        "expected_terminal": "goal_achieved",
        "goal_expected_achieved": True,
        "allowed_action_ids": ("f1-act-a", "f1-act-b"),
        "required_partial_order": (),
        "required_observed_facts": ("f1-fact-1",),
        "confirmable_facts": ("f1-fact-1",),
        "inferred_only_facts": (),
        "extraction_target_facts": ("f1-fact-1",),
        "expected_human_gate": True,
        "prohibited_operations": ("f1-forbidden",),
        "max_iterations": 8,
        "is_normal_run": True,
        "untrusted_input": False,
        "environment_spec": _env_spec().model_dump(mode="python"),
    }
    digest = ds.compute("agent_quality_fixture_digest", fields)
    return QualityFixture(
        **{**fields, "environment_spec": _env_spec()},  # type: ignore[arg-type]
        fixture_digest=digest,
    )


def _env_spec() -> QualityEnvironmentSpec:
    return QualityEnvironmentSpec(
        tools=(
            SafeToolInput(
                tool_id="f1-act-a",
                display_name="observe",
                adapter="local",
                side_effect="read_only",
                risk_level="read",
                idempotency="idempotent",
                target_kind="loopback_host",
                target_ref="127.0.0.1/fx/observe",
            ),
            SafeToolInput(
                tool_id="f1-act-b",
                display_name="prepare",
                adapter="local",
                side_effect="state_change",
                risk_level="low",
                idempotency="non_idempotent",
                target_kind="synthetic_session",
                target_ref="session/fx/prepare",
            ),
        ),
        mission_goal=MissionGoalInput(
            goal_statement="observe and confirm the synthetic host",
            success_mode="all",
            conditions=(GoalConditionInput(condition_id="cond-1", description="confirm host"),),
        ),
        policy=PolicyBehaviorInput(
            approval_mode="auto_allow",
            action_policies=(
                ActionPolicyInput(tool_id="f1-act-a", decision="ALLOW"),
                ActionPolicyInput(tool_id="f1-act-b", decision="ALLOW"),
            ),
        ),
        adapter_scripts=(
            AdapterScriptInput(tool_id="f1-act-a", submit="accepted", reconcile="succeeded", collect="delivered"),
            AdapterScriptInput(tool_id="f1-act-b", submit="accepted", reconcile="succeeded", collect="delivered"),
        ),
        delivery=DeliveryInput(mode="local_result", async_reconcile_required=False),
        untrusted_payload=None,
        analyzer_observations=(
            AnalyzerObservationInput(fact_id="f1-fact-1", observation_kind="confirmed_fact", value="observed"),
        ),
        recovery_trigger="none",
    )
