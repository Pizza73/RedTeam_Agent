"""Executor gate negative paths (B-02 / B-04 / B-05, plan tampering #3)."""

from __future__ import annotations

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.models.common import ActionContractReference
from redteam_agent.runtime.clock import ManualClock


def _setup(*, side_effect="read_only", minimum_risk="low", args=None):
    clock = ManualClock(support.T0)
    kernel = build_test_kernel(clock=clock)
    tool = support.network_tool(side_effect=side_effect, minimum_risk=minimum_risk)
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    seeded = support.seed_running_mission(kernel, tool=tool, revision=revision)
    proposal = support.make_proposal(
        tool=seeded.tool, arguments=args or {"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    return clock, kernel, seeded, plan, decision


def _deny(kernel, decision, plan) -> str:
    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert not result.authorized
    return result.reason_code


def test_unknown_decision_id_denied() -> None:
    _clock, kernel, _seeded, plan, _decision = _setup()

    class _D:
        decision_id = "does-not-exist"

    result = kernel.authorization_gate.authorize_execution(decision_id="does-not-exist", plan=plan)
    assert not result.authorized
    assert result.reason_code == "DECISION_NOT_FOUND"


def test_plan_mission_id_tamper_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    tampered = plan.model_copy(update={"mission_id": "other-mission"})
    assert _deny(kernel, decision, tampered) in {"PLAN_MISSION_MISMATCH", "MISSION_MISMATCH"}


def test_plan_revision_tamper_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    tampered = plan.model_copy(update={"mission_revision": 999})
    assert _deny(kernel, decision, tampered) == "PLAN_MISSION_REVISION_MISMATCH"


def test_plan_observed_epoch_tamper_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    tampered = plan.model_copy(update={"observed_authorization_epoch": 999})
    assert _deny(kernel, decision, tampered) == "PLAN_EPOCH_STALE"


def test_plan_observed_state_version_tamper_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    tampered = plan.model_copy(update={"observed_mission_state_version": 999})
    assert _deny(kernel, decision, tampered) == "PLAN_STATE_VERSION_STALE"


def test_plan_action_contract_tamper_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    tampered = plan.model_copy(
        update={"action_contract_ref": ActionContractReference(contract_id="x", revision="1", digest="y")}
    )
    assert _deny(kernel, decision, tampered) == "ACTION_CONTRACT_MISMATCH"


def test_plan_snapshot_id_tamper_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    tampered = plan.model_copy(update={"available_tool_snapshot_id": "other-snap"})
    assert _deny(kernel, decision, tampered) == "PLAN_SNAPSHOT_ID_MISMATCH"


def test_plan_capability_digest_tamper_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    tampered = plan.model_copy(update={"adapter_capabilities_digest": "deadbeef"})
    assert _deny(kernel, decision, tampered) == "PLAN_ADAPTER_DIGEST_STALE"


def test_stale_authorization_epoch_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    # Operator invalidates authorization: epoch rotates, state stays RUNNING.
    kernel.mission_manager.invalidate_authorization(support.MISSION_ID, expected_version=2)
    assert _deny(kernel, decision, plan) == "AUTHORIZATION_EPOCH_STALE"


def test_mission_not_running_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup()
    kernel.mission_manager.pause_mission(support.MISSION_ID, expected_version=2)
    assert _deny(kernel, decision, plan) == "MISSION_NOT_RUNNING"


def test_outside_validity_window_denied() -> None:
    clock, kernel, seeded, plan, decision = _setup()
    clock.set(seeded.revision.valid_until)  # boundary is treated as outside (< valid_until)
    assert _deny(kernel, decision, plan) == "MISSION_OUTSIDE_VALIDITY_WINDOW"


def test_decision_expired_denied() -> None:
    from datetime import timedelta

    clock, kernel, _seeded, plan, decision = _setup()
    clock.set(decision.expires_at + timedelta(seconds=1))
    assert _deny(kernel, decision, plan) == "DECISION_EXPIRED"


def test_out_of_scope_decision_is_deny_and_not_executable() -> None:
    _clock, kernel, _seeded, plan, decision = _setup(args={"destinations": ["8.8.8.8"], "port": 443, "protocol": "tcp"})
    assert decision.decision == "DENY"
    assert _deny(kernel, decision, plan) == "DECISION_DENY"


def test_require_approval_without_approval_denied() -> None:
    _clock, kernel, _seeded, plan, decision = _setup(side_effect="destructive", minimum_risk="high")
    assert decision.decision == "REQUIRE_APPROVAL"
    assert _deny(kernel, decision, plan) == "APPROVAL_MISSING"


def test_approval_revoked_role_denied() -> None:
    _clock, kernel, seeded, plan, decision = _setup(side_effect="destructive", minimum_risk="high")
    kernel.approval_service.issue_request(approval_request_id="req-1", decision_id=decision.decision_id, plan=plan)
    support.register_approver(kernel)
    kernel.approval_service.submit_decision(
        approval_id="appr-1", approval_request_id="req-1", actor_token="tok-approver", verdict="APPROVED"
    )
    # Revoke the assignment after approval; use-time RBAC re-check must deny.
    from redteam_agent.auth.models import MissionRoleAssignment

    kernel.role_assignment_repository.save(
        MissionRoleAssignment(mission_id=support.MISSION_ID, principal_id="op-approver", role="approver", active=False)
    )
    assert _deny(kernel, decision, plan) == "APPROVAL_AUTHORITY_REVOKED"
