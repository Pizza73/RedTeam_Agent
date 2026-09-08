"""Phase 3 Human Approval fail-closed boundaries (SystemDesign §23).

The Executable predicate is exercised at every boundary: DENY is never
approvable, a REJECTED / expired / replayed / wrongly-bound record is not
executable, a plan/intent change invalidates a prior approval, and an unapproved
action never reaches the adapter through the executor.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
import support_phase0b as p0b
from redteam_agent.approval.service import (
    build_approval_record,
    evaluate_executable,
)
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import ExecutorAuthorizationError
from redteam_agent.runtime.clock import ManualClock


def _approval_decision():
    """A real REQUIRE_APPROVAL decision plus its matching request and record."""
    kernel = build_test_kernel(clock=ManualClock(support.T0))
    tool = support.network_tool(side_effect="destructive", minimum_risk="high")
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    seeded = support.seed_running_mission(kernel, tool=tool, revision=revision)
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "REQUIRE_APPROVAL"
    kernel.approval_service.issue_request(
        approval_request_id="req-1", decision_id=decision.decision_id, plan=plan
    )
    support.register_approver(kernel)
    request = kernel.request_repository.get("req-1")
    assert request is not None
    return kernel, seeded, plan, decision, request


def _record(kernel, request, decision, *, verdict="APPROVED", expires_at=None):
    return build_approval_record(
        approval_id="appr-1",
        request=request,
        decision=decision,
        approver_id="op-approver",
        approver_role="approver",
        verdict=verdict,
        issued_at=support.T0,
        expires_at=expires_at or request.expires_at,
        digest_service=kernel.digest_service,
    )


def test_deny_decision_is_never_executable_even_with_an_approved_record() -> None:
    kernel, _seeded, _plan, decision, request = _approval_decision()
    approved = _record(kernel, request, decision)
    denied = decision.model_copy(update={"decision": "DENY"})
    result = evaluate_executable(decision=denied, request=request, record=approved, now=support.T0)
    assert not result.executable and result.reason_code == "DECISION_DENY"


def test_rejected_record_is_not_executable() -> None:
    kernel, _seeded, _plan, decision, request = _approval_decision()
    rejected = _record(kernel, request, decision, verdict="REJECTED")
    result = evaluate_executable(decision=decision, request=request, record=rejected, now=support.T0)
    assert not result.executable and result.reason_code == "APPROVAL_NOT_APPROVED"


def test_expired_approval_is_not_executable() -> None:
    kernel, _seeded, _plan, decision, request = _approval_decision()
    approved = _record(kernel, request, decision)
    later = request.expires_at  # boundary time counts as expired (strict <)
    result = evaluate_executable(decision=decision, request=request, record=approved, now=later)
    assert not result.executable and result.reason_code == "APPROVAL_EXPIRED"


def test_replayed_record_bound_to_a_different_request_is_rejected() -> None:
    kernel, _seeded, _plan, decision, request = _approval_decision()
    # A record whose request id/digest do not match the current request (replay).
    other = request.model_copy(
        update={"approval_request_id": "req-other", "request_digest": "digest-other"}
    )
    replay = _record(kernel, other, decision)
    result = evaluate_executable(decision=decision, request=request, record=replay, now=support.T0)
    assert not result.executable and result.reason_code == "APPROVAL_BINDING_MISMATCH"


def test_wrong_authorization_digest_binding_is_rejected() -> None:
    kernel, _seeded, _plan, decision, request = _approval_decision()
    approved = _record(kernel, request, decision)
    drifted = decision.model_copy(update={"authorization_digest": decision.authorization_digest + "x"})
    result = evaluate_executable(decision=drifted, request=request, record=approved, now=support.T0)
    assert not result.executable and result.reason_code == "APPROVAL_BINDING_MISMATCH"


def test_wrong_epoch_and_revision_binding_are_rejected() -> None:
    kernel, _seeded, _plan, decision, request = _approval_decision()
    approved = _record(kernel, request, decision)
    stale_epoch = decision.model_copy(update={"authorization_epoch": decision.authorization_epoch + 1})
    assert evaluate_executable(
        decision=stale_epoch, request=request, record=approved, now=support.T0
    ).reason_code == "APPROVAL_BINDING_MISMATCH"
    stale_rev = decision.model_copy(update={"mission_revision": decision.mission_revision + 1})
    assert evaluate_executable(
        decision=stale_rev, request=request, record=approved, now=support.T0
    ).reason_code == "APPROVAL_BINDING_MISMATCH"


def test_approval_ttl_exceeding_decision_is_rejected() -> None:
    kernel, _seeded, _plan, decision, request = _approval_decision()
    # A record that outlives its parent decision must never be executable (§21).
    long_request = request.model_copy(update={"expires_at": decision.expires_at + timedelta(seconds=1)})
    long_record = _record(kernel, long_request, decision, expires_at=decision.expires_at + timedelta(seconds=1))
    result = evaluate_executable(decision=decision, request=long_request, record=long_record, now=support.T0)
    assert not result.executable and result.reason_code == "APPROVAL_TTL_EXCEEDS_PARENT"


def test_plan_intent_change_invalidates_prior_approval_at_the_gate() -> None:
    kernel, seeded, plan, decision, _request = _approval_decision()
    support.register_approver(kernel)
    kernel.approval_service.submit_decision(
        approval_id="appr-1", approval_request_id="req-1", actor_token="tok-approver", verdict="APPROVED"
    )
    # The approval binds this exact intent; a changed plan (different arguments,
    # hence a different proposal digest) is not covered by it.
    changed = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.4"], "port": 443, "protocol": "tcp"}
    )
    changed_plan = support.make_plan(kernel, seeded=seeded, proposal=changed, plan_id="plan-changed")
    result = kernel.authorization_gate.authorize_execution(
        decision_id=decision.decision_id, plan=changed_plan
    )
    assert not result.authorized
    assert result.reason_code in ("PLAN_MISMATCH", "PROPOSAL_MISMATCH")


def test_unapproved_action_never_reaches_the_adapter() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(
        kernel, side_effect="destructive", minimum_risk="high",
        require_for_side_effect=frozenset({"destructive"}),
    )
    assert seeded.decision.decision == "REQUIRE_APPROVAL"
    # With no approval, the execution cannot even be created, and the adapter is
    # never submitted to.
    with pytest.raises(ExecutorAuthorizationError):
        p0b.authorize(seeded)
    assert kernel.execution_repository.get(seeded.execution_id) is None
    assert kernel.mock_adapter.submit_calls == 0


def test_revoked_approval_blocks_dispatch_before_the_adapter() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(
        kernel, side_effect="destructive", minimum_risk="high",
        require_for_side_effect=frozenset({"destructive"}),
    )
    approvals = kernel.phase0a.approval_service
    approvals.issue_request(
        approval_request_id="req-1", decision_id=seeded.decision.decision_id, plan=seeded.plan
    )
    support.register_approver(kernel.phase0a)
    approvals.submit_decision(
        approval_id="appr-1", approval_request_id="req-1", actor_token="tok-approver", verdict="APPROVED"
    )
    p0b.authorize(seeded)  # AUTHORIZED with a valid approval
    # Revoke the approver's role, then dispatch: pre-dispatch revalidation blocks
    # and the adapter is never called.
    from redteam_agent.auth.models import MissionRoleAssignment

    kernel.phase0a.role_assignment_repository.save(
        MissionRoleAssignment(
            mission_id=support.MISSION_ID, principal_id="op-approver", role="approver", active=False
        )
    )
    out = kernel.executor.dispatch(execution_id=seeded.execution_id, plan=seeded.plan)
    assert out.provider_execution_state == "BLOCKED"
    assert kernel.mock_adapter.submit_calls == 0
