"""Owner-only write ports: a caller cannot persist a forged artifact (Codex #1/#2)."""

from __future__ import annotations

import pytest

import support
from redteam_agent.approval.presentation import build_presentation
from redteam_agent.approval.service import build_approval_record, build_approval_request
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import ApprovalAuthorityError, RepositoryIntegrityError
from redteam_agent.mission.models import MissionState
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.storage.guard import WriteGuard


def _kernel():
    return build_test_kernel(clock=ManualClock(support.T0))


def _running(kernel, *, side_effect="read_only", minimum_risk="low"):
    tool = support.network_tool(side_effect=side_effect, minimum_risk=minimum_risk)
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    return support.seed_running_mission(kernel, tool=tool, revision=revision)


def test_direct_mission_state_transition_without_owner_guard_is_rejected() -> None:
    kernel = _kernel()
    _running(kernel)
    # A caller holding the repository cannot transition state: it lacks the guard.
    with pytest.raises(RepositoryIntegrityError):
        kernel.state_repository.apply_transition(
            guard=WriteGuard(),
            mission_id=support.MISSION_ID,
            expected_version=2,
            expected_epoch=0,
            expected_state="RUNNING",
            target_state="PAUSED",
        )


def test_direct_mission_state_create_forged_running_is_rejected() -> None:
    kernel = _kernel()
    forged = MissionState(
        mission_id="forged", mission_revision=1, mission_state_version=0, authorization_epoch=0, state="DRAFT"
    )
    with pytest.raises(RepositoryIntegrityError):
        kernel.state_repository.create(forged, guard=WriteGuard())


def test_raw_decision_save_without_owner_guard_is_rejected() -> None:
    kernel = _kernel()
    seeded = _running(kernel)
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)  # legitimately issued + saved
    with pytest.raises(RepositoryIntegrityError):
        kernel.decision_repository.save(decision, guard=WriteGuard())


def test_forged_approval_record_raw_save_is_rejected() -> None:
    kernel = _kernel()
    seeded = _running(kernel, side_effect="destructive", minimum_risk="high")
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    request = kernel.approval_service.issue_request(
        approval_request_id="req-1", decision_id=decision.decision_id, plan=plan
    )
    support.register_approver(kernel)  # op-approver legitimately holds the role

    # Forge a record impersonating the real approver, without authenticating.
    forged = build_approval_record(
        approval_id="forged-1",
        request=request,
        decision=decision,
        approver_id="op-approver",
        approver_role="approver",
        verdict="APPROVED",
        issued_at=support.T0,
        expires_at=request.expires_at,
        digest_service=kernel.digest_service,
    )
    with pytest.raises(RepositoryIntegrityError):
        kernel.record_repository.save(forged, guard=WriteGuard())


def test_submit_decision_requires_authenticated_actor() -> None:
    kernel = _kernel()
    seeded = _running(kernel, side_effect="destructive", minimum_risk="high")
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    kernel.approval_service.issue_request(approval_request_id="req-1", decision_id=decision.decision_id, plan=plan)
    support.register_approver(kernel)
    # An unauthenticated token cannot record an approval.
    with pytest.raises(ApprovalAuthorityError):
        kernel.approval_service.submit_decision(
            approval_id="appr-1", approval_request_id="req-1", actor_token="unknown-token", verdict="APPROVED"
        )


def test_unassigned_principal_cannot_approve() -> None:
    kernel = _kernel()
    seeded = _running(kernel, side_effect="destructive", minimum_risk="high")
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    kernel.approval_service.issue_request(approval_request_id="req-1", decision_id=decision.decision_id, plan=plan)
    # Authenticated, but not assigned the approver role for this mission.
    from redteam_agent.auth.models import AuthenticatedPrincipal

    kernel.principal_resolver.register(
        "tok-x", AuthenticatedPrincipal(principal_id="op-x", roles=frozenset({"operator"}))
    )
    with pytest.raises(ApprovalAuthorityError):
        kernel.approval_service.submit_decision(
            approval_id="appr-1", approval_request_id="req-1", actor_token="tok-x", verdict="APPROVED"
        )


def test_presentation_builder_is_not_authority() -> None:
    # A pure builder cannot forge an approval request into the store.
    kernel = _kernel()
    seeded = _running(kernel, side_effect="destructive", minimum_risk="high")
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    presentation = build_presentation(
        decision=decision,
        tool=seeded.tool,
        arguments=proposal.arguments,
        current_principal_ref=None,
        current_principal_display=None,
        timeout_seconds=seeded.tool.default_timeout_seconds,
        digest_service=kernel.digest_service,
        session_id=None,
    )
    request = build_approval_request(
        approval_request_id="req-forged",
        decision=decision,
        presentation=presentation,
        issued_at=support.T0,
        expires_at=decision.expires_at,
        digest_service=kernel.digest_service,
    )
    with pytest.raises(RepositoryIntegrityError):
        kernel.request_repository.save(request, guard=WriteGuard())
