"""End-to-end authorization flow through the public entry points."""

from __future__ import annotations

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.tools.availability import CurrentSnapshotBindings, revalidate_snapshot


def _kernel():
    return build_test_kernel(clock=ManualClock(support.T0))


def _allow_args() -> dict:
    return {"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}


def test_allow_path_authorizes() -> None:
    kernel = _kernel()
    tool = support.network_tool(side_effect="read_only", minimum_risk="low")
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    seeded = support.seed_running_mission(kernel, tool=tool, revision=revision)
    proposal = support.make_proposal(tool=seeded.tool, arguments=_allow_args())
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)

    assert decision.decision == "ALLOW"
    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert result.authorized, result.reason_code


def test_snapshot_binding_is_current() -> None:
    kernel = _kernel()
    tool = support.network_tool()
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    seeded = support.seed_running_mission(kernel, tool=tool, revision=revision)
    runtime = kernel.context_resolver.resolve(support.MISSION_ID, now=support.T0)
    revalidate_snapshot(
        seeded.snapshot,
        current=runtime.bindings,
        session_snapshots=kernel.session_repository.all_snapshots(),
        now=support.T0,
        selected_tool_ref=seeded.tool.tool_ref,
    )
    assert isinstance(runtime.bindings, CurrentSnapshotBindings)


def test_require_approval_path_authorizes_with_valid_approval() -> None:
    kernel = _kernel()
    tool = support.network_tool(side_effect="destructive", minimum_risk="high")
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    seeded = support.seed_running_mission(kernel, tool=tool, revision=revision)
    proposal = support.make_proposal(tool=seeded.tool, arguments=_allow_args())
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "REQUIRE_APPROVAL"

    kernel.approval_service.issue_request(
        approval_request_id="req-1", decision_id=decision.decision_id, plan=plan
    )
    support.register_approver(kernel)
    kernel.approval_service.submit_decision(
        approval_id="appr-1", approval_request_id="req-1", actor_token="tok-approver", verdict="APPROVED"
    )

    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert result.authorized, result.reason_code
