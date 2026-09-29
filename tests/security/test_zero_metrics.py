"""Zero-metric probes through the public authorization path (H-06 regression)."""

from __future__ import annotations

import pytest

import support
from redteam_agent.approval.presentation import build_presentation
from redteam_agent.approval.service import verify_presentation_matches_intent
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import MisleadingApprovalPresentationError, PolicyEvaluationIndeterminateError
from redteam_agent.models.common import ToolRef
from redteam_agent.policy.scope_models import NetworkScopeRule
from redteam_agent.runtime.clock import ManualClock


def _kernel():
    return build_test_kernel(clock=ManualClock(support.T0))


def _seed(kernel, *, tool=None, revision=None, **seed_kwargs):
    tool = tool or support.network_tool()
    revision = revision or support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    return support.seed_running_mission(kernel, tool=tool, revision=revision, **seed_kwargs)


def test_scope_false_allow_zero_for_out_of_scope_argument() -> None:
    # requested_targets are in-scope, but the actual argument destination is not.
    kernel = _kernel()
    seeded = _seed(kernel)
    from redteam_agent.policy.scope_models import IpTargetReference

    proposal = support.make_proposal(
        tool=seeded.tool,
        arguments={"destinations": ["8.8.8.8"], "port": 443, "protocol": "tcp"},
        requested_targets=(IpTargetReference(type="ip", address="10.0.0.1"),),
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "DENY"


def test_prohibited_ipv4_mapped_rule_full_path_denies() -> None:
    kernel = _kernel()
    prohibited = (NetworkScopeRule(type="network", cidrs=("::ffff:10.1.2.3/128",), ports=None, protocols=None),)
    revision = support.mission_revision(
        kernel.digest_service, profile=support.make_profile(kernel.digest_service), prohibited_scope=prohibited
    )
    seeded = _seed(kernel, revision=revision)
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "DENY"


def test_adjacent_ip_allowed_under_specific_prohibition() -> None:
    kernel = _kernel()
    prohibited = (NetworkScopeRule(type="network", cidrs=("::ffff:10.1.2.3/128",), ports=None, protocols=None),)
    revision = support.mission_revision(
        kernel.digest_service, profile=support.make_profile(kernel.digest_service), prohibited_scope=prohibited
    )
    seeded = _seed(kernel, revision=revision)
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.4"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "ALLOW"
    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert result.authorized


def test_unauthorized_tool_rejected_at_issue() -> None:
    kernel = _kernel()
    seeded = _seed(kernel)
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    # Swap the proposal to reference a tool not in the registry.
    hijacked = proposal.model_copy(update={"tool_ref": ToolRef(tool_id="ghost", registry_revision=1)})
    plan = support.make_plan(kernel, seeded=seeded, proposal=hijacked)
    with pytest.raises(PolicyEvaluationIndeterminateError):
        support.issue_decision(kernel, plan=plan)


def test_secret_not_confirmed_denies() -> None:
    kernel = _kernel()
    tool = support.network_tool(secret_paths=("/credential",))
    revision = support.mission_revision(
        kernel.digest_service,
        profile=support.make_profile(kernel.digest_service),
        data_access_policy=support.secret_data_access_policy(),
    )
    seeded = _seed(kernel, tool=tool, revision=revision)
    md = support.confirmed_secret_metadata(kernel.digest_service).model_copy(update={"state": "REVOKED"})
    kernel.secret_metadata_store.put(md)
    proposal = support.make_proposal(
        tool=seeded.tool,
        arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp", "credential": support.secret_reference()},
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "DENY"


def test_secret_confirmed_binds_grant_from_source_of_truth() -> None:
    kernel = _kernel()
    tool = support.network_tool(secret_paths=("/credential",))
    revision = support.mission_revision(
        kernel.digest_service,
        profile=support.make_profile(kernel.digest_service),
        data_access_policy=support.secret_data_access_policy(),
    )
    seeded = _seed(kernel, tool=tool, revision=revision)
    md = support.confirmed_secret_metadata(kernel.digest_service)
    kernel.secret_metadata_store.put(md)
    proposal = support.make_proposal(
        tool=seeded.tool,
        arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp", "credential": support.secret_reference()},
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision in {"ALLOW", "REQUIRE_APPROVAL"}
    grant = decision.authorized_data_access[0]
    # The binding comes from the metadata source of truth, not the caller leaf.
    assert grant.resource.resource_digest == md.metadata_digest
    assert grant.authorization_state_digest == md.lifecycle_head_digest
    assert decision.effective_risk in {"medium", "high"}


def test_misleading_presentation_rejected() -> None:
    kernel = _kernel()
    tool = support.network_tool(side_effect="destructive", minimum_risk="high")
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    seeded = _seed(kernel, tool=tool, revision=revision)
    proposal = support.make_proposal(
        tool=seeded.tool, arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    # A presentation built for different arguments must not match the intent.
    other = build_presentation(
        decision=decision,
        tool=seeded.tool,
        arguments={"destinations": ["10.9.9.9"], "port": 443, "protocol": "tcp"},
        current_principal_ref=None,
        current_principal_display=None,
        timeout_seconds=seeded.tool.default_timeout_seconds,
        digest_service=kernel.digest_service,
        session_id=None,
    )
    with pytest.raises(MisleadingApprovalPresentationError):
        verify_presentation_matches_intent(
            presentation=other,
            decision=decision,
            tool=seeded.tool,
            arguments=proposal.arguments,
            session_id=None,
            current_principal_ref=None,
            current_principal_display=None,
            timeout_seconds=seeded.tool.default_timeout_seconds,
            digest_service=kernel.digest_service,
        )
