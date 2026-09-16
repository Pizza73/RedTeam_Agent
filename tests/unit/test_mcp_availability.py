"""MCP live-schema and execution-location trust availability rules."""

from __future__ import annotations

import pytest

import support
from mcp_test_server import build_offline_mcp_fixture
from redteam_agent.adapters.mcp import MCPTrustPolicy, compute_mcp_trust_policy_digest
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import RemoteMCPTrustError
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.tools.availability import (
    ToolAvailabilityInputs,
    build_available_tool_snapshot,
    resolve_available_tools,
)


def _mcp_tool(capability_id: str, *, side_effect: str = "read_only"):
    return support.network_tool(
        tool_id="mcp-health",
        side_effect=side_effect,
    ).model_copy(
        update={
            "display_name": "MCP health",
            "adapter": "mcp",
            "adapter_id": "mcp-primary",
            "provider_tool_name": "offline.echo",
            "provider_definition_revision": "offline-test-catalog-v1",
            "provider_schema_digest": capability_id.rsplit(":", 1)[-1],
            "parameter_schema": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            "target_mode": "none",
            "target_extractor_id": None,
            "required_adapter_capabilities": frozenset({capability_id}),
            "required_target_binding_modes": frozenset({"none"}),
            "required_data_access_types": frozenset(),
            "secret_argument_paths": (),
            "sandbox_requirement": None,
        }
    )


def _inputs(*, ds: DigestService, policy: MCPTrustPolicy | None, side_effect: str = "read_only"):
    fixture = build_offline_mcp_fixture(
        digest_service=ds, clock=ManualClock(support.T0)
    )
    tool = _mcp_tool(fixture.tool_capability_id, side_effect=side_effect)
    registry, _tools, _catalog = support.build_registered_registry(ds, (tool,))
    policies = {} if policy is None else {policy.adapter_id: policy}
    digest = (
        "unresolved"
        if policy is None
        else compute_mcp_trust_policy_digest((policy,), ds)
    )
    return ToolAvailabilityInputs(
        registry=registry,
        adapters={"mcp-primary": fixture.adapter.get_capabilities()},
        sandbox_capabilities={},
        session_snapshots={},
        remote_mcp_trust_policy_digest=digest,
        mcp_trust_policies=policies,
    )


def test_mcp_tool_requires_an_explicit_location_bound_trust_policy() -> None:
    ds = DigestService()
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    assert resolve_available_tools(_inputs(ds=ds, policy=None), revision, support.T0) == ()


def test_live_schema_capability_and_matching_trust_make_read_tool_available() -> None:
    ds = DigestService()
    policy = MCPTrustPolicy(
        adapter_id="mcp-primary", execution_location="local_process"
    )
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    views = resolve_available_tools(
        _inputs(ds=ds, policy=policy), revision, support.T0
    )
    assert [view.tool_ref.tool_id for view in views] == ["mcp-health"]


def test_policy_digest_mismatch_prevents_snapshot_publication() -> None:
    ds = DigestService()
    policy = MCPTrustPolicy(
        adapter_id="mcp-primary", execution_location="local_process"
    )
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    inputs = _inputs(ds=ds, policy=policy)
    inputs = ToolAvailabilityInputs(
        registry=inputs.registry,
        adapters=inputs.adapters,
        sandbox_capabilities=inputs.sandbox_capabilities,
        session_snapshots=inputs.session_snapshots,
        remote_mcp_trust_policy_digest="stale",
        mcp_trust_policies=inputs.mcp_trust_policies,
    )
    with pytest.raises(RemoteMCPTrustError):
        build_available_tool_snapshot(
            snapshot_id="mcp-snapshot",
            revision=revision,
            authorization_epoch=0,
            policy_version="risk-policy-v1",
            inputs=inputs,
            digest_service=ds,
            created_at=support.T0,
        )


def test_state_change_requires_explicit_policy_permission() -> None:
    ds = DigestService()
    policy = MCPTrustPolicy(
        adapter_id="mcp-primary", execution_location="local_process"
    )
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    assert (
        resolve_available_tools(
            _inputs(ds=ds, policy=policy, side_effect="state_change"),
            revision,
            support.T0,
        )
        == ()
    )


def test_provider_tool_list_revision_mismatch_excludes_the_tool() -> None:
    ds = DigestService()
    policy = MCPTrustPolicy(
        adapter_id="mcp-primary", execution_location="local_process"
    )
    inputs = _inputs(ds=ds, policy=policy)
    drifted_tool = inputs.registry.tools[0].model_copy(
        update={"provider_definition_revision": "unapproved-catalog-v2"}
    )
    registry, _tools, _catalog = support.build_registered_registry(ds, (drifted_tool,))
    drifted_inputs = ToolAvailabilityInputs(
        registry=registry,
        adapters=inputs.adapters,
        sandbox_capabilities={},
        session_snapshots={},
        remote_mcp_trust_policy_digest=inputs.remote_mcp_trust_policy_digest,
        mcp_trust_policies=inputs.mcp_trust_policies,
    )
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    assert resolve_available_tools(drifted_inputs, revision, support.T0) == ()
