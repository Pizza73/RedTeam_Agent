"""Tool availability resolver exclusions and snapshot revalidation."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AvailableToolSnapshotStaleError
from redteam_agent.tools.availability import (
    CurrentSnapshotBindings,
    ToolAvailabilityInputs,
    build_available_tool_snapshot,
    resolve_available_tools,
    revalidate_snapshot,
)


def _inputs(ds: DigestService, *, adapters=None, sessions=None):
    registry, _tools, _catalog = support.build_registered_registry(ds, (support.network_tool(),))
    return ToolAvailabilityInputs(
        registry=registry,
        adapters=adapters if adapters is not None else {support.ADAPTER_ID: support.adapter_capabilities()},
        sandbox_capabilities={},
        session_snapshots=sessions or {},
        remote_mcp_trust_policy_digest="rmt",
    )


def test_tool_available_with_matching_adapter_and_scope() -> None:
    ds = DigestService()
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    views = resolve_available_tools(_inputs(ds), revision, support.T0)
    assert len(views) == 1


def test_tool_excluded_without_adapter() -> None:
    ds = DigestService()
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    views = resolve_available_tools(_inputs(ds, adapters={}), revision, support.T0)
    assert views == ()


def test_tool_excluded_when_mission_lacks_network_scope() -> None:
    ds = DigestService()
    from redteam_agent.policy.scope_models import HostScopeRule

    revision = support.mission_revision(
        ds, profile=support.make_profile(ds), allowed_scope=(HostScopeRule(type="host", host_id="h1"),)
    )
    views = resolve_available_tools(_inputs(ds), revision, support.T0)
    assert views == ()  # network tool needs a network scope


def test_session_required_tool_excluded_without_eligible_session() -> None:
    ds = DigestService()
    tool = support.network_tool(requires_session=True)
    registry, _tools, _catalog = support.build_registered_registry(ds, (tool,))
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    inputs = ToolAvailabilityInputs(
        registry=registry,
        adapters={support.ADAPTER_ID: support.adapter_capabilities()},
        sandbox_capabilities={},
        session_snapshots={},
        remote_mcp_trust_policy_digest="rmt",
    )
    assert resolve_available_tools(inputs, revision, support.T0) == ()


def test_snapshot_ttl_exceeding_mission_validity_is_rejected() -> None:
    ds = DigestService()
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    from redteam_agent.errors import AuthorizationTtlError

    with pytest.raises(AuthorizationTtlError):
        build_available_tool_snapshot(
            snapshot_id="s", revision=revision, authorization_epoch=0, policy_version="risk-policy-v1",
            inputs=_inputs(ds), digest_service=ds, created_at=support.T0,
            ttl_seconds=10 * 24 * 3600,  # far beyond valid_until
        )


def _bindings(snapshot) -> CurrentSnapshotBindings:
    return CurrentSnapshotBindings(
        mission_id=snapshot.mission_id,
        mission_revision=snapshot.mission_revision,
        authorization_epoch=snapshot.authorization_epoch,
        registry_digest=snapshot.registry_digest,
        policy_version=snapshot.policy_version,
        execution_scope_digest=snapshot.execution_scope_digest,
        session_security_context_digest=snapshot.session_security_context_digest,
        adapter_capabilities_digest=snapshot.adapter_capabilities_digest,
        sandbox_capabilities_digest=snapshot.sandbox_capabilities_digest,
        remote_mcp_trust_policy_digest=snapshot.remote_mcp_trust_policy_digest,
    )


def test_revalidate_rejects_expired_snapshot() -> None:
    ds = DigestService()
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    snapshot = build_available_tool_snapshot(
        snapshot_id="s", revision=revision, authorization_epoch=0, policy_version="risk-policy-v1",
        inputs=_inputs(ds), digest_service=ds, created_at=support.T0,
    )
    with pytest.raises(AvailableToolSnapshotStaleError):
        revalidate_snapshot(
            snapshot, current=_bindings(snapshot), session_snapshots={},
            now=snapshot.expires_at + timedelta(seconds=1),
        )


def test_revalidate_rejects_binding_drift() -> None:
    ds = DigestService()
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    snapshot = build_available_tool_snapshot(
        snapshot_id="s", revision=revision, authorization_epoch=0, policy_version="risk-policy-v1",
        inputs=_inputs(ds), digest_service=ds, created_at=support.T0,
    )
    drifted = CurrentSnapshotBindings(
        mission_id=snapshot.mission_id,
        mission_revision=snapshot.mission_revision,
        authorization_epoch=snapshot.authorization_epoch + 1,  # epoch drift
        registry_digest=snapshot.registry_digest,
        policy_version=snapshot.policy_version,
        execution_scope_digest=snapshot.execution_scope_digest,
        session_security_context_digest=snapshot.session_security_context_digest,
        adapter_capabilities_digest=snapshot.adapter_capabilities_digest,
        sandbox_capabilities_digest=snapshot.sandbox_capabilities_digest,
        remote_mcp_trust_policy_digest=snapshot.remote_mcp_trust_policy_digest,
    )
    with pytest.raises(AvailableToolSnapshotStaleError):
        revalidate_snapshot(snapshot, current=drifted, session_snapshots={}, now=support.T0)
