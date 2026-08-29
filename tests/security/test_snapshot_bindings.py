from __future__ import annotations

from datetime import timedelta

import pytest

from redteam_agent.executor import authorize_execution
from redteam_agent.canonical import digest_model
from redteam_agent.models.capabilities import (
    AdapterCapabilities,
    RemoteMCPTrust,
    SandboxCapabilities,
    SessionSecurityContext,
)
from redteam_agent.seeds import FIXED_TIME, mock_capability_snapshots, mock_mission
from redteam_agent.tools.capability_snapshots import (
    build_adapter_snapshot,
    build_remote_trust_snapshot,
    build_sandbox_snapshot,
    build_session_snapshot,
)
from redteam_agent.repositories import AuthorizationRuntimeBindingRepository
from redteam_agent.repositories import SessionSecurityContextSnapshotRepository
from redteam_agent.storage import Database
from tests.helpers import build_environment, persist_environment, persisted_gate_kwargs


def test_telemetry_timestamp_does_not_change_session_security_digest() -> None:
    mission = mock_mission()
    first, _, _, _ = mock_capability_snapshots(mission.mission_id)
    second = build_session_snapshot(
        mission_id=mission.mission_id,
        contexts=first.contexts,
        source=first.source,
        created_at=FIXED_TIME + timedelta(minutes=5),
    )
    assert first.snapshot_id != second.snapshot_id
    assert first.snapshot_digest == second.snapshot_digest


def test_current_principal_change_changes_session_security_digest() -> None:
    mission = mock_mission()
    first, _, _, _ = mock_capability_snapshots(mission.mission_id)
    original = first.contexts[0]
    changed = SessionSecurityContext(
        **{**original.model_dump(mode="python"), "current_principal": "uid:0"}
    )
    second = build_session_snapshot(
        mission_id=mission.mission_id,
        contexts=(changed,),
        source=first.source,
        created_at=first.created_at,
    )
    assert first.snapshot_digest != second.snapshot_digest


@pytest.mark.parametrize(
    "binding_field",
    [
        "session_security_context_snapshot_id",
        "adapter_capability_snapshot_id",
        "sandbox_capability_snapshot_id",
        "remote_mcp_trust_snapshot_id",
    ],
)
def test_capability_binding_change_invalidates_snapshot(binding_field: str) -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        repository = AuthorizationRuntimeBindingRepository(database)
        current = repository.get(kernel.environment.mission.mission_id)
        changed = current.model_copy(
            update={
                "binding_version": current.binding_version + 1,
                binding_field: "missing-current-snapshot",
                "binding_digest": "pending",
            }
        )
        changed = changed.model_copy(
            update={"binding_digest": digest_model(changed, exclude={"binding_digest"})}
        )
        repository.set_current(changed)
        assert authorize_execution(**persisted_gate_kwargs(kernel)).status == "STALE"


def test_adapter_security_change_changes_digest() -> None:
    _, adapter, _, _ = mock_capability_snapshots(mock_mission().mission_id)
    current = adapter.adapters[0]
    changed = AdapterCapabilities(
        **{**current.model_dump(mode="python"), "available": False}
    )
    updated = build_adapter_snapshot(
        adapters=(changed,), source=adapter.source, created_at=adapter.created_at
    )
    assert updated.snapshot_digest != adapter.snapshot_digest


def test_sandbox_security_change_changes_digest() -> None:
    _, _, sandbox, _ = mock_capability_snapshots(mock_mission().mission_id)
    current = sandbox.sandboxes[0]
    changed = SandboxCapabilities(
        **{**current.model_dump(mode="python"), "network_egress_control": False}
    )
    updated = build_sandbox_snapshot(
        sandboxes=(changed,), source=sandbox.source, created_at=sandbox.created_at
    )
    assert updated.snapshot_digest != sandbox.snapshot_digest


def test_remote_trust_change_changes_digest() -> None:
    _, _, _, remote = mock_capability_snapshots(mock_mission().mission_id)
    current = remote.policies[0]
    changed = RemoteMCPTrust(
        **{**current.model_dump(mode="python"), "scope_enforcement": False}
    )
    updated = build_remote_trust_snapshot(
        policies=(changed,), source=remote.source, created_at=remote.created_at
    )
    assert updated.snapshot_digest != remote.snapshot_digest


def test_newer_snapshot_is_not_current_until_explicitly_bound() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        current = kernel.runtime_resolver.resolve(kernel.environment.mission.mission_id)
        newer = build_session_snapshot(
            mission_id=current.mission.mission_id,
            contexts=current.session_snapshot.contexts,
            source=current.session_snapshot.source,
            created_at=current.session_snapshot.created_at + timedelta(minutes=10),
        )
        SessionSecurityContextSnapshotRepository(database).add(newer)
        resolved = kernel.runtime_resolver.resolve(current.mission.mission_id)
        assert resolved.session_snapshot.snapshot_id == current.session_snapshot.snapshot_id
        assert resolved.session_snapshot.snapshot_id != newer.snapshot_id
