"""Available-tool snapshot publishing service (owner of snapshots).

Builds an AvailableToolSnapshot from current trusted repositories for a mission
and persists it with the write guard. A caller cannot raw-save a forged
snapshot.
"""

from __future__ import annotations

from redteam_agent.adapters.mcp import MCPTrustPolicy
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import RepositoryIntegrityError
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    AdapterCapabilityRepository,
    AvailableToolSnapshotRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    SandboxCapabilityRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.tools.availability import (
    AvailableToolSnapshot,
    ToolAvailabilityInputs,
    build_available_tool_snapshot,
)


class ToolAvailabilityService:
    def __init__(
        self,
        *,
        state_repository: MissionStateRepository,
        revision_repository: MissionRevisionRepository,
        registry_repository: ToolRegistryRepository,
        adapter_repository: AdapterCapabilityRepository,
        sandbox_repository: SandboxCapabilityRepository,
        session_repository: SessionSecurityContextSnapshotRepository,
        snapshot_repository: AvailableToolSnapshotRepository,
        digest_service: DigestService,
        clock: Clock,
        write_guard: WriteGuard,
        registry_revision: int,
        remote_mcp_trust_policy_digest: str,
        policy_version: str,
        mcp_trust_policies: dict[str, MCPTrustPolicy] | None = None,
        ttl_seconds: int = 900,
    ) -> None:
        self._states = state_repository
        self._revisions = revision_repository
        self._registry_repo = registry_repository
        self._adapters = adapter_repository
        self._sandbox = sandbox_repository
        self._sessions = session_repository
        self._snapshots = snapshot_repository
        self._digests = digest_service
        self._clock = clock
        self._guard = write_guard
        self._registry_revision = registry_revision
        self._remote_trust_digest = remote_mcp_trust_policy_digest
        self._policy_version = policy_version
        self._mcp_trust_policies = dict(mcp_trust_policies or {})
        self._ttl_seconds = ttl_seconds
        snapshot_repository.bind_owner(write_guard)

    def publish(self, *, snapshot_id: str, mission_id: str) -> AvailableToolSnapshot:
        state = self._states.get(mission_id)
        if state is None:
            raise RepositoryIntegrityError("mission state not found")
        revision = self._revisions.get(mission_id, state.mission_revision)
        registry = self._registry_repo.get(self._registry_revision)
        if revision is None or registry is None:
            raise RepositoryIntegrityError("mission revision or registry not found")
        inputs = ToolAvailabilityInputs(
            registry=registry,
            adapters=self._adapters.all_capabilities(),
            sandbox_capabilities=self._sandbox.all_capabilities(),
            session_snapshots=self._sessions.all_snapshots(),
            remote_mcp_trust_policy_digest=self._remote_trust_digest,
            mcp_trust_policies=self._mcp_trust_policies,
        )
        snapshot = build_available_tool_snapshot(
            snapshot_id=snapshot_id,
            revision=revision,
            authorization_epoch=state.authorization_epoch,
            policy_version=self._policy_version,
            inputs=inputs,
            digest_service=self._digests,
            created_at=self._clock.now(),
            ttl_seconds=self._ttl_seconds,
        )
        self._snapshots.save(snapshot, guard=self._guard)
        return snapshot
