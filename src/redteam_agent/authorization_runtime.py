"""Resolve all current authorization inputs from trusted repositories."""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.errors import CurrentAuthorizationStateError
from redteam_agent.models.capabilities import (
    AdapterCapabilitySnapshot,
    RemoteMCPTrustSnapshot,
    SandboxCapabilitySnapshot,
    SessionSecurityContextSnapshot,
)
from redteam_agent.models.mission import Mission
from redteam_agent.models.runtime import AuthorizationRuntimeBinding, PolicyState
from redteam_agent.models.tools import AvailableToolSnapshot, ToolRegistryRevision
from redteam_agent.repositories.capabilities import (
    AdapterCapabilitySnapshotRepository,
    RemoteMCPTrustSnapshotRepository,
    SandboxCapabilitySnapshotRepository,
    SessionSecurityContextSnapshotRepository,
)
from redteam_agent.repositories.mission import (
    MissionRevisionRepository,
    MissionStateRepository,
    compose_mission,
)
from redteam_agent.repositories.runtime import (
    AuthorizationRuntimeBindingRepository,
    PolicyStateRepository,
)
from redteam_agent.repositories.tools import (
    AvailableToolSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.tools.availability import ToolAvailabilityResolver
from redteam_agent.tools.target_extractors import TrustedTargetExtractorRegistry


@dataclass(frozen=True)
class AuthorizationRuntimeContext:
    mission: Mission
    policy_state: PolicyState
    binding: AuthorizationRuntimeBinding
    registry: ToolRegistryRevision
    snapshot: AvailableToolSnapshot
    session_snapshot: SessionSecurityContextSnapshot
    adapter_snapshot: AdapterCapabilitySnapshot
    sandbox_snapshot: SandboxCapabilitySnapshot
    remote_trust_snapshot: RemoteMCPTrustSnapshot


class AuthorizationRuntimeContextResolver:
    """Uses an explicit binding row; timestamps never select security snapshots."""

    def __init__(
        self,
        *,
        revisions: MissionRevisionRepository,
        states: MissionStateRepository,
        policies: PolicyStateRepository,
        bindings: AuthorizationRuntimeBindingRepository,
        registries: ToolRegistryRepository,
        available_snapshots: AvailableToolSnapshotRepository,
        sessions: SessionSecurityContextSnapshotRepository,
        adapters: AdapterCapabilitySnapshotRepository,
        sandboxes: SandboxCapabilitySnapshotRepository,
        remote_trust: RemoteMCPTrustSnapshotRepository,
    ) -> None:
        self.revisions = revisions
        self.states = states
        self.policies = policies
        self.bindings = bindings
        self.registries = registries
        self.available_snapshots = available_snapshots
        self.sessions = sessions
        self.adapters = adapters
        self.sandboxes = sandboxes
        self.remote_trust = remote_trust

    def resolve(self, mission_id: str) -> AuthorizationRuntimeContext:
        state = self.states.get(mission_id)
        binding = self.bindings.get(mission_id)
        policy = self.policies.get(mission_id)
        if state is None or binding is None or policy is None:
            raise CurrentAuthorizationStateError("current authorization state is incomplete")
        revision = self.revisions.get(mission_id, binding.mission_revision)
        latest_revision = self.revisions.latest(mission_id)
        registry = self.registries.get(binding.registry_revision)
        snapshot = self.available_snapshots.get(binding.available_tool_snapshot_id)
        session = self.sessions.get(binding.session_security_context_snapshot_id)
        adapter = self.adapters.get(binding.adapter_capability_snapshot_id)
        sandbox = self.sandboxes.get(binding.sandbox_capability_snapshot_id)
        remote = self.remote_trust.get(binding.remote_mcp_trust_snapshot_id)
        if any(
            item is None
            for item in (
                revision,
                latest_revision,
                registry,
                snapshot,
                session,
                adapter,
                sandbox,
                remote,
            )
        ):
            raise CurrentAuthorizationStateError("a bound authorization artifact is missing")
        assert revision is not None and latest_revision is not None
        assert registry is not None and snapshot is not None
        assert (
            session is not None
            and adapter is not None
            and sandbox is not None
            and remote is not None
        )
        mission = compose_mission(revision, state)
        valid = (
            binding.mission_revision == latest_revision.mission_revision
            and revision == latest_revision
            and binding.mission_revision == mission.mission_revision
            and binding.authorization_epoch == mission.authorization_epoch
            and binding.policy_version == policy.policy_version
            and binding.registry_digest == registry.registry_digest
            and binding.available_tool_snapshot_id == snapshot.snapshot_id
            and snapshot.mission_id == mission_id
            and snapshot.mission_revision == mission.mission_revision
            and snapshot.authorization_epoch == mission.authorization_epoch
            and snapshot.policy_version == policy.policy_version
            and snapshot.registry_digest == registry.registry_digest
            and snapshot.session_security_context_digest == session.snapshot_digest
            and snapshot.adapter_capabilities_digest == adapter.snapshot_digest
            and snapshot.sandbox_capabilities_digest == sandbox.snapshot_digest
            and snapshot.remote_mcp_trust_policy_digest == remote.snapshot_digest
        )
        if not valid:
            raise CurrentAuthorizationStateError("current authorization binding is stale")
        recalculated = ToolAvailabilityResolver(TrustedTargetExtractorRegistry()).calculate(
            mission=mission,
            registry=registry,
            session_snapshot=session,
            adapter_snapshot=adapter,
            sandbox_snapshot=sandbox,
            remote_trust_snapshot=remote,
            policy_version=policy.policy_version,
        )
        if not (
            recalculated.calculation_digest == snapshot.calculation_digest
            and recalculated.tools == snapshot.tools
        ):
            raise CurrentAuthorizationStateError(
                "available-tool snapshot does not match current trusted capabilities"
            )
        return AuthorizationRuntimeContext(
            mission=mission,
            policy_state=policy,
            binding=binding,
            registry=registry,
            snapshot=snapshot,
            session_snapshot=session,
            adapter_snapshot=adapter,
            sandbox_snapshot=sandbox,
            remote_trust_snapshot=remote,
        )
