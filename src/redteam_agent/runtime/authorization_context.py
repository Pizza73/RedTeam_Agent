"""Current Authorization Runtime Context (H-01, SystemDesign §17.1).

The runtime context is resolved *only* from trusted repositories: the current
mission state and revision, the pinned tool registry, and the current capability
snapshots. A caller cannot supply these values; downstream gates compare a
decision against this trusted context to reject stale epochs, revisions,
policies and snapshots (B-04).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import RepositoryIntegrityError
from redteam_agent.mission.models import Mission, join_mission
from redteam_agent.session.models import compute_session_security_context_digest
from redteam_agent.storage.repositories import (
    AdapterCapabilityRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    PolicyRevisionRepository,
    SandboxCapabilityRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.tools.availability import (
    CurrentSnapshotBindings,
    compute_adapter_capabilities_digest,
    compute_execution_scope_digest,
    compute_sandbox_capabilities_digest,
)


@dataclass(frozen=True)
class CurrentAuthorizationRuntimeContext:
    mission: Mission
    registry_digest: str
    policy_version: str
    bindings: CurrentSnapshotBindings
    trusted_now: datetime


class AuthorizationContextResolver:
    def __init__(
        self,
        *,
        state_repository: MissionStateRepository,
        revision_repository: MissionRevisionRepository,
        registry_repository: ToolRegistryRepository,
        policy_repository: PolicyRevisionRepository,
        adapter_repository: AdapterCapabilityRepository,
        sandbox_repository: SandboxCapabilityRepository,
        session_repository: SessionSecurityContextSnapshotRepository,
        digest_service: DigestService,
        registry_revision: int,
        policy_version: str,
        remote_mcp_trust_policy_digest: str,
    ) -> None:
        self._states = state_repository
        self._revisions = revision_repository
        self._registry_repo = registry_repository
        self._policy_repo = policy_repository
        self._adapters = adapter_repository
        self._sandbox = sandbox_repository
        self._sessions = session_repository
        self._digests = digest_service
        self._registry_revision = registry_revision
        self._policy_version = policy_version
        self._remote_trust_digest = remote_mcp_trust_policy_digest

    def resolve(self, mission_id: str, *, now: datetime) -> CurrentAuthorizationRuntimeContext:
        state = self._states.get(mission_id)
        if state is None:
            raise RepositoryIntegrityError("mission state not found")
        revision = self._revisions.get(mission_id, state.mission_revision)
        if revision is None:
            raise RepositoryIntegrityError("mission revision not found for current state")
        registry = self._registry_repo.get(self._registry_revision)
        if registry is None:
            raise RepositoryIntegrityError("tool registry revision not found")
        # Load and verify the current policy revision (digest checked on load),
        # rather than trusting a bare configured version string.
        policy = self._policy_repo.get(self._policy_version)
        if policy is None:
            raise RepositoryIntegrityError("current policy revision not found")
        sandboxes = self._sandbox.all_capabilities()
        adapters = self._adapters.all_capabilities()
        sessions = self._sessions.all_snapshots()
        session_contexts = tuple(snapshot.context for snapshot in sessions.values())

        bindings = CurrentSnapshotBindings(
            mission_revision=state.mission_revision,
            authorization_epoch=state.authorization_epoch,
            registry_digest=registry.registry_digest,
            policy_version=policy.policy_version,
            execution_scope_digest=compute_execution_scope_digest(revision, self._digests),
            session_security_context_digest=compute_session_security_context_digest(
                session_contexts, self._digests
            ),
            adapter_capabilities_digest=compute_adapter_capabilities_digest(adapters, self._digests),
            sandbox_capabilities_digest=compute_sandbox_capabilities_digest(sandboxes, self._digests),
            remote_mcp_trust_policy_digest=self._remote_trust_digest,
        )
        return CurrentAuthorizationRuntimeContext(
            mission=join_mission(revision, state),
            registry_digest=registry.registry_digest,
            policy_version=policy.policy_version,
            bindings=bindings,
            trusted_now=now,
        )
