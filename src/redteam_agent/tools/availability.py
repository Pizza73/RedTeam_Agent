"""Pure candidate-tool calculation and deterministic snapshot materialization."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from redteam_agent.canonical import digest_model, sha256_digest, stable_id, verify_model_digest
from redteam_agent.errors import AvailableToolSnapshotStaleError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.capabilities import (
    AdapterCapabilities,
    AdapterCapabilitySnapshot,
    RemoteMCPTrustSnapshot,
    SandboxCapabilities,
    SandboxCapabilitySnapshot,
    SessionSecurityContextSnapshot,
)
from redteam_agent.models.mission import Mission
from redteam_agent.models.scope import HostScopeRule, NetworkScopeRule, SessionScopeRule
from redteam_agent.models.tools import (
    AvailableToolSnapshot,
    AvailableToolView,
    ToolDefinition,
    ToolRegistryRevision,
)

from .capability_snapshots import verify_capability_snapshot
from .target_extractors import TrustedTargetExtractorRegistry


class ToolAvailabilityCalculation(StrictImmutableBoundaryModel):
    calculation_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    registry_digest: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    execution_scope_digest: str = Field(min_length=1)
    session_security_context_digest: str = Field(min_length=1)
    adapter_capabilities_digest: str = Field(min_length=1)
    sandbox_capabilities_digest: str = Field(min_length=1)
    remote_mcp_trust_policy_digest: str = Field(min_length=1)
    tools: tuple[AvailableToolView, ...]


def execution_scope_digest(mission: Mission) -> str:
    allowed = sorted(
        (rule.model_dump(mode="python") for rule in mission.allowed_execution_scope),
        key=lambda item: sha256_digest(item),
    )
    prohibited = sorted(
        (rule.model_dump(mode="python") for rule in mission.prohibited_execution_scope),
        key=lambda item: sha256_digest(item),
    )
    return sha256_digest(
        {
            "schema_version": "execution-scope-v1",
            "implemented_scope_types": ["cidr", "host", "ip", "session"],
            "allowed": allowed,
            "prohibited": prohibited,
        }
    )


class ToolAvailabilityResolver:
    """Determines planning candidates, never concrete target authorization."""

    def __init__(self, extractors: TrustedTargetExtractorRegistry) -> None:
        self.extractors = extractors

    def calculate(
        self,
        *,
        mission: Mission,
        registry: ToolRegistryRevision,
        session_snapshot: SessionSecurityContextSnapshot,
        adapter_snapshot: AdapterCapabilitySnapshot,
        sandbox_snapshot: SandboxCapabilitySnapshot,
        remote_trust_snapshot: RemoteMCPTrustSnapshot,
        policy_version: str,
    ) -> ToolAvailabilityCalculation:
        for snapshot in (
            session_snapshot,
            adapter_snapshot,
            sandbox_snapshot,
            remote_trust_snapshot,
        ):
            verify_capability_snapshot(snapshot)
        views: list[AvailableToolView] = []
        for tool in registry.tools:
            view = self._available_view(
                tool,
                mission,
                session_snapshot,
                adapter_snapshot,
                sandbox_snapshot,
                remote_trust_snapshot,
            )
            if view is not None:
                views.append(view)
        views.sort(key=lambda item: (item.tool_ref.tool_id, item.tool_ref.registry_revision))
        scope_digest = execution_scope_digest(mission)
        base = {
            "schema_version": "tool-availability-calculation-v1",
            "mission_id": mission.mission_id,
            "mission_revision": mission.mission_revision,
            "authorization_epoch": mission.authorization_epoch,
            "registry_digest": registry.registry_digest,
            "policy_version": policy_version,
            "execution_scope_digest": scope_digest,
            "session_security_context_digest": session_snapshot.snapshot_digest,
            "adapter_capabilities_digest": adapter_snapshot.snapshot_digest,
            "sandbox_capabilities_digest": sandbox_snapshot.snapshot_digest,
            "remote_mcp_trust_policy_digest": remote_trust_snapshot.snapshot_digest,
            "tools": [view.model_dump(mode="python") for view in views],
        }
        return ToolAvailabilityCalculation(
            calculation_digest=sha256_digest(base),
            mission_id=mission.mission_id,
            mission_revision=mission.mission_revision,
            authorization_epoch=mission.authorization_epoch,
            registry_digest=registry.registry_digest,
            policy_version=policy_version,
            execution_scope_digest=scope_digest,
            session_security_context_digest=session_snapshot.snapshot_digest,
            adapter_capabilities_digest=adapter_snapshot.snapshot_digest,
            sandbox_capabilities_digest=sandbox_snapshot.snapshot_digest,
            remote_mcp_trust_policy_digest=remote_trust_snapshot.snapshot_digest,
            tools=tuple(views),
        )

    def persistable_snapshot(
        self,
        calculation: ToolAvailabilityCalculation,
        *,
        created_at: datetime,
        expires_at: datetime,
        mission_valid_until: datetime,
    ) -> AvailableToolSnapshot:
        if created_at >= expires_at or expires_at > mission_valid_until:
            raise AvailableToolSnapshotStaleError("snapshot TTL violates mission validity")
        identity = {
            "schema_version": "available-tool-snapshot-v1",
            "calculation_digest": calculation.calculation_digest,
            "created_at": created_at,
            "expires_at": expires_at,
        }
        provisional = AvailableToolSnapshot(
            snapshot_id=stable_id("toolsnapshot", identity),
            snapshot_digest="pending",
            calculation_digest=calculation.calculation_digest,
            mission_id=calculation.mission_id,
            mission_revision=calculation.mission_revision,
            authorization_epoch=calculation.authorization_epoch,
            registry_digest=calculation.registry_digest,
            policy_version=calculation.policy_version,
            execution_scope_digest=calculation.execution_scope_digest,
            session_security_context_digest=calculation.session_security_context_digest,
            adapter_capabilities_digest=calculation.adapter_capabilities_digest,
            sandbox_capabilities_digest=calculation.sandbox_capabilities_digest,
            remote_mcp_trust_policy_digest=calculation.remote_mcp_trust_policy_digest,
            tools=calculation.tools,
            created_at=created_at,
            expires_at=expires_at,
        )
        return provisional.model_copy(
            update={"snapshot_digest": digest_model(provisional, exclude={"snapshot_digest"})}
        )

    @staticmethod
    def revalidate(
        snapshot: AvailableToolSnapshot,
        *,
        mission: Mission,
        registry_digest: str,
        policy_version: str,
        execution_scope_digest_value: str,
        session_security_context_digest: str,
        adapter_capabilities_digest: str,
        sandbox_capabilities_digest: str,
        remote_mcp_trust_policy_digest: str,
        now: datetime,
    ) -> None:
        verify_model_digest(snapshot, snapshot.snapshot_digest, exclude={"snapshot_digest"})
        expected = (
            snapshot.mission_id == mission.mission_id
            and snapshot.mission_revision == mission.mission_revision
            and snapshot.authorization_epoch == mission.authorization_epoch
            and snapshot.registry_digest == registry_digest
            and snapshot.policy_version == policy_version
            and snapshot.execution_scope_digest == execution_scope_digest_value
            and snapshot.session_security_context_digest == session_security_context_digest
            and snapshot.adapter_capabilities_digest == adapter_capabilities_digest
            and snapshot.sandbox_capabilities_digest == sandbox_capabilities_digest
            and snapshot.remote_mcp_trust_policy_digest == remote_mcp_trust_policy_digest
            and now < snapshot.expires_at
        )
        if not expected:
            raise AvailableToolSnapshotStaleError("available-tool snapshot binding is stale")

    def _available_view(
        self,
        tool: ToolDefinition,
        mission: Mission,
        session_snapshot: SessionSecurityContextSnapshot,
        adapter_snapshot: AdapterCapabilitySnapshot,
        sandbox_snapshot: SandboxCapabilitySnapshot,
        remote_snapshot: RemoteMCPTrustSnapshot,
    ) -> AvailableToolView | None:
        if tool.target_extractor_id is not None:
            try:
                self.extractors.resolve(tool.target_extractor_id)
            except Exception:
                return None
        if not self._scope_compatible(tool, mission):
            return None
        adapter = next(
            (
                item
                for item in adapter_snapshot.adapters
                if item.adapter_type == tool.adapter and item.adapter_id == tool.adapter_id
            ),
            None,
        )
        if adapter is None or not self._adapter_satisfies(tool, adapter):
            return None
        if not self._sandbox_satisfies(tool, sandbox_snapshot.sandboxes):
            return None
        if not self._remote_trust_satisfies(tool, remote_snapshot):
            return None
        eligible = tuple(
            sorted(
                context.session_id
                for context in session_snapshot.contexts
                if context.status == "active"
                and context.os in tool.supported_os
                and context.architecture in tool.supported_architectures
                and tool.required_session_capabilities.issubset(context.capabilities)
                and context.os in adapter.supported_os
                and context.architecture in adapter.supported_architectures
                and self._session_in_scope(context.session_id, mission)
            )
        )
        if tool.requires_session and not eligible:
            return None
        return AvailableToolView(
            tool_ref=tool.tool_ref,
            display_name=tool.display_name,
            version=tool.version,
            description=tool.description,
            parameter_schema=tool.parameter_schema,
            requires_session=tool.requires_session,
            eligible_session_ids=eligible if tool.requires_session else (),
        )

    @staticmethod
    def _scope_compatible(tool: ToolDefinition, mission: Mission) -> bool:
        if tool.target_mode == "none":
            return True
        if tool.target_extractor_id is None:
            return False
        rule_type = {
            "network_target_v1": NetworkScopeRule,
            "host_target_v1": HostScopeRule,
            "session_target_v1": SessionScopeRule,
        }.get(tool.target_extractor_id)
        return rule_type is not None and any(
            isinstance(rule, rule_type) for rule in mission.allowed_execution_scope
        )

    @staticmethod
    def _adapter_satisfies(tool: ToolDefinition, adapter: AdapterCapabilities) -> bool:
        return (
            adapter.available
            and adapter.runtime_id == tool.execution_runtime_id
            and tool.required_adapter_capabilities.issubset(adapter.capabilities)
            and bool(tool.supported_os & adapter.supported_os)
            and bool(tool.supported_architectures & adapter.supported_architectures)
        )

    @staticmethod
    def _sandbox_satisfies(
        tool: ToolDefinition,
        sandboxes: tuple[SandboxCapabilities, ...],
    ) -> bool:
        requirement = tool.sandbox_requirement
        if requirement is None:
            return True

        execution_location = tool.execution_location if tool.adapter == "mcp" else "local_process"

        def meets(item: SandboxCapabilities) -> bool:
            checks = {
                "dedicated_os_user": requirement.dedicated_os_user,
                "process_isolation": requirement.process_isolation,
                "container_or_namespace": requirement.container_or_namespace,
                "filesystem_allowlist": requirement.filesystem_allowlist_required,
                "network_egress_control": requirement.network_egress_control_required,
                "environment_allowlist": requirement.environment_allowlist_required,
                "secret_injection_control": requirement.secret_injection_control_required,
                "cpu_limit": requirement.cpu_limit_required,
                "memory_limit": requirement.memory_limit_required,
                "process_limit": requirement.process_limit_required,
            }
            return all(
                not required or getattr(item, capability) for capability, required in checks.items()
            )

        return any(
            item.runtime_id == tool.execution_runtime_id
            and item.adapter_id == tool.adapter_id
            and item.execution_location == execution_location
            and meets(item)
            for item in sandboxes
        )

    @staticmethod
    def _session_in_scope(session_id: str, mission: Mission) -> bool:
        if any(
            isinstance(rule, SessionScopeRule) and rule.session_id == session_id
            for rule in mission.prohibited_execution_scope
        ):
            return False
        return any(
            isinstance(rule, SessionScopeRule) and rule.session_id == session_id
            for rule in mission.allowed_execution_scope
        )

    @staticmethod
    def _remote_trust_satisfies(tool: ToolDefinition, snapshot: RemoteMCPTrustSnapshot) -> bool:
        if tool.adapter != "mcp":
            return True
        trust = next(
            (item for item in snapshot.policies if item.adapter_id == tool.adapter_id), None
        )
        if trust is None or trust.execution_location != tool.execution_location:
            return False
        if trust.execution_location == "local_process":
            return trust.stable_transport_identity
        if trust.execution_location == "untrusted_remote":
            return (
                tool.side_effect.value == "read_only"
                and tool.minimum_risk_level.value != "high"
                and not tool.required_data_access_types
                and trust.stable_transport_identity
                and trust.explicitly_allowed_read_only
            )
        return all(
            (
                trust.stable_transport_identity,
                trust.scope_enforcement,
                trust.authentication_authorization,
                trust.audit,
                trust.network_egress_enforcement,
                trust.sandbox_process_isolation,
            )
        )
