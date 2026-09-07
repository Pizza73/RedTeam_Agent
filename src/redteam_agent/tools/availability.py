"""Tool Availability Resolver and AvailableToolSnapshot (SystemDesign §20.2 / §20.3).

Tool availability is a deterministic planning-candidate calculation: the
intersection of registry, adapter/session/sandbox capabilities, mission scope
compatibility, implemented scope capability and target-binding availability. It
is *not* execution authorization; the policy engine still authorizes concrete
actions. The snapshot is bound to every current digest and re-validated after
planning; any drift is fail-closed and stale.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pydantic import Field

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.errors import (
    AuthorizationTtlError,
    AvailableToolSnapshotStaleError,
    SandboxCapabilityStaleError,
)
from redteam_agent.mission.models import MissionRevision
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ToolRef
from redteam_agent.policy.scope_engine import IMPLEMENTED_SCOPE_TYPES, mission_supports_scope_type
from redteam_agent.policy.target_binding import select_binding_mode
from redteam_agent.policy.ttl import enforce_ttl
from redteam_agent.sandbox.models import SandboxCapabilities
from redteam_agent.session.models import (
    SessionSecurityContextSnapshot,
    compute_session_security_context_digest,
)
from redteam_agent.tools.models import ToolDefinition
from redteam_agent.tools.registry import ToolRegistryRevision

# Map from a tool's target extractor to the scope type its targets require.
_EXTRACTOR_SCOPE_TYPE: dict[str, str | None] = {
    "network_target_v1": "network",
    "host_target_v1": "host",
    "session_target_v1": "session",
    "artifact_target_v1": None,
}


class AvailableToolView(StrictImmutableBoundaryModel):
    tool_ref: ToolRef
    display_name: str
    version: str
    description: str
    parameter_schema: CanonicalJsonObject
    requires_session: bool
    eligible_session_ids: tuple[str, ...]


class AvailableToolSnapshot(StrictImmutableBoundaryModel):
    snapshot_id: str = Field(min_length=1)
    snapshot_digest: str = Field(min_length=1)
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
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class ToolAvailabilityInputs:
    registry: ToolRegistryRevision
    adapters: dict[str, AdapterCapabilities]
    # Sandbox capabilities keyed by the adapter/runtime they are bound to (H-04).
    sandbox_capabilities: dict[str, SandboxCapabilities]
    session_snapshots: dict[str, SessionSecurityContextSnapshot]
    remote_mcp_trust_policy_digest: str


def compute_execution_scope_digest(revision: MissionRevision, digest_service: DigestService) -> str:
    payload = {
        "allowed": [rule.model_dump(mode="python") for rule in revision.allowed_execution_scope],
        "prohibited": [rule.model_dump(mode="python") for rule in revision.prohibited_execution_scope],
        "implemented_scope_types": sorted(IMPLEMENTED_SCOPE_TYPES),
    }
    return digest_service.compute("execution_scope_digest", payload)


def compute_adapter_capabilities_digest(
    adapters: dict[str, AdapterCapabilities], digest_service: DigestService
) -> str:
    entries = []
    for adapter_id in sorted(adapters):
        dumped = adapters[adapter_id].model_dump(mode="python")
        dumped.pop("observed_at", None)  # telemetry timestamp excluded
        entries.append(dumped)
    return digest_service.compute("adapter_capabilities_digest", {"adapters": entries})


def compute_sandbox_capabilities_digest(
    capabilities: dict[str, SandboxCapabilities], digest_service: DigestService
) -> str:
    entries = [capabilities[adapter_id].model_dump(mode="python") for adapter_id in sorted(capabilities)]
    return digest_service.compute("sandbox_capabilities_digest", {"sandboxes": entries})


_SANDBOX_SUPPORTED_LOCATIONS: frozenset[str] = frozenset({"local_process", "managed_remote"})


def _eligible_sessions(tool: ToolDefinition, inputs: ToolAvailabilityInputs, now: datetime) -> tuple[str, ...]:
    eligible: list[str] = []
    for session_id in sorted(inputs.session_snapshots):
        snapshot = inputs.session_snapshots[session_id]
        context = snapshot.context
        if not (now < snapshot.session_fresh_until):  # exclude expired/lost sessions (R15)
            continue
        if context.os not in tool.supported_os:
            continue
        if context.architecture not in tool.supported_architectures:
            continue
        if context.security_status != "ok":
            continue
        if not tool.required_session_capabilities <= context.session_capabilities:
            continue
        eligible.append(session_id)
    return tuple(eligible)


def _adapter_available(tool: ToolDefinition, inputs: ToolAvailabilityInputs) -> bool:
    adapter = inputs.adapters.get(tool.adapter_id)
    if adapter is None or adapter.adapter_type != tool.adapter:
        return False
    if not tool.required_adapter_capabilities <= adapter.capabilities:
        return False
    if tool.target_mode != "none":
        mode = select_binding_mode(tool.required_target_binding_modes, adapter.target_binding_modes)
        if mode is None:
            return False
    return True


def _scope_compatible(tool: ToolDefinition, revision: MissionRevision) -> bool:
    if tool.target_extractor_id is None:
        return tool.target_mode == "none"
    scope_type = _EXTRACTOR_SCOPE_TYPE.get(tool.target_extractor_id)
    if scope_type is None:
        return True  # artifact/no-target tools need no execution scope
    if scope_type not in IMPLEMENTED_SCOPE_TYPES:
        return False
    return mission_supports_scope_type(scope_type, revision.allowed_execution_scope)


def _sandbox_ok(tool: ToolDefinition, inputs: ToolAvailabilityInputs) -> bool:
    if tool.sandbox_requirement is None:
        return True
    sandbox = inputs.sandbox_capabilities.get(tool.adapter_id)
    adapter = inputs.adapters.get(tool.adapter_id)
    # The sandbox must be bound to *this* adapter/runtime and its execution
    # location must match the adapter's and be a supported location; an
    # untrusted-remote location cannot borrow local capabilities (H-04).
    if sandbox is None or adapter is None:
        return False
    if sandbox.execution_location != adapter.execution_location:
        return False
    if sandbox.execution_location not in _SANDBOX_SUPPORTED_LOCATIONS:
        return False
    return sandbox.satisfies(tool.sandbox_requirement)


def _tool_available(
    tool: ToolDefinition, inputs: ToolAvailabilityInputs, revision: MissionRevision, now: datetime
) -> bool:
    if not _adapter_available(tool, inputs):
        return False
    if not _scope_compatible(tool, revision):
        return False
    if not _sandbox_ok(tool, inputs):
        return False
    return not (tool.requires_session and not _eligible_sessions(tool, inputs, now))


def resolve_available_tools(
    inputs: ToolAvailabilityInputs, revision: MissionRevision, now: datetime
) -> tuple[AvailableToolView, ...]:
    views: list[AvailableToolView] = []
    for tool in inputs.registry.tools:
        if not _tool_available(tool, inputs, revision, now):
            continue
        eligible = _eligible_sessions(tool, inputs, now) if tool.requires_session else ()
        views.append(
            AvailableToolView(
                tool_ref=tool.tool_ref,
                display_name=tool.display_name,
                version=tool.version,
                description=tool.description,
                parameter_schema=tool.parameter_schema,
                requires_session=tool.requires_session,
                eligible_session_ids=eligible,
            )
        )
    views.sort(key=lambda view: (view.tool_ref.tool_id, view.tool_ref.registry_revision))
    return tuple(views)


def _snapshot_expiry(
    revision: MissionRevision,
    views: tuple[AvailableToolView, ...],
    inputs: ToolAvailabilityInputs,
    created_at: datetime,
    ttl_seconds: int,
) -> datetime:
    from datetime import timedelta

    requested = created_at + timedelta(seconds=ttl_seconds)
    # Explicit rejection rather than silent clamp when the requested TTL exceeds
    # mission validity (§21). Session freshness is a data-driven resource bound,
    # re-checked at revalidation, so the snapshot may not outlive an eligible
    # session either.
    enforce_ttl(
        label="available_tool_snapshot", issued_at=created_at, expires_at=requested,
        mission_valid_until=revision.valid_until,
    )
    candidates = [requested]
    used_sessions = {sid for view in views for sid in view.eligible_session_ids}
    for session_id in used_sessions:
        candidates.append(inputs.session_snapshots[session_id].session_fresh_until)
    expires_at = min(candidates)
    # A snapshot must never be published with a non-positive lifetime (R15).
    if not (created_at < expires_at):
        raise AuthorizationTtlError("available tool snapshot has a non-positive lifetime")
    return expires_at


def build_available_tool_snapshot(
    *,
    snapshot_id: str,
    revision: MissionRevision,
    authorization_epoch: int,
    policy_version: str,
    inputs: ToolAvailabilityInputs,
    digest_service: DigestService,
    created_at: datetime,
    ttl_seconds: int = 900,
) -> AvailableToolSnapshot:
    views = resolve_available_tools(inputs, revision, created_at)
    session_contexts = tuple(snapshot.context for snapshot in inputs.session_snapshots.values())
    binding = {
        "registry_digest": inputs.registry.registry_digest,
        "policy_version": policy_version,
        "execution_scope_digest": compute_execution_scope_digest(revision, digest_service),
        "session_security_context_digest": compute_session_security_context_digest(
            session_contexts, digest_service
        ),
        "adapter_capabilities_digest": compute_adapter_capabilities_digest(inputs.adapters, digest_service),
        "sandbox_capabilities_digest": compute_sandbox_capabilities_digest(
            inputs.sandbox_capabilities, digest_service
        ),
        "remote_mcp_trust_policy_digest": inputs.remote_mcp_trust_policy_digest,
    }
    expires_at = _snapshot_expiry(revision, views, inputs, created_at, ttl_seconds)
    draft = {
        "snapshot_id": snapshot_id,
        "mission_id": revision.mission_id,
        "mission_revision": revision.mission_revision,
        "authorization_epoch": authorization_epoch,
        "tools": [view.model_dump(mode="python") for view in views],
        "created_at": created_at,
        "expires_at": expires_at,
        **binding,
    }
    snapshot_digest = digest_service.compute("snapshot_digest", draft)
    return AvailableToolSnapshot(
        snapshot_id=snapshot_id,
        snapshot_digest=snapshot_digest,
        mission_id=revision.mission_id,
        mission_revision=revision.mission_revision,
        authorization_epoch=authorization_epoch,
        tools=views,
        created_at=created_at,
        expires_at=expires_at,
        **binding,
    )


@dataclass(frozen=True)
class CurrentSnapshotBindings:
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    registry_digest: str
    policy_version: str
    execution_scope_digest: str
    session_security_context_digest: str
    adapter_capabilities_digest: str
    sandbox_capabilities_digest: str
    remote_mcp_trust_policy_digest: str


def revalidate_snapshot(
    snapshot: AvailableToolSnapshot,
    *,
    current: CurrentSnapshotBindings,
    session_snapshots: dict[str, SessionSecurityContextSnapshot],
    now: datetime,
    selected_tool_ref: ToolRef | None = None,
    selected_session_id: str | None = None,
) -> None:
    """Fail closed if the snapshot is stale relative to current bindings (§20.3)."""
    if not (now < snapshot.expires_at):
        raise AvailableToolSnapshotStaleError("snapshot expired")
    if snapshot.sandbox_capabilities_digest != current.sandbox_capabilities_digest:
        raise SandboxCapabilityStaleError("sandbox capability digest changed")
    binding_checks = (
        snapshot.mission_id == current.mission_id,
        snapshot.mission_revision == current.mission_revision,
        snapshot.authorization_epoch == current.authorization_epoch,
        snapshot.registry_digest == current.registry_digest,
        snapshot.policy_version == current.policy_version,
        snapshot.execution_scope_digest == current.execution_scope_digest,
        snapshot.session_security_context_digest == current.session_security_context_digest,
        snapshot.adapter_capabilities_digest == current.adapter_capabilities_digest,
        snapshot.remote_mcp_trust_policy_digest == current.remote_mcp_trust_policy_digest,
    )
    if not all(binding_checks):
        raise AvailableToolSnapshotStaleError("snapshot binding drift")

    if selected_tool_ref is not None:
        view = next((v for v in snapshot.tools if v.tool_ref == selected_tool_ref), None)
        if view is None:
            raise AvailableToolSnapshotStaleError("selected tool not present in snapshot")
        if selected_session_id is not None and selected_session_id not in view.eligible_session_ids:
            raise AvailableToolSnapshotStaleError("selected session not eligible in snapshot")

    # Freshness: every eligible session used by the snapshot must still be fresh.
    used_sessions = {sid for view in snapshot.tools for sid in view.eligible_session_ids}
    for session_id in used_sessions:
        snap = session_snapshots.get(session_id)
        if snap is None or not (now < snap.session_fresh_until):
            raise AvailableToolSnapshotStaleError("eligible session is stale")
