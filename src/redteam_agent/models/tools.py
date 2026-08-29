"""Trusted tool registry and immutable planner-facing snapshots."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from redteam_agent.canonical.models import CanonicalJsonObject

from .base import StrictImmutableBoundaryModel
from .common import RiskLevel, SideEffect, UtcDatetime

TargetExtractorId = Literal[
    "network_target_v1", "session_target_v1", "host_target_v1", "artifact_target_v1"
]


class ToolRef(StrictImmutableBoundaryModel):
    tool_id: str = Field(min_length=1)
    registry_revision: int = Field(ge=1)


class SandboxRequirement(StrictImmutableBoundaryModel):
    dedicated_os_user: bool
    process_isolation: bool
    container_or_namespace: bool
    filesystem_allowlist_required: bool
    network_egress_control_required: bool
    environment_allowlist_required: bool
    secret_injection_control_required: bool
    cpu_limit_required: bool
    memory_limit_required: bool
    process_limit_required: bool


class ToolDefinition(StrictImmutableBoundaryModel):
    tool_ref: ToolRef
    display_name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    adapter: Literal["c2", "mcp", "local"]
    adapter_id: str = Field(min_length=1)
    execution_runtime_id: str = Field(min_length=1)
    provider_tool_name: str = Field(min_length=1)
    provider_definition_revision: str | None = None
    provider_schema_digest: str = Field(min_length=1)
    execution_location: Literal[
        "local_process", "managed_remote", "untrusted_remote", "not_applicable"
    ] = "not_applicable"
    minimum_risk_level: RiskLevel
    approval_rule: Literal["policy", "always"]
    side_effect: SideEffect
    idempotency: Literal["idempotent", "provider_deduplicated", "non_idempotent"]
    parameter_schema: CanonicalJsonObject
    target_mode: Literal["required", "optional", "none"]
    target_extractor_id: TargetExtractorId | None
    default_timeout_seconds: int = Field(gt=0)
    max_timeout_seconds: int = Field(gt=0)
    max_output_bytes: int = Field(gt=0)
    secret_argument_paths: tuple[str, ...] = ()
    requires_session: bool
    supported_os: frozenset[Literal["windows", "linux", "macos", "other"]]
    supported_architectures: frozenset[str]
    required_adapter_capabilities: frozenset[str]
    required_session_capabilities: frozenset[str]
    required_data_access_types: frozenset[str]
    sandbox_requirement: SandboxRequirement | None

    @model_validator(mode="after")
    def definition_invariants(self) -> ToolDefinition:
        if self.default_timeout_seconds > self.max_timeout_seconds:
            raise ValueError("default timeout must not exceed maximum timeout")
        if self.target_mode == "required" and self.target_extractor_id is None:
            raise ValueError("required targets need a trusted target extractor")
        if self.target_mode == "none" and self.target_extractor_id is not None:
            raise ValueError("target_mode=none must not declare an extractor")
        if self.side_effect == SideEffect.DESTRUCTIVE and self.minimum_risk_level != RiskLevel.HIGH:
            raise ValueError("destructive tools require minimum risk high")
        if (
            self.side_effect == SideEffect.STATE_CHANGE
            and self.minimum_risk_level == RiskLevel.READ
        ):
            raise ValueError("state-changing tools cannot have read risk")
        if (
            self.adapter in {"local", "mcp"}
            and self.minimum_risk_level == RiskLevel.HIGH
            and self.sandbox_requirement is None
        ):
            raise ValueError("high-risk local/MCP tools require a sandbox declaration")
        if self.adapter != "mcp" and self.execution_location != "not_applicable":
            raise ValueError("execution_location applies only to MCP tools")
        if self.adapter == "mcp" and self.execution_location == "not_applicable":
            raise ValueError("MCP tools require an execution location")
        return self


class ToolRegistryRevision(StrictImmutableBoundaryModel):
    registry_revision: int = Field(ge=1)
    registry_digest: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    tools: tuple[ToolDefinition, ...]
    created_at: UtcDatetime

    @model_validator(mode="after")
    def unique_sorted_tools(self) -> ToolRegistryRevision:
        refs = [(tool.tool_ref.tool_id, tool.tool_ref.registry_revision) for tool in self.tools]
        if len(refs) != len(set(refs)):
            raise ValueError("tool references must be unique")
        if any(tool.tool_ref.registry_revision != self.registry_revision for tool in self.tools):
            raise ValueError("tool reference must bind to the enclosing registry revision")
        if refs != sorted(refs):
            raise ValueError("tools must be sorted by ToolRef")
        return self


class AvailableToolView(StrictImmutableBoundaryModel):
    tool_ref: ToolRef
    display_name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    parameter_schema: CanonicalJsonObject
    requires_session: bool
    eligible_session_ids: tuple[str, ...]

    @field_validator("eligible_session_ids")
    @classmethod
    def sorted_sessions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("eligible sessions must be sorted and unique")
        return value


class AvailableToolSnapshot(StrictImmutableBoundaryModel):
    snapshot_id: str = Field(min_length=1)
    snapshot_digest: str = Field(min_length=1)
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
    created_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def snapshot_invariants(self) -> AvailableToolSnapshot:
        if self.created_at >= self.expires_at:
            raise ValueError("snapshot created_at must be before expires_at")
        refs = [(item.tool_ref.tool_id, item.tool_ref.registry_revision) for item in self.tools]
        if refs != sorted(set(refs)):
            raise ValueError("available tools must be sorted and unique")
        return self
