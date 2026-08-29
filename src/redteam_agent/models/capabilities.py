"""Security-relevant capability snapshots used by availability and authorization."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .base import StrictImmutableBoundaryModel
from .common import UtcDatetime


class SessionSecurityContext(StrictImmutableBoundaryModel):
    session_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    os: Literal["windows", "linux", "macos", "other"]
    architecture: str = Field(min_length=1)
    current_principal: str = Field(min_length=1)
    effective_privilege_context: str = Field(min_length=1)
    capabilities: frozenset[str]
    network_context: tuple[str, ...]
    status: Literal["active", "inactive", "lost"]


class SessionSecurityContextSnapshot(StrictImmutableBoundaryModel):
    snapshot_id: str = Field(min_length=1)
    snapshot_digest: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    contexts: tuple[SessionSecurityContext, ...]
    source: str = Field(min_length=1)
    created_at: UtcDatetime

    @model_validator(mode="after")
    def sorted_unique_contexts(self) -> "SessionSecurityContextSnapshot":
        ids = tuple(item.session_id for item in self.contexts)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("session contexts must be sorted and unique")
        return self


class AdapterCapabilities(StrictImmutableBoundaryModel):
    adapter_type: Literal["c2", "mcp", "local"]
    adapter_id: str = Field(min_length=1)
    runtime_id: str = Field(min_length=1)
    capabilities: frozenset[str]
    provider_tool_catalog_digest: str = Field(min_length=1)
    supported_os: frozenset[Literal["windows", "linux", "macos", "other"]]
    supported_architectures: frozenset[str]
    available: bool


class AdapterCapabilitySnapshot(StrictImmutableBoundaryModel):
    snapshot_id: str = Field(min_length=1)
    snapshot_digest: str = Field(min_length=1)
    adapters: tuple[AdapterCapabilities, ...]
    source: str = Field(min_length=1)
    created_at: UtcDatetime

    @model_validator(mode="after")
    def sorted_unique_adapters(self) -> "AdapterCapabilitySnapshot":
        ids = tuple((item.adapter_type, item.adapter_id) for item in self.adapters)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("adapter capabilities must be sorted and unique")
        return self


class SandboxCapabilities(StrictImmutableBoundaryModel):
    sandbox_id: str = Field(min_length=1)
    runtime_id: str = Field(min_length=1)
    adapter_id: str = Field(min_length=1)
    execution_location: Literal[
        "local_process", "managed_remote", "untrusted_remote", "not_applicable"
    ]
    dedicated_os_user: bool
    process_isolation: bool
    container_or_namespace: bool
    filesystem_allowlist: bool
    network_egress_control: bool
    environment_allowlist: bool
    secret_injection_control: bool
    cpu_limit: bool
    memory_limit: bool
    process_limit: bool


class SandboxCapabilitySnapshot(StrictImmutableBoundaryModel):
    snapshot_id: str = Field(min_length=1)
    snapshot_digest: str = Field(min_length=1)
    sandboxes: tuple[SandboxCapabilities, ...]
    source: str = Field(min_length=1)
    created_at: UtcDatetime

    @model_validator(mode="after")
    def sorted_unique_sandboxes(self) -> "SandboxCapabilitySnapshot":
        ids = tuple(item.sandbox_id for item in self.sandboxes)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("sandbox capabilities must be sorted and unique")
        return self


class RemoteMCPTrust(StrictImmutableBoundaryModel):
    adapter_id: str = Field(min_length=1)
    execution_location: Literal["local_process", "managed_remote", "untrusted_remote", "not_applicable"]
    stable_transport_identity: bool
    scope_enforcement: bool
    authentication_authorization: bool
    audit: bool
    network_egress_enforcement: bool
    sandbox_process_isolation: bool
    explicitly_allowed_read_only: bool = False


class RemoteMCPTrustSnapshot(StrictImmutableBoundaryModel):
    snapshot_id: str = Field(min_length=1)
    snapshot_digest: str = Field(min_length=1)
    policies: tuple[RemoteMCPTrust, ...]
    source: str = Field(min_length=1)
    created_at: UtcDatetime

    @model_validator(mode="after")
    def sorted_unique_policies(self) -> "RemoteMCPTrustSnapshot":
        ids = tuple(item.adapter_id for item in self.policies)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("remote trust policies must be sorted and unique")
        return self
