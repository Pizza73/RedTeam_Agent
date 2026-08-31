"""Sandbox policy and fail-closed capability checks for later execution phases."""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from redteam_agent.errors import SandboxCapabilityStaleError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.capabilities import SandboxCapabilities
from redteam_agent.models.scope import NormalizedTarget


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


class SandboxPolicy(StrictImmutableBoundaryModel):
    sandbox_id: str = Field(min_length=1)
    filesystem_allowlist: tuple[str, ...]
    allowed_egress_targets: tuple[NormalizedTarget, ...]
    allowed_environment_keys: frozenset[str]
    cpu_limit_millis: int | None = Field(default=None, gt=0)
    memory_limit_bytes: int | None = Field(default=None, gt=0)
    process_limit: int | None = Field(default=None, gt=0)

    @field_validator("filesystem_allowlist")
    @classmethod
    def canonical_absolute_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        from pathlib import Path

        paths = tuple(str(Path(item).resolve(strict=False)) for item in value)
        has_relative_path = any(not Path(item).is_absolute() for item in value)
        if paths != tuple(sorted(set(paths))) or has_relative_path:
            raise ValueError("filesystem allowlist must contain sorted unique absolute paths")
        return paths

    @model_validator(mode="after")
    def sorted_environment_keys(self) -> SandboxPolicy:
        if any(not key or "=" in key for key in self.allowed_environment_keys):
            raise ValueError("sandbox environment allowlist contains an invalid key")
        return self


def require_sandbox_capabilities(
    *,
    requirement: SandboxRequirement,
    policy: SandboxPolicy,
    capabilities: SandboxCapabilities,
    expected_runtime_id: str,
    expected_adapter_id: str,
) -> None:
    if not (
        capabilities.sandbox_id == policy.sandbox_id
        and capabilities.runtime_id == expected_runtime_id
        and capabilities.adapter_id == expected_adapter_id
    ):
        raise SandboxCapabilityStaleError("sandbox runtime binding is stale")
    checks = (
        (requirement.dedicated_os_user, capabilities.dedicated_os_user),
        (requirement.process_isolation, capabilities.process_isolation),
        (requirement.container_or_namespace, capabilities.container_or_namespace),
        (requirement.filesystem_allowlist_required, capabilities.filesystem_allowlist),
        (requirement.network_egress_control_required, capabilities.network_egress_control),
        (requirement.environment_allowlist_required, capabilities.environment_allowlist),
        (requirement.secret_injection_control_required, capabilities.secret_injection_control),
        (requirement.cpu_limit_required, capabilities.cpu_limit),
        (requirement.memory_limit_required, capabilities.memory_limit),
        (requirement.process_limit_required, capabilities.process_limit),
    )
    if any(required and not available for required, available in checks):
        raise SandboxCapabilityStaleError("required sandbox enforcement is unavailable")
    resource_limits = (
        (requirement.cpu_limit_required, policy.cpu_limit_millis),
        (requirement.memory_limit_required, policy.memory_limit_bytes),
        (requirement.process_limit_required, policy.process_limit),
    )
    if any(required and limit is None for required, limit in resource_limits):
        raise SandboxCapabilityStaleError("required sandbox resource limit is undefined")
