"""Sandbox requirement, capability and policy models (SystemDesign §19.3, H-04).

A ``SandboxCapabilities`` snapshot is bound to a specific execution location and
adapter/runtime, so a tool cannot borrow another runtime's capabilities, and a
local capability cannot stand in for a remote execution location. Unsupported
locations are Default Deny. The binding digest is an object-integrity digest.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel

ExecutionLocation = Literal["local_process", "managed_remote", "untrusted_remote"]


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


class SandboxCapabilities(StrictImmutableBoundaryModel):
    sandbox_id: str = Field(min_length=1)
    adapter_id: str = Field(min_length=1)
    execution_location: ExecutionLocation
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
    sandbox_binding_digest: str = Field(min_length=1)

    def satisfies(self, requirement: SandboxRequirement) -> bool:
        checks = (
            (requirement.dedicated_os_user, self.dedicated_os_user),
            (requirement.process_isolation, self.process_isolation),
            (requirement.container_or_namespace, self.container_or_namespace),
            (requirement.filesystem_allowlist_required, self.filesystem_allowlist),
            (requirement.network_egress_control_required, self.network_egress_control),
            (requirement.environment_allowlist_required, self.environment_allowlist),
            (requirement.secret_injection_control_required, self.secret_injection_control),
            (requirement.cpu_limit_required, self.cpu_limit),
            (requirement.memory_limit_required, self.memory_limit),
            (requirement.process_limit_required, self.process_limit),
        )
        return all((not required) or provided for required, provided in checks)


def _sandbox_payload(
    *,
    sandbox_id: str,
    adapter_id: str,
    execution_location: ExecutionLocation,
    capabilities: dict[str, bool],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "sandbox_id": sandbox_id,
        "adapter_id": adapter_id,
        "execution_location": execution_location,
    }
    payload.update(capabilities)
    return payload


def build_sandbox_capabilities(
    *,
    sandbox_id: str,
    adapter_id: str,
    execution_location: ExecutionLocation,
    digest_service: DigestService,
    all_enabled: bool = True,
) -> SandboxCapabilities:
    caps = {
        "dedicated_os_user": all_enabled,
        "process_isolation": all_enabled,
        "container_or_namespace": all_enabled,
        "filesystem_allowlist": all_enabled,
        "network_egress_control": all_enabled,
        "environment_allowlist": all_enabled,
        "secret_injection_control": all_enabled,
        "cpu_limit": all_enabled,
        "memory_limit": all_enabled,
        "process_limit": all_enabled,
    }
    digest = digest_service.compute(
        "sandbox_binding_digest",
        _sandbox_payload(
            sandbox_id=sandbox_id, adapter_id=adapter_id, execution_location=execution_location, capabilities=caps
        ),
    )
    return SandboxCapabilities(
        sandbox_id=sandbox_id,
        adapter_id=adapter_id,
        execution_location=execution_location,
        sandbox_binding_digest=digest,
        **caps,
    )
