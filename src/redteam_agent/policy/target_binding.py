"""Target dispatch binding (SystemDesign §13 / §22.2).

Phase 0A resolves the binding mode from the intersection of the tool's required
binding modes and the adapter's advertised binding modes. There is no external
dispatch; the binding is a signed (digest-bound) part of the authorization
intent, and redirects are always disabled in the MVP.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.policy.scope_models import NormalizedTarget

TargetBindingMode = Literal[
    "exact_ip_enforced",
    "local_resolver_pinned",
    "provider_attested",
    "none",
]

# Deterministic preference order when multiple modes are available.
_MODE_PREFERENCE: tuple[TargetBindingMode, ...] = (
    "exact_ip_enforced",
    "local_resolver_pinned",
    "provider_attested",
    "none",
)


class TargetDispatchBinding(StrictImmutableBoundaryModel):
    normalized_target: NormalizedTarget
    binding_mode: TargetBindingMode
    connection_addresses: tuple[str, ...]
    dns_resolution_digest: str | None
    redirect_mode: Literal["disabled"] = "disabled"
    binding_digest: str = Field(min_length=1)


def select_binding_mode(
    required_modes: frozenset[TargetBindingMode],
    adapter_modes: frozenset[TargetBindingMode],
) -> TargetBindingMode | None:
    """Choose the preferred mode from the intersection, or ``None`` if empty."""
    intersection = required_modes & adapter_modes
    for mode in _MODE_PREFERENCE:
        if mode in intersection:
            return mode
    return None


def build_target_dispatch_binding(
    *,
    normalized_target: NormalizedTarget,
    binding_mode: TargetBindingMode,
    connection_addresses: tuple[str, ...],
    digest_service: DigestService,
) -> TargetDispatchBinding:
    payload = {
        "normalized_target": _target_payload(normalized_target),
        "binding_mode": binding_mode,
        "connection_addresses": sorted(connection_addresses),
        "redirect_mode": "disabled",
    }
    digest = digest_service.compute("binding_digest", payload)
    return TargetDispatchBinding(
        normalized_target=normalized_target,
        binding_mode=binding_mode,
        connection_addresses=connection_addresses,
        dns_resolution_digest=None,
        binding_digest=digest,
    )


def _target_payload(target: NormalizedTarget) -> dict[str, object]:
    return {
        "type": target.type,
        "canonical_value": target.canonical_value,
        "host_ref": target.host_ref,
        "port": target.port,
        "protocol": target.protocol,
        "resolved_addresses": sorted(target.resolved_addresses),
        "source": target.source,
    }
