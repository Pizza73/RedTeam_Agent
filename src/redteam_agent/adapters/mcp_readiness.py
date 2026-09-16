"""Digest-bound, non-production Phase 5 MCP offline readiness evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from redteam_agent.adapters.mcp import (
    MCP_PROTOCOL_REVISION,
    MCP_SCHEMA_SHA256,
    MCP_SPEC_COMMIT,
    MCPFoundationProfile,
)
from redteam_agent.adapters.mcp_contract import (
    MCP_API_CONTRACT_REVISION,
    MCPApiContractV20260728,
    MCPOperation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import MCPAdapterUnavailableError, MCPTaskCapabilityError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.runtime.clock import Clock

_SHA256_PATTERN = r"^[0-9a-f]{64}$"

type MCPOfflineBlocker = Literal[
    "mcp_server_product_unresolved",
    "mcp_server_config_unresolved",
    "mcp_trust_policy_unresolved",
    "mcp_transport_identity_unresolved",
    "mcp_production_transport_unselected",
    "mcp_sandbox_attestation_unverified",
    "mcp_approved_tool_catalog_empty",
    "mcp_live_discovery_unverified",
    "mcp_production_integration_unverified",
]

_IMPLEMENTED_OPERATIONS: tuple[MCPOperation, ...] = (
    "server_discover",
    "tools_list",
    "tools_call",
)


class MCPOfflineReadinessReport(StrictImmutableBoundaryModel):
    report_revision: Literal["mcp-offline-readiness-v1"] = (
        "mcp-offline-readiness-v1"
    )
    evidence_kind: Literal["offline_contract"] = "offline_contract"
    protocol_revision: Literal["2026-07-28"] = MCP_PROTOCOL_REVISION
    specification_commit: Literal[
        "5f5440bb26a62e2cf3440b92da5a667efa03b267"
    ] = MCP_SPEC_COMMIT
    schema_sha256: Literal[
        "ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203"
    ] = MCP_SCHEMA_SHA256
    contract_revision: Literal["mcp-2026-07-28-offline-v1"] = (
        MCP_API_CONTRACT_REVISION
    )
    profile_digest: str = Field(pattern=_SHA256_PATTERN)
    contract_digest: str = Field(pattern=_SHA256_PATTERN)
    implemented_operations: tuple[MCPOperation, ...]
    task_implementation_mode: Literal["disabled"] = "disabled"
    result_delivery_mode: Literal["local_result"] = "local_result"
    configuration_blockers: tuple[MCPOfflineBlocker, ...]
    offline_implementation_ready: Literal[True] = True
    production_eligible: Literal[False] = False
    evaluated_at: datetime
    report_digest: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("evaluated_at")
    @classmethod
    def _time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("MCP readiness time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _offline_evidence_retains_live_blockers(self) -> MCPOfflineReadinessReport:
        if self.implemented_operations != _IMPLEMENTED_OPERATIONS:
            raise ValueError("MCP offline operation coverage is incomplete")
        required_live_blockers = {
            "mcp_production_transport_unselected",
            "mcp_sandbox_attestation_unverified",
            "mcp_live_discovery_unverified",
            "mcp_production_integration_unverified",
        }
        if not required_live_blockers <= set(self.configuration_blockers):
            raise ValueError("MCP offline evidence must retain every live blocker")
        return self


def build_mcp_offline_readiness_report(
    *,
    profile: MCPFoundationProfile,
    contract: MCPApiContractV20260728,
    clock: Clock,
    digest_service: DigestService,
) -> MCPOfflineReadinessReport:
    profile_payload = profile.model_dump(mode="python")
    profile_digest = str(profile_payload.pop("profile_digest"))
    digest_service.verify(
        "mcp_provider_profile_digest", profile_payload, profile_digest
    )
    if (
        profile.server_config is not None
        and profile.server_config.task_implementation_mode != "disabled"
    ):
        raise MCPTaskCapabilityError(
            "offline MCP readiness only covers the disabled Tasks mode"
        )
    blockers: list[MCPOfflineBlocker] = []
    if profile.provider_product is None:
        blockers.append("mcp_server_product_unresolved")
    if profile.server_config is None:
        blockers.extend(
            ("mcp_server_config_unresolved", "mcp_transport_identity_unresolved")
        )
    if profile.trust_policy is None:
        blockers.append("mcp_trust_policy_unresolved")
    blockers.extend(
        (
            "mcp_production_transport_unselected",
            "mcp_sandbox_attestation_unverified",
        )
    )
    if not contract.approved_tools:
        blockers.append("mcp_approved_tool_catalog_empty")
    blockers.extend(
        ("mcp_live_discovery_unverified", "mcp_production_integration_unverified")
    )
    draft = MCPOfflineReadinessReport(
        profile_digest=profile.profile_digest,
        contract_digest=contract.contract_digest(),
        implemented_operations=_IMPLEMENTED_OPERATIONS,
        configuration_blockers=tuple(blockers),
        evaluated_at=clock.now(),
        report_digest="0" * 64,
    )
    report_digest = digest_service.compute(
        "mcp_offline_readiness_report_digest", draft.model_dump(mode="python")
    )
    return draft.model_copy(update={"report_digest": report_digest})


def verify_mcp_offline_readiness_report(
    report: MCPOfflineReadinessReport, digest_service: DigestService
) -> None:
    digest_service.verify(
        "mcp_offline_readiness_report_digest",
        report.model_dump(mode="python"),
        report.report_digest,
    )
    if report.production_eligible:
        raise MCPAdapterUnavailableError(
            "offline MCP readiness evidence cannot authorize production"
        )


__all__ = [
    "MCPOfflineBlocker",
    "MCPOfflineReadinessReport",
    "build_mcp_offline_readiness_report",
    "verify_mcp_offline_readiness_report",
]
