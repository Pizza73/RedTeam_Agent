"""Offline-only readiness evidence for the pinned Tuoni adapter.

The report proves that every implementation property that can be established
without a provider is present and digest-bound.  It deliberately remains
``test_double`` evidence and can never authorize production activation.  Live
TLS, credential, vCenter, target, and provider observations stay explicit
blockers instead of being replaced with synthetic values.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from redteam_agent.adapters.tuoni import (
    TUONI_SERVER_IMAGE_DIGEST_PIN,
    TUONI_SOURCE_COMMIT_PIN,
    TUONI_VERSION_PIN,
    TuoniFoundationProfile,
)
from redteam_agent.adapters.tuoni_contract import (
    TuoniApiContractV0161,
    TuoniOperation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterQualificationError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.runtime.clock import Clock

_SHA256_PATTERN = r"^[0-9a-f]{64}$"

type TuoniOfflineBlocker = Literal[
    "tls_certificate_unresolved",
    "credential_secret_reference_unresolved",
    "vcenter_port_group_unresolved",
    "openapi_digest_unresolved",
    "openapi_artifact_live_unverified",
    "command_template_allowlist_empty",
    "target_operating_system_edition_live_unverified",
    "target_architecture_live_unverified",
    "live_provider_attestation_unverified",
]

_IMPLEMENTED_OPERATIONS: tuple[TuoniOperation, ...] = (
    "openapi",
    "current_user",
    "permissions",
    "list_active_agents",
    "get_agent",
    "list_agent_command_templates",
    "submit_command",
    "get_command",
    "stop_command",
)


class TuoniOfflineReadinessReport(StrictImmutableBoundaryModel):
    """Digest-bound evidence that is useful for review but never activation."""

    report_revision: Literal["tuoni-offline-readiness-v1"] = (
        "tuoni-offline-readiness-v1"
    )
    evidence_kind: Literal["test_double"] = "test_double"
    provider_product: Literal["tuoni"] = "tuoni"
    provider_edition: Literal["commercial"] = "commercial"
    provider_version: Literal["0.16.1"] = "0.16.1"
    source_commit: Literal[
        "7d9a2057b309481c530f7c7a71b4ad2f8c5a615e"
    ] = "7d9a2057b309481c530f7c7a71b4ad2f8c5a615e"
    openapi_sha256: None = None
    container_image_digest: Literal[
        "sha256:e1e24a1f0fcee7ce8728f1d7fd0790da116651505c6ad88afe58daf1067d6e95"
    ] = "sha256:e1e24a1f0fcee7ce8728f1d7fd0790da116651505c6ad88afe58daf1067d6e95"
    contract_revision: Literal["tuoni-rest-0.16.1-v1"] = (
        "tuoni-rest-0.16.1-v1"
    )
    profile_digest: str = Field(pattern=_SHA256_PATTERN)
    contract_digest: str = Field(pattern=_SHA256_PATTERN)
    implemented_operations: tuple[TuoniOperation, ...]
    configuration_blockers: tuple[TuoniOfflineBlocker, ...]
    offline_implementation_ready: Literal[True] = True
    production_eligible: Literal[False] = False
    evaluated_at: datetime
    report_digest: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Tuoni readiness time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _offline_evidence_cannot_claim_live_readiness(self) -> TuoniOfflineReadinessReport:
        if self.implemented_operations != _IMPLEMENTED_OPERATIONS:
            raise ValueError("Tuoni readiness operation coverage is incomplete")
        if "live_provider_attestation_unverified" not in self.configuration_blockers:
            raise ValueError("offline evidence must retain the live-provider blocker")
        if "openapi_artifact_live_unverified" not in self.configuration_blockers:
            raise ValueError("offline evidence must retain the live-OpenAPI blocker")
        if "target_architecture_live_unverified" not in self.configuration_blockers:
            raise ValueError("offline evidence must retain the target-architecture blocker")
        if (
            "target_operating_system_edition_live_unverified"
            not in self.configuration_blockers
        ):
            raise ValueError("offline evidence must retain the target-edition blocker")
        return self


def build_tuoni_offline_readiness_report(
    *,
    profile: TuoniFoundationProfile,
    contract: TuoniApiContractV0161,
    clock: Clock,
    digest_service: DigestService,
) -> TuoniOfflineReadinessReport:
    """Verify the static release/profile contract and emit non-production evidence."""

    profile_payload = profile.model_dump(mode="python")
    expected_profile_digest = str(profile_payload.pop("profile_digest"))
    digest_service.verify(
        "tuoni_provider_profile_digest",
        profile_payload,
        expected_profile_digest,
    )
    provider = profile.provider
    if (
        provider.product != "tuoni"
        or provider.edition != "commercial"
        or provider.server_version != TUONI_VERSION_PIN
        or provider.source_commit != TUONI_SOURCE_COMMIT_PIN
        or provider.container_image_digest != TUONI_SERVER_IMAGE_DIGEST_PIN
    ):
        raise C2AdapterQualificationError(
            "Tuoni offline readiness requires the exact approved provider release"
        )

    blockers: list[TuoniOfflineBlocker] = []
    if profile.connection.tls_certificate_sha256 is None:
        blockers.append("tls_certificate_unresolved")
    if profile.authentication.credential_secret_version_id is None:
        blockers.append("credential_secret_reference_unresolved")
    if profile.isolation.vcenter_port_group_name is None:
        blockers.append("vcenter_port_group_unresolved")
    if profile.provider.openapi_sha256 is None:
        blockers.append("openapi_digest_unresolved")
    if not contract.approved_command_templates:
        blockers.append("command_template_allowlist_empty")
    blockers.extend(
        (
            "openapi_artifact_live_unverified",
            "target_operating_system_edition_live_unverified",
            "target_architecture_live_unverified",
            "live_provider_attestation_unverified",
        )
    )
    blocker_values = tuple(blockers)
    contract_digest = contract.contract_digest(digest_service)
    evaluated_at = clock.now()
    draft = TuoniOfflineReadinessReport(
        implemented_operations=_IMPLEMENTED_OPERATIONS,
        configuration_blockers=blocker_values,
        profile_digest=profile.profile_digest,
        contract_digest=contract_digest,
        evaluated_at=evaluated_at,
        report_digest="0" * 64,
    )
    report_digest = digest_service.compute(
        "tuoni_offline_readiness_report_digest",
        draft.model_dump(mode="python"),
    )
    return TuoniOfflineReadinessReport(
        implemented_operations=_IMPLEMENTED_OPERATIONS,
        configuration_blockers=blocker_values,
        profile_digest=profile.profile_digest,
        contract_digest=contract_digest,
        evaluated_at=evaluated_at,
        report_digest=report_digest,
    )


def verify_tuoni_offline_readiness_report(
    report: TuoniOfflineReadinessReport,
    digest_service: DigestService,
) -> None:
    """Verify report integrity while preserving its non-production provenance."""

    digest_service.verify(
        "tuoni_offline_readiness_report_digest",
        report.model_dump(mode="python"),
        report.report_digest,
    )
    if report.evidence_kind != "test_double" or report.production_eligible:
        raise C2AdapterQualificationError(
            "offline Tuoni readiness evidence cannot authorize production"
        )


__all__ = [
    "TuoniOfflineBlocker",
    "TuoniOfflineReadinessReport",
    "build_tuoni_offline_readiness_report",
    "verify_tuoni_offline_readiness_report",
]
