"""Digest-bound offline readiness evidence for Sliver v1.7.3."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, cast

from pydantic import Field, field_validator, model_validator

from redteam_agent.adapters.sliver import (
    SLIVER_SOURCE_COMMIT_PIN,
    SLIVER_VERSION_PIN,
    SliverFoundationProfile,
)
from redteam_agent.adapters.sliver_contract import SliverOperation, SliverRpcContractV173
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterQualificationError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.runtime.clock import Clock

type SliverOfflineBlocker = Literal[
    "operator_config_secret_reference_unresolved",
    "operator_config_digest_unresolved",
    "operator_server_endpoint_unresolved",
    "operator_ca_certificate_unresolved",
    "operator_certificate_unresolved",
    "sliver_binary_not_discovered",
    "live_provider_attestation_unverified",
    "http_beacon_unavailable",
]

_IMPLEMENTED_OPERATIONS: tuple[SliverOperation, ...] = (
    "get_version",
    "list_sessions",
    "list_beacons",
    "get_beacon",
    "list_beacon_tasks",
    "get_beacon_task_content",
    "cancel_beacon_task",
)


class SliverOfflineReadinessReport(StrictImmutableBoundaryModel):
    report_revision: Literal["sliver-offline-readiness-v1"] = "sliver-offline-readiness-v1"
    evidence_kind: Literal["test_double"] = "test_double"
    provider_product: Literal["sliver"] = "sliver"
    provider_version: Literal["1.7.3"] = "1.7.3"
    source_commit: Literal[
        "3bbaf805104dcc4a75414ee0084e8de50702cad4"
    ] = "3bbaf805104dcc4a75414ee0084e8de50702cad4"
    implant_transport: Literal["http"] = "http"
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    implemented_operations: tuple[SliverOperation, ...]
    configuration_blockers: tuple[SliverOfflineBlocker, ...]
    offline_implementation_ready: Literal[True] = True
    production_eligible: Literal[False] = False
    evaluated_at: datetime
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("evaluated_at")
    @classmethod
    def _time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Sliver readiness time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _offline_evidence_keeps_live_blockers(self) -> SliverOfflineReadinessReport:
        if self.implemented_operations != _IMPLEMENTED_OPERATIONS:
            raise ValueError("Sliver readiness operation coverage is incomplete")
        for blocker in (
            "live_provider_attestation_unverified",
            "http_beacon_unavailable",
        ):
            if blocker not in self.configuration_blockers:
                raise ValueError("Sliver offline evidence lacks a live blocker")
        return self


def build_sliver_offline_readiness_report(
    *,
    profile: SliverFoundationProfile,
    contract: SliverRpcContractV173,
    binary_discovered: bool,
    beacon_present: bool,
    clock: Clock,
    digest_service: DigestService,
) -> SliverOfflineReadinessReport:
    payload = profile.model_dump(mode="python")
    expected = str(payload.pop("profile_digest"))
    digest_service.verify("sliver_provider_profile_digest", payload, expected)
    if (
        profile.provider.version != SLIVER_VERSION_PIN
        or profile.provider.source_commit != SLIVER_SOURCE_COMMIT_PIN
        or profile.target.implant_transport != "http"
    ):
        raise C2AdapterQualificationError(
            "Sliver readiness requires the exact approved release and HTTP transport"
        )
    blockers = list(
        cast(tuple[SliverOfflineBlocker, ...], profile.configuration_blockers())
    )
    if not binary_discovered:
        blockers.append("sliver_binary_not_discovered")
    blockers.append("live_provider_attestation_unverified")
    if not beacon_present:
        blockers.append("http_beacon_unavailable")
    blocker_values = tuple(blockers)
    contract_digest = contract.contract_digest(digest_service)
    draft = SliverOfflineReadinessReport(
        profile_digest=profile.profile_digest,
        contract_digest=contract_digest,
        implemented_operations=_IMPLEMENTED_OPERATIONS,
        configuration_blockers=blocker_values,
        evaluated_at=clock.now(),
        report_digest="0" * 64,
    )
    report_digest = digest_service.compute(
        "sliver_offline_readiness_report_digest", draft.model_dump(mode="python")
    )
    return draft.model_copy(update={"report_digest": report_digest})


def verify_sliver_offline_readiness_report(
    report: SliverOfflineReadinessReport, digest_service: DigestService
) -> None:
    digest_service.verify(
        "sliver_offline_readiness_report_digest",
        report.model_dump(mode="python"),
        report.report_digest,
    )
    if report.evidence_kind != "test_double" or report.production_eligible:
        raise C2AdapterQualificationError(
            "offline Sliver readiness cannot authorize production"
        )


__all__ = [
    "SliverOfflineBlocker",
    "SliverOfflineReadinessReport",
    "build_sliver_offline_readiness_report",
    "verify_sliver_offline_readiness_report",
]
