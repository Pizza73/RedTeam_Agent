"""Offline readiness evidence remains useful but non-production."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redteam_agent.adapters.tuoni import (
    TuoniProviderPin,
    build_tuoni_foundation_profile,
)
from redteam_agent.adapters.tuoni_contract import TuoniApiContractV0161
from redteam_agent.adapters.tuoni_readiness import (
    build_tuoni_offline_readiness_report,
    verify_tuoni_offline_readiness_report,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterQualificationError, DigestIntegrityError
from redteam_agent.runtime.clock import ManualClock

NOW = datetime(2026, 9, 13, 8, 0, tzinfo=UTC)


def test_default_offline_report_proves_static_coverage_and_retains_live_blockers() -> None:
    digest_service = DigestService()
    profile = build_tuoni_foundation_profile(digest_service=digest_service)
    report = build_tuoni_offline_readiness_report(
        profile=profile,
        contract=TuoniApiContractV0161(),
        clock=ManualClock(NOW),
        digest_service=digest_service,
    )

    verify_tuoni_offline_readiness_report(report, digest_service)
    assert report.offline_implementation_ready is True
    assert report.evidence_kind == "test_double"
    assert report.production_eligible is False
    assert report.openapi_sha256 is None
    assert report.implemented_operations == (
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
    assert report.configuration_blockers == (
        "tls_certificate_unresolved",
        "credential_secret_reference_unresolved",
        "vcenter_port_group_unresolved",
        "openapi_digest_unresolved",
        "command_template_allowlist_empty",
        "openapi_artifact_live_unverified",
        "target_operating_system_edition_live_unverified",
        "target_architecture_live_unverified",
        "live_provider_attestation_unverified",
    )


def test_approved_template_removes_only_the_offline_allowlist_blocker() -> None:
    digest_service = DigestService()
    report = build_tuoni_offline_readiness_report(
        profile=build_tuoni_foundation_profile(digest_service=digest_service),
        contract=TuoniApiContractV0161(approved_command_templates=("ps",)),
        clock=ManualClock(NOW),
        digest_service=digest_service,
    )

    assert "command_template_allowlist_empty" not in report.configuration_blockers
    assert "live_provider_attestation_unverified" in report.configuration_blockers
    assert report.production_eligible is False


def test_offline_report_rejects_a_different_provider_release() -> None:
    digest_service = DigestService()
    profile = build_tuoni_foundation_profile(
        digest_service=digest_service,
        provider=TuoniProviderPin(server_version="candidate-version"),
    )

    with pytest.raises(C2AdapterQualificationError):
        build_tuoni_offline_readiness_report(
            profile=profile,
            contract=TuoniApiContractV0161(),
            clock=ManualClock(NOW),
            digest_service=digest_service,
        )


def test_offline_report_digest_tampering_is_rejected() -> None:
    digest_service = DigestService()
    report = build_tuoni_offline_readiness_report(
        profile=build_tuoni_foundation_profile(digest_service=digest_service),
        contract=TuoniApiContractV0161(),
        clock=ManualClock(NOW),
        digest_service=digest_service,
    ).model_copy(update={"report_digest": "f" * 64})

    with pytest.raises(DigestIntegrityError):
        verify_tuoni_offline_readiness_report(report, digest_service)
