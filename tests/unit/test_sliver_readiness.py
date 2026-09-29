"""Offline evidence remains separate from Sliver production activation."""

from __future__ import annotations

import pytest

import support
from redteam_agent.adapters.sliver import build_sliver_foundation_profile
from redteam_agent.adapters.sliver_contract import SliverRpcContractV177
from redteam_agent.adapters.sliver_readiness import (
    build_sliver_offline_readiness_report,
    verify_sliver_offline_readiness_report,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import DigestIntegrityError
from redteam_agent.runtime.clock import ManualClock


def test_offline_report_records_current_environment_blockers() -> None:
    digests = DigestService()
    report = build_sliver_offline_readiness_report(
        profile=build_sliver_foundation_profile(digest_service=digests),
        contract=SliverRpcContractV177(),
        binary_discovered=False,
        beacon_present=False,
        clock=ManualClock(support.T0),
        digest_service=digests,
    )
    verify_sliver_offline_readiness_report(report, digests)

    assert report.offline_implementation_ready is True
    assert report.production_eligible is False
    assert report.implant_transport == "http"
    assert "sliver_binary_not_discovered" in report.configuration_blockers
    assert "http_beacon_unavailable" in report.configuration_blockers
    assert report.implemented_operations[-1] == "cancel_beacon_task"


def test_readiness_digest_detects_tampering() -> None:
    digests = DigestService()
    report = build_sliver_offline_readiness_report(
        profile=build_sliver_foundation_profile(digest_service=digests),
        contract=SliverRpcContractV177(),
        binary_discovered=False,
        beacon_present=False,
        clock=ManualClock(support.T0),
        digest_service=digests,
    )
    with pytest.raises(DigestIntegrityError):
        verify_sliver_offline_readiness_report(
            report.model_copy(update={"report_digest": "f" * 64}), digests
        )
