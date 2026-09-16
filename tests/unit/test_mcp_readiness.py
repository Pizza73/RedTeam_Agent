"""Non-promotable Phase 5 offline readiness evidence."""

from __future__ import annotations

import pytest

import support
from redteam_agent.adapters.mcp import build_mcp_foundation_profile
from redteam_agent.adapters.mcp_contract import MCPApiContractV20260728
from redteam_agent.adapters.mcp_readiness import (
    build_mcp_offline_readiness_report,
    verify_mcp_offline_readiness_report,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import DigestIntegrityError
from redteam_agent.runtime.clock import ManualClock


def test_default_report_is_offline_ready_but_production_blocked() -> None:
    ds = DigestService()
    report = build_mcp_offline_readiness_report(
        profile=build_mcp_foundation_profile(digest_service=ds),
        contract=MCPApiContractV20260728(digest_service=ds),
        clock=ManualClock(support.T0),
        digest_service=ds,
    )

    assert report.offline_implementation_ready is True
    assert report.production_eligible is False
    assert report.task_implementation_mode == "disabled"
    assert report.implemented_operations == (
        "server_discover",
        "tools_list",
        "tools_call",
    )
    assert "mcp_server_product_unresolved" in report.configuration_blockers
    assert "mcp_production_integration_unverified" in report.configuration_blockers
    verify_mcp_offline_readiness_report(report, ds)


def test_report_tamper_is_detected() -> None:
    ds = DigestService()
    report = build_mcp_offline_readiness_report(
        profile=build_mcp_foundation_profile(digest_service=ds),
        contract=MCPApiContractV20260728(digest_service=ds),
        clock=ManualClock(support.T0),
        digest_service=ds,
    ).model_copy(update={"contract_digest": "f" * 64})
    with pytest.raises(DigestIntegrityError):
        verify_mcp_offline_readiness_report(report, ds)
