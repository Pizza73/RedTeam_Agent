"""Print non-production Phase 5 readiness evidence without network access."""

from __future__ import annotations

from redteam_agent.adapters.mcp import build_mcp_foundation_profile
from redteam_agent.adapters.mcp_contract import MCPApiContractV20260728
from redteam_agent.adapters.mcp_readiness import build_mcp_offline_readiness_report
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.runtime.clock import SystemUtcClock


def main() -> int:
    digest_service = DigestService()
    report = build_mcp_offline_readiness_report(
        profile=build_mcp_foundation_profile(digest_service=digest_service),
        contract=MCPApiContractV20260728(digest_service=digest_service),
        clock=SystemUtcClock(),
        digest_service=digest_service,
    )
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
