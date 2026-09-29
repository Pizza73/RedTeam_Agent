"""Print non-production Sliver readiness evidence without network access."""

from __future__ import annotations

import shutil

from redteam_agent.adapters.sliver import build_sliver_foundation_profile
from redteam_agent.adapters.sliver_contract import SliverRpcContractV177
from redteam_agent.adapters.sliver_readiness import build_sliver_offline_readiness_report
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.runtime.clock import SystemUtcClock


def main() -> int:
    digest_service = DigestService()
    binary_discovered = any(
        shutil.which(name) is not None
        for name in ("sliver-client", "sliver-server", "sliver")
    )
    report = build_sliver_offline_readiness_report(
        profile=build_sliver_foundation_profile(digest_service=digest_service),
        contract=SliverRpcContractV177(),
        binary_discovered=binary_discovered,
        beacon_present=False,
        clock=SystemUtcClock(),
        digest_service=digest_service,
    )
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
