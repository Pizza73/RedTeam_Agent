"""Print non-production Phase 4 readiness evidence without network access."""

from __future__ import annotations

from redteam_agent.adapters.tuoni import build_tuoni_foundation_profile
from redteam_agent.adapters.tuoni_contract import TuoniApiContractV0161
from redteam_agent.adapters.tuoni_readiness import (
    build_tuoni_offline_readiness_report,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.runtime.clock import SystemUtcClock


def main() -> int:
    digest_service = DigestService()
    report = build_tuoni_offline_readiness_report(
        profile=build_tuoni_foundation_profile(digest_service=digest_service),
        contract=TuoniApiContractV0161(),
        clock=SystemUtcClock(),
        digest_service=digest_service,
    )
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
