"""Fixed Linux composition for the Sliver read/control adapter."""

from __future__ import annotations

from redteam_agent.adapters.sliver import SliverFoundationProfile
from redteam_agent.adapters.sliver_adapter import SliverAdapter
from redteam_agent.adapters.sliver_contract import SliverRpcContractV173
from redteam_agent.adapters.sliver_linux_transport import SliverLinuxProcessTransport
from redteam_agent.adapters.sliver_transport import SliverTransportAttestation
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError
from redteam_agent.runtime.clock import Clock


def build_sliver_linux_adapter(
    *,
    profile: SliverFoundationProfile,
    attestation: SliverTransportAttestation,
    clock: Clock,
    digest_service: DigestService,
) -> SliverAdapter:
    if profile.configuration_blockers():
        raise C2AdapterUnavailableError(
            "Sliver Linux composition requires every deployment identity"
        )
    if attestation.evidence_kind != "live" or not attestation.production_eligible:
        raise C2AdapterUnavailableError(
            "Sliver Linux composition requires production-eligible live evidence"
        )
    contract = SliverRpcContractV173()
    transport = SliverLinuxProcessTransport(attestation)
    return SliverAdapter(
        profile=profile,
        contract=contract,
        transport=transport,
        clock=clock,
        digest_service=digest_service,
    )


__all__ = ["build_sliver_linux_adapter"]
