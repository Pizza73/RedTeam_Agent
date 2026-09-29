"""Trusted Linux composition for the production-shaped Tuoni adapter.

This is the only product constructor that wires the concrete HTTPS process
transport.  It accepts no transport factory, endpoint, credential path,
subprocess command, proxy, or retry option, preventing test doubles and caller
routing choices from entering the production-shaped adapter composition.
"""

from __future__ import annotations

from collections.abc import Iterable

from redteam_agent.adapters.tuoni import TuoniFoundationProfile
from redteam_agent.adapters.tuoni_adapter import TuoniAdapter
from redteam_agent.adapters.tuoni_contract import TuoniApiContractV0161
from redteam_agent.adapters.tuoni_linux_transport import TuoniLinuxProcessTransport
from redteam_agent.adapters.tuoni_transport import TuoniTransportAttestation
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError
from redteam_agent.runtime.clock import Clock


def build_tuoni_linux_adapter(
    *,
    profile: TuoniFoundationProfile,
    attestation: TuoniTransportAttestation,
    approved_command_templates: Iterable[str],
    clock: Clock,
    digest_service: DigestService,
) -> TuoniAdapter:
    """Build the fixed Ubuntu transport and exact Tuoni 0.16.1 adapter.

    Deployment identities are checked before the OS-specific transport is
    constructed.  An incomplete profile therefore fails before subprocess,
    file, credential, or network access.
    """

    if profile.configuration_blockers():
        raise C2AdapterUnavailableError(
            "Tuoni Linux composition requires every deployment identity"
        )
    contract = TuoniApiContractV0161(
        approved_command_templates=approved_command_templates
    )
    transport = TuoniLinuxProcessTransport(attestation)
    return TuoniAdapter(
        profile=profile,
        contract=contract,
        transport=transport,
        clock=clock,
        digest_service=digest_service,
    )


__all__ = ["build_tuoni_linux_adapter"]
