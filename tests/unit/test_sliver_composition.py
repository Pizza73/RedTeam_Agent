"""The production Sliver builder accepts only live qualified evidence."""

from __future__ import annotations

import inspect

import pytest

import support
from redteam_agent.adapters.sliver import (
    SliverConnectionPolicy,
    build_sliver_foundation_profile,
)
from redteam_agent.adapters.sliver_composition import build_sliver_linux_adapter
from redteam_agent.adapters.sliver_contract import SliverRpcContractV177
from redteam_agent.adapters.sliver_transport import (
    SliverTransportAttestation,
    finalize_sliver_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError
from redteam_agent.runtime.clock import ManualClock


def test_builder_has_no_transport_or_operator_config_injection() -> None:
    assert set(inspect.signature(build_sliver_linux_adapter).parameters) == {
        "profile",
        "attestation",
        "clock",
        "digest_service",
    }


def test_offline_attestation_cannot_enter_the_production_composition() -> None:
    digests = DigestService()
    connection = SliverConnectionPolicy(
        operator_config_secret_version_id="secret://sliver/operator#v1",
        operator_config_sha256="1" * 64,
        server_address="10.0.0.2",
        server_port=31337,
        server_tls_name="multiplayer",
        ca_certificate_sha256="2" * 64,
        operator_certificate_sha256="3" * 64,
    )
    profile = build_sliver_foundation_profile(
        digest_service=digests, connection=connection
    )
    attestation = finalize_sliver_transport_attestation(
        SliverTransportAttestation(
            evidence_kind="test_double",
            production_eligible=False,
            adapter_profile_digest=profile.profile_digest,
            contract_digest=SliverRpcContractV177().contract_digest(digests),
            operator_config_secret_version_id="secret://sliver/operator#v1",
            operator_config_sha256="1" * 64,
            server_address="10.0.0.2",
            server_port=31337,
            server_tls_name="multiplayer",
            ca_certificate_sha256="2" * 64,
            operator_certificate_sha256="3" * 64,
            server_identity_verified=False,
            operator_identity_verified=False,
            http_beacon_verified=False,
            attested_at=support.T0,
            attestation_digest="0" * 64,
        ),
        digests,
    )
    with pytest.raises(C2AdapterUnavailableError):
        build_sliver_linux_adapter(
            profile=profile,
            attestation=attestation,
            clock=ManualClock(support.T0),
            digest_service=digests,
        )
