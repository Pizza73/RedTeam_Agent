"""Fail-closed Sliver provider foundation tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redteam_agent.adapters.sliver import (
    SLIVER_SOURCE_COMMIT_PIN,
    SLIVER_VERSION_PIN,
    SliverAdapterFoundation,
    SliverConnectionPolicy,
    build_sliver_foundation_profile,
)
from redteam_agent.canonical.digest_catalog import DEFAULT_DIGEST_CATALOG
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError, DigestIntegrityError


def test_defaults_capture_the_approved_release_and_user_inputs() -> None:
    profile = build_sliver_foundation_profile(digest_service=DigestService())

    assert profile.provider.version == SLIVER_VERSION_PIN
    assert profile.provider.source_commit == SLIVER_SOURCE_COMMIT_PIN
    assert profile.connection.operator_name == "joe"
    assert profile.connection.operator_config_location_hint == "downloads"
    assert profile.connection.operator_channel == "grpc_mtls_direct"
    assert profile.target.implant_transport == "http"
    assert profile.target.existing_beacon_required_for_activation is True
    assert profile.target.implant_generation_allowed is False
    assert profile.target.arbitrary_command_allowed is False
    assert profile.configuration_blockers() == (
        "operator_config_secret_reference_unresolved",
        "operator_config_digest_unresolved",
        "operator_server_endpoint_unresolved",
        "operator_ca_certificate_unresolved",
        "operator_certificate_unresolved",
    )


def test_foundation_is_structurally_available_but_never_operational() -> None:
    digests = DigestService()
    adapter = SliverAdapterFoundation(
        build_sliver_foundation_profile(digest_service=digests), digests
    )

    assert adapter.identity().adapter_id == "sliver-c2"
    assert adapter.activation_blockers()[-3:] == (
        "grpc_mtls_transport_unconfigured",
        "live_provider_attestation_unverified",
        "http_beacon_unavailable",
    )
    with pytest.raises(C2AdapterUnavailableError):
        adapter.list_sessions()


def test_connection_requires_an_atomic_canonical_server_identity() -> None:
    with pytest.raises(ValidationError):
        SliverConnectionPolicy(server_address="10.0.0.2")
    with pytest.raises(ValidationError):
        SliverConnectionPolicy(
            server_address="10.0.0.2:31337",
            server_port=31337,
            server_tls_name="multiplayer",
        )


def test_security_relevant_change_changes_profile_digest() -> None:
    digests = DigestService()
    unresolved = build_sliver_foundation_profile(digest_service=digests)
    configured = build_sliver_foundation_profile(
        digest_service=digests,
        connection=SliverConnectionPolicy(
            operator_config_secret_version_id="secret://sliver/operator#v1",
            operator_config_sha256="1" * 64,
            server_address="10.0.0.2",
            server_port=31337,
            server_tls_name="multiplayer",
            ca_certificate_sha256="2" * 64,
            operator_certificate_sha256="3" * 64,
        ),
    )
    assert unresolved.profile_digest != configured.profile_digest


def test_tampered_profile_digest_is_rejected() -> None:
    digests = DigestService()
    profile = build_sliver_foundation_profile(digest_service=digests)
    with pytest.raises(DigestIntegrityError):
        SliverAdapterFoundation(
            profile.model_copy(update={"profile_digest": "f" * 64}), digests
        )


def test_sliver_digest_definitions_are_registered() -> None:
    assert {
        "sliver_provider_profile_digest",
        "sliver_rpc_contract_digest",
        "sliver_transport_attestation_digest",
        "sliver_adapter_identity_digest",
        "sliver_offline_readiness_report_digest",
    } <= DEFAULT_DIGEST_CATALOG.names()
