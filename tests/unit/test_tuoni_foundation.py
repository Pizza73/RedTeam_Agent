"""Version-neutral Tuoni foundation configuration tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redteam_agent.adapters.tuoni import (
    TUONI_OPENAPI_SHA256_PIN,
    TUONI_SERVER_IMAGE_DIGEST_PIN,
    TUONI_SOURCE_COMMIT_PIN,
    TUONI_VERSION_PIN,
    TuoniAdapterFoundation,
    TuoniAuthenticationPolicy,
    TuoniConnectionPolicy,
    TuoniLabIsolationPolicy,
    TuoniProviderPin,
    build_tuoni_foundation_profile,
)
from redteam_agent.canonical.digest_catalog import DEFAULT_DIGEST_CATALOG
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError, DigestIntegrityError


def test_tuoni_foundation_defaults_capture_approved_lab_and_unresolved_inputs() -> None:
    profile = build_tuoni_foundation_profile(digest_service=DigestService())

    assert profile.adapter_id == "tuoni-c2"
    assert profile.provider.server_version == TUONI_VERSION_PIN
    assert profile.provider.openapi_sha256 == TUONI_OPENAPI_SHA256_PIN
    assert profile.provider.source_commit == TUONI_SOURCE_COMMIT_PIN
    assert profile.provider.container_image_digest == TUONI_SERVER_IMAGE_DIGEST_PIN
    assert profile.provider.edition == "commercial"
    assert profile.connection.api_origin == "https://127.0.0.1:8443"
    assert profile.isolation.topology == "colocated_control_vm_disposable_target"
    assert profile.isolation.control_vm_operating_system == "ubuntu_24_04_lts"
    assert profile.isolation.control_vm_architecture == "x86_64"
    assert profile.isolation.adapter_placement == "same_control_vm_loopback"
    assert profile.isolation.target_listener_port == 8444
    assert profile.isolation.validation_target_operating_systems == (
        "windows_server",
        "windows_11",
    )
    assert profile.isolation.target_implementation_owner == "external_to_project"
    assert profile.isolation.tuoni_agent_provisioning == "manually_preinstalled"
    assert profile.authentication.credential_delivery == (
        "systemd_load_credential_encrypted"
    )
    assert profile.configuration_blockers() == (
        "openapi_digest_unresolved",
        "tls_certificate_unresolved",
        "credential_secret_reference_unresolved",
        "vcenter_port_group_unresolved",
    )


def test_security_relevant_profile_change_changes_digest() -> None:
    digest_service = DigestService()
    unresolved = build_tuoni_foundation_profile(digest_service=digest_service)
    pinned = build_tuoni_foundation_profile(
        digest_service=digest_service,
        provider=TuoniProviderPin(server_version="candidate-version"),
    )

    assert unresolved.profile_digest != pinned.profile_digest


def test_provider_artifact_identities_are_required_for_activation() -> None:
    profile = build_tuoni_foundation_profile(
        digest_service=DigestService(),
        provider=TuoniProviderPin(
            server_version=TUONI_VERSION_PIN,
            openapi_sha256="1" * 64,
        ),
    )

    assert "container_image_digest_unresolved" in profile.configuration_blockers()
    assert "source_commit_unresolved" in profile.configuration_blockers()


def test_default_profile_is_constructible_but_lists_every_activation_blocker() -> None:
    ds = DigestService()
    adapter = TuoniAdapterFoundation(build_tuoni_foundation_profile(digest_service=ds), ds)

    # A foundation profile may be created before the Provider Human Gate resolves
    # the external identities, but it enumerates every reason it cannot activate
    # and exposes only non-secret identity metadata.
    assert adapter.activation_blockers() == (
        "openapi_digest_unresolved",
        "tls_certificate_unresolved",
        "credential_secret_reference_unresolved",
        "vcenter_port_group_unresolved",
        "authenticated_process_transport_unconfigured",
        "live_provider_attestation_unverified",
    )
    assert adapter.identity().adapter_id == "tuoni-c2"


def test_complete_configuration_still_requires_transport_and_live_attestation() -> None:
    ds = DigestService()
    profile = build_tuoni_foundation_profile(
        digest_service=ds,
        provider=TuoniProviderPin(
            server_version=TUONI_VERSION_PIN,
            openapi_sha256="1" * 64,
            container_image_digest=TUONI_SERVER_IMAGE_DIGEST_PIN,
            source_commit=TUONI_SOURCE_COMMIT_PIN,
        ),
        connection=TuoniConnectionPolicy(tls_certificate_sha256="2" * 64),
        authentication=TuoniAuthenticationPolicy(
            credential_secret_version_id="tuoni-credential#v1"
        ),
        isolation=TuoniLabIsolationPolicy(vcenter_port_group_name="isolated-tuoni-lab"),
    )
    adapter = TuoniAdapterFoundation(profile, ds)

    assert profile.configuration_blockers() == ()
    assert adapter.activation_blockers() == (
        "authenticated_process_transport_unconfigured",
        "live_provider_attestation_unverified",
    )
    with pytest.raises(C2AdapterUnavailableError):
        adapter.list_sessions()


@pytest.mark.parametrize(
    "origin",
    [
        "http://127.0.0.1:8443",
        "https://localhost:8443",
        "https://127.0.0.1:443",
        "https://127.0.0.1:8443/api",
        "https://user:password@127.0.0.1:8443",
        "https://127.0.0.1:8443?next=external",
    ],
)
def test_connection_policy_rejects_unapproved_origin(origin: str) -> None:
    with pytest.raises(ValidationError):
        TuoniConnectionPolicy(api_origin=origin)


def test_isolation_and_authentication_policies_cannot_be_weakened() -> None:
    with pytest.raises(ValidationError):
        build_tuoni_foundation_profile(
            digest_service=DigestService(),
            connection=TuoniConnectionPolicy.model_validate(
                {
                    "api_origin": "https://127.0.0.1:8443",
                    "tls_certificate_sha256": None,
                    "redirects_allowed": True,
                    "proxy_allowed": False,
                    "dns_resolution_allowed": False,
                }
            ),
        )
    with pytest.raises(ValidationError):
        TuoniAuthenticationPolicy(administrator_account_allowed=True)
    with pytest.raises(ValidationError):
        TuoniAuthenticationPolicy(credential_secret_version_id="version with spaces")
    with pytest.raises(ValidationError):
        TuoniLabIsolationPolicy(vcenter_port_group_name="p" * 257)


def test_profile_digest_tampering_is_rejected() -> None:
    ds = DigestService()
    profile = build_tuoni_foundation_profile(digest_service=ds)
    tampered = profile.model_copy(update={"profile_digest": "0" * 64})

    with pytest.raises(DigestIntegrityError):
        TuoniAdapterFoundation(tampered, ds)


def test_tuoni_profile_digest_is_registered() -> None:
    assert "tuoni_provider_profile_digest" in DEFAULT_DIGEST_CATALOG.names()
