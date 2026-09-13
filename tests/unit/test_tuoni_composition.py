"""The Linux composition exposes no injectable production transport path."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

import pytest

import redteam_agent.adapters.tuoni_linux_transport as linux_transport
from redteam_agent.adapters.tuoni import (
    TUONI_SERVER_IMAGE_DIGEST_PIN,
    TUONI_SOURCE_COMMIT_PIN,
    TUONI_VERSION_PIN,
    TuoniAuthenticationPolicy,
    TuoniConnectionPolicy,
    TuoniLabIsolationPolicy,
    TuoniProviderPin,
    build_tuoni_foundation_profile,
)
from redteam_agent.adapters.tuoni_composition import build_tuoni_linux_adapter
from redteam_agent.adapters.tuoni_contract import TuoniApiContractV0161
from redteam_agent.adapters.tuoni_linux_transport import TuoniLinuxProcessTransport
from redteam_agent.adapters.tuoni_transport import (
    TuoniTransportAttestation,
    finalize_tuoni_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError
from redteam_agent.runtime.clock import ManualClock

NOW = datetime(2026, 9, 13, 8, 0, tzinfo=UTC)
TLS_DIGEST = "1" * 64
SECRET_VERSION = "secret://tuoni/service-account#v1"
PORT_GROUP = "isolated-tuoni-lab"
OPENAPI_DIGEST = "3" * 64


def _complete_profile(digest_service: DigestService):
    return build_tuoni_foundation_profile(
        digest_service=digest_service,
        provider=TuoniProviderPin(
            server_version=TUONI_VERSION_PIN,
            openapi_sha256=OPENAPI_DIGEST,
            container_image_digest=TUONI_SERVER_IMAGE_DIGEST_PIN,
            source_commit=TUONI_SOURCE_COMMIT_PIN,
        ),
        connection=TuoniConnectionPolicy(tls_certificate_sha256=TLS_DIGEST),
        authentication=TuoniAuthenticationPolicy(
            credential_secret_version_id=SECRET_VERSION
        ),
        isolation=TuoniLabIsolationPolicy(vcenter_port_group_name=PORT_GROUP),
    )


def _attestation(profile, digest_service: DigestService):
    contract = TuoniApiContractV0161(approved_command_templates=("ps",))
    return finalize_tuoni_transport_attestation(
        TuoniTransportAttestation(
            adapter_profile_digest=profile.profile_digest,
            contract_digest=contract.contract_digest(digest_service),
            server_version=TUONI_VERSION_PIN,
            openapi_sha256=OPENAPI_DIGEST,
            container_image_digest=TUONI_SERVER_IMAGE_DIGEST_PIN,
            source_commit=TUONI_SOURCE_COMMIT_PIN,
            tls_certificate_sha256=TLS_DIGEST,
            credential_secret_version_id=SECRET_VERSION,
            vcenter_port_group_name=PORT_GROUP,
            attested_at=NOW,
            attestation_digest="0" * 64,
        ),
        digest_service,
    )


def test_production_shaped_builder_has_no_transport_or_endpoint_injection() -> None:
    parameters = inspect.signature(build_tuoni_linux_adapter).parameters

    assert set(parameters) == {
        "profile",
        "attestation",
        "approved_command_templates",
        "clock",
        "digest_service",
    }


def test_incomplete_profile_fails_before_linux_transport_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest_service = DigestService()
    incomplete = build_tuoni_foundation_profile(digest_service=digest_service)
    complete = _complete_profile(digest_service)
    called = False

    def forbidden(_attestation: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(
        "redteam_agent.adapters.tuoni_composition.TuoniLinuxProcessTransport",
        forbidden,
    )
    with pytest.raises(C2AdapterUnavailableError):
        build_tuoni_linux_adapter(
            profile=incomplete,
            attestation=_attestation(complete, digest_service),
            approved_command_templates=("ps",),
            clock=ManualClock(NOW),
            digest_service=digest_service,
        )
    assert called is False


def test_complete_builder_wires_the_fixed_linux_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest_service = DigestService()
    profile = _complete_profile(digest_service)
    monkeypatch.setattr(
        linux_transport,
        "_verify_ubuntu_24_04_x86_64",
        lambda: None,
    )

    adapter = build_tuoni_linux_adapter(
        profile=profile,
        attestation=_attestation(profile, digest_service),
        approved_command_templates=("ps",),
        clock=ManualClock(NOW),
        digest_service=digest_service,
    )

    assert isinstance(adapter._transport, TuoniLinuxProcessTransport)
