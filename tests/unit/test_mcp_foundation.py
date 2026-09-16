"""Pinned MCP foundation and configuration invariants."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

import support
from mcp_test_server import build_offline_mcp_fixture
from redteam_agent.adapters.mcp import (
    MCP_PROTOCOL_REVISION,
    MCP_SCHEMA_SHA256,
    MCP_SPEC_COMMIT,
    MCPAdapterFoundation,
    MCPFoundationProfile,
    MCPServerCapabilities,
    MCPServerConfig,
    MCPTransportIdentity,
    MCPTrustPolicy,
    build_mcp_foundation_profile,
)
from redteam_agent.adapters.mcp_transport import MCPTransportAttestation
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import DigestIntegrityError, MCPAdapterUnavailableError
from redteam_agent.runtime.clock import ManualClock


def test_protocol_source_and_schema_are_immutable_pins() -> None:
    assert MCP_PROTOCOL_REVISION == "2026-07-28"
    assert MCP_SPEC_COMMIT == "5f5440bb26a62e2cf3440b92da5a667efa03b267"
    assert MCP_SCHEMA_SHA256 == "ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203"


def test_unresolved_foundation_is_fail_closed() -> None:
    ds = DigestService()
    profile = build_mcp_foundation_profile(digest_service=ds)
    foundation = MCPAdapterFoundation(profile, ds)

    assert profile.configuration_blockers() == (
        "mcp_server_product_unresolved",
        "mcp_server_config_unresolved",
        "mcp_trust_policy_unresolved",
    )
    assert foundation.identity().result_delivery_mode == "local_result"
    with pytest.raises(MCPAdapterUnavailableError):
        foundation.discover()


def test_complete_offline_profile_has_no_configuration_blockers() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    assert fixture.profile.configuration_blockers() == ()
    assert fixture.transport.attestation.evidence_kind == "test_server"
    assert fixture.transport.attestation.production_eligible is False


def test_test_server_evidence_cannot_be_marked_production_eligible() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    values = fixture.transport.attestation.model_dump(mode="python")
    values["production_eligible"] = True
    with pytest.raises(ValidationError):
        MCPTransportAttestation.model_validate(values)


def test_local_configuration_requires_complete_stdio_identity_set() -> None:
    with pytest.raises(ValidationError):
        MCPServerConfig(
            server_id="local",
            expected_server_name="server",
            expected_server_version="1",
            transport="stdio",
            execution_location="local_process",
            configured_transport_identities=(
                MCPTransportIdentity(
                    transport_type="stdio",
                    identity_type="executable_path",
                    identity_value="/opt/mcp/server",
                ),
            ),
            tool_list_revision="v1",
            required_capabilities=MCPServerCapabilities(
                tools=True,
                tools_list_changed_subscription=False,
                cancellation=False,
                task_extension=False,
                reconciliation=False,
            ),
            config_digest="0" * 64,
        )


def test_noncanonical_stdio_path_is_rejected() -> None:
    with pytest.raises(ValidationError):
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="executable_path",
            identity_value="/opt//mcp/server",
        )


def test_remote_configuration_requires_cryptographic_peer_identity() -> None:
    with pytest.raises(ValidationError):
        MCPServerConfig(
            server_id="remote",
            expected_server_name="server",
            expected_server_version="1",
            transport="streamable_http",
            execution_location="managed_remote",
            configured_transport_identities=(
                MCPTransportIdentity(
                    transport_type="streamable_http",
                    identity_type="configured_url",
                    identity_value="https://mcp.invalid/rpc",
                ),
                MCPTransportIdentity(
                    transport_type="streamable_http",
                    identity_type="oauth_resource",
                    identity_value="https://mcp.invalid/",
                ),
            ),
            tool_list_revision="v1",
            required_capabilities=MCPServerCapabilities(
                tools=True,
                tools_list_changed_subscription=False,
                cancellation=False,
                task_extension=False,
                reconciliation=False,
            ),
            config_digest="0" * 64,
        )


def test_untrusted_remote_cannot_enable_unsafe_tools_or_self_attest() -> None:
    with pytest.raises(ValidationError):
        MCPTrustPolicy(
            adapter_id="mcp-primary",
            execution_location="untrusted_remote",
            allow_state_change=True,
        )


def test_profile_digest_tamper_is_rejected() -> None:
    ds = DigestService()
    fixture = build_offline_mcp_fixture(
        digest_service=ds, clock=ManualClock(support.T0)
    )
    tampered = MCPFoundationProfile.model_validate(
        {
            **fixture.profile.model_dump(mode="python"),
            "provider_product": "changed",
        }
    )
    with pytest.raises(DigestIntegrityError):
        MCPAdapterFoundation(tampered, ds)
