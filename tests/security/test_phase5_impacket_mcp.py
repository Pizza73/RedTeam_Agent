"""Negative security probes for the local Impacket MCP boundary."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

import support
from redteam_agent.adapters.mcp import MCPServerCapabilities, MCPServerConfig, MCPTransportIdentity
from redteam_agent.adapters.mcp_stdio_transport import (
    MCPStdioProcessTransport,
    inspect_mcp_stdio_identities,
)
from redteam_agent.adapters.mcp_transport import (
    MCPTransportAttestation,
    finalize_mcp_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import MCPContractError, MCPTransportIdentityMismatchError
from redteam_agent.mcp_servers.impacket_catalog import (
    build_impacket_mcp_contract,
    build_impacket_mcp_profile,
)
from redteam_agent.mcp_servers.impacket_server import ImpacketMCPServer, ImpacketServerPolicy


class _NeverBackend:
    def __getattr__(self, name: str):
        raise AssertionError(f"backend must not be reached: {name}")


def test_empty_server_allowlist_fails_closed() -> None:
    server = ImpacketMCPServer(
        policy=ImpacketServerPolicy.from_strings(()), backend=_NeverBackend()
    )
    contract = build_impacket_mcp_contract(digest_service=DigestService())
    request = contract.tools_call_wire_bytes(
        support_mcp_request("10.20.30.40", contract.adapter_id), ()
    )
    with pytest.raises(MCPContractError):
        server.handle(request)


def test_hostname_destination_is_rejected_without_dns_resolution() -> None:
    server = ImpacketMCPServer(
        policy=ImpacketServerPolicy.from_strings(("10.20.30.0/24",)),
        backend=_NeverBackend(),
    )
    contract = build_impacket_mcp_contract(digest_service=DigestService())
    request = contract.tools_call_wire_bytes(
        support_mcp_request("target.internal", contract.adapter_id), ()
    )
    with pytest.raises(MCPContractError):
        server.handle(request)


def test_process_socket_audit_denies_non_allowlisted_egress_and_ports() -> None:
    policy = ImpacketServerPolicy.from_strings(("10.20.30.0/24",))
    policy.audit_hook("socket.connect", (object(), ("10.20.30.40", 445)))
    with pytest.raises(PermissionError):
        policy.audit_hook("socket.connect", (object(), ("10.20.31.40", 445)))
    with pytest.raises(PermissionError):
        policy.audit_hook("socket.connect", (object(), ("10.20.30.40", 443)))
    with pytest.raises(PermissionError):
        policy.audit_hook("socket.connect", (object(), ("target.internal", 445)))


def test_remote_mcp_configuration_cannot_enable_ephemeral_secret_extension() -> None:
    with pytest.raises(ValidationError):
        MCPServerConfig(
            server_id="remote-impacket",
            expected_server_name="redteam-impacket-mcp",
            expected_server_version="1.0.0",
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
                    identity_type="spki_sha256",
                    identity_value="1" * 64,
                ),
            ),
            tool_list_revision="impacket-readonly-v1",
            required_capabilities=MCPServerCapabilities(
                tools=True,
                tools_list_changed_subscription=False,
                cancellation=False,
                task_extension=False,
                reconciliation=False,
            ),
            target_binding_modes=frozenset({"exact_ip_enforced"}),
            secret_delivery_mode="ephemeral_meta_v1",
            config_digest="0" * 64,
        )


def test_stdio_executable_change_invalidates_runtime_identity(tmp_path: Path) -> None:
    executable = tmp_path / "mcp-server"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    argv = (str(executable.resolve(strict=True)), "--allow-target", "10.20.30.0/24")
    package_identity = "redteam-impacket-mcp/1.0.0;impacket/0.13.1"
    ds = DigestService()
    identities = inspect_mcp_stdio_identities(argv=argv, package_version=package_identity)
    contract = build_impacket_mcp_contract(digest_service=ds)
    profile = build_impacket_mcp_profile(identities=identities, digest_service=ds)
    config = profile.server_config
    assert config is not None
    attestation = finalize_mcp_transport_attestation(
        MCPTransportAttestation(
            evidence_kind="test_server",
            production_eligible=False,
            adapter_profile_digest=profile.profile_digest,
            server_config_digest=config.config_digest,
            contract_digest=contract.contract_digest(),
            server_id=config.server_id,
            transport="stdio",
            execution_location="local_process",
            verified_transport_identities=identities,
            sandbox_verified=True,
            redirects_disabled=True,
            attested_at=support.T0,
            attestation_digest="0" * 64,
        ),
        ds,
    )
    transport = MCPStdioProcessTransport(
        argv=argv, package_version=package_identity, attestation=attestation
    )
    executable.write_bytes(b"#!/bin/sh\nexit 1\n")

    with pytest.raises(MCPTransportIdentityMismatchError):
        transport.request(b"{}", timeout_seconds=1, max_response_bytes=1024)


def support_mcp_request(target: str, adapter_id: str):
    from redteam_agent.execution.adapter import ExecutionRequest
    from redteam_agent.models.common import ToolRef

    return ExecutionRequest(
        execution_id="exec-security",
        task_id="task-security",
        tool_ref=ToolRef(tool_id="impacket.smb.negotiate", registry_revision=1),
        adapter_id=adapter_id,
        provider_tool_name="impacket.smb.negotiate",
        result_delivery_mode="local_result",
        idempotency_key="idempotency-security",
        timeout_seconds=5,
        arguments={
            "destinations": [target],
            "port": 445,
            "protocol": "tcp",
            "timeout_seconds": 5,
        },
    )
