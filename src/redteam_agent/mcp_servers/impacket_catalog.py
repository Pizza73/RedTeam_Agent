"""Closed read-only tool catalog for the Fortra Impacket MCP server."""

from __future__ import annotations

from collections.abc import Mapping

from redteam_agent.adapters.mcp import (
    MCPFoundationProfile,
    MCPServerCapabilities,
    MCPServerConfig,
    MCPTransportIdentity,
    MCPTrustPolicy,
    build_mcp_foundation_profile,
    finalize_mcp_server_config,
)
from redteam_agent.adapters.mcp_contract import (
    MCPApiContractV20260728,
    MCPApprovedTool,
    build_mcp_approved_tool,
    mcp_tool_capability_id,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.tools.models import ToolDefinition

IMPACKET_MCP_SERVER_NAME = "redteam-impacket-mcp"
IMPACKET_MCP_SERVER_VERSION = "1.0.0"
IMPACKET_VERSION = "0.13.1"
IMPACKET_TOOL_LIST_REVISION = "impacket-readonly-v1"
IMPACKET_ADAPTER_ID = "mcp-impacket-local"
IMPACKET_SERVER_ID = "impacket-local"

_DESTINATIONS = {"type": "array", "items": {"type": "string"}, "minItems": 1}
_TIMEOUT = {"type": "integer", "minimum": 1, "maximum": 30}
_SMB_PORT = {"type": "integer", "const": 445}
_RPC_PORT = {"type": "integer", "const": 135}
_TCP = {"type": "string", "const": "tcp"}
_SECRET_REFERENCE = {
    "type": "object",
    "properties": {
        "credential_type": {
            "type": "string",
            "enum": ["password", "ntlm_hash"],
        },
        "secret_version_id": {"type": "string"},
        "secret_version": {"type": "string"},
        "principal_ref": {"type": "string"},
    },
    "required": [
        "credential_type",
        "secret_version_id",
        "secret_version",
        "principal_ref",
    ],
    "additionalProperties": False,
}


def _network_schema(
    *, port: dict[str, object], credential: bool
) -> dict[str, object]:
    properties: dict[str, object] = {
        "destinations": _DESTINATIONS,
        "port": port,
        "protocol": _TCP,
        "timeout_seconds": _TIMEOUT,
    }
    required = ["destinations", "port", "protocol", "timeout_seconds"]
    if credential:
        properties["credential"] = _SECRET_REFERENCE
        required.append("credential")
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


IMPACKET_TOOL_SCHEMAS: dict[str, dict[str, object]] = {
    "impacket.smb.negotiate": _network_schema(port=_SMB_PORT, credential=False),
    "impacket.smb.authenticate": _network_schema(port=_SMB_PORT, credential=True),
    "impacket.smb.list_shares": _network_schema(port=_SMB_PORT, credential=True),
    "impacket.rpc.endpoint_map": _network_schema(port=_RPC_PORT, credential=False),
}

IMPACKET_TOOL_METADATA: dict[str, tuple[str, str]] = {
    "impacket.smb.negotiate": (
        "SMB negotiate",
        "Negotiate SMB 2/3 and return bounded server protocol metadata.",
    ),
    "impacket.smb.authenticate": (
        "SMB authenticate",
        "Validate an approved password or NTLM-hash credential without changing the target.",
    ),
    "impacket.smb.list_shares": (
        "SMB list shares",
        "List bounded SMB share names and types using an approved credential.",
    ),
    "impacket.rpc.endpoint_map": (
        "RPC endpoint map",
        "Enumerate a bounded set of endpoint-mapper bindings over TCP/135.",
    ),
}


def build_impacket_approved_tools(
    digest_service: DigestService,
) -> tuple[MCPApprovedTool, ...]:
    return tuple(
        build_mcp_approved_tool(
            name=name,
            input_schema=IMPACKET_TOOL_SCHEMAS[name],
            digest_service=digest_service,
        )
        for name in sorted(IMPACKET_TOOL_SCHEMAS)
    )


def build_impacket_mcp_contract(
    *,
    digest_service: DigestService,
    adapter_id: str = IMPACKET_ADAPTER_ID,
) -> MCPApiContractV20260728:
    return MCPApiContractV20260728(
        adapter_id=adapter_id,
        approved_tools=build_impacket_approved_tools(digest_service),
        digest_service=digest_service,
    )


def build_impacket_mcp_profile(
    *,
    identities: tuple[MCPTransportIdentity, ...],
    digest_service: DigestService,
    adapter_id: str = IMPACKET_ADAPTER_ID,
    server_id: str = IMPACKET_SERVER_ID,
) -> MCPFoundationProfile:
    config = finalize_mcp_server_config(
        MCPServerConfig(
            server_id=server_id,
            expected_server_name=IMPACKET_MCP_SERVER_NAME,
            expected_server_version=IMPACKET_MCP_SERVER_VERSION,
            transport="stdio",
            execution_location="local_process",
            configured_transport_identities=identities,
            tool_list_revision=IMPACKET_TOOL_LIST_REVISION,
            required_capabilities=MCPServerCapabilities(
                tools=True,
                tools_list_changed_subscription=False,
                cancellation=False,
                task_extension=False,
                reconciliation=False,
            ),
            target_binding_modes=frozenset({"exact_ip_enforced"}),
            secret_delivery_mode="ephemeral_meta_v1",  # noqa: S106
            config_digest="0" * 64,
        ),
        digest_service,
    )
    return build_mcp_foundation_profile(
        digest_service=digest_service,
        adapter_id=adapter_id,
        provider_product=f"fortra-impacket-{IMPACKET_VERSION}",
        server_config=config,
        trust_policy=MCPTrustPolicy(
            adapter_id=adapter_id,
            execution_location="local_process",
            allow_secret_resolution=True,
        ),
    )


def build_impacket_tool_definitions(
    *,
    registry_revision: int,
    action_contract_refs: Mapping[str, ActionContractReference],
    output_publication_rule_id: str,
    evidence_rule_ids: tuple[str, ...],
    digest_service: DigestService,
    adapter_id: str = IMPACKET_ADAPTER_ID,
) -> tuple[ToolDefinition, ...]:
    """Build Tool Registry entries bound to the exact MCP catalog schemas."""

    approved = {
        tool.name: tool for tool in build_impacket_approved_tools(digest_service)
    }
    if set(action_contract_refs) != set(approved):
        raise ValueError("Impacket action contract references must cover every tool")
    tools: list[ToolDefinition] = []
    for name in sorted(approved):
        schema_tool = approved[name]
        title, description = IMPACKET_TOOL_METADATA[name]
        credential_tool = name in {
            "impacket.smb.authenticate",
            "impacket.smb.list_shares",
        }
        capability = mcp_tool_capability_id(
            name=name,
            tool_list_revision=IMPACKET_TOOL_LIST_REVISION,
            input_schema_digest=schema_tool.input_schema_digest,
        )
        tools.append(
            ToolDefinition(
                tool_ref=ToolRef(tool_id=name, registry_revision=registry_revision),
                display_name=title,
                version=IMPACKET_MCP_SERVER_VERSION,
                description=description,
                adapter="mcp",
                adapter_id=adapter_id,
                provider_tool_name=name,
                provider_definition_revision=IMPACKET_TOOL_LIST_REVISION,
                provider_schema_digest=schema_tool.input_schema_digest,
                minimum_risk_level="low",
                approval_rule="policy",
                side_effect="read_only",
                idempotency="idempotent",
                parameter_schema=IMPACKET_TOOL_SCHEMAS[name],
                output_publication_rule_id=output_publication_rule_id,
                evidence_rule_ids=evidence_rule_ids,
                action_contract_ref=action_contract_refs[name],
                target_mode="required",
                target_extractor_id="network_target_v1",
                default_timeout_seconds=10,
                max_timeout_seconds=30,
                max_output_bytes=4 * 1024 * 1024,
                secret_argument_paths=(("/credential",) if credential_tool else ()),
                requires_session=False,
                supported_os=frozenset({"windows"}),
                supported_architectures=frozenset({"x86_64", "amd64"}),
                required_adapter_capabilities=frozenset(
                    {"server.discover", "tools.list", "tools.call", capability}
                ),
                required_session_capabilities=frozenset(),
                required_data_access_types=(
                    frozenset({"secret_reference"})
                    if credential_tool
                    else frozenset()
                ),
                required_target_binding_modes=frozenset({"exact_ip_enforced"}),
                allows_redirects=False,
                sandbox_requirement=None,
            )
        )
    return tuple(tools)


__all__ = [
    "IMPACKET_ADAPTER_ID",
    "IMPACKET_MCP_SERVER_NAME",
    "IMPACKET_MCP_SERVER_VERSION",
    "IMPACKET_SERVER_ID",
    "IMPACKET_TOOL_LIST_REVISION",
    "IMPACKET_TOOL_METADATA",
    "IMPACKET_TOOL_SCHEMAS",
    "IMPACKET_VERSION",
    "build_impacket_approved_tools",
    "build_impacket_mcp_contract",
    "build_impacket_mcp_profile",
    "build_impacket_tool_definitions",
]
