"""Stateful, credential-free MCP 2026-07-28 test server and transport."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from redteam_agent.adapters.mcp import (
    MCPFoundationProfile,
    MCPServerCapabilities,
    MCPServerConfig,
    MCPTransportIdentity,
    MCPTrustPolicy,
    build_mcp_foundation_profile,
    finalize_mcp_server_config,
)
from redteam_agent.adapters.mcp_adapter import MCPAdapter
from redteam_agent.adapters.mcp_contract import (
    MCPApiContractV20260728,
    MCPApprovedTool,
    build_mcp_approved_tool,
    mcp_tool_capability_id,
)
from redteam_agent.adapters.mcp_transport import (
    MCPTransportAttestation,
    MCPTransportResponse,
    finalize_mcp_transport_attestation,
)
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import MCPContractError, MCPTransportError
from redteam_agent.runtime.clock import Clock

ECHO_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {"message": {"type": "string"}},
    "required": ["message"],
    "additionalProperties": False,
}


class StatefulMCPTestServer:
    """Small deterministic server implementing only the Phase 5 approved surface."""

    def __init__(self) -> None:
        self.server_name = "redteam-offline-mcp"
        self.server_version = "1.0.0-test"
        self.supported_versions = ["2026-07-28"]
        self.tools: list[dict[str, object]] = [
            {
                "name": "offline.echo",
                "title": "Offline echo",
                "description": "Returns a deterministic local test result.",
                "inputSchema": deepcopy(ECHO_SCHEMA),
            }
        ]
        self.requests: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.fail_next_method: str | None = None
        self.drop_response_after_method: str | None = None
        self.response_id_offset = 0
        self.paginate_tools = False
        self.tool_is_error = False

    def handle(self, request_bytes: bytes) -> bytes:
        try:
            request = parse_json_no_duplicate_keys(request_bytes)
        except Exception as exc:
            raise MCPContractError("test server received malformed JSON") from exc
        if not isinstance(request, dict) or set(request) != {
            "jsonrpc",
            "id",
            "method",
            "params",
        }:
            raise MCPContractError("test server received an invalid request envelope")
        request_id = request["id"]
        method = request["method"]
        params = request["params"]
        if (
            request["jsonrpc"] != "2.0"
            or type(request_id) is not int
            or type(method) is not str
            or not isinstance(params, dict)
        ):
            raise MCPContractError("test server request binding is invalid")
        self._validate_meta(params)
        self.requests.append(request)
        if self.fail_next_method == method:
            self.fail_next_method = None
            raise MCPTransportError("injected MCP transport failure")
        if method == "server/discover":
            result = self._discover_result()
        elif method == "tools/list":
            result = self._tools_result()
        elif method == "tools/call":
            result = self._call_result(params)
        else:
            raise MCPContractError("test server method is not implemented")
        if self.drop_response_after_method == method:
            self.drop_response_after_method = None
            raise MCPTransportError("injected MCP response loss after dispatch")
        return canonical_dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id + self.response_id_offset,
                "result": result,
            }
        )

    @staticmethod
    def _validate_meta(params: dict[str, Any]) -> None:
        meta = params.get("_meta")
        expected = {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {
                "name": "redteam-agent",
                "version": "phase5-offline-v1",
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        if meta != expected:
            raise MCPContractError("test server request metadata is not exact")

    def _discover_result(self) -> dict[str, object]:
        return {
            "resultType": "complete",
            "supportedVersions": list(self.supported_versions),
            "capabilities": {"tools": {"listChanged": True}},
            "ttlMs": 0,
            "cacheScope": "private",
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version,
                }
            },
        }

    def _tools_result(self) -> dict[str, object]:
        result: dict[str, object] = {
            "resultType": "complete",
            "tools": deepcopy(self.tools),
            "ttlMs": 0,
            "cacheScope": "private",
        }
        if self.paginate_tools:
            result["nextCursor"] = "unapproved-pagination"
        return result

    def _call_result(self, params: dict[str, Any]) -> dict[str, object]:
        if set(params) != {"name", "arguments", "_meta"}:
            raise MCPContractError("test server call parameters are not exact")
        name = params["name"]
        arguments = params["arguments"]
        if name != "offline.echo" or not isinstance(arguments, dict):
            raise MCPContractError("test server received an unapproved call")
        self.calls.append({"name": name, "arguments": deepcopy(arguments)})
        message = arguments.get("message")
        if type(message) is not str:
            raise MCPContractError("test server echo argument is invalid")
        return {
            "resultType": "complete",
            "content": [{"type": "text", "text": f"echo:{message}"}],
            "isError": self.tool_is_error,
        }

    @staticmethod
    def tool_list_changed_notification(subscription_id: str | int) -> bytes:
        return canonical_dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/subscriptionId": subscription_id
                    }
                },
            }
        )


class StatefulMCPTestTransport:
    """In-memory transport with an attested identity and bounded responses."""

    def __init__(
        self,
        *,
        server: StatefulMCPTestServer,
        attestation: MCPTransportAttestation,
    ) -> None:
        self._server = server
        self._attestation = attestation
        self.request_count = 0

    @property
    def attestation(self) -> MCPTransportAttestation:
        return self._attestation

    def request(
        self,
        request: bytes,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> MCPTransportResponse:
        if type(request) is not bytes or not request:
            raise MCPTransportError("MCP test transport request must be non-empty bytes")
        if timeout_seconds < 1 or max_response_bytes < 1:
            raise MCPTransportError("MCP test transport bounds are invalid")
        self.request_count += 1
        body = self._server.handle(request)
        if len(body) > max_response_bytes:
            raise MCPTransportError("MCP test response exceeded its fixed bound")
        return MCPTransportResponse(body)


@dataclass(frozen=True)
class OfflineMCPFixture:
    approved_tool: MCPApprovedTool
    contract: MCPApiContractV20260728
    profile: MCPFoundationProfile
    server: StatefulMCPTestServer
    transport: StatefulMCPTestTransport
    adapter: MCPAdapter

    @property
    def tool_capability_id(self) -> str:
        config = self.profile.server_config
        assert config is not None
        return mcp_tool_capability_id(
            name=self.approved_tool.name,
            tool_list_revision=config.tool_list_revision,
            input_schema_digest=self.approved_tool.input_schema_digest,
        )


def build_offline_mcp_fixture(
    *,
    digest_service: DigestService,
    clock: Clock,
    adapter_id: str = "mcp-primary",
    server_id: str = "mcp-offline-test",
) -> OfflineMCPFixture:
    identities = (
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="executable_path",
            identity_value="/opt/redteam-agent/tests/mcp-stateful-server",
        ),
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="executable_sha256",
            identity_value="1" * 64,
        ),
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="command_configuration_digest",
            identity_value="2" * 64,
        ),
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="package_version",
            identity_value="offline-test-1.0.0",
        ),
    )
    config = finalize_mcp_server_config(
        MCPServerConfig(
            server_id=server_id,
            expected_server_name="redteam-offline-mcp",
            expected_server_version="1.0.0-test",
            transport="stdio",
            execution_location="local_process",
            configured_transport_identities=identities,
            tool_list_revision="offline-test-catalog-v1",
            required_capabilities=MCPServerCapabilities(
                tools=True,
                tools_list_changed_subscription=True,
                cancellation=False,
                task_extension=False,
                reconciliation=False,
            ),
            config_digest="0" * 64,
        ),
        digest_service,
    )
    policy = MCPTrustPolicy(adapter_id=adapter_id, execution_location="local_process")
    profile = build_mcp_foundation_profile(
        digest_service=digest_service,
        adapter_id=adapter_id,
        provider_product="stateful-offline-test-server",
        server_config=config,
        trust_policy=policy,
    )
    approved_tool = build_mcp_approved_tool(
        name="offline.echo", input_schema=ECHO_SCHEMA, digest_service=digest_service
    )
    contract = MCPApiContractV20260728(
        adapter_id=adapter_id,
        approved_tools=(approved_tool,),
        digest_service=digest_service,
    )
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
            attested_at=clock.now(),
            attestation_digest="0" * 64,
        ),
        digest_service,
    )
    server = StatefulMCPTestServer()
    transport = StatefulMCPTestTransport(server=server, attestation=attestation)
    adapter = MCPAdapter(
        profile=profile,
        contract=contract,
        transport=transport,
        clock=clock,
        digest_service=digest_service,
    )
    return OfflineMCPFixture(
        approved_tool=approved_tool,
        contract=contract,
        profile=profile,
        server=server,
        transport=transport,
        adapter=adapter,
    )


__all__ = [
    "ECHO_SCHEMA",
    "OfflineMCPFixture",
    "StatefulMCPTestServer",
    "StatefulMCPTestTransport",
    "build_offline_mcp_fixture",
]
