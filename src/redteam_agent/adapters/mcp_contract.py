"""Closed JSON-RPC contract for MCP protocol revision 2026-07-28."""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.adapters.mcp import (
    MCP_CLIENT_NAME,
    MCP_CLIENT_VERSION,
    MCP_PROTOCOL_REVISION,
    MCP_SCHEMA_SHA256,
    MCP_SPEC_COMMIT,
)
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject, thaw
from redteam_agent.errors import MCPContractError
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.secret_binding import EphemeralSecretBinding
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.tools.parameter_schema import (
    validate_arguments,
    validate_schema_is_supported,
)
from redteam_agent.tools.secret_argument_path import (
    _discover_secret_reference_paths,
    parse_json_pointer,
    resolve_pointer,
    validate_secret_reference,
)

MCP_API_CONTRACT_REVISION: Literal["mcp-2026-07-28-offline-v1"] = (
    "mcp-2026-07-28-offline-v1"
)
MCP_EPHEMERAL_SECRET_META_KEY = "io.redteam-agent/ephemeralSecretBindings"  # noqa: S105
MCP_MAX_EPHEMERAL_SECRET_BYTES = 64 * 1024
_TOOL_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
type MCPOperation = Literal["server_discover", "tools_list", "tools_call"]


class MCPApprovedTool(StrictImmutableBoundaryModel):
    name: str = Field(pattern=_TOOL_NAME_PATTERN)
    input_schema: CanonicalJsonObject
    input_schema_digest: str = Field(pattern=r"^[0-9a-f]{64}$")



def mcp_tool_capability_id(
    *, name: str, tool_list_revision: str, input_schema_digest: str
) -> str:
    if (
        re.fullmatch(_TOOL_NAME_PATTERN, name) is None
        or not tool_list_revision
        or ":" in tool_list_revision
        or re.fullmatch(r"^[0-9a-f]{64}$", input_schema_digest) is None
    ):
        raise MCPContractError("MCP tool capability identity is invalid")
    return f"mcp.tool:{name}:{tool_list_revision}:{input_schema_digest}"


def build_mcp_approved_tool(
    *, name: str, input_schema: object, digest_service: DigestService
) -> MCPApprovedTool:
    if re.fullmatch(_TOOL_NAME_PATTERN, name) is None:
        raise MCPContractError("MCP approved tool name is invalid")
    validate_schema_is_supported(input_schema)
    digest = digest_service.compute(
        "mcp_approved_tool_schema_digest",
        {"name": name, "input_schema": input_schema},
    )
    return MCPApprovedTool(
        name=name,
        input_schema=input_schema,
        input_schema_digest=digest,
    )


class MCPWireRequest(StrictImmutableBoundaryModel):
    contract_revision: Literal["mcp-2026-07-28-offline-v1"] = (
        MCP_API_CONTRACT_REVISION
    )
    operation: MCPOperation
    jsonrpc: Literal["2.0"] = "2.0"
    request_id: int = Field(alias="id", gt=0)
    method: Literal["server/discover", "tools/list", "tools/call"]
    params: CanonicalJsonObject

    @model_validator(mode="after")
    def _operation_matches_method(self) -> MCPWireRequest:
        expected = {
            "server_discover": "server/discover",
            "tools_list": "tools/list",
            "tools_call": "tools/call",
        }[self.operation]
        if self.method != expected:
            raise ValueError("MCP operation and method disagree")
        return self

    def to_wire_bytes(self) -> bytes:
        return canonical_dumps(
            {
                "jsonrpc": self.jsonrpc,
                "id": self.request_id,
                "method": self.method,
                "params": thaw(self.params),
            }
        )


def _request_meta() -> dict[str, object]:
    return {
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_REVISION,
        "io.modelcontextprotocol/clientInfo": {
            "name": MCP_CLIENT_NAME,
            "version": MCP_CLIENT_VERSION,
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


class MCPApiContractV20260728:
    """Exact stateless requests and approved live tool schema bindings."""

    def __init__(
        self,
        *,
        adapter_id: str = "mcp-primary",
        approved_tools: Iterable[MCPApprovedTool] = (),
        digest_service: DigestService,
    ) -> None:
        if re.fullmatch(r"^[a-z0-9][a-z0-9._-]{0,127}$", adapter_id) is None:
            raise MCPContractError("MCP contract adapter ID is invalid")
        by_name: dict[str, MCPApprovedTool] = {}
        for tool in approved_tools:
            if tool.name in by_name:
                raise MCPContractError("MCP approved tool names must be unique")
            validate_schema_is_supported(tool.input_schema)
            digest_service.verify(
                "mcp_approved_tool_schema_digest",
                {"name": tool.name, "input_schema": thaw(tool.input_schema)},
                tool.input_schema_digest,
            )
            by_name[tool.name] = tool
        self._approved_tools = tuple(by_name[name] for name in sorted(by_name))
        self._by_name = by_name
        self._adapter_id = adapter_id
        self._digest_service = digest_service

    @property
    def approved_tools(self) -> tuple[MCPApprovedTool, ...]:
        return self._approved_tools

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    def contract_digest(self) -> str:
        return self._digest_service.compute(
            "mcp_api_contract_digest",
            {
                "contract_revision": MCP_API_CONTRACT_REVISION,
                "adapter_id": self._adapter_id,
                "protocol_revision": MCP_PROTOCOL_REVISION,
                "spec_commit": MCP_SPEC_COMMIT,
                "schema_sha256": MCP_SCHEMA_SHA256,
                "request_model": "stateless-jsonrpc-per-request-meta",
                "secret_delivery_extension": "ephemeral-meta-v1-local-process-only",
                "task_implementation_mode": "disabled",
                "operations": ["server/discover", "tools/list", "tools/call"],
                "approved_tools": [
                    {
                        "name": tool.name,
                        "input_schema_digest": tool.input_schema_digest,
                    }
                    for tool in self._approved_tools
                ],
            },
        )

    @staticmethod
    def discover(*, request_id: int = 1) -> MCPWireRequest:
        return MCPWireRequest(
            operation="server_discover",
            id=request_id,
            method="server/discover",
            params={"_meta": _request_meta()},
        )

    @staticmethod
    def tools_list(*, request_id: int = 2) -> MCPWireRequest:
        return MCPWireRequest(
            operation="tools_list",
            id=request_id,
            method="tools/list",
            params={"_meta": _request_meta()},
        )

    def tools_call(
        self, request: ExecutionRequest, *, request_id: int = 3
    ) -> MCPWireRequest:
        if request.adapter_id != self._adapter_id:
            raise MCPContractError("execution request is bound to another adapter")
        if request.result_delivery_mode != "local_result":
            raise MCPContractError("offline MCP requires local_result capture")
        tool = self._by_name.get(request.provider_tool_name)
        if tool is None:
            raise MCPContractError("MCP tool is not in the approved catalog")
        try:
            validate_arguments(tool.input_schema, request.arguments)
        except Exception as exc:
            raise MCPContractError("MCP tool arguments violate the approved schema") from exc
        return MCPWireRequest(
            operation="tools_call",
            id=request_id,
            method="tools/call",
            params={
                "name": tool.name,
                "arguments": thaw(request.arguments),
                "_meta": _request_meta(),
            },
        )

    def tools_call_wire_bytes(
        self,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        *,
        request_id: int = 3,
    ) -> bytes:
        """Encode one call, adding exact ephemeral bindings only when present.

        Secret plaintext never enters ``ExecutionRequest`` or a Pydantic model.
        The extension is restricted by the adapter to an attested local stdio
        process, and the one-shot Impacket server exits after the request.
        """

        wire_request = self.tools_call(request, request_id=request_id)
        self.validate_secret_bindings(request, secret_bindings)
        if not secret_bindings:
            return wire_request.to_wire_bytes()

        encoded: list[dict[str, object]] = []
        for binding in sorted(
            secret_bindings, key=lambda item: item.secret_argument_path
        ):
            material = binding.consume()
            if not material or len(material) > MCP_MAX_EPHEMERAL_SECRET_BYTES:
                raise MCPContractError("MCP ephemeral secret size is invalid")
            encoded.append(
                {
                    "argumentPath": binding.secret_argument_path,
                    "secretVersionId": binding.secret_version_id,
                    "encoding": "base64",
                    "material": base64.b64encode(material).decode("ascii"),
                }
            )

        params = thaw(wire_request.params)
        meta = params.get("_meta")
        if not isinstance(meta, dict):  # pragma: no cover - construction invariant
            raise MCPContractError("MCP request metadata is unavailable")
        params["_meta"] = {**meta, MCP_EPHEMERAL_SECRET_META_KEY: encoded}
        return canonical_dumps(
            {
                "jsonrpc": wire_request.jsonrpc,
                "id": wire_request.request_id,
                "method": wire_request.method,
                "params": params,
            }
        )

    def validate_secret_bindings(
        self,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
    ) -> None:
        """Validate exact reference coverage without opening secret material."""

        self.tools_call(request)
        discovered = {
            _tokens_to_pointer(tokens)
            for tokens in _discover_secret_reference_paths(request.arguments)
        }
        supplied = {binding.secret_argument_path for binding in secret_bindings}
        if not secret_bindings and discovered:
            raise MCPContractError("MCP Secret References require ephemeral bindings")
        if len(supplied) != len(secret_bindings) or supplied != discovered:
            raise MCPContractError(
                "MCP secret bindings do not exactly cover Secret References"
            )
        for binding in secret_bindings:
            tokens = parse_json_pointer(binding.secret_argument_path)
            reference = resolve_pointer(tokens, request.arguments)
            validate_secret_reference(reference)
            if binding.secret_version_id != reference["secret_version_id"]:
                raise MCPContractError("MCP secret version binding mismatch")
            if binding.length() < 1 or binding.length() > MCP_MAX_EPHEMERAL_SECRET_BYTES:
                raise MCPContractError("MCP ephemeral secret size is invalid")


def _tokens_to_pointer(tokens: tuple[str, ...]) -> str:
    return "/" + "/".join(
        token.replace("~", "~0").replace("/", "~1") for token in tokens
    )


__all__ = [
    "MCP_API_CONTRACT_REVISION",
    "MCP_EPHEMERAL_SECRET_META_KEY",
    "MCP_MAX_EPHEMERAL_SECRET_BYTES",
    "MCPApiContractV20260728",
    "MCPApprovedTool",
    "MCPOperation",
    "MCPWireRequest",
    "build_mcp_approved_tool",
    "mcp_tool_capability_id",
]
