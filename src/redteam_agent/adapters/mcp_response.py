"""Strict MCP 2026-07-28 JSON-RPC response normalization."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, cast

from pydantic import Field, TypeAdapter, ValidationError

from redteam_agent.adapters.mcp import (
    MCPDiscoverResult,
    MCPLogicalServerInfo,
    MCPServerCapabilities,
    MCPServerConfig,
    MCPTransportIdentity,
    RemoteMCPEnforcementCapabilities,
)
from redteam_agent.adapters.mcp_contract import MCPApprovedTool
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import (
    AuthorizationKernelError,
    MCPContractError,
    MCPProtocolRevisionMismatchError,
    MCPServerIdentityMismatchError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.tools.parameter_schema import validate_schema_is_supported

_TOOL_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_CANONICAL_OBJECT_ADAPTER = TypeAdapter(CanonicalJsonObject)


class MCPCandidateToolDefinition(StrictImmutableBoundaryModel):
    name: str = Field(pattern=_TOOL_NAME_PATTERN)
    title: str | None = Field(default=None, max_length=512)
    description: str | None = Field(default=None, max_length=4096)
    input_schema: CanonicalJsonObject
    input_schema_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class MCPToolCatalogObservation(StrictImmutableBoundaryModel):
    candidates: tuple[MCPCandidateToolDefinition, ...]
    approved_tool_names: frozenset[str]
    live_catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class MCPCallControl(StrictImmutableBoundaryModel):
    is_error: bool
    content_count: int = Field(ge=0)


class MCPToolListChangedSignal(StrictImmutableBoundaryModel):
    subscription_id: str | int


def _response_result(raw: str | bytes, *, expected_request_id: int) -> dict[str, Any]:
    try:
        value = parse_json_no_duplicate_keys(raw)
        if not isinstance(value, dict):
            raise ValueError("response is not an object")
        if set(value) != {"jsonrpc", "id", "result"}:
            raise ValueError("response envelope is not a successful exact shape")
        if (
            value["jsonrpc"] != "2.0"
            or type(value["id"]) is not int
            or value["id"] != expected_request_id
            or not isinstance(value["result"], dict)
        ):
            raise ValueError("response envelope binding mismatch")
        return value["result"]
    except (AuthorizationKernelError, ValueError, TypeError) as exc:
        raise MCPContractError("MCP response violated the JSON-RPC boundary") from exc


def decode_mcp_tool_list_changed_notification(
    raw: str | bytes, *, expected_subscription_id: str | int
) -> MCPToolListChangedSignal:
    try:
        value = parse_json_no_duplicate_keys(raw)
        if not isinstance(value, dict) or set(value) != {
            "jsonrpc",
            "method",
            "params",
        }:
            raise ValueError("notification envelope is invalid")
        params = value["params"]
        if (
            value["jsonrpc"] != "2.0"
            or value["method"] != "notifications/tools/list_changed"
            or not isinstance(params, dict)
            or set(params) != {"_meta"}
        ):
            raise ValueError("tool-list notification is invalid")
        meta = params["_meta"]
        if not isinstance(meta, dict) or set(meta) != {
            "io.modelcontextprotocol/subscriptionId"
        }:
            raise ValueError("subscription metadata is invalid")
        subscription_id = meta["io.modelcontextprotocol/subscriptionId"]
        if (
            type(subscription_id) not in {str, int}
            or subscription_id != expected_subscription_id
            or (type(subscription_id) is str and not subscription_id)
        ):
            raise ValueError("subscription identity mismatch")
        return MCPToolListChangedSignal(
            subscription_id=cast(str | int, subscription_id)
        )
    except (AuthorizationKernelError, ValueError, TypeError) as exc:
        raise MCPContractError("MCP tool-list notification violated its boundary") from exc


def _safe_text(value: object, *, required: bool, max_length: int) -> str | None:
    if value is None and not required:
        return None
    if type(value) is not str or not value or len(value) > max_length:
        raise MCPContractError("MCP text metadata is invalid")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise MCPContractError("MCP text metadata contains control characters")
    return value


def _capabilities(value: object) -> MCPServerCapabilities:
    if not isinstance(value, dict):
        raise MCPContractError("MCP server capabilities are invalid")
    tools = value.get("tools")
    if not isinstance(tools, dict):
        raise MCPContractError("MCP server does not expose tools")
    if set(tools) - {"listChanged"}:
        raise MCPContractError("MCP tools capability has unknown control fields")
    list_changed = tools.get("listChanged", False)
    if type(list_changed) is not bool:
        raise MCPContractError("MCP tools listChanged capability is invalid")
    extensions = value.get("extensions", {})
    if not isinstance(extensions, dict):
        raise MCPContractError("MCP extensions capability is invalid")
    task_extension = "io.modelcontextprotocol/tasks" in extensions
    return MCPServerCapabilities(
        tools=True,
        tools_list_changed_subscription=list_changed,
        cancellation=False,
        task_extension=task_extension,
        reconciliation=task_extension,
    )


def decode_mcp_discover_response(
    raw: str | bytes,
    *,
    expected_request_id: int,
    config: MCPServerConfig,
    remote_enforcement_capabilities: RemoteMCPEnforcementCapabilities | None,
    verified_transport_identities: tuple[MCPTransportIdentity, ...],
    verified_at: datetime,
    digest_service: DigestService,
) -> MCPDiscoverResult:
    """Build digest-bound discovery evidence from self-reported metadata."""

    result = _response_result(raw, expected_request_id=expected_request_id)
    required = {
        "resultType",
        "supportedVersions",
        "capabilities",
        "ttlMs",
        "cacheScope",
        "_meta",
    }
    if not required <= set(result) or set(result) - (required | {"instructions"}):
        raise MCPContractError("MCP discover result fields are invalid")
    if (
        result["resultType"] != "complete"
        or type(result["ttlMs"]) is not int
        or result["ttlMs"] < 0
        or result["cacheScope"] not in {"public", "private"}
    ):
        raise MCPContractError("MCP discover cache/result metadata is invalid")
    versions = result["supportedVersions"]
    if (
        not isinstance(versions, list)
        or not versions
        or any(type(item) is not str for item in versions)
        or len(versions) != len(set(versions))
        or config.protocol_revision not in versions
    ):
        raise MCPProtocolRevisionMismatchError(
            "MCP server does not support the configured revision"
        )
    meta = result["_meta"]
    if not isinstance(meta, dict):
        raise MCPContractError("MCP discover result metadata is invalid")
    server_info = meta.get("io.modelcontextprotocol/serverInfo")
    if not isinstance(server_info, dict) or set(server_info) - {
        "name",
        "version",
        "title",
        "description",
        "websiteUrl",
        "icons",
    }:
        raise MCPContractError("MCP logical server metadata is invalid")
    name = _safe_text(server_info.get("name"), required=True, max_length=256)
    version = _safe_text(server_info.get("version"), required=True, max_length=128)
    assert name is not None and version is not None
    if name != config.expected_server_name or version != config.expected_server_version:
        raise MCPServerIdentityMismatchError("MCP logical server identity changed")
    capabilities = _capabilities(result["capabilities"])
    server_info_draft = MCPLogicalServerInfo(
        server_name=name,
        server_version=version,
        server_info_digest="0" * 64,
    )
    server_info_digest = digest_service.compute(
        "mcp_server_info_digest", server_info_draft.model_dump(mode="python")
    )
    logical_info = server_info_draft.model_copy(
        update={"server_info_digest": server_info_digest}
    )
    draft = MCPDiscoverResult(
        discover_result_id=f"discover-{config.server_id}",
        server_id=config.server_id,
        logical_server_info=logical_info,
        verified_transport_identities=verified_transport_identities,
        transport=config.transport,
        reported_capabilities=capabilities,
        remote_enforcement_capabilities=remote_enforcement_capabilities,
        tool_list_revision=config.tool_list_revision,
        task_extension_id=config.task_extension_id,
        task_extension_version=config.task_extension_version,
        task_implementation_mode=config.task_implementation_mode,
        discover_digest="0" * 64,
        verified_at=verified_at,
    )
    discover_digest = digest_service.compute(
        "mcp_discover_result_digest", draft.model_dump(mode="python")
    )
    return draft.model_copy(update={"discover_digest": discover_digest})


def _candidate(
    raw_tool: object, *, digest_service: DigestService
) -> MCPCandidateToolDefinition:
    if not isinstance(raw_tool, dict):
        raise MCPContractError("MCP candidate tool is not an object")
    allowed = {
        "name",
        "title",
        "description",
        "inputSchema",
        "outputSchema",
        "annotations",
        "_meta",
        "icons",
    }
    if set(raw_tool) - allowed:
        raise MCPContractError("MCP candidate tool has unknown control fields")
    name = _safe_text(raw_tool.get("name"), required=True, max_length=128)
    assert name is not None
    if re.fullmatch(_TOOL_NAME_PATTERN, name) is None:
        raise MCPContractError("MCP candidate tool name is invalid")
    title = _safe_text(raw_tool.get("title"), required=False, max_length=512)
    description = _safe_text(
        raw_tool.get("description"), required=False, max_length=4096
    )
    input_schema = raw_tool.get("inputSchema")
    if not isinstance(input_schema, dict) or input_schema.get("type") != "object":
        raise MCPContractError("MCP candidate input schema is invalid")
    try:
        validate_schema_is_supported(input_schema)
    except AuthorizationKernelError as exc:
        raise MCPContractError("MCP candidate input schema is unsupported") from exc
    input_schema_digest = digest_service.compute(
        "mcp_approved_tool_schema_digest",
        {"name": name, "input_schema": input_schema},
    )
    draft = MCPCandidateToolDefinition(
        name=name,
        title=title,
        description=description,
        input_schema=input_schema,
        input_schema_digest=input_schema_digest,
        candidate_digest="0" * 64,
    )
    candidate_digest = digest_service.compute(
        "mcp_candidate_tool_definition_digest", draft.model_dump(mode="python")
    )
    return draft.model_copy(update={"candidate_digest": candidate_digest})


def decode_mcp_tools_list_response(
    raw: str | bytes,
    *,
    expected_request_id: int,
    approved_tools: tuple[MCPApprovedTool, ...],
    tool_list_revision: str,
    digest_service: DigestService,
) -> MCPToolCatalogObservation:
    result = _response_result(raw, expected_request_id=expected_request_id)
    required = {"resultType", "tools", "ttlMs", "cacheScope"}
    if not required <= set(result) or set(result) - (required | {"_meta"}):
        # Pagination is deliberately unavailable until a bounded multi-page
        # transport contract is approved; silently using the first page would
        # create an incomplete live catalog.
        raise MCPContractError("MCP tools list is incomplete or has unknown fields")
    if (
        result["resultType"] != "complete"
        or type(result["ttlMs"]) is not int
        or result["ttlMs"] < 0
        or result["cacheScope"] not in {"public", "private"}
        or not isinstance(result["tools"], list)
        or len(result["tools"]) > 1024
    ):
        raise MCPContractError("MCP tools list metadata is invalid")
    candidates = tuple(
        _candidate(item, digest_service=digest_service) for item in result["tools"]
    )
    names = [item.name for item in candidates]
    if len(names) != len(set(names)):
        raise MCPContractError("MCP live tool names are not unique")
    approved_by_name = {item.name: item for item in approved_tools}
    approved_names = frozenset(
        item.name
        for item in candidates
        if item.name in approved_by_name
        and item.input_schema_digest
        == approved_by_name[item.name].input_schema_digest
    )
    live_catalog_digest = digest_service.compute(
        "mcp_live_tool_catalog_digest",
        {
            "tool_list_revision": tool_list_revision,
            "tools": [
                {
                    "name": item.name,
                    "input_schema_digest": item.input_schema_digest,
                }
                for item in sorted(candidates, key=lambda value: value.name)
            ],
        },
    )
    return MCPToolCatalogObservation(
        candidates=candidates,
        approved_tool_names=approved_names,
        live_catalog_digest=live_catalog_digest,
    )


def decode_mcp_call_response(
    raw: str | bytes, *, expected_request_id: int
) -> MCPCallControl:
    result = _response_result(raw, expected_request_id=expected_request_id)
    required = {"resultType", "content"}
    if not required <= set(result) or set(result) - {
        "resultType",
        "content",
        "structuredContent",
        "isError",
        "_meta",
    }:
        raise MCPContractError("MCP tool result fields are invalid")
    content = result["content"]
    is_error = result.get("isError", False)
    if (
        result["resultType"] != "complete"
        or not isinstance(content, list)
        or len(content) > 4096
        or type(is_error) is not bool
    ):
        raise MCPContractError("MCP tool result metadata is invalid")
    try:
        for item in content:
            if not isinstance(item, dict) or type(item.get("type")) is not str:
                raise ValueError("invalid content block")
            # CanonicalJsonObject validation ensures every nested value is JSON.
            _CANONICAL_OBJECT_ADAPTER.validate_python(item)
    except (ValidationError, ValueError, TypeError) as exc:
        raise MCPContractError("MCP tool content is invalid") from exc
    return MCPCallControl(is_error=is_error, content_count=len(content))


__all__ = [
    "MCPCallControl",
    "MCPCandidateToolDefinition",
    "MCPToolCatalogObservation",
    "MCPToolListChangedSignal",
    "decode_mcp_call_response",
    "decode_mcp_discover_response",
    "decode_mcp_tool_list_changed_notification",
    "decode_mcp_tools_list_response",
]
