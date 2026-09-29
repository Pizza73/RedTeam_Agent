"""Closed MCP request contract tests."""

from __future__ import annotations

import pytest

import support
from mcp_test_server import ECHO_SCHEMA, build_offline_mcp_fixture
from redteam_agent.adapters.mcp_contract import (
    MCPApiContractV20260728,
    build_mcp_approved_tool,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import DigestIntegrityError, MCPContractError
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.models.common import ToolRef
from redteam_agent.runtime.clock import ManualClock


def _request(*, arguments: object = None, provider_tool_name: str = "offline.echo") -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="execution-1",
        task_id="task-1",
        tool_ref=ToolRef(tool_id="offline-echo", registry_revision=1),
        adapter_id="mcp-primary",
        provider_tool_name=provider_tool_name,
        result_delivery_mode="local_result",
        idempotency_key="idempotency-1",
        timeout_seconds=60,
        arguments={"message": "hello"} if arguments is None else arguments,
    )


def test_each_request_carries_exact_protocol_and_client_metadata() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    for request in (
        fixture.contract.discover(),
        fixture.contract.tools_list(),
        fixture.contract.tools_call(_request()),
    ):
        wire = parse_json_no_duplicate_keys(request.to_wire_bytes())
        assert wire["params"]["_meta"] == {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {
                "name": "redteam-agent",
                "version": "phase5-offline-v1",
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }


def test_unapproved_tool_is_rejected_before_a_wire_request_exists() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    with pytest.raises(MCPContractError):
        fixture.contract.tools_call(_request(provider_tool_name="unknown"))


def test_arguments_must_match_the_approved_schema() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    with pytest.raises(MCPContractError):
        fixture.contract.tools_call(_request(arguments={"unexpected": True}))


def test_approved_schema_digest_tamper_is_rejected() -> None:
    ds = DigestService()
    tool = build_mcp_approved_tool(
        name="offline.echo", input_schema=ECHO_SCHEMA, digest_service=ds
    ).model_copy(update={"input_schema_digest": "f" * 64})
    with pytest.raises(DigestIntegrityError):
        MCPApiContractV20260728(approved_tools=(tool,), digest_service=ds)


def test_contract_digest_is_stable_for_ordered_approved_tools() -> None:
    ds = DigestService()
    first = build_mcp_approved_tool(
        name="offline.z", input_schema=ECHO_SCHEMA, digest_service=ds
    )
    second = build_mcp_approved_tool(
        name="offline.a", input_schema=ECHO_SCHEMA, digest_service=ds
    )
    left = MCPApiContractV20260728(approved_tools=(first, second), digest_service=ds)
    right = MCPApiContractV20260728(approved_tools=(second, first), digest_service=ds)
    assert left.contract_digest() == right.contract_digest()
