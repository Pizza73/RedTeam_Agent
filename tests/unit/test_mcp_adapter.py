"""Stateful MCP adapter behavior and fail-closed drift handling."""

from __future__ import annotations

from copy import deepcopy

import pytest

import support
from mcp_test_server import StatefulMCPTestTransport, build_offline_mcp_fixture
from redteam_agent.adapters.mcp import MCPTransportIdentity
from redteam_agent.adapters.mcp_adapter import MCPAdapter
from redteam_agent.adapters.mcp_response import decode_mcp_call_response
from redteam_agent.adapters.mcp_transport import finalize_mcp_transport_attestation
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    MCPContractError,
    MCPProtocolRevisionMismatchError,
    MCPServerIdentityMismatchError,
    MCPTransportError,
    MCPTransportIdentityMismatchError,
    ResultCollectionError,
)
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.sink import StreamingQuarantineSink
from redteam_agent.models.common import ToolRef
from redteam_agent.runtime.clock import ManualClock


def _request(*, arguments: object = None) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="execution-1",
        task_id="task-1",
        tool_ref=ToolRef(tool_id="offline-echo", registry_revision=1),
        adapter_id="mcp-primary",
        provider_tool_name="offline.echo",
        result_delivery_mode="local_result",
        idempotency_key="idempotency-1",
        timeout_seconds=60,
        arguments={"message": "hello"} if arguments is None else arguments,
    )


def _capture() -> tuple[DispatchResultCapture, StreamingQuarantineSink]:
    sink = StreamingQuarantineSink(
        sink_id="sink-1",
        execution_id="execution-1",
        quarantine_id="quarantine-1",
        task_binding_digest="local-result-binding",
        max_output_bytes=1024 * 1024,
        committed_at=support.T0,
    )
    return (
        DispatchResultCapture(mode="local_result", capture_id="capture-1", sink=sink),
        sink,
    )


def test_capabilities_include_only_live_schema_matched_tools() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    capabilities = fixture.adapter.get_capabilities()

    assert capabilities.result_delivery_mode == "local_result"
    assert capabilities.reconciliation is False
    assert capabilities.cancellation is False
    assert fixture.tool_capability_id in capabilities.capabilities
    assert [item["method"] for item in fixture.server.requests] == [
        "server/discover",
        "tools/list",
    ]


def test_local_result_call_is_requalified_and_streamed_to_owned_sink() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    request = _request()
    capture, sink = _capture()

    handle = fixture.adapter.submit(request, (), capture, request.idempotency_key)
    receipt = sink.commit()

    assert handle.provider_task_id is None
    assert handle.result_delivery_mode == "local_result"
    control = capture.control()
    assert control is not None
    assert control.provider_status == "succeeded"
    assert receipt.stdout_bytes > 0
    assert fixture.server.calls == [
        {"name": "offline.echo", "arguments": {"message": "hello"}}
    ]
    assert [item["method"] for item in fixture.server.requests] == [
        "server/discover",
        "tools/list",
        "tools/call",
    ]


def test_live_schema_drift_prevents_call_dispatch() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    drifted = deepcopy(fixture.server.tools[0])
    drifted["inputSchema"] = {
        "type": "object",
        "properties": {"changed": {"type": "string"}},
        "required": ["changed"],
        "additionalProperties": False,
    }
    fixture.server.tools[0] = drifted
    request = _request()
    capture, _ = _capture()

    with pytest.raises(MCPContractError):
        fixture.adapter.submit(request, (), capture, request.idempotency_key)

    assert fixture.server.calls == []
    assert [item["method"] for item in fixture.server.requests] == [
        "server/discover",
        "tools/list",
    ]


def test_tool_change_refresh_creates_candidate_without_approving_schema_drift() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    drifted = deepcopy(fixture.server.tools[0])
    drifted["inputSchema"] = {
        "type": "object",
        "properties": {"changed": {"type": "string"}},
        "required": ["changed"],
        "additionalProperties": False,
    }
    fixture.server.tools[0] = drifted

    observation = fixture.adapter.observe_tools_list_changed(
        fixture.server.tool_list_changed_notification("subscription-1"),
        expected_subscription_id="subscription-1",
    )

    assert len(observation.candidates) == 1
    assert observation.candidates[0].name == "offline.echo"
    assert observation.approved_tool_names == frozenset()
    assert fixture.contract.approved_tools == (fixture.approved_tool,)


def test_tool_change_notification_requires_the_exact_subscription_identity() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    notification = fixture.server.tool_list_changed_notification("subscription-1")
    with pytest.raises(MCPContractError):
        fixture.adapter.observe_tools_list_changed(
            notification, expected_subscription_id="subscription-2"
        )
    assert fixture.transport.request_count == 0


def test_logical_server_identity_drift_is_rejected() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    fixture.server.server_version = "2.0.0-unapproved"
    with pytest.raises(MCPServerIdentityMismatchError):
        fixture.adapter.discover()


def test_protocol_revision_drift_is_rejected() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    fixture.server.supported_versions = ["2025-11-25"]
    with pytest.raises(MCPProtocolRevisionMismatchError):
        fixture.adapter.discover()


def test_response_id_mismatch_is_rejected() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    fixture.server.response_id_offset = 1
    with pytest.raises(MCPContractError):
        fixture.adapter.discover()


def test_duplicate_json_key_in_response_is_rejected() -> None:
    raw = (
        b'{"jsonrpc":"2.0","id":3,"result":'
        b'{"resultType":"complete","content":[],"content":[]}}'
    )
    with pytest.raises(MCPContractError):
        decode_mcp_call_response(raw, expected_request_id=3)


def test_unbounded_tools_pagination_is_rejected() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    fixture.server.paginate_tools = True
    with pytest.raises(MCPContractError):
        fixture.adapter.observe_tool_catalog()


def test_attested_stdio_identity_drift_raises_the_typed_identity_error() -> None:
    ds = DigestService()
    clock = ManualClock(support.T0)
    fixture = build_offline_mcp_fixture(digest_service=ds, clock=clock)
    identities = list(fixture.transport.attestation.verified_transport_identities)
    identities[-1] = MCPTransportIdentity(
        transport_type="stdio",
        identity_type="package_version",
        identity_value="drifted-test-version",
    )
    attestation = finalize_mcp_transport_attestation(
        fixture.transport.attestation.model_copy(
            update={
                "verified_transport_identities": tuple(identities),
                "attestation_digest": "0" * 64,
            }
        ),
        ds,
    )
    transport = StatefulMCPTestTransport(
        server=fixture.server, attestation=attestation
    )
    with pytest.raises(MCPTransportIdentityMismatchError):
        MCPAdapter(
            profile=fixture.profile,
            contract=fixture.contract,
            transport=transport,
            clock=clock,
            digest_service=ds,
        )


def test_transport_failure_is_not_silently_retried() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    fixture.server.fail_next_method = "server/discover"
    with pytest.raises(MCPTransportError):
        fixture.adapter.discover()
    assert fixture.transport.request_count == 1


def test_lost_call_response_is_not_retried_and_reconciliation_is_unsupported() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    fixture.server.drop_response_after_method = "tools/call"
    request = _request()
    capture, _sink = _capture()

    with pytest.raises(MCPTransportError):
        fixture.adapter.submit(request, (), capture, request.idempotency_key)

    assert len(fixture.server.calls) == 1
    assert [item["method"] for item in fixture.server.requests].count("tools/call") == 1
    assert fixture.adapter.reconcile(request.execution_id, None).status == "UNSUPPORTED"


def test_task_apis_are_explicitly_unsupported_without_transport_calls() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    assert fixture.adapter.reconcile("execution-1", None).status == "UNSUPPORTED"
    assert fixture.adapter.cancel("execution-1", "provider-task-1").result == "FAILED"
    with pytest.raises(ResultCollectionError):
        fixture.adapter.get_task_control("execution-1", None)  # type: ignore[arg-type]
    assert fixture.transport.request_count == 0
