"""Phase 5 offline acceptance over the trusted dispatch boundary."""

from __future__ import annotations

import support
from mcp_test_server import build_offline_mcp_fixture
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.dispatch_port import FixedTrustedAdapterDispatchPort
from redteam_agent.execution.sink import StreamingQuarantineSink
from redteam_agent.models.common import ToolRef
from redteam_agent.runtime.clock import ManualClock


def _request(sequence: int, *, adapter_id: str = "mcp-primary") -> ExecutionRequest:
    return ExecutionRequest(
        execution_id=f"execution-{sequence}",
        task_id=f"task-{sequence}",
        tool_ref=ToolRef(tool_id="offline-echo", registry_revision=1),
        adapter_id=adapter_id,
        provider_tool_name="offline.echo",
        result_delivery_mode="local_result",
        idempotency_key=f"idempotency-{sequence}",
        timeout_seconds=60,
        arguments={"message": f"message-{sequence}"},
    )


def _capture(sequence: int) -> tuple[DispatchResultCapture, StreamingQuarantineSink]:
    sink = StreamingQuarantineSink(
        sink_id=f"sink-{sequence}",
        execution_id=f"execution-{sequence}",
        quarantine_id=f"quarantine-{sequence}",
        task_binding_digest=f"local-binding-{sequence}",
        max_output_bytes=1024 * 1024,
        committed_at=support.T0,
    )
    capture = DispatchResultCapture(
        mode="local_result", capture_id=f"capture-{sequence}", sink=sink
    )
    return capture, sink


def test_stateful_server_covers_discovery_catalog_and_two_local_calls() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    port = FixedTrustedAdapterDispatchPort({"mcp-primary": fixture.adapter})

    capabilities = fixture.adapter.get_capabilities()
    assert fixture.tool_capability_id in capabilities.capabilities
    receipts = []
    for sequence in (1, 2):
        request = _request(sequence)
        capture, sink = _capture(sequence)
        handle = port.dispatch_once(
            request=request,
            secret_bindings=(),
            result_capture=capture,
            idempotency_key=request.idempotency_key,
        )
        assert handle.result_delivery_mode == "local_result"
        assert handle.provider_task_id is None
        control = capture.control()
        assert control is not None and control.provider_status == "succeeded"
        receipts.append(sink.commit())

    assert [call["arguments"] for call in fixture.server.calls] == [
        {"message": "message-1"},
        {"message": "message-2"},
    ]
    assert all(receipt.stdout_bytes > 0 for receipt in receipts)
    methods = [request["method"] for request in fixture.server.requests]
    assert methods == [
        "server/discover",
        "tools/list",
        "server/discover",
        "tools/list",
        "tools/call",
        "server/discover",
        "tools/list",
        "tools/call",
    ]
    assert not any(method.startswith("tasks/") for method in methods)


def test_same_logical_server_and_tool_names_route_by_stable_adapter_id() -> None:
    ds = DigestService()
    clock = ManualClock(support.T0)
    first = build_offline_mcp_fixture(
        digest_service=ds,
        clock=clock,
        adapter_id="mcp-server-a",
        server_id="stable-server-a",
    )
    second = build_offline_mcp_fixture(
        digest_service=ds,
        clock=clock,
        adapter_id="mcp-server-b",
        server_id="stable-server-b",
    )
    port = FixedTrustedAdapterDispatchPort(
        {"mcp-server-a": first.adapter, "mcp-server-b": second.adapter}
    )

    for sequence, fixture, adapter_id in (
        (1, first, "mcp-server-a"),
        (2, second, "mcp-server-b"),
    ):
        request = _request(sequence, adapter_id=adapter_id)
        capture, _sink = _capture(sequence)
        port.dispatch_once(
            request=request,
            secret_bindings=(),
            result_capture=capture,
            idempotency_key=request.idempotency_key,
        )
        assert fixture.adapter.identity().adapter_id == adapter_id

    assert first.server.calls == [
        {"name": "offline.echo", "arguments": {"message": "message-1"}}
    ]
    assert second.server.calls == [
        {"name": "offline.echo", "arguments": {"message": "message-2"}}
    ]
