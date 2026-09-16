"""Security regressions for the offline MCP boundary."""

from __future__ import annotations

import pytest

import support
from mcp_test_server import build_offline_mcp_fixture
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import MCPContractError
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.secret_binding import _EphemeralSecretBinding
from redteam_agent.execution.sink import StreamingQuarantineSink
from redteam_agent.models.common import ToolRef
from redteam_agent.runtime.clock import ManualClock


def _request(arguments: object) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="execution-security",
        task_id="task-security",
        tool_ref=ToolRef(tool_id="offline-echo", registry_revision=1),
        adapter_id="mcp-primary",
        provider_tool_name="offline.echo",
        result_delivery_mode="local_result",
        idempotency_key="idempotency-security",
        timeout_seconds=60,
        arguments=arguments,
    )


def _capture() -> DispatchResultCapture:
    sink = StreamingQuarantineSink(
        sink_id="security-sink",
        execution_id="execution-security",
        quarantine_id="security-quarantine",
        task_binding_digest="security-local-binding",
        max_output_bytes=1024,
        committed_at=support.T0,
    )
    return DispatchResultCapture(
        mode="local_result", capture_id="security-capture", sink=sink
    )


def test_secret_binding_is_rejected_before_transport_and_never_consumed() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    request = _request({"message": "safe"})
    secret = _EphemeralSecretBinding(
        secret_argument_path="/credential",
        secret_version_id="secret-v1",
        buffer=bytearray(b"must-not-leave-boundary"),
    )

    with pytest.raises(MCPContractError):
        fixture.adapter.submit(request, (secret,), _capture(), request.idempotency_key)

    assert fixture.transport.request_count == 0
    assert secret.length() == len(b"must-not-leave-boundary")


def test_invalid_arguments_fail_before_discovery_or_tool_call() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    request = _request({"message": "safe", "extra": "not-approved"})
    with pytest.raises(MCPContractError):
        fixture.adapter.submit(request, (), _capture(), request.idempotency_key)
    assert fixture.transport.request_count == 0


def test_test_server_attestation_is_permanently_non_production() -> None:
    fixture = build_offline_mcp_fixture(
        digest_service=DigestService(), clock=ManualClock(support.T0)
    )
    assert fixture.transport.attestation.evidence_kind == "test_server"
    assert fixture.transport.attestation.production_eligible is False
