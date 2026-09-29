"""Integration boundary tests for the non-operational Tuoni foundation."""

from __future__ import annotations

import pytest

from redteam_agent.adapters.tuoni import TuoniAdapterFoundation, build_tuoni_foundation_profile
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.dispatch_port import FixedTrustedAdapterDispatchPort
from redteam_agent.models.common import ToolRef


def test_foundation_cannot_dispatch_even_if_accidentally_registered() -> None:
    digest_service = DigestService()
    adapter = TuoniAdapterFoundation(
        build_tuoni_foundation_profile(digest_service=digest_service),
        digest_service,
    )
    port = FixedTrustedAdapterDispatchPort({"tuoni-c2": adapter})
    request = ExecutionRequest(
        execution_id="execution-1",
        task_id="task-1",
        tool_ref=ToolRef(tool_id="approved-operation", registry_revision=1),
        adapter_id="tuoni-c2",
        provider_tool_name="unresolved-provider-operation",
        result_delivery_mode="provider_task",
        idempotency_key="idempotency-1",
        timeout_seconds=60,
        arguments={},
    )
    capture = DispatchResultCapture(
        mode="provider_task",
        capture_id="capture-1",
        sink=None,
    )

    with pytest.raises(C2AdapterUnavailableError):
        port.dispatch_once(
            request=request,
            secret_bindings=(),
            result_capture=capture,
            idempotency_key="idempotency-1",
        )
