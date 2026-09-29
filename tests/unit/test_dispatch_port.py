"""Fixed trusted adapter dispatch port + result-capture validation (SystemDesign §10.2)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redteam_agent.errors import ResultCollectionError, SecretInjectionError
from redteam_agent.execution.adapter import ExecutionRequest, MockExecutionAdapter, TaskHandle
from redteam_agent.execution.dispatch_port import DispatchResultCapture, FixedTrustedAdapterDispatchPort
from redteam_agent.execution.models import CollectionCancellation, CollectionResumeCursor, ProviderTaskBinding
from redteam_agent.execution.sink import StreamingQuarantineSink
from redteam_agent.models.common import ToolRef

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _request(adapter_id: str = "c2-main", mode: str = "provider_task", idem: str = "ik") -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="exec-1", task_id="t1", tool_ref=ToolRef(tool_id="net-scan", registry_revision=1),
        adapter_id=adapter_id, provider_tool_name="scan", result_delivery_mode=mode,  # type: ignore[arg-type]
        idempotency_key=idem, timeout_seconds=60, arguments={"destinations": ["10.0.0.1"]},
    )


def _port() -> FixedTrustedAdapterDispatchPort:
    return FixedTrustedAdapterDispatchPort({"c2-main": MockExecutionAdapter(adapter_id="c2-main", clock_value=T0)})


def _capture(mode: str = "provider_task") -> DispatchResultCapture:
    sink = None
    if mode == "local_result":
        sink = StreamingQuarantineSink(
            sink_id="s", execution_id="exec-1", quarantine_id="q", task_binding_digest="bd",
            max_output_bytes=1000, committed_at=T0,
        )
    return DispatchResultCapture(mode=mode, capture_id="cap", sink=sink)  # type: ignore[arg-type]


def test_unknown_adapter_rejected() -> None:
    port = _port()
    with pytest.raises(SecretInjectionError):
        port.dispatch_once(
            request=_request(adapter_id="unknown"), secret_bindings=(), result_capture=_capture(),
            idempotency_key="ik",
        )


def test_capture_mode_mismatch_rejected() -> None:
    port = _port()
    with pytest.raises(SecretInjectionError):
        port.dispatch_once(
            request=_request(mode="provider_task"), secret_bindings=(), result_capture=_capture("local_result"),
            idempotency_key="ik",
        )


def test_idempotency_key_mismatch_rejected() -> None:
    port = _port()
    with pytest.raises(SecretInjectionError):
        port.dispatch_once(
            request=_request(idem="ik"), secret_bindings=(), result_capture=_capture(), idempotency_key="other",
        )


def test_local_result_capture_requires_sink() -> None:
    with pytest.raises(SecretInjectionError):
        DispatchResultCapture(mode="local_result", capture_id="cap", sink=None)


def test_provider_task_capture_rejects_sink() -> None:
    sink = StreamingQuarantineSink(
        sink_id="s", execution_id="exec-1", quarantine_id="q", task_binding_digest="bd",
        max_output_bytes=1000, committed_at=T0,
    )
    with pytest.raises(SecretInjectionError):
        DispatchResultCapture(mode="provider_task", capture_id="cap", sink=sink)


def test_successful_dispatch_returns_matching_handle() -> None:
    port = _port()
    handle = port.dispatch_once(
        request=_request(), secret_bindings=(), result_capture=_capture(), idempotency_key="ik"
    )
    assert handle.task_id == "t1"
    assert handle.result_delivery_mode == "provider_task"
    assert handle.provider_task_id is not None


def test_mismatched_adapter_identity_from_handle_is_rejected() -> None:
    class ConfusedAdapter(MockExecutionAdapter):
        def submit(self, request, secret_bindings, result_capture, idempotency_key):  # type: ignore[no-untyped-def]
            handle = super().submit(request, secret_bindings, result_capture, idempotency_key)
            return TaskHandle(
                task_id=handle.task_id,
                result_delivery_mode=handle.result_delivery_mode,
                provider_task_id=handle.provider_task_id,
                adapter_identity_digest="wrong-adapter",
                provider_identity_digest=handle.provider_identity_digest,
            )

    port = FixedTrustedAdapterDispatchPort(
        {"c2-main": ConfusedAdapter(adapter_id="c2-main", clock_value=T0)}
    )
    with pytest.raises(SecretInjectionError):
        port.dispatch_once(
            request=_request(), secret_bindings=(), result_capture=_capture(), idempotency_key="ik"
        )


def test_collection_resume_rejects_cross_sink_binding() -> None:
    adapter = MockExecutionAdapter(adapter_id="c2-main", clock_value=T0)
    binding = ProviderTaskBinding(
        task_id="t1", execution_id="exec-1", adapter_identity_digest="adapter-identity-mock",
        provider_identity_digest="provider-identity-mock", provider_task_id="provider-t1",
        dispatch_claim_id="claim-1", binding_digest="bd",
    )
    sink = StreamingQuarantineSink(
        sink_id="sink-exec-1", execution_id="exec-1", quarantine_id="q",
        task_binding_digest="bd", max_output_bytes=1000, committed_at=T0,
    )
    cursor = CollectionResumeCursor(
        collection_id="collection-exec-1", execution_id="exec-1",
        result_delivery_mode="provider_task", task_binding_digest="bd",
        sink_id="sink-other", last_committed_chunk_sequence=0, receipt_id=None,
    )
    with pytest.raises(ResultCollectionError):
        adapter.collect_result("exec-1", binding, sink, resume=cursor)


def test_collection_cancellation_rejects_cross_execution_binding() -> None:
    adapter = MockExecutionAdapter(adapter_id="c2-main", clock_value=T0)
    binding = ProviderTaskBinding(
        task_id="t1", execution_id="exec-1", adapter_identity_digest="adapter-identity-mock",
        provider_identity_digest="provider-identity-mock", provider_task_id="provider-t1",
        dispatch_claim_id="claim-1", binding_digest="bd",
    )
    sink = StreamingQuarantineSink(
        sink_id="sink-exec-1", execution_id="exec-1", quarantine_id="q",
        task_binding_digest="bd", max_output_bytes=1000, committed_at=T0,
    )
    cancellation = CollectionCancellation(
        collection_id="collection-exec-1", execution_id="exec-other",
        task_binding_digest="bd", sink_id="sink-exec-1", reason="stop receiving",
    )
    with pytest.raises(ResultCollectionError):
        adapter.collect_result("exec-1", binding, sink, cancellation=cancellation)
