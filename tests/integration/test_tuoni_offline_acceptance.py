"""Stateful no-network acceptance scenario for the full Tuoni adapter surface."""

from __future__ import annotations

from datetime import UTC, datetime

from redteam_agent.adapters.tuoni import (
    TUONI_SERVER_IMAGE_DIGEST_PIN,
    TUONI_SOURCE_COMMIT_PIN,
    TUONI_VERSION_PIN,
    TuoniAuthenticationPolicy,
    TuoniConnectionPolicy,
    TuoniLabIsolationPolicy,
    TuoniProviderPin,
    build_tuoni_foundation_profile,
)
from redteam_agent.adapters.tuoni_adapter import TuoniAdapter
from redteam_agent.adapters.tuoni_contract import TuoniApiContractV0161
from redteam_agent.adapters.tuoni_transport import (
    TuoniTransportAttestation,
    finalize_tuoni_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.dispatch_port import FixedTrustedAdapterDispatchPort
from redteam_agent.execution.models import ProviderTaskBinding
from redteam_agent.execution.sink import StreamingQuarantineSink
from redteam_agent.models.common import ToolRef
from redteam_agent.runtime.clock import ManualClock
from tuoni_test_double import (
    AGENT_ID,
    OPENAPI_DIGEST,
    TEMPLATE_NAME,
    StatefulTuoniTransportDouble,
)

NOW = datetime(2026, 9, 13, 8, 0, tzinfo=UTC)
TLS_DIGEST = "1" * 64
SECRET_VERSION = "secret://tuoni/service-account#v1"
PORT_GROUP = "isolated-tuoni-lab"


def _adapter():
    digest_service = DigestService()
    profile = build_tuoni_foundation_profile(
        digest_service=digest_service,
        provider=TuoniProviderPin(
            server_version=TUONI_VERSION_PIN,
            openapi_sha256=OPENAPI_DIGEST,
            container_image_digest=TUONI_SERVER_IMAGE_DIGEST_PIN,
            source_commit=TUONI_SOURCE_COMMIT_PIN,
        ),
        connection=TuoniConnectionPolicy(tls_certificate_sha256=TLS_DIGEST),
        authentication=TuoniAuthenticationPolicy(
            credential_secret_version_id=SECRET_VERSION
        ),
        isolation=TuoniLabIsolationPolicy(vcenter_port_group_name=PORT_GROUP),
    )
    contract = TuoniApiContractV0161(
        approved_command_templates=(TEMPLATE_NAME,)
    )
    attestation = finalize_tuoni_transport_attestation(
        TuoniTransportAttestation(
            adapter_profile_digest=profile.profile_digest,
            contract_digest=contract.contract_digest(digest_service),
            server_version=TUONI_VERSION_PIN,
            openapi_sha256=OPENAPI_DIGEST,
            container_image_digest=TUONI_SERVER_IMAGE_DIGEST_PIN,
            source_commit=TUONI_SOURCE_COMMIT_PIN,
            tls_certificate_sha256=TLS_DIGEST,
            credential_secret_version_id=SECRET_VERSION,
            vcenter_port_group_name=PORT_GROUP,
            attested_at=NOW,
            attestation_digest="0" * 64,
        ),
        digest_service,
    )
    transport = StatefulTuoniTransportDouble(attestation)
    adapter = TuoniAdapter(
        profile=profile,
        contract=contract,
        transport=transport,
        clock=ManualClock(NOW),
        digest_service=digest_service,
    )
    return adapter, transport


def _request(*, execution_id: str, task_id: str) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id=execution_id,
        task_id=task_id,
        tool_ref=ToolRef(tool_id="process-list", registry_revision=1),
        adapter_id="tuoni-c2",
        provider_tool_name=TEMPLATE_NAME,
        result_delivery_mode="provider_task",
        idempotency_key=f"idempotency-{execution_id}",
        timeout_seconds=60,
        arguments={
            "provider_session_id": AGENT_ID,
            "configuration": {"includeSystem": False},
        },
    )


def _binding(
    adapter: TuoniAdapter,
    *,
    execution_id: str,
    task_id: str,
    provider_task_id: str,
) -> ProviderTaskBinding:
    identity = adapter.identity()
    return ProviderTaskBinding(
        task_id=task_id,
        execution_id=execution_id,
        adapter_identity_digest=identity.adapter_identity_digest,
        provider_identity_digest=identity.provider_identity_digest,
        provider_task_id=provider_task_id,
        dispatch_claim_id=f"claim-{execution_id}",
        binding_digest=f"binding-{execution_id}",
    )


def test_stateful_double_covers_session_submit_task_result_cancel_and_reconcile() -> None:
    adapter, transport = _adapter()
    port = FixedTrustedAdapterDispatchPort({"tuoni-c2": adapter})

    capabilities = adapter.get_capabilities()
    assert capabilities.adapter_type == "c2"
    session = adapter.list_sessions()[0]
    assert adapter.get_session(session.provider_session_id) == session
    assert session.os == "windows"
    assert session.architecture == "x86_64"
    assert session.capabilities == frozenset({TEMPLATE_NAME})

    first_request = _request(execution_id="execution-1", task_id="task-1")
    first_handle = port.dispatch_once(
        request=first_request,
        secret_bindings=(),
        result_capture=DispatchResultCapture(
            mode="provider_task",
            capture_id="capture-1",
            sink=None,
        ),
        idempotency_key=first_request.idempotency_key,
    )
    assert first_handle.provider_task_id == "1"
    first_binding = _binding(
        adapter,
        execution_id="execution-1",
        task_id="task-1",
        provider_task_id="1",
    )
    transport.mark_running(1)
    assert adapter.reconcile("execution-1", first_binding).status == "FOUND_RUNNING"

    transport.complete(1, output="offline-result")
    assert adapter.reconcile("execution-1", first_binding).status == "FOUND_TERMINAL"
    sink = StreamingQuarantineSink(
        sink_id="sink-1",
        execution_id="execution-1",
        quarantine_id="q-1",
        task_binding_digest=first_binding.binding_digest,
        max_output_bytes=1024 * 1024,
        committed_at=NOW,
    )
    control = adapter.collect_result("execution-1", first_binding, sink)
    receipt = sink.commit()
    assert control.provider_status == "succeeded"
    assert receipt.stdout_bytes > 0

    second_request = _request(execution_id="execution-2", task_id="task-2")
    second_handle = port.dispatch_once(
        request=second_request,
        secret_bindings=(),
        result_capture=DispatchResultCapture(
            mode="provider_task",
            capture_id="capture-2",
            sink=None,
        ),
        idempotency_key=second_request.idempotency_key,
    )
    assert second_handle.provider_task_id == "2"
    assert adapter.cancel("execution-2", "2").result == "CONFIRMED"

    operations = [request.operation for request in transport.requests]
    assert operations.count("submit_command") == 2
    assert operations.count("stop_command") == 1
    assert "list_active_agents" in operations
    assert "get_agent" in operations
    assert "get_command" in operations
    assert "current_user" in operations
    assert "permissions" in operations
