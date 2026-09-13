"""Offline end-to-end tests for the transport-bound Tuoni adapter core."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import cast

import pytest

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
from redteam_agent.adapters.tuoni_adapter import (
    TUONI_RESULT_CHUNK_BYTES,
    TuoniAdapter,
)
from redteam_agent.adapters.tuoni_contract import (
    TuoniApiContractV0161,
    TuoniWireRequest,
)
from redteam_agent.adapters.tuoni_transport import (
    TuoniTransportAttestation,
    TuoniTransportResponse,
    finalize_tuoni_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    C2AdapterContractError,
    C2AdapterTransportError,
    C2AdapterUnavailableError,
    ResultCollectionError,
)
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.dispatch_port import FixedTrustedAdapterDispatchPort
from redteam_agent.execution.models import (
    CollectionCancellation,
    CollectionResumeCursor,
    ProviderTaskBinding,
)
from redteam_agent.execution.secret_binding import EphemeralSecretBinding
from redteam_agent.execution.sink import StreamingQuarantineSink
from redteam_agent.models.common import ToolRef
from redteam_agent.runtime.clock import ManualClock

NOW = datetime(2026, 9, 13, 3, 0, tzinfo=UTC)
AGENT_ID = "33d17e49-44ca-4204-bfc2-2b8c34f40f96"
TEMPLATE_ID = "a4c85e2b-53e1-4f82-889f-7cc17c7674cc"
TLS_DIGEST = "1" * 64
SECRET_VERSION = "secret://tuoni/service-account#v1"
PORT_GROUP = "isolated-tuoni-lab"
OPENAPI_DOCUMENT = {"openapi": "3.0.0"}
OPENAPI_DIGEST = sha256(
    json.dumps(OPENAPI_DOCUMENT, separators=(",", ":")).encode("utf-8")
).hexdigest()


class _FakeTransport:
    def __init__(self, attestation: TuoniTransportAttestation) -> None:
        self._attestation = attestation
        self.responses: dict[str, list[TuoniTransportResponse]] = {}
        self.failures: dict[str, C2AdapterTransportError] = {}
        self.requests: list[TuoniWireRequest] = []
        self.timeouts: list[int] = []
        self.response_limits: list[int] = []

    @property
    def attestation(self) -> TuoniTransportAttestation:
        return self._attestation

    def queue(self, operation: str, body: object, *, status: int = 200) -> None:
        response = TuoniTransportResponse(
            status_code=status,
            content_type="application/json; charset=utf-8",
            body=json.dumps(body, separators=(",", ":")).encode(),
        )
        self.responses.setdefault(operation, []).append(response)

    def request(
        self,
        request: TuoniWireRequest,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> TuoniTransportResponse:
        self.requests.append(request)
        self.timeouts.append(timeout_seconds)
        self.response_limits.append(max_response_bytes)
        failure = self.failures.get(request.operation)
        if failure is not None:
            raise failure
        queued = self.responses.get(request.operation, [])
        if not queued:
            if request.operation == "openapi":
                self.queue("openapi", OPENAPI_DOCUMENT)
            elif request.operation == "current_user":
                self.queue("current_user", _current_user())
            elif request.operation == "permissions":
                self.queue("permissions", _permissions())
            elif request.operation == "get_agent":
                self.queue("get_agent", _agent())
            else:
                raise AssertionError(f"no fake response for {request.operation}")
            queued = self.responses[request.operation]
        return queued.pop(0)


class _SecretProbe:
    secret_argument_path = "/credential"
    secret_version_id = "target-secret#v1"

    def __init__(self) -> None:
        self.consume_calls = 0

    def length(self) -> int:
        return 6

    def consume(self) -> bytes:
        self.consume_calls += 1
        return b"secret"


def _agent(
    *,
    status: str = "ACTIVE",
    active: bool = True,
    operating_system: str = "WINDOWS",
    architecture: str | None = "X64",
) -> dict[str, object]:
    return {
        "guid": AGENT_ID,
        "firstRegistrationTime": "2026-09-13T02:00:00Z",
        "lastCallbackTime": "2026-09-13T02:59:58Z",
        "nextCallback": {"expectedTime": "2026-09-13T03:00:02Z", "randomMs": 0},
        "metadata": {
            "guid": AGENT_ID,
            "hostname": "target-lab-01",
            "username": "LAB\\operator",
            "os": operating_system,
            "osArch": architecture,
        },
        "active": active,
        "status": status,
        "recentListeners": [],
        "availableCommandTemplates": [TEMPLATE_ID],
    }


def _command(
    *, command_id: int = 42, status: str = "CREATED", result: object = None
) -> dict[str, object]:
    return {
        "id": command_id,
        "commandTemplateId": TEMPLATE_ID,
        "commandTemplateName": "ps",
        "configuration": {"includeSystem": False},
        "execConf": {"execType": "SELF"},
        "agentGuid": AGENT_ID,
        "created": "2026-09-13T02:59:00Z",
        "sent": None if status == "CREATED" else "2026-09-13T02:59:01Z",
        "sendFormat": None if status == "CREATED" else "GENERIC",
        "sends": [],
        "status": status,
        "commandUpdates": [],
        "result": result,
    }


def _template(
    *, name: str = "ps", status: str = "ENABLED", user_creatable: bool = True
) -> dict[str, object]:
    return {
        "id": TEMPLATE_ID,
        "name": name,
        "pluginId": "tuoni.process",
        "scope": "agent",
        "qualifiedName": f"agent:{name}",
        "fullyQualifiedName": f"tuoni.process:agent:{name}",
        "description": "Process listing",
        "status": status,
        "supportedExecUnitTypes": ["SHELLCODE_NATIVE"],
        "exampleConfigurations": [],
        "configurationSchema": {
            "type": "object",
            "properties": {
                "includeSystem": {"type": "boolean"},
            },
            "required": ["includeSystem"],
            "additionalProperties": False,
        },
        "updateSchema": None,
        "isUserCreatable": user_creatable,
        "isAlias": False,
    }


def _permission(code: str, *, mandatory: bool = False) -> dict[str, object]:
    return {
        "label": code,
        "code": code,
        "description": code,
        "mandatory": mandatory,
    }


def _permissions() -> list[dict[str, object]]:
    return [
        _permission("VIEW_RESOURCES", mandatory=True),
        _permission("SEND_COMMANDS"),
        _permission("MANAGE_USERS"),
    ]


def _current_user(
    *,
    enabled: bool = True,
    codes: tuple[str, ...] = ("VIEW_RESOURCES", "SEND_COMMANDS"),
) -> dict[str, object]:
    return {
        "userGuid": "d288f64b-0bb5-4168-90ad-5a0c46049444",
        "username": "red-agent-service",
        "enabled": enabled,
        "permissions": [
            _permission(code, mandatory=code == "VIEW_RESOURCES")
            for code in codes
        ],
        "createEvent": {},
        "lastUpdateEvent": {},
    }


def _complete_profile(ds: DigestService):
    return build_tuoni_foundation_profile(
        digest_service=ds,
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


def _attestation(profile, contract_digest: str, ds: DigestService):
    return finalize_tuoni_transport_attestation(
        TuoniTransportAttestation(
            adapter_profile_digest=profile.profile_digest,
            contract_digest=contract_digest,
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
        ds,
    )


def _adapter():
    ds = DigestService()
    profile = _complete_profile(ds)
    contract = TuoniApiContractV0161(approved_command_templates=("ps",))
    transport = _FakeTransport(_attestation(profile, contract.contract_digest(ds), ds))
    adapter = TuoniAdapter(
        profile=profile,
        contract=contract,
        transport=transport,
        clock=ManualClock(NOW),
        digest_service=ds,
    )
    return adapter, transport


def _request() -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="execution-1",
        task_id="task-1",
        tool_ref=ToolRef(tool_id="process-list", registry_revision=1),
        adapter_id="tuoni-c2",
        provider_tool_name="ps",
        result_delivery_mode="provider_task",
        idempotency_key="idempotency-1",
        timeout_seconds=60,
        arguments={
            "provider_session_id": AGENT_ID,
            "configuration": {"includeSystem": False},
        },
    )


def _binding(adapter: TuoniAdapter, *, provider_task_id: str = "42") -> ProviderTaskBinding:
    identity = adapter.identity()
    return ProviderTaskBinding(
        task_id="task-1",
        execution_id="execution-1",
        adapter_identity_digest=identity.adapter_identity_digest,
        provider_identity_digest=identity.provider_identity_digest,
        provider_task_id=provider_task_id,
        dispatch_claim_id="claim-execution-1",
        binding_digest="binding-digest-1",
    )


def _capture() -> DispatchResultCapture:
    return DispatchResultCapture(mode="provider_task", capture_id="capture-1", sink=None)


def test_adapter_requires_complete_deployment_profile() -> None:
    ds = DigestService()
    profile = build_tuoni_foundation_profile(digest_service=ds)
    contract = TuoniApiContractV0161(approved_command_templates=("ps",))
    transport = _FakeTransport(_attestation(_complete_profile(ds), contract.contract_digest(ds), ds))

    with pytest.raises(C2AdapterUnavailableError):
        TuoniAdapter(
            profile=profile,
            contract=contract,
            transport=transport,
            clock=ManualClock(NOW),
            digest_service=ds,
        )


def test_adapter_rejects_attestation_bound_to_another_profile() -> None:
    ds = DigestService()
    profile = _complete_profile(ds)
    contract = TuoniApiContractV0161(approved_command_templates=("ps",))
    wrong_profile = build_tuoni_foundation_profile(
        digest_service=ds,
        connection=TuoniConnectionPolicy(tls_certificate_sha256="2" * 64),
        authentication=TuoniAuthenticationPolicy(
            credential_secret_version_id=SECRET_VERSION
        ),
        isolation=TuoniLabIsolationPolicy(vcenter_port_group_name=PORT_GROUP),
    )
    transport = _FakeTransport(
        _attestation(wrong_profile, contract.contract_digest(ds), ds)
    )

    with pytest.raises(C2AdapterUnavailableError):
        TuoniAdapter(
            profile=profile,
            contract=contract,
            transport=transport,
            clock=ManualClock(NOW),
            digest_service=ds,
        )


def test_capabilities_and_session_reads_are_provider_neutral() -> None:
    adapter, transport = _adapter()
    transport.queue("list_active_agents", [_agent()])
    transport.queue("list_agent_command_templates", [_template()])
    transport.queue("get_agent", _agent())
    transport.queue("list_agent_command_templates", [_template()])

    capabilities = adapter.get_capabilities()
    sessions = adapter.list_sessions()
    session = adapter.get_session(AGENT_ID)

    assert capabilities.adapter_type == "c2"
    assert capabilities.provider_deduplication is False
    assert capabilities.result_resume is False
    assert capabilities.redirect_disable_enforcement is True
    assert sessions == (session,)
    assert session.provider_status == "active"
    assert session.capabilities == frozenset({"ps"})
    assert all(not hasattr(item, "api_origin") for item in transport.requests)


def test_capability_probe_rejects_live_openapi_mismatch_before_account_reads() -> None:
    adapter, transport = _adapter()
    transport.queue("openapi", {"openapi": "different"})

    with pytest.raises(C2AdapterContractError):
        adapter.get_capabilities()

    assert [item.operation for item in transport.requests] == ["openapi"]


def test_submit_dispatches_once_and_returns_exact_provider_task_binding() -> None:
    adapter, transport = _adapter()
    transport.queue("list_agent_command_templates", [_template()])
    transport.queue("submit_command", _command())
    port = FixedTrustedAdapterDispatchPort({"tuoni-c2": adapter})

    handle = port.dispatch_once(
        request=_request(),
        secret_bindings=(),
        result_capture=_capture(),
        idempotency_key="idempotency-1",
    )

    assert handle.provider_task_id == "42"
    assert [item.operation for item in transport.requests] == [
        "current_user",
        "get_agent",
        "list_agent_command_templates",
        "submit_command",
    ]
    assert transport.timeouts == [30, 30, 30, 60]


def test_submit_rejects_disabled_live_template_before_side_effect() -> None:
    adapter, transport = _adapter()
    transport.queue(
        "list_agent_command_templates", [_template(status="DISABLED")]
    )

    with pytest.raises(C2AdapterContractError):
        adapter.submit(_request(), (), _capture(), "idempotency-1")

    assert [item.operation for item in transport.requests] == [
        "current_user",
        "get_agent",
        "list_agent_command_templates",
    ]


@pytest.mark.parametrize(
    "user",
    [
        _current_user(enabled=False),
        _current_user(codes=("VIEW_RESOURCES",)),
        _current_user(
            codes=("VIEW_RESOURCES", "SEND_COMMANDS", "MANAGE_USERS")
        ),
    ],
)
def test_submit_rejects_non_minimal_service_account_before_template_or_side_effect(
    user: dict[str, object],
) -> None:
    adapter, transport = _adapter()
    transport.queue("current_user", user)

    with pytest.raises(C2AdapterUnavailableError):
        adapter.submit(_request(), (), _capture(), "idempotency-1")

    assert [item.operation for item in transport.requests] == ["current_user"]


@pytest.mark.parametrize(
    "agent",
    [
        _agent(status="INACTIVE", active=False),
        _agent(operating_system="LINUX"),
        _agent(architecture=None),
        _agent(architecture="X86"),
    ],
)
def test_submit_rejects_ineligible_target_before_template_or_side_effect(
    agent: dict[str, object],
) -> None:
    adapter, transport = _adapter()
    transport.queue("get_agent", agent)

    with pytest.raises(C2AdapterUnavailableError):
        adapter.submit(_request(), (), _capture(), "idempotency-1")

    assert [item.operation for item in transport.requests] == [
        "current_user",
        "get_agent",
    ]


def test_uncertain_submit_is_never_automatically_retried() -> None:
    adapter, transport = _adapter()
    transport.queue("list_agent_command_templates", [_template()])
    transport.failures["submit_command"] = C2AdapterTransportError("timeout")

    with pytest.raises(C2AdapterTransportError):
        adapter.submit(_request(), (), _capture(), "idempotency-1")
    reconciled = adapter.reconcile("execution-1", None)

    assert reconciled.status == "UNSUPPORTED"
    assert [item.operation for item in transport.requests] == [
        "current_user",
        "get_agent",
        "list_agent_command_templates",
        "submit_command",
    ]


def test_submit_rejects_execution_secret_before_transport_access() -> None:
    adapter, transport = _adapter()
    secret = _SecretProbe()

    with pytest.raises(C2AdapterContractError):
        adapter.submit(
            _request(),
            (cast(EphemeralSecretBinding, secret),),
            _capture(),
            "idempotency-1",
        )

    assert transport.requests == []
    assert secret.consume_calls == 0


@pytest.mark.parametrize(
    "provider_status, expected_status, expected_terminal",
    [
        ("ONGOING", "FOUND_RUNNING", None),
        ("COMPLETE", "FOUND_TERMINAL", "succeeded"),
        ("FAILED", "FOUND_TERMINAL", "failed"),
        ("CANCELED", "FOUND_TERMINAL", "cancelled"),
    ],
)
def test_reconcile_maps_provider_status_without_resubmission(
    provider_status: str, expected_status: str, expected_terminal: str | None
) -> None:
    adapter, transport = _adapter()
    result = (
        None
        if provider_status == "ONGOING"
        else {
            "status": provider_status,
            "errorMessage": None,
            "received": "2026-09-13T03:00:00Z",
            "childResults": [],
        }
    )
    transport.queue("get_command", _command(status=provider_status, result=result))

    reconciled = adapter.reconcile("execution-1", _binding(adapter))

    assert reconciled.status == expected_status
    assert reconciled.provider_status == expected_terminal
    assert [item.operation for item in transport.requests] == ["get_command"]


def test_unacknowledged_submit_and_not_found_are_always_uncertain() -> None:
    adapter, transport = _adapter()

    unsupported = adapter.reconcile("execution-1", None)
    transport.queue("get_command", {}, status=404)
    not_found = adapter.reconcile("execution-1", _binding(adapter))

    assert unsupported.status == "UNSUPPORTED"
    assert not_found.status == "NOT_FOUND_UNCERTAIN"
    assert len(transport.requests) == 1


def test_reconcile_transport_failure_becomes_unknown() -> None:
    adapter, transport = _adapter()
    transport.failures["get_command"] = C2AdapterTransportError("timeout")

    result = adapter.reconcile("execution-1", _binding(adapter))

    assert result.status == "UNKNOWN"


@pytest.mark.parametrize(
    "provider_status, expected",
    [
        ("CANCELED", "CONFIRMED"),
        ("ONGOING", "ACKNOWLEDGED"),
        ("COMPLETE", "FAILED"),
    ],
)
def test_cancel_maps_acknowledgement_and_terminal_state(
    provider_status: str, expected: str
) -> None:
    adapter, transport = _adapter()
    result = (
        None
        if provider_status == "ONGOING"
        else {
            "status": provider_status,
            "errorMessage": None,
            "received": "2026-09-13T03:00:00Z",
            "childResults": [],
        }
    )
    transport.queue("stop_command", _command(status=provider_status, result=result))

    outcome = adapter.cancel("execution-1", "42")

    assert outcome.result == expected


def test_cancel_transport_failure_is_unknown() -> None:
    adapter, transport = _adapter()
    transport.failures["stop_command"] = C2AdapterTransportError("timeout")

    assert adapter.cancel("execution-1", "42").result == "UNKNOWN"


def test_terminal_result_is_chunked_to_composition_owned_sink() -> None:
    adapter, transport = _adapter()
    large_value = "x" * (TUONI_RESULT_CHUNK_BYTES + 100)
    result = {
        "status": "COMPLETE",
        "errorMessage": None,
        "received": "2026-09-13T03:00:00Z",
        "childResults": [{"type": "text", "name": "stdout", "value": large_value}],
    }
    transport.queue("get_command", _command(status="COMPLETE", result=result))
    binding = _binding(adapter)
    sink = StreamingQuarantineSink(
        sink_id="sink-execution-1",
        execution_id="execution-1",
        quarantine_id="q-execution-1",
        task_binding_digest=binding.binding_digest,
        max_output_bytes=1024 * 1024,
        committed_at=NOW,
    )
    resume = CollectionResumeCursor(
        collection_id="collection-execution-1",
        execution_id="execution-1",
        result_delivery_mode="provider_task",
        task_binding_digest=binding.binding_digest,
        sink_id=sink.sink_id,
        last_committed_chunk_sequence=0,
        receipt_id=None,
    )

    control = adapter.collect_result(
        "execution-1", binding, sink, resume=resume
    )
    receipt = sink.commit()

    assert control.provider_status == "succeeded"
    assert receipt.stdout_bytes > TUONI_RESULT_CHUNK_BYTES
    assert sink.max_single_chunk_bytes <= TUONI_RESULT_CHUNK_BYTES


def test_collection_rejects_cancellation_before_provider_read() -> None:
    adapter, transport = _adapter()
    binding = _binding(adapter)
    sink = StreamingQuarantineSink(
        sink_id="sink-execution-1",
        execution_id="execution-1",
        quarantine_id="q-execution-1",
        task_binding_digest=binding.binding_digest,
        max_output_bytes=1024,
        committed_at=NOW,
    )
    cancellation = CollectionCancellation(
        collection_id="collection-execution-1",
        execution_id="execution-1",
        task_binding_digest=binding.binding_digest,
        sink_id=sink.sink_id,
        reason="lease expired",
    )

    with pytest.raises(ResultCollectionError):
        adapter.collect_result(
            "execution-1", binding, sink, cancellation=cancellation
        )

    assert transport.requests == []


def test_collection_rejects_nonzero_resume_cursor_before_provider_read() -> None:
    adapter, transport = _adapter()
    binding = _binding(adapter)
    sink = StreamingQuarantineSink(
        sink_id="sink-execution-1",
        execution_id="execution-1",
        quarantine_id="q-execution-1",
        task_binding_digest=binding.binding_digest,
        max_output_bytes=1024,
        committed_at=NOW,
    )
    resume = CollectionResumeCursor(
        collection_id="collection-execution-1",
        execution_id="execution-1",
        result_delivery_mode="provider_task",
        task_binding_digest=binding.binding_digest,
        sink_id=sink.sink_id,
        last_committed_chunk_sequence=1,
        receipt_id="receipt-prior",
    )

    with pytest.raises(ResultCollectionError):
        adapter.collect_result("execution-1", binding, sink, resume=resume)

    assert transport.requests == []


def test_metadata_only_control_read_does_not_touch_a_sink() -> None:
    adapter, transport = _adapter()
    result = {
        "status": "COMPLETE",
        "errorMessage": None,
        "received": "2026-09-13T03:00:00Z",
        "childResults": [{"type": "text", "name": "stdout", "value": "data"}],
    }
    transport.queue("get_command", _command(status="COMPLETE", result=result))

    control = adapter.get_task_control("execution-1", _binding(adapter))

    assert control.provider_status == "succeeded"
    assert [item.operation for item in transport.requests] == ["get_command"]


def test_wrong_binding_is_rejected_before_provider_read() -> None:
    adapter, transport = _adapter()
    binding = _binding(adapter).model_copy(
        update={"provider_identity_digest": "wrong-provider"}
    )

    with pytest.raises(C2AdapterContractError):
        adapter.reconcile("execution-1", binding)
    assert transport.requests == []


def test_transport_response_repr_never_contains_provider_body() -> None:
    response = TuoniTransportResponse(
        status_code=200,
        content_type="application/json",
        body=b'{"credential":"must-not-appear"}',
    )

    assert "must-not-appear" not in repr(response)
