"""Read-only Impacket MCP server and adapter boundary tests."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import version
from types import SimpleNamespace

import pytest

import support
from redteam_agent.adapters.mcp import MCPTransportIdentity
from redteam_agent.adapters.mcp_adapter import MCPAdapter
from redteam_agent.adapters.mcp_transport import (
    MCPTransportAttestation,
    MCPTransportResponse,
    finalize_mcp_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import MCPContractError
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.executor import Executor
from redteam_agent.execution.sink import StreamingQuarantineSink
from redteam_agent.mcp_servers.impacket_backend import (
    FortraImpacketBackend,
    ImpacketCredential,
)
from redteam_agent.mcp_servers.impacket_catalog import (
    build_impacket_mcp_contract,
    build_impacket_mcp_profile,
    build_impacket_tool_definitions,
)
from redteam_agent.mcp_servers.impacket_server import (
    ImpacketMCPServer,
    ImpacketServerPolicy,
)
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.policy.scope_models import NormalizedTarget
from redteam_agent.policy.target_binding import build_target_dispatch_binding
from redteam_agent.runtime.clock import ManualClock


class _FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    def smb_negotiate(self, target: str, port: int, timeout: int) -> dict[str, object]:
        self.calls.append(("negotiate", target, None))
        return {"target": target, "port": port, "timeout": timeout, "dialect": "0x0311"}

    def smb_authenticate(
        self, target: str, port: int, timeout: int, credential: ImpacketCredential
    ) -> dict[str, object]:
        self.calls.append(("authenticate", target, credential.username))
        return {"target": target, "port": port, "timeout": timeout, "authenticated": True}

    def smb_list_shares(
        self, target: str, port: int, timeout: int, credential: ImpacketCredential
    ) -> dict[str, object]:
        self.calls.append(("list_shares", target, credential.username))
        return {"target": target, "port": port, "timeout": timeout, "shares": [{"name": "IPC$"}]}

    def rpc_endpoint_map(self, target: str, port: int, timeout: int) -> dict[str, object]:
        self.calls.append(("rpc_endpoint_map", target, None))
        return {"target": target, "port": port, "timeout": timeout, "endpoints": []}


class _Binding:
    def __init__(self, material: bytes, version_id: str = "sv-impacket-1") -> None:
        self._material = material
        self._version_id = version_id

    @property
    def secret_argument_path(self) -> str:
        return "/credential"

    @property
    def secret_version_id(self) -> str:
        return self._version_id

    def length(self) -> int:
        return len(self._material)

    def consume(self) -> bytes:
        return self._material


def _credential_reference() -> dict[str, str]:
    return {
        "credential_type": "password",
        "secret_version_id": "sv-impacket-1",
        "secret_version": "1",
        "principal_ref": "lab-user",
    }


def _arguments(*, credential: bool = False, target: str = "10.20.30.40") -> dict[str, object]:
    result: dict[str, object] = {
        "destinations": [target],
        "port": 445,
        "protocol": "tcp",
        "timeout_seconds": 5,
    }
    if credential:
        result["credential"] = _credential_reference()
    return result


def _target_binding(ds: DigestService, target: str = "10.20.30.40"):
    normalized = NormalizedTarget(
        type="ip",
        canonical_value=target,
        port=445,
        protocol="tcp",
        resolved_addresses=(target,),
        source="argument",
    )
    return build_target_dispatch_binding(
        normalized_target=normalized,
        binding_mode="exact_ip_enforced",
        connection_addresses=(target,),
        digest_service=ds,
    )


def _request(
    ds: DigestService,
    *,
    name: str = "impacket.smb.negotiate",
    credential: bool = False,
    argument_target: str = "10.20.30.40",
    binding_target: str = "10.20.30.40",
) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="execution-impacket-1",
        task_id="task-impacket-1",
        tool_ref=ToolRef(tool_id=name, registry_revision=1),
        adapter_id="mcp-impacket-local",
        provider_tool_name=name,
        result_delivery_mode="local_result",
        idempotency_key="idempotency-impacket-1",
        timeout_seconds=10,
        arguments=_arguments(credential=credential, target=argument_target),
        target_dispatch_bindings=(_target_binding(ds, binding_target),),
    )


def _server(backend: _FakeBackend) -> ImpacketMCPServer:
    return ImpacketMCPServer(
        policy=ImpacketServerPolicy.from_strings(("10.20.30.0/24",)),
        backend=backend,
    )


def test_server_exposes_only_the_four_approved_read_only_tools() -> None:
    ds = DigestService()
    contract = build_impacket_mcp_contract(digest_service=ds)
    server = _server(_FakeBackend())
    response = parse_json_no_duplicate_keys(server.handle(contract.tools_list().to_wire_bytes()))

    names = [tool["name"] for tool in response["result"]["tools"]]
    assert names == [
        "impacket.rpc.endpoint_map",
        "impacket.smb.authenticate",
        "impacket.smb.list_shares",
        "impacket.smb.negotiate",
    ]
    assert not any("exec" in name or "dump" in name or "relay" in name for name in names)


def test_pinned_impacket_runtime_exposes_the_used_smb_api() -> None:
    assert version("impacket") == "0.13.1"
    smb_class = FortraImpacketBackend._smb_class()
    assert all(
        hasattr(smb_class, name)
        for name in (
            "close",
            "getDialect",
            "getServerDNSDomainName",
            "getServerDNSHostName",
            "getServerDomain",
            "getServerName",
            "getServerOS",
            "isSigningRequired",
            "listShares",
            "login",
        )
    )


def test_rpc_endpoint_map_passes_complete_floor_set_to_impacket_formatter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    floors = ["interface", "data-representation", "protocol", "port", "address"]
    calls: list[object] = []

    class FakeDce:
        def connect(self) -> None:
            calls.append("connect")

        def disconnect(self) -> None:
            calls.append("disconnect")

    class FakeRpcTransport:
        def set_connect_timeout(self, timeout: int) -> None:
            calls.append(("timeout", timeout))

        def get_dce_rpc(self) -> FakeDce:
            return FakeDce()

    def format_binding(value: object) -> str:
        assert value is floors
        calls.append(("format", value))
        return "ncacn_ip_tcp:10.0.10.212[49152]"

    fake_epm = SimpleNamespace(
        hept_lookup=lambda _target, *, dce: [
            {"tower": {"Floors": floors}, "annotation": b"Endpoint"}
        ],
        PrintStringBinding=format_binding,
    )
    fake_transport = SimpleNamespace(
        DCERPCTransportFactory=lambda binding: (
            calls.append(("factory", binding)) or FakeRpcTransport()
        )
    )

    def import_module(name: str) -> object:
        return fake_epm if name.endswith(".epm") else fake_transport

    monkeypatch.setattr(
        "redteam_agent.mcp_servers.impacket_backend.importlib.import_module",
        import_module,
    )

    result = FortraImpacketBackend().rpc_endpoint_map("10.0.10.212", 135, 8)

    assert result["endpoint_count"] == 1
    assert result["endpoints"][0]["bindings"] == [  # type: ignore[index]
        "ncacn_ip_tcp:10.0.10.212[49152]"
    ]
    assert calls == [
        ("factory", "ncacn_ip_tcp:10.0.10.212[135]"),
        ("timeout", 8),
        "connect",
        ("format", floors),
        "disconnect",
    ]


def test_impacket_tool_definitions_pass_the_registry_safety_contract() -> None:
    ds = DigestService()
    names = tuple(
        tool.name
        for tool in build_impacket_mcp_contract(digest_service=ds).approved_tools
    )
    refs = {
        name: ActionContractReference(
            contract_id=f"placeholder-{name}", revision="1", digest="placeholder"
        )
        for name in names
    }
    tools = build_impacket_tool_definitions(
        registry_revision=1,
        action_contract_refs=refs,
        output_publication_rule_id="quarantine-only",
        evidence_rule_ids=("impacket-readonly-evidence",),
        digest_service=ds,
    )

    registry, rebound, _ = support.build_registered_registry(ds, tools)

    assert len(registry.tools) == 4
    assert all(tool.target_extractor_id == "network_target_v1" for tool in rebound)
    credential_tools = [tool for tool in rebound if tool.secret_argument_paths]
    assert [tool.provider_tool_name for tool in credential_tools] == [
        "impacket.smb.authenticate",
        "impacket.smb.list_shares",
    ]


def test_password_secret_is_bound_to_reference_and_absent_from_response() -> None:
    ds = DigestService()
    backend = _FakeBackend()
    server = _server(backend)
    contract = build_impacket_mcp_contract(digest_service=ds)
    request = _request(ds, name="impacket.smb.authenticate", credential=True)
    material = b'{"domain":"LAB","password":"top-secret","username":"operator"}'

    wire = contract.tools_call_wire_bytes(request, (_Binding(material),))
    response = server.handle(wire)

    assert b"top-secret" not in response
    assert backend.calls == [("authenticate", "10.20.30.40", "operator")]
    parsed = parse_json_no_duplicate_keys(response)
    assert parsed["result"]["isError"] is False


def test_server_rejects_targets_outside_the_fixed_allowlist_before_backend() -> None:
    ds = DigestService()
    backend = _FakeBackend()
    server = _server(backend)
    contract = build_impacket_mcp_contract(digest_service=ds)
    request = _request(ds, argument_target="10.20.31.40", binding_target="10.20.31.40")

    with pytest.raises(MCPContractError):
        server.handle(contract.tools_call_wire_bytes(request, ()))
    assert backend.calls == []


def test_server_rejects_unknown_or_high_risk_tool_names() -> None:
    ds = DigestService()
    contract = build_impacket_mcp_contract(digest_service=ds)
    request = _request(ds).model_copy(update={"provider_tool_name": "impacket.secretsdump"})
    with pytest.raises(MCPContractError):
        contract.tools_call(request)


@dataclass
class _ServerTransport:
    server: ImpacketMCPServer
    attestation: MCPTransportAttestation

    def request(
        self, request: bytes, *, timeout_seconds: int, max_response_bytes: int
    ) -> MCPTransportResponse:
        assert timeout_seconds > 0
        body = self.server.handle(request)
        assert len(body) <= max_response_bytes
        return MCPTransportResponse(body)


def _adapter(ds: DigestService, backend: _FakeBackend) -> MCPAdapter:
    identities = (
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="executable_path",
            identity_value="/opt/redteam-agent/bin/redteam-impacket-mcp",
        ),
        MCPTransportIdentity(
            transport_type="stdio", identity_type="executable_sha256", identity_value="1" * 64
        ),
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="command_configuration_digest",
            identity_value="2" * 64,
        ),
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="package_version",
            identity_value="redteam-impacket-mcp/1.0.0;impacket/0.13.1",
        ),
    )
    contract = build_impacket_mcp_contract(digest_service=ds)
    profile = build_impacket_mcp_profile(identities=identities, digest_service=ds)
    config = profile.server_config
    assert config is not None
    attestation = finalize_mcp_transport_attestation(
        MCPTransportAttestation(
            evidence_kind="test_server",
            production_eligible=False,
            adapter_profile_digest=profile.profile_digest,
            server_config_digest=config.config_digest,
            contract_digest=contract.contract_digest(),
            server_id=config.server_id,
            transport="stdio",
            execution_location="local_process",
            verified_transport_identities=identities,
            sandbox_verified=True,
            redirects_disabled=True,
            attested_at=support.T0,
            attestation_digest="0" * 64,
        ),
        ds,
    )
    return MCPAdapter(
        profile=profile,
        contract=contract,
        transport=_ServerTransport(_server(backend), attestation),
        clock=ManualClock(support.T0),
        digest_service=ds,
    )


def _capture() -> tuple[DispatchResultCapture, StreamingQuarantineSink]:
    sink = StreamingQuarantineSink(
        sink_id="sink-impacket-1",
        execution_id="execution-impacket-1",
        quarantine_id="quarantine-impacket-1",
        task_binding_digest="binding-impacket-1",
        max_output_bytes=1024 * 1024,
        committed_at=support.T0,
    )
    return DispatchResultCapture(mode="local_result", capture_id="capture-impacket-1", sink=sink), sink


def test_adapter_enforces_target_and_secret_then_streams_local_result() -> None:
    ds = DigestService()
    backend = _FakeBackend()
    adapter = _adapter(ds, backend)
    request = _request(ds, name="impacket.smb.list_shares", credential=True)
    material = b'{"domain":"LAB","password":"top-secret","username":"operator"}'
    capture, sink = _capture()

    capabilities = adapter.get_capabilities()
    assert capabilities.target_binding_modes == frozenset({"exact_ip_enforced"})
    handle = adapter.submit(
        request, (_Binding(material),), capture, request.idempotency_key
    )
    receipt = sink.commit()

    assert handle.result_delivery_mode == "local_result"
    assert receipt.stdout_bytes > 0
    assert backend.calls == [("list_shares", "10.20.30.40", "operator")]


def test_adapter_rejects_argument_and_authorized_target_mismatch_before_server() -> None:
    ds = DigestService()
    backend = _FakeBackend()
    adapter = _adapter(ds, backend)
    request = _request(ds, argument_target="10.20.30.40", binding_target="10.20.30.41")
    capture, _ = _capture()

    with pytest.raises(MCPContractError):
        adapter.submit(request, (), capture, request.idempotency_key)
    assert backend.calls == []


def test_secret_reference_without_ephemeral_binding_fails_before_server() -> None:
    ds = DigestService()
    backend = _FakeBackend()
    adapter = _adapter(ds, backend)
    request = _request(ds, name="impacket.smb.authenticate", credential=True)
    capture, _ = _capture()

    with pytest.raises(MCPContractError):
        adapter.submit(request, (), capture, request.idempotency_key)
    assert backend.calls == []


def test_executor_builds_mcp_as_local_result_with_authorized_target_binding() -> None:
    ds = DigestService()
    binding = _target_binding(ds)
    executor = object.__new__(Executor)
    request = executor._build_request(  # type: ignore[attr-defined]
        record=SimpleNamespace(
            execution_id="execution-impacket-1",
            task_id="task-impacket-1",
            idempotency_key="idempotency-impacket-1",
        ),
        decision=SimpleNamespace(
            tool_ref=ToolRef(tool_id="impacket.smb.negotiate", registry_revision=1),
            resolved_adapter_id="mcp-impacket-local",
            target_dispatch_bindings=(binding,),
        ),
        tool=SimpleNamespace(
            adapter="mcp",
            provider_tool_name="impacket.smb.negotiate",
            default_timeout_seconds=10,
        ),
        plan=SimpleNamespace(proposal=SimpleNamespace(arguments=_arguments())),
    )

    assert request.result_delivery_mode == "local_result"
    assert request.target_dispatch_bindings == (binding,)
