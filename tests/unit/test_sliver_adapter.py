"""Offline adapter scenarios for Sliver inventory and Beacon Task control."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.adapters.sliver import SliverConnectionPolicy, build_sliver_foundation_profile
from redteam_agent.adapters.sliver_adapter import SliverAdapter
from redteam_agent.adapters.sliver_contract import SliverRpcContractV173, SliverWireRequest
from redteam_agent.adapters.sliver_response import decode_sessions
from redteam_agent.adapters.sliver_transport import (
    SliverTransportAttestation,
    SliverTransportResponse,
    finalize_sliver_transport_attestation,
)
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterContractError, C2AdapterUnavailableError, ResultCollectionError
from redteam_agent.execution.models import ProviderTaskBinding
from redteam_agent.runtime.clock import ManualClock


class SliverTestTransport:
    def __init__(self, attestation: SliverTransportAttestation) -> None:
        self._attestation = attestation
        self.operations: list[str] = []

    @property
    def attestation(self) -> SliverTransportAttestation:
        return self._attestation

    def request(
        self,
        request: SliverWireRequest,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> SliverTransportResponse:
        assert timeout_seconds == 30
        assert max_response_bytes == 4 * 1024 * 1024
        self.operations.append(request.operation)
        endpoint = {
            "id": "endpoint-1",
            "name": "WIN11",
            "hostname": "WIN11",
            "username": "LAB\\joe",
            "os": "windows",
            "arch": "x86_64",
            "transport": "http(s)",
            "active_c2": "http://10.0.10.212",
            "last_checkin": int(support.T0.timestamp()),
            "is_dead": False,
        }
        task_id = str(request.fields.get("ID", "task-1"))
        responses: dict[str, object] = {
            "get_version": {
                "major": 1,
                "minor": 7,
                "patch": 3,
                "commit": "3bbaf805",
                "dirty": False,
                "os": "linux",
                "arch": "amd64",
            },
            "list_sessions": {"sessions": [endpoint]},
            "list_beacons": {
                "beacons": [
                    {**endpoint, "id": "beacon-1", "next_checkin": int((support.T0 + timedelta(minutes=1)).timestamp())}
                ]
            },
            "get_beacon": {
                "beacon": {**endpoint, "id": task_id, "next_checkin": int((support.T0 + timedelta(minutes=1)).timestamp())}
            },
            "list_beacon_tasks": {
                "beacon_id": task_id,
                "tasks": [{
                    "id": "task-1", "beacon_id": task_id, "state": "pending",
                    "created_at": 1, "sent_at": 0, "completed_at": 0, "description": "inventory task",
                }],
            },
            "get_beacon_task_content": {
                "task": {
                    "id": task_id, "beacon_id": "beacon-1", "state": "completed",
                    "created_at": 1, "sent_at": 2, "completed_at": 3, "description": "inventory task",
                }
            },
            "cancel_beacon_task": {
                "task": {
                    "id": task_id, "beacon_id": "beacon-1", "state": "canceled",
                    "created_at": 1, "sent_at": 0, "completed_at": 0, "description": "inventory task",
                }
            },
        }
        return SliverTransportResponse(canonical_dumps(responses[request.operation]))


def _adapter() -> tuple[SliverAdapter, SliverTestTransport]:
    digests = DigestService()
    connection = SliverConnectionPolicy(
        operator_config_secret_version_id="secret://sliver/operator#v1",
        operator_config_sha256="1" * 64,
        server_address="10.0.0.2",
        server_port=31337,
        server_tls_name="multiplayer",
        ca_certificate_sha256="2" * 64,
        operator_certificate_sha256="3" * 64,
    )
    profile = build_sliver_foundation_profile(
        digest_service=digests, connection=connection
    )
    contract = SliverRpcContractV173()
    attestation = finalize_sliver_transport_attestation(
        SliverTransportAttestation(
            evidence_kind="test_double",
            production_eligible=False,
            adapter_profile_digest=profile.profile_digest,
            contract_digest=contract.contract_digest(digests),
            operator_config_secret_version_id="secret://sliver/operator#v1",
            operator_config_sha256="1" * 64,
            server_address="10.0.0.2",
            server_port=31337,
            server_tls_name="multiplayer",
            ca_certificate_sha256="2" * 64,
            operator_certificate_sha256="3" * 64,
            server_identity_verified=False,
            operator_identity_verified=False,
            http_beacon_verified=False,
            attested_at=support.T0,
            attestation_digest="0" * 64,
        ),
        digests,
    )
    transport = SliverTestTransport(attestation)
    return (
        SliverAdapter(
            profile=profile,
            contract=contract,
            transport=transport,
            clock=ManualClock(support.T0),
            digest_service=digests,
        ),
        transport,
    )


def test_capabilities_verify_the_exact_clean_release() -> None:
    adapter, transport = _adapter()
    capabilities = adapter.get_capabilities()
    assert capabilities.adapter_id == "sliver-c2"
    assert "beacon.task.cancel" in capabilities.capabilities
    assert "task.submit" not in capabilities.capabilities
    assert capabilities.result_streaming is False
    assert transport.operations == ["get_version"]


def test_sessions_and_http_beacons_are_projected_to_provider_neutral_observations() -> None:
    adapter, _transport = _adapter()
    observations = adapter.list_sessions()
    assert [item.provider_session_id for item in observations] == [
        "session:endpoint-1",
        "beacon:beacon-1",
    ]
    assert all(item.provider_status == "active" for item in observations)
    assert all("sliver.transport.http" in item.capabilities for item in observations)
    assert adapter.get_session("beacon:beacon-1").host == "WIN11"


def test_existing_beacon_tasks_can_be_listed_reconciled_and_cancelled() -> None:
    adapter, _transport = _adapter()
    tasks = adapter.list_beacon_tasks("beacon:beacon-1")
    assert [(task.id, task.state) for task in tasks] == [("task-1", "pending")]
    binding = ProviderTaskBinding(
        task_id="task-local",
        execution_id="execution-1",
        adapter_identity_digest=adapter.identity().adapter_identity_digest,
        provider_identity_digest=adapter.identity().provider_identity_digest,
        provider_task_id="task-1",
        dispatch_claim_id="claim-1",
        binding_digest="binding-1",
    )
    reconciled = adapter.reconcile("execution-1", binding)
    assert reconciled.status == "FOUND_TERMINAL"
    assert reconciled.provider_status == "succeeded"
    assert adapter.cancel("execution-1", "task-1").result == "CONFIRMED"


def test_submission_and_result_collection_remain_unavailable() -> None:
    adapter, _transport = _adapter()
    with pytest.raises(C2AdapterUnavailableError):
        adapter.submit(None, (), None, "none")  # type: ignore[arg-type]
    with pytest.raises(ResultCollectionError):
        adapter.collect_result("execution-1", None, None)  # type: ignore[arg-type]


def test_response_boundary_rejects_unknown_and_duplicate_fields() -> None:
    with pytest.raises(C2AdapterContractError):
        decode_sessions(b'{"sessions":[],"native_command":"whoami"}')
    with pytest.raises(C2AdapterContractError):
        decode_sessions(b'{"sessions":[],"sessions":[]}')
