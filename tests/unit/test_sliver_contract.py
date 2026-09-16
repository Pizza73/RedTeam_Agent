"""Exact Sliver v1.7.3 RPC allowlist tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redteam_agent.adapters.sliver_contract import SliverRpcContractV173, SliverWireRequest
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterContractError


def test_contract_contains_only_inventory_and_existing_task_control() -> None:
    contract = SliverRpcContractV173()

    assert contract.allowed_operations() == (
        "get_version",
        "list_sessions",
        "list_beacons",
        "get_beacon",
        "list_beacon_tasks",
        "get_beacon_task_content",
        "cancel_beacon_task",
    )
    assert contract.get_version().rpc_method == "/rpcpb.SliverRPC/GetVersion"
    assert contract.list_sessions().fields == {}
    assert contract.get_beacon("beacon-1").fields == {"ID": "beacon-1"}
    assert contract.cancel_beacon_task("task-1").rpc_method.endswith("/CancelBeaconTask")
    assert len(contract.contract_digest(DigestService())) == 64


@pytest.mark.parametrize("value", ("", "../task", "task/one", " task", "task\n"))
def test_provider_ids_are_canonical(value: str) -> None:
    with pytest.raises(C2AdapterContractError):
        SliverRpcContractV173.cancel_beacon_task(value)


def test_rpc_method_cannot_be_replaced_by_a_high_risk_method() -> None:
    with pytest.raises(ValidationError):
        SliverWireRequest(
            operation="list_sessions",
            rpc_method="/rpcpb.SliverRPC/Execute",
            request_message="commonpb.Empty",
            response_message="clientpb.Sessions",
            fields={},
        )
