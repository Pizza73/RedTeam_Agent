"""Closed, transport-free RPC allowlist for Sliver v1.7.3."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.adapters.sliver import (
    SLIVER_SOURCE_COMMIT_PIN,
    SLIVER_VERSION_PIN,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.errors import C2AdapterContractError
from redteam_agent.models.base import StrictImmutableBoundaryModel

SLIVER_RPC_CONTRACT_REVISION: Literal["sliver-grpc-1.7.3-read-control-v1"] = (
    "sliver-grpc-1.7.3-read-control-v1"
)

type SliverOperation = Literal[
    "get_version",
    "list_sessions",
    "list_beacons",
    "get_beacon",
    "list_beacon_tasks",
    "get_beacon_task_content",
    "cancel_beacon_task",
]

_METHODS: dict[SliverOperation, str] = {
    "get_version": "/rpcpb.SliverRPC/GetVersion",
    "list_sessions": "/rpcpb.SliverRPC/GetSessions",
    "list_beacons": "/rpcpb.SliverRPC/GetBeacons",
    "get_beacon": "/rpcpb.SliverRPC/GetBeacon",
    "list_beacon_tasks": "/rpcpb.SliverRPC/GetBeaconTasks",
    "get_beacon_task_content": "/rpcpb.SliverRPC/GetBeaconTaskContent",
    "cancel_beacon_task": "/rpcpb.SliverRPC/CancelBeaconTask",
}
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class SliverWireRequest(StrictImmutableBoundaryModel):
    contract_revision: Literal["sliver-grpc-1.7.3-read-control-v1"] = (
        SLIVER_RPC_CONTRACT_REVISION
    )
    operation: SliverOperation
    rpc_method: str = Field(pattern=r"^/rpcpb\.SliverRPC/[A-Za-z]+$")
    request_message: Literal["commonpb.Empty", "clientpb.Beacon", "clientpb.BeaconTask"]
    response_message: Literal[
        "clientpb.Version",
        "clientpb.Sessions",
        "clientpb.Beacons",
        "clientpb.Beacon",
        "clientpb.BeaconTasks",
        "clientpb.BeaconTask",
    ]
    fields: CanonicalJsonObject

    @model_validator(mode="after")
    def _operation_is_exact(self) -> SliverWireRequest:
        if self.rpc_method != _METHODS[self.operation]:
            raise ValueError("Sliver operation and RPC method disagree")
        return self


def _canonical_id(value: str, label: str) -> str:
    if _ID_PATTERN.fullmatch(value) is None:
        raise C2AdapterContractError(f"Sliver {label} is invalid")
    return value


class SliverRpcContractV173:
    """Only inventory, task metadata, and task cancellation RPCs are reachable."""

    @staticmethod
    def allowed_operations() -> tuple[SliverOperation, ...]:
        return tuple(_METHODS)

    def contract_digest(self, digest_service: DigestService) -> str:
        return digest_service.compute(
            "sliver_rpc_contract_digest",
            {
                "contract_revision": SLIVER_RPC_CONTRACT_REVISION,
                "provider_version": SLIVER_VERSION_PIN,
                "source_commit": SLIVER_SOURCE_COMMIT_PIN,
                "implant_transport": "http",
                "rpc_methods": {operation: _METHODS[operation] for operation in _METHODS},
                "explicitly_excluded": [
                    "listener_management",
                    "implant_generation",
                    "shell_and_execute",
                    "upload_and_download",
                    "process_injection",
                    "pivot_and_port_forward",
                    "credential_collection",
                ],
            },
        )

    @staticmethod
    def get_version() -> SliverWireRequest:
        return _request("get_version", "commonpb.Empty", "clientpb.Version")

    @staticmethod
    def list_sessions() -> SliverWireRequest:
        return _request("list_sessions", "commonpb.Empty", "clientpb.Sessions")

    @staticmethod
    def list_beacons() -> SliverWireRequest:
        return _request("list_beacons", "commonpb.Empty", "clientpb.Beacons")

    @staticmethod
    def get_beacon(beacon_id: str) -> SliverWireRequest:
        return _request(
            "get_beacon", "clientpb.Beacon", "clientpb.Beacon", ID=_canonical_id(beacon_id, "Beacon ID")
        )

    @staticmethod
    def list_beacon_tasks(beacon_id: str) -> SliverWireRequest:
        return _request(
            "list_beacon_tasks",
            "clientpb.Beacon",
            "clientpb.BeaconTasks",
            ID=_canonical_id(beacon_id, "Beacon ID"),
        )

    @staticmethod
    def get_beacon_task_content(task_id: str) -> SliverWireRequest:
        return _request(
            "get_beacon_task_content",
            "clientpb.BeaconTask",
            "clientpb.BeaconTask",
            ID=_canonical_id(task_id, "Beacon Task ID"),
        )

    @staticmethod
    def cancel_beacon_task(task_id: str) -> SliverWireRequest:
        return _request(
            "cancel_beacon_task",
            "clientpb.BeaconTask",
            "clientpb.BeaconTask",
            ID=_canonical_id(task_id, "Beacon Task ID"),
        )


def _request(
    operation: SliverOperation,
    request_message: Literal["commonpb.Empty", "clientpb.Beacon", "clientpb.BeaconTask"],
    response_message: Literal[
        "clientpb.Version",
        "clientpb.Sessions",
        "clientpb.Beacons",
        "clientpb.Beacon",
        "clientpb.BeaconTasks",
        "clientpb.BeaconTask",
    ],
    **fields: object,
) -> SliverWireRequest:
    return SliverWireRequest(
        operation=operation,
        rpc_method=_METHODS[operation],
        request_message=request_message,
        response_message=response_message,
        fields=fields,
    )


__all__ = [
    "SLIVER_RPC_CONTRACT_REVISION",
    "SliverOperation",
    "SliverRpcContractV173",
    "SliverWireRequest",
]
