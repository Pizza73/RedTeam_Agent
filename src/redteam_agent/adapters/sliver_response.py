"""Strict normalization of secret-free Sliver RPC projections."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator

from redteam_agent.adapters.c2 import C2SessionObservation
from redteam_agent.errors import (
    C2AdapterContractError,
    DuplicateJsonKeyError,
    PydanticBoundaryValidationError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel

type SliverEndpointKind = Literal["session", "beacon"]
type SliverTaskState = Literal["pending", "sent", "completed", "canceled"]


class SliverVersionResponse(StrictImmutableBoundaryModel):
    major: int = Field(ge=0)
    minor: int = Field(ge=0)
    patch: int = Field(ge=0)
    commit: str = Field(pattern=r"^[0-9a-f]{7,40}$")
    dirty: bool
    os: str = Field(min_length=1, max_length=64)
    arch: str = Field(min_length=1, max_length=64)

    def semantic_version(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


class SliverEndpointRecord(StrictImmutableBoundaryModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    name: str = Field(max_length=256)
    hostname: str = Field(max_length=255)
    username: str = Field(max_length=512)
    os: str = Field(min_length=1, max_length=64)
    arch: str = Field(min_length=1, max_length=64)
    transport: str = Field(min_length=1, max_length=64)
    active_c2: str = Field(max_length=2048)
    last_checkin: int = Field(ge=0)
    is_dead: bool
    next_checkin: int | None = Field(default=None, ge=0)


class SliverSessionsResponse(StrictImmutableBoundaryModel):
    sessions: tuple[SliverEndpointRecord, ...]


class SliverBeaconsResponse(StrictImmutableBoundaryModel):
    beacons: tuple[SliverEndpointRecord, ...]

    @field_validator("beacons")
    @classmethod
    def _beacons_have_next_checkin(
        cls, value: tuple[SliverEndpointRecord, ...]
    ) -> tuple[SliverEndpointRecord, ...]:
        if any(item.next_checkin is None for item in value):
            raise ValueError("Sliver Beacon response lacks next check-in")
        return value


class SliverBeaconResponse(StrictImmutableBoundaryModel):
    beacon: SliverEndpointRecord

    @field_validator("beacon")
    @classmethod
    def _beacon_has_next_checkin(
        cls, value: SliverEndpointRecord
    ) -> SliverEndpointRecord:
        if value.next_checkin is None:
            raise ValueError("Sliver Beacon response lacks next check-in")
        return value


class SliverBeaconTaskRecord(StrictImmutableBoundaryModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    beacon_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    state: SliverTaskState
    created_at: int = Field(ge=0)
    sent_at: int = Field(ge=0)
    completed_at: int = Field(ge=0)
    description: str = Field(max_length=2048)


class SliverBeaconTasksResponse(StrictImmutableBoundaryModel):
    beacon_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    tasks: tuple[SliverBeaconTaskRecord, ...]


class SliverBeaconTaskResponse(StrictImmutableBoundaryModel):
    task: SliverBeaconTaskRecord


def decode_version(raw: bytes) -> SliverVersionResponse:
    return _decode(SliverVersionResponse, raw)


def decode_sessions(raw: bytes) -> SliverSessionsResponse:
    result = _decode(SliverSessionsResponse, raw)
    _require_unique_ids(result.sessions)
    return result


def decode_beacons(raw: bytes) -> SliverBeaconsResponse:
    result = _decode(SliverBeaconsResponse, raw)
    _require_unique_ids(result.beacons)
    return result


def decode_beacon(raw: bytes) -> SliverBeaconResponse:
    return _decode(SliverBeaconResponse, raw)


def decode_beacon_tasks(raw: bytes) -> SliverBeaconTasksResponse:
    result = _decode(SliverBeaconTasksResponse, raw)
    if len({item.id for item in result.tasks}) != len(result.tasks):
        raise C2AdapterContractError("Sliver returned duplicate Beacon Task IDs")
    if any(item.beacon_id != result.beacon_id for item in result.tasks):
        raise C2AdapterContractError("Sliver Beacon Task ownership mismatch")
    return result


def decode_beacon_task(raw: bytes) -> SliverBeaconTaskResponse:
    return _decode(SliverBeaconTaskResponse, raw)


def endpoint_observation(
    endpoint: SliverEndpointRecord,
    *,
    kind: SliverEndpointKind,
    observed_at: datetime,
    required_transport: Literal["http"] = "http",
) -> C2SessionObservation:
    if observed_at.tzinfo is None:
        raise C2AdapterContractError("Sliver observation time must be timezone-aware")
    transport_matches = _normalizes_to_http(endpoint.transport, endpoint.active_c2)
    if endpoint.is_dead:
        status: Literal["active", "stale", "lost", "terminated", "unknown"] = "lost"
    elif not transport_matches:
        status = "unknown"
    elif kind == "beacon" and endpoint.next_checkin is not None:
        grace = 60
        status = "stale" if observed_at.timestamp() > endpoint.next_checkin + grace else "active"
    else:
        status = "active"
    os_value: Literal["windows", "linux", "macos", "other"]
    normalized_os = endpoint.os.lower()
    if normalized_os == "windows":
        os_value = "windows"
    elif normalized_os == "linux":
        os_value = "linux"
    elif normalized_os in {"darwin", "macos"}:
        os_value = "macos"
    else:
        os_value = "other"
    capabilities = (
        frozenset(
            {
                "sliver.inventory.read",
                "sliver.beacon.task.read",
                "sliver.beacon.task.cancel",
                f"sliver.endpoint.{kind}",
                f"sliver.transport.{required_transport}",
            }
        )
        if transport_matches and status in {"active", "stale"}
        else frozenset()
    )
    return C2SessionObservation(
        provider_session_id=f"{kind}:{endpoint.id}",
        provider_status=status,
        host=endpoint.hostname or None,
        os=os_value,
        architecture=endpoint.arch or None,
        current_principal=endpoint.username or None,
        capabilities=capabilities,
        observed_at=observed_at.astimezone(UTC),
    )


def _normalizes_to_http(transport: str, active_c2: str) -> bool:
    normalized = transport.lower().strip()
    active = active_c2.lower().strip()
    return normalized in {"http", "http(s)"} and (
        active.startswith("http://") or (not active and normalized == "http")
    )


def _require_unique_ids(endpoints: tuple[SliverEndpointRecord, ...]) -> None:
    if len({item.id for item in endpoints}) != len(endpoints):
        raise C2AdapterContractError("Sliver returned duplicate endpoint IDs")


def _decode[T: StrictImmutableBoundaryModel](model: type[T], raw: bytes) -> T:
    try:
        return model.from_untrusted_json(raw)
    except (DuplicateJsonKeyError, PydanticBoundaryValidationError) as exc:
        raise C2AdapterContractError("Sliver response violated the pinned boundary") from exc


__all__ = [
    "SliverBeaconResponse",
    "SliverBeaconTaskRecord",
    "SliverBeaconTaskResponse",
    "SliverBeaconTasksResponse",
    "SliverBeaconsResponse",
    "SliverEndpointRecord",
    "SliverSessionsResponse",
    "SliverTaskState",
    "SliverVersionResponse",
    "decode_beacon",
    "decode_beacon_task",
    "decode_beacon_tasks",
    "decode_beacons",
    "decode_sessions",
    "decode_version",
    "endpoint_observation",
]
