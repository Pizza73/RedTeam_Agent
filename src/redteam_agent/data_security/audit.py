"""Atomic mission-scoped append-only audit chains."""

from __future__ import annotations

import hmac
import secrets
from datetime import datetime
from threading import RLock
from typing import Literal, Protocol

from pydantic import Field, model_validator

from redteam_agent.canonical import CanonicalJsonObject, sha256_digest, stable_id
from redteam_agent.errors import AuditIntegrityError, AuditSequenceConflictError
from redteam_agent.models.base import StrictImmutableBoundaryModel

from .models import AuditEvent

AuditResourceType = Literal[
    "artifact",
    "secret_reference",
    "raw_result_quarantine",
]
AuditOperation = Literal[
    "create",
    "write_chunk",
    "commit_artifact",
    "commit",
    "abort",
    "resume",
    "read",
    "export",
    "resolve",
    "revoke",
    "delete",
]


class AuditReferencePayload(StrictImmutableBoundaryModel):
    """Reference-only audit payload; arbitrary values and raw content are impossible."""

    resource_type: AuditResourceType
    resource_id: str = Field(min_length=1)
    operation: AuditOperation
    operation_id: str = Field(
        default_factory=lambda: "auditop_" + secrets.token_hex(16),
        pattern=r"^auditop_[0-9a-f]{32}$",
    )
    metadata_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def reference_id_matches_type(self) -> AuditReferencePayload:
        prefixes = {
            "artifact": "artifact_",
            "secret_reference": "secret_",
            "raw_result_quarantine": "quarantine_",
        }
        if not self.resource_id.startswith(prefixes[self.resource_type]):
            raise ValueError("audit resource must be an internal reference ID")
        suffix = self.resource_id.removeprefix(prefixes[self.resource_type])
        if len(suffix) != 32 or any(character not in "0123456789abcdef" for character in suffix):
            raise ValueError("audit resource reference ID is malformed")
        return self


class AuditContext(StrictImmutableBoundaryModel):
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)


class AuditContextResolver(Protocol):
    def current_context(self, mission_id: str, *, now: datetime) -> AuditContext: ...


class DataStoreAuditRecorder(Protocol):
    def record(
        self,
        *,
        mission_id: str,
        resource_type: AuditResourceType,
        resource_id: str,
        operation: AuditOperation,
        metadata_digest: str,
        occurred_at: datetime,
        operation_id: str | None = None,
    ) -> AuditEvent: ...


class MissionAuditRecorder:
    """Resolves current mission authority before appending a typed store event."""

    def __init__(self, *, audit_log: MissionAuditLog, contexts: AuditContextResolver) -> None:
        self._audit_log = audit_log
        self._contexts = contexts

    def record(
        self,
        *,
        mission_id: str,
        resource_type: AuditResourceType,
        resource_id: str,
        operation: AuditOperation,
        metadata_digest: str,
        occurred_at: datetime,
        operation_id: str | None = None,
    ) -> AuditEvent:
        context = self._contexts.current_context(mission_id, now=occurred_at)
        payload = AuditReferencePayload(
            resource_type=resource_type,
            resource_id=resource_id,
            operation=operation,
            operation_id=(
                "auditop_" + secrets.token_hex(16)
                if operation_id is None
                else operation_id
            ),
            metadata_digest=metadata_digest,
        )
        return self._audit_log.append(
            mission_id=mission_id,
            mission_revision=context.mission_revision,
            authorization_epoch=context.authorization_epoch,
            payload=payload,
            occurred_at=occurred_at,
        )


class MissionAuditLog:
    """Application-level append-only log; persistence adapters can wrap this contract."""

    def __init__(self) -> None:
        self._events: dict[str, list[AuditEvent]] = {}
        self._event_ids: dict[str, AuditEvent] = {}
        self._heads: dict[str, tuple[int, str]] = {}
        self._lock = RLock()

    def append(
        self,
        *,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        payload: AuditReferencePayload,
        occurred_at: datetime,
        expected_sequence_number: int | None = None,
    ) -> AuditEvent:
        canonical_payload = CanonicalJsonObject(payload.model_dump(mode="python"))
        with self._lock:
            event_type = f"{payload.resource_type}.{payload.operation}"
            event_id = stable_id(
                "auditevent",
                {
                    "mission_id": mission_id,
                    "mission_revision": mission_revision,
                    "authorization_epoch": authorization_epoch,
                    "event_type": event_type,
                    "canonical_payload": canonical_payload,
                    "occurred_at": occurred_at,
                },
            )
            existing = self._event_ids.get(event_id)
            if existing is not None:
                if not self._matches_request(
                    existing,
                    mission_id=mission_id,
                    mission_revision=mission_revision,
                    authorization_epoch=authorization_epoch,
                    event_type=event_type,
                    canonical_payload=canonical_payload,
                    occurred_at=occurred_at,
                ):
                    raise AuditSequenceConflictError(
                        "derived audit event identifier conflicted"
                    )
                return existing
            mission_events = self._events.setdefault(mission_id, [])
            sequence = len(mission_events) + 1
            if expected_sequence_number is not None and expected_sequence_number != sequence:
                raise AuditSequenceConflictError("audit sequence allocation conflict")
            previous_hash = mission_events[-1].event_hash if mission_events else None
            base = self._event_payload(
                event_id=event_id,
                mission_id=mission_id,
                mission_revision=mission_revision,
                authorization_epoch=authorization_epoch,
                sequence_number=sequence,
                previous_event_hash=previous_hash,
                event_type=event_type,
                canonical_payload=canonical_payload,
                occurred_at=occurred_at,
            )
            event = AuditEvent(
                event_id=event_id,
                mission_id=mission_id,
                mission_revision=mission_revision,
                authorization_epoch=authorization_epoch,
                chain_scope="mission",
                sequence_number=sequence,
                previous_event_hash=previous_hash,
                event_hash=sha256_digest(base),
                event_type=event_type,
                canonical_payload=canonical_payload,
                occurred_at=occurred_at,
            )
            mission_events.append(event)
            self._event_ids[event_id] = event
            self._heads[mission_id] = (sequence, event.event_hash)
            return event

    def events_for(self, mission_id: str) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events.get(mission_id, ()))

    def verify(
        self, mission_id: str, *, events: tuple[AuditEvent, ...] | None = None
    ) -> tuple[AuditEvent, ...]:
        candidates = self.events_for(mission_id) if events is None else events
        previous_hash: str | None = None
        seen_ids: set[str] = set()
        for expected_sequence, event in enumerate(candidates, start=1):
            if not (
                event.mission_id == mission_id
                and event.chain_scope == "mission"
                and event.sequence_number == expected_sequence
                and event.previous_event_hash == previous_hash
                and event.event_id not in seen_ids
            ):
                raise AuditIntegrityError("mission audit chain binding failed")
            expected_hash = sha256_digest(
                self._event_payload(
                    event_id=event.event_id,
                    mission_id=event.mission_id,
                    mission_revision=event.mission_revision,
                    authorization_epoch=event.authorization_epoch,
                    sequence_number=event.sequence_number,
                    previous_event_hash=event.previous_event_hash,
                    event_type=event.event_type,
                    canonical_payload=event.canonical_payload,
                    occurred_at=event.occurred_at,
                )
            )
            if not hmac.compare_digest(expected_hash, event.event_hash):
                raise AuditIntegrityError("mission audit event hash failed")
            seen_ids.add(event.event_id)
            previous_hash = event.event_hash
        trusted_head = self._heads.get(mission_id)
        if trusted_head is None:
            if candidates:
                raise AuditIntegrityError("mission audit chain has no trusted head")
        elif trusted_head != (len(candidates), previous_hash):
            raise AuditIntegrityError("mission audit chain head failed")
        return candidates

    @staticmethod
    def _event_payload(
        *,
        event_id: str,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        sequence_number: int,
        previous_event_hash: str | None,
        event_type: str,
        canonical_payload: CanonicalJsonObject,
        occurred_at: datetime,
    ) -> dict[str, object]:
        return {
            "event_id": event_id,
            "mission_id": mission_id,
            "mission_revision": mission_revision,
            "authorization_epoch": authorization_epoch,
            "chain_scope": "mission",
            "sequence_number": sequence_number,
            "previous_event_hash": previous_event_hash,
            "event_type": event_type,
            "canonical_payload": canonical_payload,
            "occurred_at": occurred_at,
        }

    @staticmethod
    def _matches_request(
        event: AuditEvent,
        *,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        event_type: str,
        canonical_payload: CanonicalJsonObject,
        occurred_at: datetime,
    ) -> bool:
        return (
            event.mission_id == mission_id
            and event.mission_revision == mission_revision
            and event.authorization_epoch == authorization_epoch
            and event.event_type == event_type
            and event.canonical_payload == canonical_payload
            and event.occurred_at == occurred_at
        )
