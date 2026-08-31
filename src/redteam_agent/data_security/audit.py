"""Atomic mission-scoped append-only audit chains."""

from __future__ import annotations

import hmac
import secrets
import sqlite3
from datetime import datetime
from threading import RLock
from typing import Literal, Protocol

from pydantic import Field, model_validator

from redteam_agent.canonical import (
    CanonicalJsonObject,
    canonical_loads,
    canonicalize,
    sha256_digest,
    stable_id,
)
from redteam_agent.errors import AuditIntegrityError, AuditSequenceConflictError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.repositories.audit import AuditLogRepository
from redteam_agent.storage import Database

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
    """Application-level append-only log with an optional durable SQLite boundary."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database
        self._repository = None if database is None else AuditLogRepository(database)
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
        if self._database is not None:
            return self._append_persistent(
                mission_id=mission_id,
                mission_revision=mission_revision,
                authorization_epoch=authorization_epoch,
                payload=payload,
                canonical_payload=canonical_payload,
                occurred_at=occurred_at,
                expected_sequence_number=expected_sequence_number,
            )
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
        if self._database is not None:
            if self._repository is None:
                raise AuditIntegrityError("durable audit repository is unavailable")
            rows = self._repository.events_for(mission_id)
            events: list[AuditEvent] = []
            for row in rows:
                event = self._parse_event(str(row["payload_json"]))
                if not (
                    event.event_id == row["event_id"]
                    and event.mission_id == row["mission_id"]
                    and event.sequence_number == row["sequence_number"]
                    and event.event_hash == row["event_hash"]
                ):
                    raise AuditIntegrityError("persisted audit row binding failed")
                events.append(event)
            return tuple(events)
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
        trusted_head = self._trusted_head(mission_id)
        if trusted_head is None:
            if candidates:
                raise AuditIntegrityError("mission audit chain has no trusted head")
        elif trusted_head != (len(candidates), previous_hash):
            raise AuditIntegrityError("mission audit chain head failed")
        return candidates

    def _append_persistent(
        self,
        *,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        payload: AuditReferencePayload,
        canonical_payload: CanonicalJsonObject,
        occurred_at: datetime,
        expected_sequence_number: int | None,
    ) -> AuditEvent:
        if self._database is None or self._repository is None:
            raise AuditIntegrityError("durable audit database is unavailable")
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
        try:
            with self._repository.transaction():
                self.verify(mission_id)
                existing_row = self._repository.event_by_id(event_id)
                if existing_row is not None:
                    existing = self._parse_event(str(existing_row["payload_json"]))
                    if not (
                        existing.event_id == existing_row["event_id"]
                        and existing.mission_id == existing_row["mission_id"]
                        and existing.sequence_number == existing_row["sequence_number"]
                        and existing.event_hash == existing_row["event_hash"]
                        and self._matches_request(
                            existing,
                            mission_id=mission_id,
                            mission_revision=mission_revision,
                            authorization_epoch=authorization_epoch,
                            event_type=event_type,
                            canonical_payload=canonical_payload,
                            occurred_at=occurred_at,
                        )
                    ):
                        raise AuditSequenceConflictError(
                            "derived audit event identifier conflicted"
                        )
                    return existing
                head = self._repository.head(mission_id)
                sequence = 1 if head is None else int(head["sequence_number"]) + 1
                previous_hash = None if head is None else str(head["event_hash"])
                if (
                    expected_sequence_number is not None
                    and expected_sequence_number != sequence
                ):
                    raise AuditSequenceConflictError("audit sequence allocation conflict")
                if head is None and self._repository.has_event(mission_id):
                    raise AuditIntegrityError("audit chain has no trusted head")
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
                event_json = canonicalize(event.model_dump(mode="python")).decode(
                    "utf-8"
                )
                self._repository.insert_event(
                    event_id=event.event_id,
                    mission_id=event.mission_id,
                    sequence_number=event.sequence_number,
                    event_hash=event.event_hash,
                    payload_json=event_json,
                )
                if head is None:
                    self._repository.insert_head(
                        mission_id=mission_id,
                        sequence_number=event.sequence_number,
                        event_hash=event.event_hash,
                    )
                else:
                    if not self._repository.update_head(
                        mission_id=mission_id,
                        previous_sequence_number=int(head["sequence_number"]),
                        previous_event_hash=str(head["event_hash"]),
                        sequence_number=event.sequence_number,
                        event_hash=event.event_hash,
                    ):
                        raise AuditSequenceConflictError("audit head update conflicted")
                return event
        except (AuditIntegrityError, AuditSequenceConflictError):
            raise
        except sqlite3.IntegrityError as exc:
            raise AuditSequenceConflictError("audit sequence allocation conflict") from exc

    def _trusted_head(self, mission_id: str) -> tuple[int, str] | None:
        if self._database is None:
            return self._heads.get(mission_id)
        if self._repository is None:
            raise AuditIntegrityError("durable audit repository is unavailable")
        row = self._repository.head(mission_id)
        return (
            None
            if row is None
            else (int(row["sequence_number"]), str(row["event_hash"]))
        )

    @staticmethod
    def _parse_event(payload: str | bytes) -> AuditEvent:
        try:
            duplicate_free = canonical_loads(payload)
            return AuditEvent.model_validate_json(canonicalize(duplicate_free), strict=True)
        except (TypeError, ValueError) as exc:
            raise AuditIntegrityError("persisted audit event is invalid") from exc

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
