"""Atomic mission-scoped append-only audit chains."""

from __future__ import annotations

import hmac
from datetime import datetime
from threading import RLock

from redteam_agent.canonical import CanonicalJsonObject, sha256_digest
from redteam_agent.errors import AuditIntegrityError, AuditSequenceConflictError

from .models import AuditEvent


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
        event_id: str,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        event_type: str,
        canonical_payload: CanonicalJsonObject,
        occurred_at: datetime,
        expected_sequence_number: int | None = None,
    ) -> AuditEvent:
        self._validate_payload(canonical_payload)
        with self._lock:
            existing = self._event_ids.get(event_id)
            if existing is not None:
                if self._matches_request(
                    existing,
                    mission_id=mission_id,
                    mission_revision=mission_revision,
                    authorization_epoch=authorization_epoch,
                    event_type=event_type,
                    canonical_payload=canonical_payload,
                    occurred_at=occurred_at,
                ):
                    return existing
                raise AuditSequenceConflictError("audit event identifier was reused")
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
    def _validate_payload(payload: CanonicalJsonObject) -> None:
        forbidden = {
            "body",
            "ciphertext",
            "content",
            "password",
            "raw_stderr",
            "raw_stdout",
            "raw_tool_output",
            "secret",
            "secret_value",
            "token",
        }

        def inspect(value: object) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if key.casefold() in forbidden:
                        raise AuditIntegrityError("audit payload contains prohibited raw data")
                    inspect(item)
            elif isinstance(value, list):
                for item in value:
                    inspect(item)

        inspect(payload.to_dict())

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
