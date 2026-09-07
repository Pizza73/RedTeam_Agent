"""Mission-scoped append-only audit log + event hash chain (SystemDesign §34.2).

Each mission has its own monotonically increasing sequence; every event binds the
previous event's digest, so a reordered, dropped, duplicated or edited event is
detected on verification. The store participates in the caller's ApplicationUnitOfWork
(state transition, audit and intent commit together); it never opens its own commit.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

from redteam_agent.audit.models import AuditChainHead, AuditEvent
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AuditChainError
from redteam_agent.storage.database import Database

if TYPE_CHECKING:
    from redteam_agent.audit.critical_witness import CriticalWitnessBarrier

_LOG_NS = "audit_log"
_HEAD_NS = "audit_chain_head"


def _seq_key(mission_id: str, sequence_number: int) -> str:
    return f"{mission_id}/{sequence_number:020d}"


class AuditStore:
    def __init__(
        self, database: Database, digest_service: DigestService,
        critical_witness_barrier: CriticalWitnessBarrier | None = None,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._critical_witness_barrier = critical_witness_barrier

    def set_critical_witness_barrier(self, barrier: CriticalWitnessBarrier) -> None:
        """Composition-only bootstrap hook, called before workers are constructed."""
        if self._critical_witness_barrier is not None:
            raise AuditChainError("critical witness barrier is already configured")
        self._critical_witness_barrier = barrier

    def _event_digest(self, fields: dict[str, object]) -> str:
        payload = {k: v for k, v in fields.items() if k != "event_digest"}
        return self._ds.compute("audit_event_digest", payload)

    def _head_digest(self, mission_id: str, head_sequence: int, head_event_digest: str, updated_at_iso: str) -> str:
        return self._ds.compute("audit_head_digest", {
            "mission_id": mission_id, "head_sequence": head_sequence,
            "head_event_digest": head_event_digest, "updated_at_iso": updated_at_iso,
        })

    def head(self, mission_id: str) -> AuditChainHead | None:
        row = self._db.occ_get(_HEAD_NS, mission_id)
        if row is None:
            return None
        head = AuditChainHead.model_validate_json(row[1])
        expected = self._head_digest(head.mission_id, head.head_sequence, head.head_event_digest, head.updated_at_iso)
        if not hmac.compare_digest(expected, head.head_digest):
            raise AuditChainError("audit chain head digest mismatch")
        return head

    def append_in_txn(
        self, *, mission_id: str, event_type: str, payload_digest: str, actor_id: str, occurred_at_iso: str,
        record_type: str | None = None, record_id: str | None = None,
        state_version: int | None = None, security_projection_digest: str | None = None,
    ) -> AuditEvent:
        """Append one event within the caller's open transaction; returns the event."""
        if not self._db.in_transaction:
            raise AuditChainError("audit append requires an active unit of work")
        head = self.head(mission_id)
        sequence_number = 1 if head is None else head.head_sequence + 1
        previous = None if head is None else head.head_event_digest
        fields = {
            "mission_id": mission_id, "sequence_number": sequence_number, "event_type": event_type,
            "payload_digest": payload_digest, "actor_id": actor_id, "previous_event_digest": previous,
            "occurred_at_iso": occurred_at_iso,
        }
        event = AuditEvent(**fields, event_digest=self._event_digest(fields))  # type: ignore[arg-type]
        self._db.occ_insert(_LOG_NS, _seq_key(mission_id, sequence_number), 1, _dump(event))
        new_head = AuditChainHead(
            mission_id=mission_id, head_sequence=sequence_number, head_event_digest=event.event_digest,
            updated_at_iso=occurred_at_iso,
            head_digest=self._head_digest(mission_id, sequence_number, event.event_digest, occurred_at_iso),
        )
        if head is None:
            self._db.occ_insert(_HEAD_NS, mission_id, 1, _dump(new_head))
        else:
            existing = self._db.occ_get(_HEAD_NS, mission_id)
            assert existing is not None
            self._db.occ_update(
                _HEAD_NS, mission_id, expected_version=existing[0], new_version=existing[0] + 1,
                json_text=_dump(new_head),
            )
        if self._critical_witness_barrier is not None:
            self._critical_witness_barrier.prepare_in_txn(
                event=event,
                record_type=record_type or event_type.lower(),
                record_id=record_id or f"{mission_id}/{sequence_number}",
                state_version=state_version or sequence_number,
                security_projection_digest=security_projection_digest or payload_digest,
            )
        return event

    def events(self, mission_id: str) -> tuple[AuditEvent, ...]:
        rows = self._db.occ_get_all(_LOG_NS)
        prefix = f"{mission_id}/"
        out = [AuditEvent.model_validate_json(j) for k, _v, j in rows if k.startswith(prefix)]
        return tuple(sorted(out, key=lambda e: e.sequence_number))

    def verify_chain(self, mission_id: str) -> None:
        """Recompute the chain and fail closed on any gap, duplicate, reorder or edit."""
        events = self.events(mission_id)
        previous_digest: str | None = None
        expected_seq = 1
        for event in events:
            if event.sequence_number != expected_seq:
                raise AuditChainError(
                    f"audit sequence gap/duplicate for {mission_id}: "
                    f"expected {expected_seq}, got {event.sequence_number}"
                )
            fields = event.model_dump(mode="python")
            if not hmac.compare_digest(self._event_digest(fields), event.event_digest):
                raise AuditChainError(f"audit event {event.sequence_number} digest mismatch (tamper)")
            if event.previous_event_digest != previous_digest:
                raise AuditChainError(f"audit event {event.sequence_number} previous-digest chain broken")
            previous_digest = event.event_digest
            expected_seq += 1
        head = self.head(mission_id)
        if head is None:
            if events:
                raise AuditChainError("audit head missing while events exist")
            return
        if head.head_sequence != len(events) or (events and head.head_event_digest != events[-1].event_digest):
            raise AuditChainError("audit head does not match the chain tip")


def _dump(model: AuditEvent | AuditChainHead) -> str:
    import json

    return json.dumps(model.model_dump(mode="json"), sort_keys=True)


def payload_digest_for(digest_service: DigestService, event_type: str, payload: dict[str, object]) -> str:
    """Helper: a content digest of an audit event's non-secret payload."""
    return hashlib.sha256(
        b"audit-payload-v1\x00" + event_type.encode() + b"\x00"
        + _canonical(digest_service, payload)
    ).hexdigest()


def _canonical(digest_service: DigestService, payload: dict[str, object]) -> bytes:
    from redteam_agent.canonical.canonical_json import canonical_dumps

    return canonical_dumps(payload)
