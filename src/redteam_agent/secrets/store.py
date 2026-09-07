"""Durable append-only secret lifecycle store (SystemDesign §34 / §10.2 / R10).

Value updates add a new immutable version under the logical head; state moves only via
append-only ``DETECTED -> CONFIRMED -> REVOKED/SUPERSEDED`` events, each binding a
sequence, previous digest, actor/evidence and an audit event in one transaction. The
logical head (latest version) and active head (current CONFIRMED) are separate, OCC-
guarded records. The store also backs the executor's :class:`TrustedSecretSource`
(decrypt an exact version's value through the envelope key provider) and the
:class:`SecretMetadataReader` view the executor uses for its dispatch/consume checks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto.key_provider import EncryptionKeyProvider
from redteam_agent.crypto.models import EncryptionMetadata, EnvelopeCiphertext
from redteam_agent.errors import (
    EncryptionKeyUnavailableError,
    SecretConfirmationError,
    SecretLifecycleError,
)
from redteam_agent.quarantine.blob_store import QuarantineBlobStore
from redteam_agent.resources.secret_metadata import SecretVersionMetadata as SecretMetadataView
from redteam_agent.runtime.clock import Clock
from redteam_agent.secrets.models import (
    SecretActiveHead,
    SecretConfirmationRecord,
    SecretLifecycleEvent,
    SecretLifecycleState,
    SecretLogicalHead,
    SecretVersionRecord,
)
from redteam_agent.storage.database import Database
from redteam_agent.storage.unit_of_work import (
    ApplicationUnitOfWork,
    FaultInjector,
    NoFaultInjector,
    compute_input_digest,
)

_VERSION_NS = "secret_version"
_EVENT_NS = "secret_lifecycle_event"
_CONFIRM_NS = "secret_confirmation"
_LOGICAL_HEAD_NS = "secret_logical_head"
_ACTIVE_HEAD_NS = "secret_active_head"
_ENC_NS = "secret_encryption"

_LEGAL_TRANSITIONS: dict[SecretLifecycleState, frozenset[SecretLifecycleState]] = {
    "DETECTED": frozenset({"CONFIRMED", "REVOKED"}),
    "CONFIRMED": frozenset({"REVOKED", "SUPERSEDED"}),
    "REVOKED": frozenset(),
    "SUPERSEDED": frozenset(),
}


@dataclass
class _PreparedDetect:
    record: SecretVersionRecord
    event: SecretLifecycleEvent
    new_logical: SecretLogicalHead
    previous_logical: SecretLogicalHead | None
    enc: EncryptionMetadata
    envelope_json: str
    actor_id: str
    occurred_at: datetime


class SecretLifecycleStore:
    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        clock: Clock,
        audit_store: AuditStore,
        key_provider: EncryptionKeyProvider,
        secret_blob_store: QuarantineBlobStore,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._audit = audit_store
        self._keys = key_provider
        self._blobs = secret_blob_store
        self._fault = fault_injector if fault_injector is not None else NoFaultInjector()

    # --- digests ----------------------------------------------------------

    def _version_digest(self, fields: dict[str, object]) -> str:
        return self._ds.compute("secret_version_metadata_digest",
                                {k: v for k, v in fields.items() if k != "metadata_digest"})

    def _event_digest(self, fields: dict[str, object]) -> str:
        return self._ds.compute("secret_lifecycle_event_digest",
                                {k: v for k, v in fields.items() if k != "event_digest"})

    def lifecycle_head_digest(self, event: SecretLifecycleEvent) -> str:
        return self._ds.compute("secret_lifecycle_head_digest", {
            "secret_version_id": event.secret_version_id, "sequence_number": event.sequence_number,
            "event_digest": event.event_digest, "state": event.event_type,
        })

    # --- reads ------------------------------------------------------------

    def get_version(self, secret_version_id: str) -> SecretVersionRecord | None:
        row = self._db.occ_get(_VERSION_NS, secret_version_id)
        if row is None:
            return None
        record = SecretVersionRecord.model_validate_json(row[1])
        self._ds.verify("secret_version_metadata_digest",
                        {k: v for k, v in record.model_dump(mode="python").items() if k != "metadata_digest"},
                        record.metadata_digest)
        return record

    def events_for(self, secret_version_id: str) -> tuple[SecretLifecycleEvent, ...]:
        rows = self._db.occ_get_all(_EVENT_NS)
        prefix = f"{secret_version_id}/"
        out = [SecretLifecycleEvent.model_validate_json(j) for k, _v, j in rows if k.startswith(prefix)]
        return tuple(sorted(out, key=lambda e: e.sequence_number))

    def latest_event(self, secret_version_id: str) -> SecretLifecycleEvent | None:
        events = self.events_for(secret_version_id)
        return events[-1] if events else None

    def current_state(self, secret_version_id: str) -> SecretLifecycleState | None:
        event = self.latest_event(secret_version_id)
        return None if event is None else event.event_type

    def current_security_projection(self, secret_version_id: str) -> tuple[int, str] | None:
        """Return the exact current lifecycle head used by the witness barrier."""
        event = self.latest_event(secret_version_id)
        if event is None:
            return None
        return event.sequence_number, self.lifecycle_head_digest(event)

    def logical_head(self, secret_id: str) -> SecretLogicalHead | None:
        row = self._db.occ_get(_LOGICAL_HEAD_NS, secret_id)
        return None if row is None else SecretLogicalHead.model_validate_json(row[1])

    def active_head(self, secret_id: str) -> SecretActiveHead | None:
        row = self._db.occ_get(_ACTIVE_HEAD_NS, secret_id)
        return None if row is None else SecretActiveHead.model_validate_json(row[1])

    def metadata_view(self, secret_version_id: str) -> SecretMetadataView | None:
        record = self.get_version(secret_version_id)
        event = self.latest_event(secret_version_id)
        if record is None or event is None:
            return None
        return SecretMetadataView(
            secret_version_id=secret_version_id, secret_id=record.secret_id, version=str(record.version),
            metadata_digest=record.metadata_digest, lifecycle_head_digest=self.lifecycle_head_digest(event),
            state=event.event_type, expires_at=record.expires_at,
        )

    # --- value source (executor-owned) ------------------------------------

    def open_version(self, secret_version_id: str) -> bytearray:
        record = self.get_version(secret_version_id)
        enc_row = self._db.occ_get(_ENC_NS, secret_version_id)
        blob_handle = f"secret/{secret_version_id}"
        if record is None or enc_row is None or not self._blobs.exists(blob_handle):
            raise EncryptionKeyUnavailableError("secret version value is unavailable")
        enc = EncryptionMetadata.model_validate_json(enc_row[1])
        envelope = EnvelopeCiphertext.model_validate_json(self._blobs.get(blob_handle).decode("utf-8"))
        handle = self._keys.open_resource_key_handle(metadata=enc, operation="decrypt")
        try:
            plaintext = handle.decrypt(
                record=envelope,
                aad_fields={"mission_id": record.mission_id, "secret_id": record.secret_id,
                            "secret_version_id": secret_version_id},
            )
        finally:
            handle.close()
        return bytearray(plaintext)

    # --- detect (add immutable version) -----------------------------------

    def prepare_detect(
        self, *, secret_id: str, mission_id: str, credential_type: str, associated_principal_ref: str | None,
        value: bytes, actor_id: str, actor_role: str, evidence_digest: str, reason_code: str,
        expires_at: datetime | None = None, expected_logical_head_digest: str | None = None,
    ) -> _PreparedDetect:
        """Build (but do not persist) a new immutable DETECTED version + envelope.

        Encryption happens here (no DB writes); :meth:`apply_detect_in_txn` performs all
        writes inside the caller's unit of work so ingestion can publish atomically.
        """
        logical = self.logical_head(secret_id)
        if expected_logical_head_digest is not None:
            current_head = None if logical is None else logical.head_digest
            if current_head != expected_logical_head_digest:
                raise SecretLifecycleError("logical head OCC mismatch on version add")
        version = 1 if logical is None else logical.head_version + 1
        secret_version_id = f"{secret_id}#v{version}"
        supersedes = None if logical is None else logical.head_version_id
        enc = self._keys.create_resource_key(
            domain="secret_store", resource_binding_type="secret_version_id", resource_binding_id=secret_version_id
        )
        handle = self._keys.open_resource_key_handle(metadata=enc, operation="encrypt")
        try:
            envelope = handle.encrypt(
                encryption_metadata_id=enc.resource_key_id, nonce=self._nonce(), plaintext=value,
                aad_fields={"mission_id": mission_id, "secret_id": secret_id,
                            "secret_version_id": secret_version_id},
            )
        finally:
            handle.close()
        now = self._clock.now()
        fields = {
            "secret_id": secret_id, "secret_version_id": secret_version_id, "version": version,
            "supersedes_secret_version_id": supersedes, "mission_id": mission_id,
            "credential_type": credential_type, "associated_principal_ref": associated_principal_ref,
            "encryption_metadata_id": enc.resource_key_id, "created_at": now, "expires_at": expires_at,
        }
        record = SecretVersionRecord(**fields, metadata_digest=self._version_digest(fields))  # type: ignore[arg-type]
        event = self._build_event(
            secret_version_id=secret_version_id, sequence_number=1, event_type="DETECTED", actor_id=actor_id,
            actor_role=actor_role, evidence_digest=evidence_digest, confirmation_record_id=None,
            reason_code=reason_code, previous=None, now=now,
        )
        new_logical = self._build_logical_head(secret_id, version, secret_version_id)
        return _PreparedDetect(
            record=record, event=event, new_logical=new_logical, previous_logical=logical, enc=enc,
            envelope_json=json.dumps(envelope.model_dump(mode="json"), sort_keys=True),
            actor_id=actor_id, occurred_at=now,
        )

    def apply_detect_in_txn(self, prepared: _PreparedDetect) -> SecretVersionRecord:
        """Persist a prepared DETECTED version inside the caller's open unit of work."""
        record = prepared.record
        if self.get_version(record.secret_version_id) is not None:
            existing = self.get_version(record.secret_version_id)
            assert existing is not None
            return existing  # create-or-verify idempotency
        self._db.occ_insert_idempotent(_ENC_NS, record.secret_version_id, 1,
                                       json.dumps(prepared.enc.model_dump(mode="json"), sort_keys=True))
        self._blobs.put(f"secret/{record.secret_version_id}", prepared.envelope_json.encode("utf-8"))
        self._db.occ_insert(_VERSION_NS, record.secret_version_id, 1, _dump(record))
        self._append_event(prepared.event)
        self._upsert_logical_head(prepared.new_logical, previous=prepared.previous_logical)
        self._audit.append_in_txn(mission_id=record.mission_id, event_type="SECRET_DETECTED",
                                  payload_digest=prepared.event.event_digest, actor_id=prepared.actor_id,
                                  occurred_at_iso=_iso(prepared.occurred_at),
                                  record_type="secret_lifecycle_head",
                                  record_id=record.secret_version_id,
                                  state_version=prepared.event.sequence_number,
                                  security_projection_digest=self.lifecycle_head_digest(prepared.event))
        return record

    def detect(
        self, *, secret_id: str, mission_id: str, credential_type: str, associated_principal_ref: str | None,
        value: bytes, actor_id: str, actor_role: str, evidence_digest: str, reason_code: str,
        expires_at: datetime | None = None,
        expected_logical_head_digest: str | None = None,
    ) -> SecretVersionRecord:
        logical = self.logical_head(secret_id)
        next_version = 1 if logical is None else logical.head_version + 1
        existing = self.get_version(f"{secret_id}#v{next_version}")
        if existing is not None:
            return existing
        prepared = self.prepare_detect(
            secret_id=secret_id, mission_id=mission_id, credential_type=credential_type,
            associated_principal_ref=associated_principal_ref, value=value, actor_id=actor_id,
            actor_role=actor_role, evidence_digest=evidence_digest, reason_code=reason_code,
            expires_at=expires_at, expected_logical_head_digest=expected_logical_head_digest,
        )
        op = compute_input_digest({"detect": prepared.record.secret_version_id})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="SecretLifecycleAggregate",
            operation_id=f"detect-{prepared.record.secret_version_id}", input_digest=op, fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                self.apply_detect_in_txn(prepared)
                uow.record_result(prepared.record.metadata_digest)
        return prepared.record

    # --- confirm ----------------------------------------------------------

    def confirm(
        self, *, secret_version_id: str, mission_id: str, mission_revision: int, authorization_epoch: int,
        approver_id: str, source_evidence_digest: str, reason_code: str,
        expected_lifecycle_head_digest: str, expected_logical_version_head_digest: str,
        expected_active_version_id: str | None,
    ) -> SecretConfirmationRecord:
        record = self.get_version(secret_version_id)
        if record is None:
            raise SecretConfirmationError("secret version not found")
        latest = self.latest_event(secret_version_id)
        if latest is None or latest.event_type != "DETECTED":
            raise SecretConfirmationError("only a DETECTED version can be confirmed")
        if self.lifecycle_head_digest(latest) != expected_lifecycle_head_digest:
            raise SecretConfirmationError("lifecycle head OCC mismatch")
        logical = self.logical_head(record.secret_id)
        if logical is None or logical.head_version_id != secret_version_id:
            raise SecretConfirmationError("only the latest logical candidate version can be confirmed")
        if logical.head_digest != expected_logical_version_head_digest:
            raise SecretConfirmationError("logical version head OCC mismatch")
        active = self.active_head(record.secret_id)
        current_active = None if active is None else active.active_version_id
        if current_active != expected_active_version_id:
            raise SecretConfirmationError("active head OCC mismatch")
        now = self._clock.now()
        confirmation = self._build_confirmation(
            record=record, mission_revision=mission_revision, authorization_epoch=authorization_epoch,
            approver_id=approver_id, source_evidence_digest=source_evidence_digest,
            expected_lifecycle_head_digest=expected_lifecycle_head_digest,
            expected_logical_version_head_digest=expected_logical_version_head_digest,
            replaces_active_version_id=current_active, now=now,
        )
        confirmed_event = self._build_event(
            secret_version_id=secret_version_id, sequence_number=latest.sequence_number + 1,
            event_type="CONFIRMED", actor_id=approver_id, actor_role="approver",
            evidence_digest=source_evidence_digest, confirmation_record_id=confirmation.confirmation_id,
            reason_code=reason_code, previous=latest.event_digest, now=now,
        )
        superseded_event = None
        if current_active is not None:
            prior_latest = self.latest_event(current_active)
            if prior_latest is not None and prior_latest.event_type == "CONFIRMED":
                superseded_event = self._build_event(
                    secret_version_id=current_active, sequence_number=prior_latest.sequence_number + 1,
                    event_type="SUPERSEDED", actor_id=approver_id, actor_role="approver",
                    evidence_digest=source_evidence_digest, confirmation_record_id=None,
                    reason_code="superseded_by_new_active", previous=prior_latest.event_digest, now=now,
                )
        new_active = self._build_active_head(record.secret_id, secret_version_id, active)
        op = compute_input_digest({"confirm": secret_version_id, "active": current_active})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="SecretLifecycleAggregate", operation_id=f"confirm-{confirmation.confirmation_id}",
            input_digest=op, fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                self._db.occ_insert(_CONFIRM_NS, confirmation.confirmation_id, 1, _dump(confirmation))
                self._append_event(confirmed_event)
                if superseded_event is not None:
                    self._append_event(superseded_event)
                    self._audit.append_in_txn(
                        mission_id=mission_id,
                        event_type="SECRET_SUPERSEDED",
                        payload_digest=superseded_event.event_digest,
                        actor_id=approver_id,
                        occurred_at_iso=_iso(now),
                        record_type="secret_lifecycle_head",
                        record_id=superseded_event.secret_version_id,
                        state_version=superseded_event.sequence_number,
                        security_projection_digest=self.lifecycle_head_digest(superseded_event),
                    )
                self._upsert_active_head(new_active, previous=active)
                self._audit.append_in_txn(mission_id=mission_id, event_type="SECRET_CONFIRMED",
                                          payload_digest=confirmed_event.event_digest, actor_id=approver_id,
                                          occurred_at_iso=_iso(now),
                                          record_type="secret_lifecycle_head",
                                          record_id=secret_version_id,
                                          state_version=confirmed_event.sequence_number,
                                          security_projection_digest=self.lifecycle_head_digest(confirmed_event))
                uow.record_result(confirmation.record_digest)
        return confirmation

    # --- revoke -----------------------------------------------------------

    def revoke(
        self, *, secret_version_id: str, mission_id: str, actor_id: str, actor_role: str,
        evidence_digest: str, reason_code: str,
    ) -> SecretLifecycleEvent:
        record = self.get_version(secret_version_id)
        latest = self.latest_event(secret_version_id)
        if record is None or latest is None:
            raise SecretLifecycleError("secret version not found")
        if "REVOKED" not in _LEGAL_TRANSITIONS[latest.event_type]:
            raise SecretLifecycleError(f"cannot revoke from {latest.event_type}")
        now = self._clock.now()
        event = self._build_event(
            secret_version_id=secret_version_id, sequence_number=latest.sequence_number + 1, event_type="REVOKED",
            actor_id=actor_id, actor_role=actor_role, evidence_digest=evidence_digest, confirmation_record_id=None,
            reason_code=reason_code, previous=latest.event_digest, now=now,
        )
        active = self.active_head(record.secret_id)
        clear_active = active is not None and active.active_version_id == secret_version_id
        new_active = self._build_active_head(record.secret_id, None, active) if clear_active else None
        op = compute_input_digest({"revoke": secret_version_id, "seq": event.sequence_number})
        revoke_op = f"revoke-{secret_version_id}-{event.sequence_number}"
        with ApplicationUnitOfWork(
            self._db, aggregate_name="SecretLifecycleAggregate", operation_id=revoke_op,
            input_digest=op, fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                self._append_event(event)
                if new_active is not None:
                    self._upsert_active_head(new_active, previous=active)
                self._audit.append_in_txn(mission_id=mission_id, event_type="SECRET_REVOKED",
                                          payload_digest=event.event_digest, actor_id=actor_id,
                                          occurred_at_iso=_iso(now),
                                          record_type="secret_lifecycle_head",
                                          record_id=secret_version_id,
                                          state_version=event.sequence_number,
                                          security_projection_digest=self.lifecycle_head_digest(event))
                uow.record_result(event.event_digest)
        return event

    # --- builders ---------------------------------------------------------

    def _nonce(self) -> bytes:
        import os
        return os.urandom(12)

    def _build_event(
        self, *, secret_version_id: str, sequence_number: int, event_type: SecretLifecycleState, actor_id: str,
        actor_role: str, evidence_digest: str, confirmation_record_id: str | None, reason_code: str,
        previous: str | None, now: datetime,
    ) -> SecretLifecycleEvent:
        fields = {
            "event_id": f"{secret_version_id}/event/{sequence_number}", "secret_version_id": secret_version_id,
            "sequence_number": sequence_number, "event_type": event_type, "actor_id": actor_id,
            "actor_role": actor_role, "evidence_digest": evidence_digest,
            "confirmation_record_id": confirmation_record_id, "reason_code": reason_code, "occurred_at": now,
            "previous_event_digest": previous,
        }
        return SecretLifecycleEvent(**fields, event_digest=self._event_digest(fields))  # type: ignore[arg-type]

    def _build_confirmation(
        self, *, record: SecretVersionRecord, mission_revision: int, authorization_epoch: int, approver_id: str,
        source_evidence_digest: str, expected_lifecycle_head_digest: str,
        expected_logical_version_head_digest: str, replaces_active_version_id: str | None, now: datetime,
    ) -> SecretConfirmationRecord:
        fields = {
            "confirmation_id": f"confirm-{record.secret_version_id}", "mission_id": record.mission_id,
            "mission_revision": mission_revision, "authorization_epoch": authorization_epoch,
            "secret_version_id": record.secret_version_id, "secret_metadata_digest": record.metadata_digest,
            "expected_lifecycle_head_digest": expected_lifecycle_head_digest,
            "expected_logical_version_head_digest": expected_logical_version_head_digest,
            "replaces_active_version_id": replaces_active_version_id,
            "source_evidence_digest": source_evidence_digest, "method": "operator_review",
            "approver_id": approver_id, "approver_role": "approver", "confirmed_at": now,
        }
        digest = self._ds.compute("secret_confirmation_digest", fields)
        return SecretConfirmationRecord(**fields, record_digest=digest)  # type: ignore[arg-type]

    def _build_logical_head(self, secret_id: str, version: int, version_id: str) -> SecretLogicalHead:
        payload = {"secret_id": secret_id, "head_version": version, "head_version_id": version_id}
        return SecretLogicalHead(**payload, head_digest=self._ds.compute("secret_logical_head_digest", payload))  # type: ignore[arg-type]

    def _build_active_head(
        self, secret_id: str, active_version_id: str | None, previous: SecretActiveHead | None
    ) -> SecretActiveHead:
        revision = 1 if previous is None else previous.revision + 1
        payload = {"secret_id": secret_id, "active_version_id": active_version_id, "revision": revision}
        return SecretActiveHead(**payload, head_digest=self._ds.compute("secret_active_head_digest", payload))  # type: ignore[arg-type]

    def _append_event(self, event: SecretLifecycleEvent) -> None:
        self._db.occ_insert(_EVENT_NS, f"{event.secret_version_id}/{event.sequence_number}", 1, _dump(event))

    def _upsert_logical_head(self, head: SecretLogicalHead, *, previous: SecretLogicalHead | None) -> None:
        if previous is None:
            self._db.occ_insert(_LOGICAL_HEAD_NS, head.secret_id, 1, _dump(head))
        else:
            row = self._db.occ_get(_LOGICAL_HEAD_NS, head.secret_id)
            assert row is not None
            self._db.occ_update(_LOGICAL_HEAD_NS, head.secret_id, expected_version=row[0],
                                new_version=row[0] + 1, json_text=_dump(head))

    def _upsert_active_head(self, head: SecretActiveHead, *, previous: SecretActiveHead | None) -> None:
        if previous is None:
            self._db.occ_insert(_ACTIVE_HEAD_NS, head.secret_id, 1, _dump(head))
        else:
            row = self._db.occ_get(_ACTIVE_HEAD_NS, head.secret_id)
            assert row is not None
            self._db.occ_update(_ACTIVE_HEAD_NS, head.secret_id, expected_version=row[0],
                                new_version=row[0] + 1, json_text=_dump(head))


def _dump(model: object) -> str:
    assert hasattr(model, "model_dump")
    return json.dumps(model.model_dump(mode="json"), sort_keys=True)  # type: ignore[attr-defined]


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
