"""Synchronous TPM barrier for security-critical state commits (SystemDesign §34.2).

The application mutation, audit event and immutable ``CriticalWitnessIntent`` are
committed in one SQLite transaction.  Only after that commit does the barrier create
the content-bound audit-head generation, extend the TPM witness and read it back.
The caller receives success only after this callback completes.  A crash after the DB
commit leaves enough immutable evidence for ``recover_pending``; recovery completes
the witness but never recreates the original operation's continuation.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import datetime

from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.models import (
    AuditEvent,
    CriticalWitnessIntent,
    GenerationCommitRecord,
    GenerationWitnessPolicy,
    SecurityStateBinding,
)
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AnchorRecoveryRequiredError, CriticalWitnessError
from redteam_agent.storage.database import Database

_INTENT_NS = "critical_witness_intent"


class CriticalWitnessBarrier:
    """Single-root critical commit barrier for the ``audit_head`` namespace."""

    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        coordinator: AuthenticatedGenerationCoordinator,
        policy: GenerationWitnessPolicy,
        critical_record_types: frozenset[str],
        current_binding: Callable[[SecurityStateBinding], tuple[int, str] | None],
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._coordinator = coordinator
        self._policy = policy
        self._critical_record_types = critical_record_types
        self._current_binding = current_binding
        self._lock = threading.RLock()
        self._intent_by_transaction: dict[str, str] = {}
        self._verify_policy()
        current = coordinator.current("audit_head")
        if current is None:
            raise CriticalWitnessError("critical witness barrier requires an audit-head genesis")
        self._cached_current = current
        self._last_witnessed_event_count, self._last_witnessed_at = self._witness_baseline(current)
        self._verify_current_record(current)

    @property
    def policy(self) -> GenerationWitnessPolicy:
        return self._policy

    @property
    def critical_record_types(self) -> frozenset[str]:
        return self._critical_record_types

    @property
    def database(self) -> Database:
        return self._db

    @property
    def coordinator(self) -> AuthenticatedGenerationCoordinator:
        return self._coordinator

    def _verify_policy(self) -> None:
        payload = self._policy.model_dump(mode="python")
        self._ds.verify(
            "generation_witness_policy_digest",
            {k: v for k, v in payload.items() if k != "policy_digest"},
            self._policy.policy_digest,
        )
        catalog_digest = self._ds.compute(
            "security_projection_digest",
            {
                "catalog_revision": self._policy.critical_state_catalog_revision,
                "record_types": tuple(sorted(self._critical_record_types)),
            },
        )
        if catalog_digest != self._policy.critical_state_catalog_digest:
            raise CriticalWitnessError("critical state catalog digest mismatch")

    def prepare_in_txn(
        self,
        *,
        event: AuditEvent,
        record_type: str,
        record_id: str,
        state_version: int,
        security_projection_digest: str,
    ) -> CriticalWitnessIntent | None:
        """Persist an intent in the caller's transaction and arm post-commit TPM I/O."""
        forced = event.event_type in self._policy.force_event_types
        if not forced and not self._batch_due(event):
            return None
        if not forced or record_type == "audit_chain_head":
            record_type = "audit_chain_head"
            record_id = event.mission_id
            state_version = event.sequence_number
            security_projection_digest = event.event_digest
        if record_type not in self._critical_record_types:
            raise CriticalWitnessError("critical mutation uses an unregistered record type")
        if not self._db.in_transaction:
            raise CriticalWitnessError("critical witness intent requires the mutation transaction")
        transaction_id = self._db.transaction_identity
        current = self._cached_current
        if transaction_id not in self._intent_by_transaction:
            pending = [
                key
                for key, _version, _text in self._db.occ_get_all(_INTENT_NS)
                if self._load(key).expected_generation == current.generation
            ]
            if pending:
                raise CriticalWitnessError("an earlier critical witness intent is still pending")
        binding_fields = {
            "record_type": record_type,
            "record_id": record_id,
            "state_version": state_version,
            "security_projection_digest": security_projection_digest,
            "audit_event_digest": event.event_digest,
        }
        binding = SecurityStateBinding(
            **binding_fields,  # type: ignore[arg-type]
            binding_digest=self._ds.compute("security_state_binding_digest", binding_fields),
        )
        existing_intent_id = self._intent_by_transaction.get(transaction_id)
        existing = self._load(existing_intent_id) if existing_intent_id is not None else None
        bindings = (*existing.bindings, binding) if existing is not None else (binding,)
        input_digest = self._ds.compute("security_projection_digest", {
            "binding_digests": tuple(item.binding_digest for item in bindings),
        })
        intent_fields = {
            "witness_intent_id": (
                existing.witness_intent_id if existing is not None else f"critical-{event.event_digest}"
            ),
            "operation_id": existing.operation_id if existing is not None else event.event_digest,
            "input_digest": input_digest,
            "expected_generation": existing.expected_generation if existing is not None else current.generation,
            "expected_witness_digest": (
                existing.expected_witness_digest if existing is not None else current.witness_digest
            ),
            "trust_epoch": self._coordinator.trust_epoch,
            "tpm_nv_index_identity": (
                existing.tpm_nv_index_identity if existing is not None else current.tpm_nv_index_identity
            ),
            "bindings": tuple(item.model_dump(mode="python") for item in bindings),
        }
        intent = CriticalWitnessIntent(
            **{**intent_fields, "bindings": bindings},  # type: ignore[arg-type]
            intent_digest=self._ds.compute("critical_witness_intent_digest", intent_fields),
        )
        text = json.dumps(intent.model_dump(mode="json"), sort_keys=True)
        if existing is None:
            self._db.occ_insert(_INTENT_NS, intent.witness_intent_id, 1, text)
            self._intent_by_transaction[transaction_id] = intent.witness_intent_id
            def complete_after_commit() -> None:
                try:
                    self.complete(intent.witness_intent_id)
                finally:
                    self._intent_by_transaction.pop(transaction_id, None)

            self._db.register_after_commit(complete_after_commit)
        else:
            row = self._db.occ_get(_INTENT_NS, intent.witness_intent_id)
            assert row is not None
            self._db.occ_update(
                _INTENT_NS, intent.witness_intent_id, expected_version=row[0],
                new_version=row[0] + 1, json_text=text,
            )
        return intent

    def _load(self, intent_id: str) -> CriticalWitnessIntent:
        row = self._db.occ_get(_INTENT_NS, intent_id)
        if row is None:
            raise CriticalWitnessError("critical witness intent is missing")
        intent = CriticalWitnessIntent.model_validate_json(row[1])
        payload = intent.model_dump(mode="python")
        self._ds.verify(
            "critical_witness_intent_digest",
            {k: v for k, v in payload.items() if k != "intent_digest"},
            intent.intent_digest,
        )
        for binding in intent.bindings:
            fields = binding.model_dump(mode="python")
            self._ds.verify(
                "security_state_binding_digest",
                {k: v for k, v in fields.items() if k != "binding_digest"},
                binding.binding_digest,
            )
        return intent

    def _content(self, intent: CriticalWitnessIntent) -> str:
        event_count, witnessed_at = self._audit_snapshot()
        heads = [json.loads(text) for _key, _version, text in self._db.occ_get_all("audit_chain_head")]
        heads.sort(key=lambda head: str(head["mission_id"]))
        previous = self._bindings_from_record(self._cached_current)
        merged = {(item.record_type, item.record_id): item for item in previous}
        for binding in intent.bindings:
            merged[(binding.record_type, binding.record_id)] = binding
        bindings = tuple(merged[key] for key in sorted(merged))
        return canonical_dumps({
            "policy_revision": self._policy.policy_revision,
            "critical_state_catalog_revision": self._policy.critical_state_catalog_revision,
            "bindings": [binding.model_dump(mode="json") for binding in bindings],
            "audit_heads": heads,
            "event_count": event_count,
            "witnessed_at_iso": witnessed_at,
        }).decode("utf-8")

    def _bindings_from_record(
        self, record: GenerationCommitRecord
    ) -> tuple[SecurityStateBinding, ...]:
        try:
            content = json.loads(self._coordinator.record_content(record))
            raw = content.get("bindings", [])
            if not isinstance(raw, list):
                raise TypeError
            return tuple(SecurityStateBinding.model_validate(item) for item in raw)
        except (TypeError, ValueError) as exc:
            raise AnchorRecoveryRequiredError("audit-head generation content is invalid") from exc

    def _verify_current_record(self, record: GenerationCommitRecord) -> None:
        try:
            content = json.loads(self._coordinator.record_content(record))
        except (TypeError, ValueError) as exc:
            raise AnchorRecoveryRequiredError("audit-head generation content is invalid") from exc
        raw_bindings = content.get("bindings", [])
        if not isinstance(raw_bindings, list):
            raise AnchorRecoveryRequiredError("audit-head security bindings are invalid")
        bindings = tuple(SecurityStateBinding.model_validate(item) for item in raw_bindings)
        recovery = content.get("trust_recovery_consumption")
        if recovery is not None:
            if not isinstance(recovery, dict) or record.state_digest != recovery.get(
                "consumption_digest"
            ):
                raise AnchorRecoveryRequiredError("audit-head recovery consumption is invalid")
        elif record.generation > 0 and record.state_digest != self._state_digest_for_content(content):
            raise AnchorRecoveryRequiredError("audit-head state digest does not bind its full content")
        for binding in bindings:
            resolved = self._current_binding(binding)
            if resolved is None or resolved != (
                binding.state_version,
                binding.security_projection_digest,
            ):
                raise AnchorRecoveryRequiredError(
                    f"current security projection does not match witnessed {binding.record_type}"
                )

    def verify_current_security_state(self) -> GenerationCommitRecord:
        """Verify TPM-selected content against current owner records before their use."""
        with self._lock:
            current = self._coordinator.current("audit_head")
            if current is None:
                raise AnchorRecoveryRequiredError("audit-head witness disappeared")
            self._verify_current_record(current)
            self._cached_current = current
            return current

    def _audit_snapshot(self) -> tuple[int, str | None]:
        events = [
            AuditEvent.model_validate_json(text)
            for _key, _version, text in self._db.occ_get_all("audit_log")
        ]
        if not events:
            return 0, None
        latest = max(events, key=lambda item: self._parse_time(item.occurred_at_iso))
        return len(events), latest.occurred_at_iso

    @staticmethod
    def _parse_time(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CriticalWitnessError("audit event has an invalid timestamp") from exc
        if parsed.tzinfo is None:
            raise CriticalWitnessError("audit event timestamp must include a timezone")
        return parsed

    def _witness_baseline(self, record: GenerationCommitRecord) -> tuple[int, str | None]:
        try:
            content = json.loads(self._coordinator.record_content(record))
        except (TypeError, ValueError):
            return 0, None
        count = content.get("event_count", 0)
        witnessed_at = content.get("witnessed_at_iso")
        return (
            count if isinstance(count, int) and count >= 0 else 0,
            witnessed_at if isinstance(witnessed_at, str) else None,
        )

    def _batch_due(self, event: AuditEvent) -> bool:
        event_count = len(self._db.occ_get_all("audit_log"))
        if event_count - self._last_witnessed_event_count >= self._policy.max_unwitnessed_events:
            return True
        current = self._parse_time(event.occurred_at_iso)
        if self._last_witnessed_at is None:
            events = [
                AuditEvent.model_validate_json(text)
                for _key, _version, text in self._db.occ_get_all("audit_log")
            ]
            if not events:
                return False
            previous = min(self._parse_time(item.occurred_at_iso) for item in events)
        else:
            previous = self._parse_time(self._last_witnessed_at)
        return (current - previous).total_seconds() >= self._policy.max_unwitnessed_seconds

    def _state_digest_for_content(self, content: dict[str, object]) -> str:
        return self._ds.compute("security_projection_digest", {
            "policy_digest": self._policy.policy_digest,
            "audit_head_state": content,
        })

    def complete(self, intent_id: str) -> GenerationCommitRecord:
        """Complete or reconcile one exact intent; never creates an app continuation."""
        with self._lock:
            intent = self._load(intent_id)
            if intent.trust_epoch != self._coordinator.trust_epoch:
                raise CriticalWitnessError("critical intent trust epoch mismatch")
            current = self._coordinator.current("audit_head")
            if current is None:
                raise AnchorRecoveryRequiredError("audit-head witness disappeared")
            if current.generation == intent.expected_generation:
                if current.witness_digest != intent.expected_witness_digest:
                    raise AnchorRecoveryRequiredError("critical intent expected witness mismatch")
                content = self._content(intent)
                parsed_content = json.loads(content)
                state_digest = self._state_digest_for_content(parsed_content)
                record = self._coordinator.commit(
                    "audit_head",
                    new_state_digest=state_digest,
                    new_content=content,
                    operation_id=f"critical-witness-{intent.operation_id}",
                )
            else:
                reconciled = self._coordinator.record_at("audit_head", intent.expected_generation + 1)
                if reconciled is None:
                    raise AnchorRecoveryRequiredError("critical intent has no exact witnessed generation")
                reconciled_bindings = self._bindings_from_record(reconciled)
                expected = {(item.record_type, item.record_id): item.binding_digest for item in intent.bindings}
                actual = {(item.record_type, item.record_id): item.binding_digest for item in reconciled_bindings}
                if any(actual.get(key) != digest for key, digest in expected.items()):
                    raise AnchorRecoveryRequiredError("critical intent has no exact witnessed generation")
                record = reconciled
                if current.generation < record.generation:
                    raise AnchorRecoveryRequiredError("TPM witness is behind the critical record")
            verified = self._coordinator.current("audit_head")
            if verified is None or verified.generation < record.generation:
                raise AnchorRecoveryRequiredError("critical witness read-back did not confirm the generation")
            self._verify_current_record(verified)
            self._cached_current = verified
            self._last_witnessed_event_count, self._last_witnessed_at = self._witness_baseline(record)
            return record

    def recover_pending(self) -> tuple[str, ...]:
        """Complete all unwitnessed intents in generation order without continuation."""
        completed: list[str] = []
        while True:
            current = self._coordinator.current("audit_head")
            if current is None:
                raise AnchorRecoveryRequiredError("audit-head witness disappeared during recovery")
            candidates = []
            for key, _version, _text in self._db.occ_get_all(_INTENT_NS):
                intent = self._load(key)
                if intent.expected_generation == current.generation:
                    candidates.append(intent)
            if not candidates:
                self._cached_current = current
                return tuple(completed)
            if len(candidates) != 1:
                raise AnchorRecoveryRequiredError("multiple critical intents target the same witness generation")
            self.complete(candidates[0].witness_intent_id)
            for transaction_id, intent_id in tuple(self._intent_by_transaction.items()):
                if intent_id == candidates[0].witness_intent_id:
                    self._intent_by_transaction.pop(transaction_id, None)
            completed.append(candidates[0].witness_intent_id)
