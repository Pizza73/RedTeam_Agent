"""VerifiedQuarantineEraser: the only path that erases quarantine (SystemDesign §33.2 / §34.1).

The eraser consumes a bound deletion intent, verifies the reason-specific evidence
(for ``post_ingestion`` the committed publication trail read back from storage), and, in
one transaction, creates an *already-consumed* single-use erasure claim while moving
``DELETE_PENDING -> ERASURE_CLAIMED``. It then reconciles the key destruction first
(``NOT_STARTED`` only may start a destroy; ``UNKNOWN`` reconciles only), unlinks the
ciphertext only after a read-back ``CONFIRMED``, and rebuilds the ExecutionResult from
the projection alone (no body read, no provider re-query). Ingestion has no erasure
capability; only this composition-fixed eraser does.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto.key_provider import EncryptionKeyProvider
from redteam_agent.crypto.models import KeyDestructionResult
from redteam_agent.erasure.models import QuarantineDeletionIntent, QuarantineErasureClaim
from redteam_agent.errors import VerifiedErasureError
from redteam_agent.execution.models import (
    ExecutionRecord,
    ExecutionResult,
    ExecutionResultProjection,
    LocalResultBinding,
    ProviderTaskBinding,
    ResultIngestionStateRecord,
    ResultIngestionStatus,
)
from redteam_agent.execution.records import finalize_object_digest
from redteam_agent.execution.state_machine import is_legal_ingestion_edge
from redteam_agent.ingestion.manifest import SecureIngestionManifest
from redteam_agent.models.common import ToolRef
from redteam_agent.quarantine.store import EncryptedQuarantineStore
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionResultProjectionRepository,
    ExecutionResultRepository,
    ResultIngestionStateRepository,
)
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.unit_of_work import (
    ApplicationUnitOfWork,
    FaultInjector,
    NoFaultInjector,
    compute_input_digest,
)

_INTENT_NS = "quarantine_deletion_intent"
_MANIFEST_NS = "secure_ingestion_manifest"
_CLAIM_NS = "quarantine_erasure_claim"
_CLAIM_BY_INTENT_NS = "quarantine_erasure_by_intent"
_RESULT_STATUS = {"succeeded": "SUCCEEDED", "failed": "FAILED", "cancelled": "CANCELLED"}


@dataclass(frozen=True)
class ErasureOutcome:
    erasure_id: str
    ingestion_status: str
    key_destruction_state: str
    ciphertext_unlinked: bool
    execution_result_present: bool


class VerifiedQuarantineEraser:
    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        clock: Clock,
        exec_guard: WriteGuard,
        ingestion_repository: ResultIngestionStateRepository,
        execution_repository: ExecutionRecordRepository,
        projection_repository: ExecutionResultProjectionRepository,
        result_repository: ExecutionResultRepository,
        quarantine_store: EncryptedQuarantineStore,
        key_provider: EncryptionKeyProvider,
        audit_store: AuditStore,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._guard = exec_guard
        self._ingestion = ingestion_repository
        self._executions = execution_repository
        self._projections = projection_repository
        self._results = result_repository
        self._quarantine = quarantine_store
        self._keys = key_provider
        self._audit = audit_store
        self._fault = fault_injector if fault_injector is not None else NoFaultInjector()

    # --- entry point ------------------------------------------------------

    def run(self, *, deletion_intent_id: str) -> ErasureOutcome:
        intent = self._require_intent(deletion_intent_id)
        erasure_id = f"erasure-{deletion_intent_id}"
        has_ingestion = intent.intent_type in ("post_ingestion", "retention_expiry")

        # A terminal projection does not prove that the external key operation or blob
        # unlink survived a crash/rollback.  Replays therefore follow the same
        # reconcile/read-back path and only skip the already-completed state changes.
        terminal_status: str | None = None
        if has_ingestion:
            done = self._ingestion.find_by_execution(intent.execution_id)
            if done is not None and done.status in ("QUARANTINE_ERASED", "SUCCEEDED", "ERASURE_COMPLETED_UNRESOLVED"):
                terminal_status = done.status
        else:
            q = self._quarantine.get_metadata(intent.quarantine_id)
            if q is not None and q.status == "DELETED":
                terminal_status = "QUARANTINE_ERASED"

        # 1. Verify reason-specific evidence.
        if intent.intent_type == "post_ingestion":
            self._verify_publication_trail(intent)
        elif intent.intent_type == "retention_expiry":
            self._verify_retention_expiry(intent)
        else:
            self._verify_incomplete(intent)

        # 2. Claim (created already-consumed) + optional DELETE_PENDING -> ERASURE_CLAIMED.
        claim = self._claim(intent=intent, erasure_id=erasure_id, has_ingestion=has_ingestion)

        # 3. Reconcile-first key destruction (outside any DB transaction).
        destroyed = self._destroy_key(intent=intent, erasure_id=erasure_id)

        # 4. Unlink ciphertext (only after read-back CONFIRMED).
        self._quarantine.unlink_ciphertext(intent.quarantine_id)
        if self._quarantine.ciphertext_handles(intent.quarantine_id):
            raise VerifiedErasureError("ciphertext unlink read-back found remaining blobs")
        self._quarantine.set_status(intent.quarantine_id, "DELETED")

        if terminal_status is not None:
            present = has_ingestion and self._results.get(intent.execution_id) is not None
            return ErasureOutcome(
                erasure_id=erasure_id, ingestion_status=terminal_status,
                key_destruction_state=destroyed.state, ciphertext_unlinked=True,
                execution_result_present=present,
            )

        present = False
        status = "QUARANTINE_ERASED"
        if has_ingestion:
            state = self._require_ingestion_by_execution(intent.execution_id)
            state = self._transition_ingestion(state, "QUARANTINE_ERASED", payload_digest=claim.claim_digest,
                                               event="QUARANTINE_ERASED")
            if intent.intent_type == "post_ingestion":
                present = self._materialize_result(intent.execution_id)
                state = self._transition_ingestion(state, "SUCCEEDED", payload_digest=claim.claim_digest,
                                                   event="INGESTION_SUCCEEDED")
            else:
                # No manifest: keep the provider outcome unresolved, produce no ExecutionResult.
                state = self._transition_ingestion(state, "ERASURE_COMPLETED_UNRESOLVED",
                                                   payload_digest=claim.claim_digest,
                                                   event="ERASURE_COMPLETED_UNRESOLVED")
            status = state.status
        return ErasureOutcome(
            erasure_id=erasure_id, ingestion_status=status, key_destruction_state=destroyed.state,
            ciphertext_unlinked=True, execution_result_present=present,
        )

    def _destroy_key(self, *, intent: QuarantineDeletionIntent, erasure_id: str) -> KeyDestructionResult:
        enc = self._quarantine.encryption_metadata(intent.quarantine_id)
        reconciled = self._keys.reconcile_resource_key_destruction(
            erasure_id=erasure_id, metadata=enc, key_metadata_digest=intent.key_metadata_digest,
            resource_copy_inventory_digest=intent.resource_copy_inventory_digest,
        )
        self._fault.check("after_reconcile")
        if reconciled.state == "NOT_STARTED":
            self._keys.destroy_resource_key(
                erasure_id=erasure_id, metadata=enc, key_metadata_digest=intent.key_metadata_digest,
                resource_copy_inventory_digest=intent.resource_copy_inventory_digest,
            )
            self._fault.check("after_destroy")
            destroyed = self._keys.reconcile_resource_key_destruction(
                erasure_id=erasure_id, metadata=enc, key_metadata_digest=intent.key_metadata_digest,
                resource_copy_inventory_digest=intent.resource_copy_inventory_digest,
            )
        elif reconciled.state == "CONFIRMED":
            destroyed = reconciled
        elif reconciled.state == "UNKNOWN":
            raise VerifiedErasureError("key destruction UNKNOWN; reconcile-only, holding")
        else:
            raise VerifiedErasureError(f"key destruction failed: {reconciled.state}")
        if destroyed.state != "CONFIRMED":
            raise VerifiedErasureError("ciphertext unlink requires a read-back CONFIRMED key destruction")
        return destroyed

    # --- claim ------------------------------------------------------------

    def _claim(
        self, *, intent: QuarantineDeletionIntent, erasure_id: str, has_ingestion: bool
    ) -> QuarantineErasureClaim:
        existing = self._db.occ_get(_CLAIM_NS, erasure_id)
        if existing is not None:
            return QuarantineErasureClaim.model_validate_json(existing[1])
        now = self._clock.now()
        claim = self._build_claim(intent=intent, erasure_id=erasure_id, now=now)
        record = self._require_execution(intent.execution_id)
        state = self._ingestion.find_by_execution(intent.execution_id) if has_ingestion else None
        if has_ingestion:
            if state is None or state.status != "DELETE_PENDING":
                raise VerifiedErasureError("erasure claim requires a DELETE_PENDING ingestion")
            if not is_legal_ingestion_edge(state.status, "ERASURE_CLAIMED"):
                raise VerifiedErasureError("illegal ingestion transition to ERASURE_CLAIMED")
        else:
            quarantine = self._quarantine.get_metadata(intent.quarantine_id)
            if quarantine is None or quarantine.status != "RETENTION_EXPIRED":
                raise VerifiedErasureError("incomplete erasure requires a RETENTION_EXPIRED quarantine")
        op = compute_input_digest({"erase-claim": erasure_id})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="ErasureClaimAggregate", operation_id=f"erase-claim-{erasure_id}",
            input_digest=op, fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                # The claim is created already consumed and stored only as consumed.
                self._db.occ_insert(_CLAIM_NS, erasure_id, 1, _dump(claim))
                self._db.occ_insert(_CLAIM_BY_INTENT_NS, intent.deletion_intent_id, 1,
                                    json.dumps({"erasure_id": erasure_id}, sort_keys=True))
                if has_ingestion and state is not None:
                    claimed = finalize_object_digest(
                        state.model_copy(update={
                            "state_version": state.state_version + 1, "status": "ERASURE_CLAIMED", "updated_at": now,
                        }),
                        digest_field="record_digest", digest_name="result_ingestion_state_digest",
                        digest_service=self._ds,
                    )
                    self._ingestion.update(claimed, expected_version=state.state_version, guard=self._guard)
                    self._executions.transition(self._mirror(record, "ERASURE_CLAIMED"),
                                                expected_version=record.execution_state_version, guard=self._guard)
                self._audit.append_in_txn(mission_id=record.mission_id, event_type="ERASURE_CLAIMED",
                                          payload_digest=claim.claim_digest, actor_id="verified-eraser",
                                          occurred_at_iso=_iso(now), record_type="quarantine_erasure_claim",
                                          record_id=claim.erasure_id, state_version=1,
                                          security_projection_digest=claim.claim_digest)
                if has_ingestion and state is not None:
                    self._db.record_critical_mutation(
                        CriticalMutation(
                            mission_id=record.mission_id,
                            event_type="INGESTION_STATE_CHANGED",
                            actor_id="verified-eraser",
                            occurred_at_iso=_iso(now),
                            record_type="result_ingestion_state",
                            record_id=claimed.ingestion_id,
                            state_version=claimed.state_version,
                            security_projection_digest=claimed.record_digest,
                        )
                    )
                uow.record_result(claim.claim_digest)
        return claim

    def _verify_retention_expiry(self, intent: QuarantineDeletionIntent) -> None:
        quarantine = self._quarantine.get_metadata(intent.quarantine_id)
        if quarantine is None or quarantine.ciphertext_digest != intent.quarantine_ciphertext_digest:
            raise VerifiedErasureError("retention_expiry quarantine binding mismatch")
        if intent.receipt_id is None or intent.final_ingestion_state is None:
            raise VerifiedErasureError("retention_expiry requires receipt + final ingestion evidence")

    def _verify_incomplete(self, intent: QuarantineDeletionIntent) -> None:
        quarantine = self._quarantine.get_metadata(intent.quarantine_id)
        if quarantine is None:
            raise VerifiedErasureError("incomplete_collection_expiry quarantine missing")
        if intent.last_committed_chunk_sequence is None or intent.quarantine_status is None:
            raise VerifiedErasureError("incomplete_collection_expiry requires chunk/status evidence")

    def _build_claim(
        self, *, intent: QuarantineDeletionIntent, erasure_id: str, now: datetime
    ) -> QuarantineErasureClaim:
        model = QuarantineErasureClaim(
            erasure_id=erasure_id, deletion_intent_id=intent.deletion_intent_id, intent_type=intent.intent_type,
            quarantine_id=intent.quarantine_id, encryption_metadata_id=intent.encryption_metadata_id,
            key_metadata_digest=intent.key_metadata_digest,
            resource_copy_inventory_digest=intent.resource_copy_inventory_digest, intent_digest=intent.intent_digest,
            claim_state="consumed", consumption_id=f"consume-{erasure_id}", consumed_at=now, claim_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="claim_digest", digest_name="erasure_claim_digest", digest_service=self._ds
        )

    # --- publication trail verification -----------------------------------

    def _verify_publication_trail(self, intent: QuarantineDeletionIntent) -> None:
        if intent.manifest_id is None:
            raise VerifiedErasureError("post_ingestion intent lacks a manifest binding")
        row = self._db.occ_get(_MANIFEST_NS, intent.manifest_id)
        if row is None:
            raise VerifiedErasureError("committed publication trail (manifest) is missing")
        manifest = SecureIngestionManifest.model_validate_json(row[1])
        self._ds.verify("manifest_digest",
                        {k: v for k, v in manifest.model_dump(mode="python").items() if k != "manifest_digest"},
                        manifest.manifest_digest)
        if manifest.manifest_digest != intent.manifest_digest:
            raise VerifiedErasureError("manifest digest does not match the deletion intent")
        if manifest.quarantine_ciphertext_digest != intent.quarantine_ciphertext_digest:
            raise VerifiedErasureError("manifest quarantine binding does not match the intent")
        projection = self._projections.get(manifest.execution_result_projection_id)
        if projection is None or projection.projection_digest != manifest.execution_result_projection_digest:
            raise VerifiedErasureError("committed projection missing or mismatched")
        # Target quarantine binding / key / copy inventory read-back.
        quarantine = self._quarantine.get_metadata(intent.quarantine_id)
        if quarantine is None or quarantine.ciphertext_digest != intent.quarantine_ciphertext_digest:
            raise VerifiedErasureError("quarantine ciphertext binding mismatch")
        if self._quarantine.encryption_key_metadata_digest(intent.quarantine_id) != intent.key_metadata_digest:
            raise VerifiedErasureError("quarantine key metadata mismatch")

    # --- result rebuild (projection only) ---------------------------------

    def _materialize_result(self, execution_id: str) -> bool:
        projection = self._projections.find_by_execution(execution_id)
        record = self._executions.get(execution_id)
        if projection is None or record is None:
            raise VerifiedErasureError("cannot rebuild result without a committed projection")
        result = self._result_from_projection(record=record, projection=projection)
        with UnitOfWork(self._db):
            self._results.upsert(result, guard=self._guard)
        return self._results.get(execution_id) is not None

    def _result_from_projection(
        self, *, record: ExecutionRecord, projection: ExecutionResultProjection
    ) -> ExecutionResult:
        binding = projection.task_binding
        provider_task_id = binding.provider_task_id if isinstance(binding, ProviderTaskBinding) else None
        if isinstance(binding, LocalResultBinding):
            provider_task_id = None
        return ExecutionResult(
            execution_id=record.execution_id, provider_task_id=provider_task_id,
            adapter_id=record.resolved_adapter_id,
            tool_ref=ToolRef(tool_id=record.tool_ref.tool_id, registry_revision=record.tool_ref.registry_revision),
            policy_decision_id=record.policy_decision_id, secure_ingestion_id=f"ingestion-{record.execution_id}",
            status=_RESULT_STATUS[projection.provider_status],  # type: ignore[arg-type]
            timed_out=projection.timed_out, started_at=projection.started_at, finished_at=projection.finished_at,
            stdout_preview=None, stderr_preview=None, redacted_artifact_ids=(), exit_code=projection.exit_code,
        )

    # --- ingestion transitions --------------------------------------------

    def _transition_ingestion(
        self, state: ResultIngestionStateRecord, status: ResultIngestionStatus, *,
        payload_digest: str, event: str,
    ) -> ResultIngestionStateRecord:
        current = self._ingestion.get(state.ingestion_id)
        assert current is not None
        if current.status == status:
            return current
        if not is_legal_ingestion_edge(current.status, status):
            raise VerifiedErasureError(f"illegal ingestion transition {current.status} -> {status}")
        now = self._clock.now()
        nxt = finalize_object_digest(
            current.model_copy(update={
                "state_version": current.state_version + 1, "status": status, "updated_at": now,
            }),
            digest_field="record_digest", digest_name="result_ingestion_state_digest", digest_service=self._ds,
        )
        record = self._require_execution(current.execution_id)
        mirror = self._mirror(record, status)
        op = compute_input_digest({"erase-transition": state.ingestion_id, "to": status})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="ErasureClaimAggregate",
            operation_id=f"erase-{state.ingestion_id}-{status}", input_digest=op, fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                self._ingestion.update(nxt, expected_version=current.state_version, guard=self._guard)
                self._executions.transition(mirror, expected_version=record.execution_state_version, guard=self._guard)
                self._audit.append_in_txn(mission_id=record.mission_id, event_type=event,
                                          payload_digest=payload_digest, actor_id="verified-eraser",
                                          occurred_at_iso=_iso(now), record_type="result_ingestion_state",
                                          record_id=nxt.ingestion_id, state_version=nxt.state_version,
                                          security_projection_digest=nxt.record_digest)
                uow.record_result(nxt.record_digest)
        return nxt

    def _mirror(self, record: ExecutionRecord, status: ResultIngestionStatus) -> ExecutionRecord:
        return finalize_object_digest(
            record.model_copy(update={
                "result_ingestion_state": status, "execution_state_version": record.execution_state_version + 1,
                "updated_at": self._clock.now(),
            }),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )

    # --- lookups ----------------------------------------------------------

    def _require_intent(self, deletion_intent_id: str) -> QuarantineDeletionIntent:
        row = self._db.occ_get(_INTENT_NS, deletion_intent_id)
        if row is None:
            raise VerifiedErasureError("deletion intent not found")
        intent = QuarantineDeletionIntent.model_validate_json(row[1])
        self._ds.verify("deletion_intent_digest",
                        {k: v for k, v in intent.model_dump(mode="python").items() if k != "intent_digest"},
                        intent.intent_digest)
        return intent

    def _require_ingestion_by_execution(self, execution_id: str) -> ResultIngestionStateRecord:
        state = self._ingestion.find_by_execution(execution_id)
        if state is None:
            raise VerifiedErasureError("ingestion state not found")
        return state

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self._executions.get(execution_id)
        if record is None:
            raise VerifiedErasureError("execution not found")
        return record


def _dump(model: object) -> str:
    assert hasattr(model, "model_dump")
    return json.dumps(model.model_dump(mode="json"), sort_keys=True)  # type: ignore[attr-defined]


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
