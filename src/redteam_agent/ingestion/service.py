"""Repository-bound secure ingestion + atomic durable publication (SystemDesign §33.2).

The only application entry point is ``ingest(ingestion_id)``. The coordinator resolves
the execution / receipt / quarantine / rule / lease / retention from the repository-
bound ingestion id; a caller-minted receipt, quarantine reference or publication object
is not authority. It decrypts the committed quarantine, runs the fixed publication rule
(bounded parse + allowlist + secret detection/redaction), and then commits — in one unit
of work — the redacted artifacts, the DETECTED secret versions, the manifest, the
projection, the INGESTED_DURABLE milestone, the post_ingestion deletion intent, the
DELETE_PENDING transition, the ingestion lease release and the audit event. A same-input
retry is create-or-verify (stable identities under a stable operation id).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.erasure.models import QuarantineDeletionIntent
from redteam_agent.errors import SecureIngestionError
from redteam_agent.execution.models import (
    ExecutionRecord,
    ExecutionResult,
    ExecutionResultProjection,
    LeaseFence,
    LocalResultBinding,
    ProviderTaskBinding,
    RawControlMetadataRecord,
    ResultIngestionStateRecord,
    ResultIngestionStatus,
    ResultTaskBinding,
)
from redteam_agent.execution.records import finalize_object_digest
from redteam_agent.execution.state_machine import is_legal_ingestion_edge
from redteam_agent.ingestion.artifact_store import ArtifactReference, ArtifactStore
from redteam_agent.ingestion.manifest import (
    RedactionMetadata,
    SecretVersionManifestEntry,
    SecureIngestionManifest,
)
from redteam_agent.ingestion.publication_rule import (
    OutputPublicationParser,
    OutputPublicationRule,
    OutputPublicationRuleCatalog,
    ParsedOutput,
)
from redteam_agent.leases.service import LeaseService
from redteam_agent.models.common import ToolRef
from redteam_agent.quarantine.models import RawResultQuarantineMetadata
from redteam_agent.quarantine.store import EncryptedQuarantineStore
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.secrets.store import SecretLifecycleStore
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionResultProjectionRepository,
    ExecutionResultRepository,
    RawControlMetadataRepository,
    ResultIngestionStateRepository,
    ResultTaskBindingRepository,
)
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import ToolRegistryRepository
from redteam_agent.storage.unit_of_work import (
    ApplicationUnitOfWork,
    FaultInjector,
    NoFaultInjector,
    compute_input_digest,
)

_MANIFEST_NS = "secure_ingestion_manifest"
_INTENT_NS = "quarantine_deletion_intent"
_RESULT_STATUS = {"succeeded": "SUCCEEDED", "failed": "FAILED", "cancelled": "CANCELLED"}


@dataclass(frozen=True)
class SecureIngestionOutcome:
    ingestion_id: str
    status: str
    manifest_id: str | None
    deletion_intent_id: str | None
    redacted_artifact_ids: tuple[str, ...]
    detected_secret_version_ids: tuple[str, ...]


class SecureIngestionService:
    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        clock: Clock,
        exec_guard: WriteGuard,
        context_resolver: AuthorizationContextResolver,
        ingestion_repository: ResultIngestionStateRepository,
        execution_repository: ExecutionRecordRepository,
        task_binding_repository: ResultTaskBindingRepository,
        control_metadata_repository: RawControlMetadataRepository,
        projection_repository: ExecutionResultProjectionRepository,
        result_repository: ExecutionResultRepository,
        registry_repository: ToolRegistryRepository,
        registry_revision: int,
        quarantine_store: EncryptedQuarantineStore,
        secret_store: SecretLifecycleStore,
        artifact_store: ArtifactStore,
        rule_catalog: OutputPublicationRuleCatalog,
        parser: OutputPublicationParser,
        lease_service: LeaseService,
        audit_store: AuditStore,
        owner_id: str = "ingestion-worker-1",
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._guard = exec_guard
        self._resolver = context_resolver
        self._ingestion = ingestion_repository
        self._executions = execution_repository
        self._bindings = task_binding_repository
        self._control = control_metadata_repository
        self._projections = projection_repository
        self._results = result_repository
        self._registry_repo = registry_repository
        self._registry_revision = registry_revision
        self._quarantine = quarantine_store
        self._secrets = secret_store
        self._artifacts = artifact_store
        self._rules = rule_catalog
        self._parser = parser
        self._leases = lease_service
        self._audit = audit_store
        self._owner_id = owner_id
        self._fault = fault_injector if fault_injector is not None else NoFaultInjector()

    # --- entry point ------------------------------------------------------

    def ingest(self, *, ingestion_id: str) -> SecureIngestionOutcome:
        state = self._require_state(ingestion_id)
        if state.status in ("DELETE_PENDING", "ERASURE_CLAIMED", "QUARANTINE_ERASED", "SUCCEEDED"):
            return self._terminal_outcome(state)
        if state.status == "FAILED":
            raise SecureIngestionError("FAILED ingestion must be retried before ingest()")
        if state.status not in ("PENDING", "INGESTING"):
            raise SecureIngestionError(f"cannot ingest from state {state.status}")

        record = self._require_execution(state.execution_id)
        mission = self._resolver.resolve(record.mission_id, now=self._clock.now()).mission
        now = self._clock.now()
        quarantine = self._quarantine.get_metadata(state.quarantine_id or "")
        if quarantine is None or quarantine.status != "COMMITTED":
            raise SecureIngestionError("secure ingestion requires a committed quarantine")
        if now >= quarantine.retention_until or now >= mission.evidence_retention_until:
            raise SecureIngestionError("quarantine retention passed; ingestion must go to the expiry path")

        if state.status == "PENDING":
            state = self._advance_ingestion(state, "INGESTING", attempt_count=state.attempt_count + 1)

        lease = self._leases.acquire_ingestion_lease(
            ingestion_id=ingestion_id, execution_id=record.execution_id,
            receipt_digest=state.receipt_digest or "", quarantine_digest=quarantine.ciphertext_digest,
            evidence_retention_until=quarantine.retention_until, owner_id=self._owner_id,
            expected_ingestion_state_version=state.state_version,
            caps=(mission.evidence_retention_until,),
        )
        return self._publish(state=state, record=record, quarantine=quarantine, lease_fence=lease.fence,
                             lease_id=lease.lease_id)

    # --- publication ------------------------------------------------------

    def _publish(
        self, *, state: ResultIngestionStateRecord, record: ExecutionRecord,
        quarantine: RawResultQuarantineMetadata, lease_fence: LeaseFence, lease_id: str,
    ) -> SecureIngestionOutcome:
        rule = self._resolve_rule(record)
        binding = self._bindings.find_by_execution(record.execution_id)
        control = self._control.find_by_execution(record.execution_id)
        if binding is None or control is None:
            raise SecureIngestionError("missing task binding or control metadata for ingestion")

        reader = self._quarantine.open_reader(quarantine.quarantine_id)
        try:
            reader.verify_ciphertext_digest()
            stdout = b"".join(reader.iter_stream("stdout"))
        finally:
            reader.close()
        parsed = self._parser.parse(rule, stdout)

        # Build redacted artifacts + prepared secret detections (encryption happens here,
        # DB writes happen inside the publication unit of work).
        artifacts: list[tuple[ArtifactReference, str, bytes]] = []
        for index, published in enumerate(parsed.redacted_records):
            body = json.dumps(published, sort_keys=True).encode("utf-8")
            ref, handle, blob = self._artifacts.build_redacted(
                artifact_id=f"artifact-{state.ingestion_id}-{index}", mission_id=record.mission_id, body=body,
                created_at=self._clock.now(), retention_until=quarantine.retention_until,
            )
            artifacts.append((ref, handle, blob))
        prepared_secrets = []
        secret_entries: list[SecretVersionManifestEntry] = []
        for index, detected in enumerate(parsed.detected_secrets):
            prepared = self._secrets.prepare_detect(
                secret_id=f"secret-{state.ingestion_id}-{index}", mission_id=record.mission_id,
                credential_type=detected.credential_type, associated_principal_ref=None, value=detected.value,
                actor_id="secure-ingestion", actor_role="ingestion",
                evidence_digest=self._ds.compute("redaction_metadata_digest", {"pointer": detected.pointer}),
                reason_code="detected_by_publication_rule",
            )
            prepared_secrets.append(prepared)
            secret_entries.append(SecretVersionManifestEntry(
                secret_id=prepared.record.secret_id, secret_version_id=prepared.record.secret_version_id,
                metadata_digest=prepared.record.metadata_digest,
                lifecycle_head_digest=self._secrets.lifecycle_head_digest(prepared.event),
            ))

        redaction = self._build_redaction(rule=rule, parsed=parsed)
        projection = self._build_projection(record=record, binding=binding, control=control, redaction=redaction)
        manifest = self._build_manifest(
            state=state, record=record, quarantine=quarantine, rule=rule, binding=binding,
            redacted=tuple(ref for ref, _h, _b in artifacts), secret_entries=tuple(secret_entries),
            redaction=redaction, projection=projection,
        )
        intent = self._build_post_ingestion_intent(
            state=state, record=record, quarantine=quarantine, binding=binding, manifest=manifest,
        )
        durable = finalize_object_digest(
            state.model_copy(update={
                "state_version": state.state_version + 1, "status": "DELETE_PENDING",
                "manifest_id": manifest.manifest_id, "manifest_digest": manifest.manifest_digest,
                "ingested_durable_at": self._clock.now(), "updated_at": self._clock.now(),
            }),
            digest_field="record_digest", digest_name="result_ingestion_state_digest", digest_service=self._ds,
        )
        if not is_legal_ingestion_edge(state.status, "DELETE_PENDING"):
            raise SecureIngestionError("illegal ingestion transition to DELETE_PENDING")
        result = self._build_result(record=record, binding=binding, control=control)
        mirror = self._mirror_execution(record, "DELETE_PENDING")

        op = compute_input_digest({"publish": state.ingestion_id, "manifest": manifest.manifest_digest})
        with ApplicationUnitOfWork(
            self._db, aggregate_name="IngestionPublicationAggregate", operation_id=f"publish-{state.ingestion_id}",
            input_digest=op, fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                # Full lease predicate under the publication transaction.
                self._leases.validate_ingestion_lease(
                    ingestion_id=state.ingestion_id, owner_id=self._owner_id, lease_id=lease_id, fence=lease_fence,
                    quarantine_digest=quarantine.ciphertext_digest,
                    expected_ingestion_state_version=state.state_version,
                )
                for ref, handle, blob in artifacts:
                    self._artifacts.persist_in_txn(ref, blob_handle=handle, blob_bytes=blob)
                for prepared in prepared_secrets:
                    self._secrets.apply_detect_in_txn(prepared)
                self._db.occ_insert_idempotent(_MANIFEST_NS, manifest.manifest_id, 1, _dump(manifest))
                self._db.occ_insert_idempotent(_INTENT_NS, intent.deletion_intent_id, 1, _dump(intent))
                self._projections.create(projection, guard=self._guard)
                self._results.upsert(result, guard=self._guard)
                self._ingestion.update(durable, expected_version=state.state_version, guard=self._guard)
                self._executions.transition(mirror, expected_version=record.execution_state_version, guard=self._guard)
                self._leases.release_ingestion_lease(ingestion_id=state.ingestion_id, owner_id=self._owner_id)
                self._audit.append_in_txn(
                    mission_id=record.mission_id, event_type="INGESTION_PUBLISHED",
                    payload_digest=manifest.manifest_digest, actor_id="secure-ingestion",
                    occurred_at_iso=_iso(self._clock.now()),
                    record_type="secure_ingestion_manifest",
                    record_id=manifest.manifest_id,
                    state_version=durable.state_version,
                    security_projection_digest=manifest.manifest_digest,
                )
                self._db.record_critical_mutation(
                    CriticalMutation(
                        mission_id=record.mission_id,
                        event_type="INGESTION_STATE_CHANGED",
                        actor_id="secure-ingestion",
                        occurred_at_iso=_iso(self._clock.now()),
                        record_type="result_ingestion_state",
                        record_id=durable.ingestion_id,
                        state_version=durable.state_version,
                        security_projection_digest=durable.record_digest,
                    )
                )
                uow.record_result(manifest.manifest_digest)
        self._read_back_publication(manifest=manifest, projection=projection, intent=intent)
        return SecureIngestionOutcome(
            ingestion_id=state.ingestion_id, status="DELETE_PENDING", manifest_id=manifest.manifest_id,
            deletion_intent_id=intent.deletion_intent_id,
            redacted_artifact_ids=tuple(ref.artifact_id for ref, _h, _b in artifacts),
            detected_secret_version_ids=tuple(e.secret_version_id for e in secret_entries),
        )

    def _read_back_publication(
        self, *, manifest: SecureIngestionManifest, projection: ExecutionResultProjection,
        intent: QuarantineDeletionIntent,
    ) -> None:
        stored_manifest = self._db.occ_get(_MANIFEST_NS, manifest.manifest_id)
        stored_intent = self._db.occ_get(_INTENT_NS, intent.deletion_intent_id)
        stored_projection = self._projections.get(projection.projection_id)
        if stored_manifest is None or stored_intent is None or stored_projection is None:
            raise SecureIngestionError("publication read-back failed (partial commit)")
        for artifact in manifest.redacted_artifacts:
            if self._artifacts.get(artifact.artifact_id) is None:
                raise SecureIngestionError("published artifact missing on read-back")
        for secret_entry in manifest.detected_secrets:
            if self._secrets.get_version(secret_entry.secret_version_id) is None:
                raise SecureIngestionError("published secret version missing on read-back")

    # --- retry / fail -----------------------------------------------------

    def fail(self, *, ingestion_id: str, reason: str) -> SecureIngestionOutcome:
        state = self._require_state(ingestion_id)
        if state.status != "INGESTING":
            raise SecureIngestionError("only an INGESTING ingestion can fail")
        failed = self._advance_ingestion(state, "FAILED", attempt_count=state.attempt_count)
        return self._terminal_outcome(failed)

    # --- read a published manifest / intent -------------------------------

    def get_manifest(self, manifest_id: str) -> SecureIngestionManifest | None:
        row = self._db.occ_get(_MANIFEST_NS, manifest_id)
        return None if row is None else SecureIngestionManifest.model_validate_json(row[1])

    # --- builders ---------------------------------------------------------

    def _resolve_rule(self, record: ExecutionRecord) -> OutputPublicationRule:
        registry = self._registry_repo.get(self._registry_revision)
        if registry is None:
            raise SecureIngestionError("tool registry not found")
        tool = registry.by_ref(record.tool_ref.tool_id, record.tool_ref.registry_revision)
        if tool is None:
            raise SecureIngestionError("tool not found for ingestion")
        return self._rules.get(tool.output_publication_rule_id)

    def _build_redaction(self, *, rule: OutputPublicationRule, parsed: ParsedOutput) -> RedactionMetadata:
        fields = {
            "rule_version": rule.rule_revision, "redaction_count": parsed.redaction_count,
            "secret_detection_count": len(parsed.detected_secrets), "publication_rule_id": rule.rule_id,
            "publication_rule_digest": rule.rule_digest, "omitted_reason_codes": parsed.omitted_reason_codes,
        }
        return RedactionMetadata(
            **fields,  # type: ignore[arg-type]
            redaction_metadata_digest=self._ds.compute("redaction_metadata_digest", fields),
        )

    def _build_projection(
        self, *, record: ExecutionRecord, binding: ResultTaskBinding, control: RawControlMetadataRecord,
        redaction: RedactionMetadata,
    ) -> ExecutionResultProjection:
        model = ExecutionResultProjection(
            projection_id=f"projection-{record.execution_id}", projection_digest="pending",
            execution_id=record.execution_id, task_binding=binding, receipt_id=control.receipt_id,
            receipt_digest=control.receipt_digest, provider_status=control.provider_status,
            exit_code=control.exit_code, timed_out=control.timed_out, started_at=control.provider_started_at,
            finished_at=control.provider_finished_at, stdout_preview_artifact_id=None,
            stderr_preview_artifact_id=None, redaction_metadata_digest=redaction.redaction_metadata_digest,
        )
        return finalize_object_digest(
            model, digest_field="projection_digest", digest_name="execution_result_projection_digest",
            digest_service=self._ds,
        )

    def _build_manifest(
        self, *, state: ResultIngestionStateRecord, record: ExecutionRecord,
        quarantine: RawResultQuarantineMetadata, rule: OutputPublicationRule,
        binding: ResultTaskBinding, redacted: tuple[ArtifactReference, ...],
        secret_entries: tuple[SecretVersionManifestEntry, ...], redaction: RedactionMetadata,
        projection: ExecutionResultProjection,
    ) -> SecureIngestionManifest:
        model = SecureIngestionManifest(
            manifest_id=f"manifest-{state.ingestion_id}", ingestion_id=state.ingestion_id,
            execution_id=record.execution_id, receipt_id=state.receipt_id or "",
            receipt_digest=state.receipt_digest or "", quarantine_id=quarantine.quarantine_id,
            quarantine_ciphertext_digest=quarantine.ciphertext_digest, rule_version=rule.rule_revision,
            output_publication_rule_id=rule.rule_id, output_publication_rule_digest=rule.rule_digest,
            result_task_binding_digest=binding.binding_digest, redacted_artifacts=redacted,
            encrypted_raw_artifacts=(), detected_secrets=secret_entries,
            redaction_metadata_digest=redaction.redaction_metadata_digest,
            execution_result_projection_id=projection.projection_id,
            execution_result_projection_digest=projection.projection_digest, created_at=self._clock.now(),
            manifest_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="manifest_digest", digest_name="manifest_digest", digest_service=self._ds
        )

    def _build_post_ingestion_intent(
        self, *, state: ResultIngestionStateRecord, record: ExecutionRecord,
        quarantine: RawResultQuarantineMetadata, binding: ResultTaskBinding, manifest: SecureIngestionManifest,
    ) -> QuarantineDeletionIntent:
        model = QuarantineDeletionIntent(
            deletion_intent_id=f"delintent-post-{state.ingestion_id}", intent_type="post_ingestion",
            reason="POST_INGESTION", quarantine_id=quarantine.quarantine_id, execution_id=record.execution_id,
            ingestion_id=state.ingestion_id, encryption_metadata_id=quarantine.encryption_metadata_id,
            key_metadata_digest=self._quarantine_key_digest(quarantine.quarantine_id),
            resource_copy_inventory_digest=self._copy_inventory_digest(quarantine.quarantine_id),
            quarantine_ciphertext_digest=quarantine.ciphertext_digest,
            result_task_binding_digest=binding.binding_digest, retention_deadline=quarantine.retention_until,
            manifest_id=manifest.manifest_id, manifest_digest=manifest.manifest_digest, receipt_id=None,
            receipt_digest=None, final_ingestion_state=None, last_committed_chunk_sequence=None,
            quarantine_status=None, created_at=self._clock.now(), intent_digest="pending",
        )
        return finalize_object_digest(
            model, digest_field="intent_digest", digest_name="deletion_intent_digest", digest_service=self._ds
        )

    def _quarantine_key_digest(self, quarantine_id: str) -> str:
        return self._quarantine.encryption_key_metadata_digest(quarantine_id)

    def _copy_inventory_digest(self, quarantine_id: str) -> str:
        return self._ds.compute("copy_inventory_digest", {"quarantine_id": quarantine_id, "class": "encrypted_blob"})

    def _build_result(
        self, *, record: ExecutionRecord, binding: ResultTaskBinding, control: RawControlMetadataRecord
    ) -> ExecutionResult:
        provider_task_id = binding.provider_task_id if isinstance(binding, ProviderTaskBinding) else None
        if isinstance(binding, LocalResultBinding):
            provider_task_id = None
        return ExecutionResult(
            execution_id=record.execution_id, provider_task_id=provider_task_id,
            adapter_id=record.resolved_adapter_id,
            tool_ref=ToolRef(tool_id=record.tool_ref.tool_id, registry_revision=record.tool_ref.registry_revision),
            policy_decision_id=record.policy_decision_id, secure_ingestion_id=f"ingestion-{record.execution_id}",
            status=_RESULT_STATUS[control.provider_status],  # type: ignore[arg-type]
            timed_out=control.timed_out, started_at=control.provider_started_at,
            finished_at=control.provider_finished_at, stdout_preview=None, stderr_preview=None,
            redacted_artifact_ids=(), exit_code=control.exit_code,
        )

    def _mirror_execution(self, record: ExecutionRecord, status: ResultIngestionStatus) -> ExecutionRecord:
        return finalize_object_digest(
            record.model_copy(update={
                "result_ingestion_state": status, "execution_state_version": record.execution_state_version + 1,
                "updated_at": self._clock.now(),
            }),
            digest_field="record_digest", digest_name="execution_record_digest", digest_service=self._ds,
        )

    def _advance_ingestion(
        self, state: ResultIngestionStateRecord, status: ResultIngestionStatus, *, attempt_count: int
    ) -> ResultIngestionStateRecord:
        if not is_legal_ingestion_edge(state.status, status):
            raise SecureIngestionError(f"illegal ingestion transition {state.status} -> {status}")
        nxt = finalize_object_digest(
            state.model_copy(update={
                "state_version": state.state_version + 1, "status": status, "attempt_count": attempt_count,
                "updated_at": self._clock.now(),
            }),
            digest_field="record_digest", digest_name="result_ingestion_state_digest", digest_service=self._ds,
        )
        with UnitOfWork(self._db):
            self._ingestion.update(nxt, expected_version=state.state_version, guard=self._guard)
            record = self._require_execution(state.execution_id)
            self._db.record_critical_mutation(
                CriticalMutation(
                    mission_id=record.mission_id,
                    event_type="INGESTION_STATE_CHANGED",
                    actor_id="secure-ingestion",
                    occurred_at_iso=_iso(nxt.updated_at),
                    record_type="result_ingestion_state",
                    record_id=nxt.ingestion_id,
                    state_version=nxt.state_version,
                    security_projection_digest=nxt.record_digest,
                )
            )
        return nxt

    def _terminal_outcome(self, state: ResultIngestionStateRecord) -> SecureIngestionOutcome:
        return SecureIngestionOutcome(
            ingestion_id=state.ingestion_id, status=state.status, manifest_id=state.manifest_id,
            deletion_intent_id=f"delintent-post-{state.ingestion_id}" if state.manifest_id else None,
            redacted_artifact_ids=(), detected_secret_version_ids=(),
        )

    def _require_state(self, ingestion_id: str) -> ResultIngestionStateRecord:
        state = self._ingestion.get(ingestion_id)
        if state is None:
            raise SecureIngestionError("ingestion state not found")
        return state

    def _require_execution(self, execution_id: str) -> ExecutionRecord:
        record = self._executions.get(execution_id)
        if record is None:
            raise SecureIngestionError("execution not found")
        return record


def _dump(model: object) -> str:
    assert hasattr(model, "model_dump")
    return json.dumps(model.model_dump(mode="json"), sort_keys=True)  # type: ignore[attr-defined]


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
