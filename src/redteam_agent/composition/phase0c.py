"""Phase 0C test/local composition root (data security / audit).

Extends the Phase 0B execution-safety kernel with the production-shaped data-security
layer wired to real AES-256-GCM envelope encryption and the deterministic in-memory TPM
witness double: envelope key provider, encrypted quarantine store, secret lifecycle,
typed leases + deployment epoch, authenticated generation coordinator + audit chain,
secure ingestion, verified eraser and the local retention scheduler. There is still no
real adapter and nothing is dispatched externally. The production composition root
(``composition/production.py``) is what forbids these in-memory doubles.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from redteam_agent.audit.critical_witness import CriticalWitnessBarrier
from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.generation_store import GenerationRecordStore, InMemoryRecordAuthenticationKey
from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.audit.models import GenerationWitnessPolicy, SecurityStateBinding
from redteam_agent.audit.nv_witness import InMemoryNvExtendWitness
from redteam_agent.audit.wrapped_key_state import WrappedKeyStateService
from redteam_agent.canonical.digest_catalog import CATALOG_REVISION
from redteam_agent.composition.execution_testing import Phase0BKernel, build_phase0b_kernel
from redteam_agent.crypto.key_provider import InMemoryEnvelopeKeyProvider
from redteam_agent.crypto.models import EnvelopeCiphertext
from redteam_agent.erasure.models import QuarantineDeletionIntent, QuarantineErasureClaim
from redteam_agent.erasure.service import VerifiedQuarantineEraser
from redteam_agent.execution.adapter import ExecutionAdapter
from redteam_agent.execution.collection import ResultCollectionCoordinator
from redteam_agent.execution.ingestion import ResultIngestionCoordinator
from redteam_agent.execution.secret_source import TrustedSecretSource
from redteam_agent.ingestion.artifact_store import ArtifactReference, ArtifactStore
from redteam_agent.ingestion.manifest import SecureIngestionManifest
from redteam_agent.ingestion.publication_rule import OutputPublicationParser, OutputPublicationRuleCatalog
from redteam_agent.ingestion.service import SecureIngestionService
from redteam_agent.knowledge.models import KnowledgeSecurityHead
from redteam_agent.leases.models import LeasePolicy
from redteam_agent.leases.service import DeploymentEpochService, LeaseService
from redteam_agent.quarantine.blob_store import InMemoryQuarantineBlobStore
from redteam_agent.quarantine.collection import QuarantineCollectionService
from redteam_agent.quarantine.models import RawResultQuarantineMetadata
from redteam_agent.quarantine.store import EncryptedQuarantineStore
from redteam_agent.retention.scheduler import LocalRetentionScheduler
from redteam_agent.runtime.clock import ClockIntegrityGuard, ManualMonotonicClock, MonotonicClock
from redteam_agent.secrets.migration import LegacySecretMigrator
from redteam_agent.secrets.models import SecretVersionRecord
from redteam_agent.secrets.store import SecretLifecycleStore
from redteam_agent.storage.database import CriticalMutation
from redteam_agent.storage.guard import WriteGuard

DEFAULT_QUARANTINE_RETENTION_SECONDS = 14 * 24 * 3600


@dataclass(frozen=True)
class _SecureCollectionStart:
    collection_id: str
    execution_id: str
    sink_id: str


class _SecureCollectionFacade:
    """Compatibility surface that converges every Phase 0C caller on encrypted collection."""

    def __init__(
        self, service: QuarantineCollectionService, phase0b: Phase0BKernel,
        adapters: dict[str, ExecutionAdapter],
    ) -> None:
        self._service = service
        self._phase0b = phase0b
        self._adapters = adapters

    def start_collection(
        self, *, execution_id: str, recovery_authority_id: str | None = None,
    ) -> _SecureCollectionStart:
        record = self._phase0b.execution_repository.get(execution_id)
        binding = self._phase0b.task_binding_repository.find_by_execution(execution_id)
        if record is None or binding is None or record.resolved_adapter_id not in self._adapters:
            raise RuntimeError("secure collection prerequisites are unavailable")
        self._service.validate_collection_request(
            execution_id=execution_id, recovery_authority_id=recovery_authority_id
        )
        return _SecureCollectionStart(
            collection_id=f"collection-{execution_id}", execution_id=execution_id,
            sink_id=f"sink-{execution_id}",
        )

    def collect(self, *, execution_id: str, recovery_authority_id: str | None = None) -> object:
        self.start_collection(execution_id=execution_id, recovery_authority_id=recovery_authority_id)
        record = self._phase0b.execution_repository.get(execution_id)
        assert record is not None
        return self._service.collect_from_adapter(
            execution_id=execution_id, adapter=self._adapters[record.resolved_adapter_id],
            recovery_authority_id=recovery_authority_id,
        )

    def prepare_local_collection(self, *, execution_id: str, binding: object) -> tuple[object, object]:
        return self._service.prepare_local_collection(
            execution_id=execution_id, binding=binding  # type: ignore[arg-type]
        )

    def finalize_local_collection(self, *, execution_id: str, sink: object, control: object) -> object:
        return self._service.finalize_local_collection(
            execution_id=execution_id, sink=sink, control=control  # type: ignore[arg-type]
        )

    def abandon(self, *, execution_id: str, reason: str) -> object:
        del execution_id, reason
        raise RuntimeError("Phase 0C collection expiry must use the retention scheduler")


class _SecureIngestionFacade:
    def __init__(self, service: SecureIngestionService, phase0b: Phase0BKernel) -> None:
        self._service = service
        self._phase0b = phase0b

    def ingest(self, *, execution_id: str) -> object:
        state = self._phase0b.ingestion_repository.find_by_execution(execution_id)
        if state is None:
            raise RuntimeError("secure ingestion state is unavailable")
        return self._service.ingest(ingestion_id=state.ingestion_id)

    def retry(self, *, execution_id: str) -> object:
        return self.ingest(execution_id=execution_id)


class _SecretLifecycleSource:
    def __init__(self, store: SecretLifecycleStore) -> None:
        self._store = store

    def open_version(self, secret_version_id: str) -> bytearray:
        return self._store._open_version_for_executor(secret_version_id)


class QuarantineMetadataView:
    """Read-only quarantine metadata exposed by the composition root."""

    def __init__(self, store: EncryptedQuarantineStore) -> None:
        self._store = store

    def get(self, quarantine_id: str) -> RawResultQuarantineMetadata | None:
        return self._store.get_metadata(quarantine_id)

    def ciphertext_handles(self, quarantine_id: str) -> tuple[str, ...]:
        return self._store.ciphertext_handles(quarantine_id)


class SecretMetadataView:
    """Read-only secret lifecycle metadata exposed by the composition root."""

    def __init__(self, store: SecretLifecycleStore) -> None:
        self._store = store

    def get(self, secret_version_id: str) -> SecretVersionRecord | None:
        return self._store.get_version(secret_version_id)

    def current_state(self, secret_version_id: str) -> str | None:
        return self._store.current_state(secret_version_id)


class ArtifactMetadataView:
    """Read-only artifact metadata exposed by the composition root."""

    def __init__(self, store: ArtifactStore) -> None:
        self._store = store

    def get(self, artifact_id: str) -> ArtifactReference | None:
        return self._store.get(artifact_id)


@dataclass
class Phase0CKernel:
    phase0b: Phase0BKernel
    monotonic_clock: MonotonicClock
    clock_guard: ClockIntegrityGuard
    data_guard: WriteGuard
    key_provider_identity: str
    nv_witness: InMemoryNvExtendWitness
    generation_coordinator: AuthenticatedGenerationCoordinator
    generation_store: GenerationRecordStore
    audit_store: AuditStore
    critical_witness_barrier: CriticalWitnessBarrier
    wrapped_key_state_service: WrappedKeyStateService
    wrapped_state_blobs: InMemoryQuarantineBlobStore
    epoch_service: DeploymentEpochService
    lease_service: LeaseService
    quarantine_metadata: QuarantineMetadataView
    secret_metadata: SecretMetadataView
    artifact_metadata: ArtifactMetadataView
    rule_catalog: OutputPublicationRuleCatalog
    parser: OutputPublicationParser
    collection_service: QuarantineCollectionService
    ingestion_service: SecureIngestionService
    eraser: VerifiedQuarantineEraser
    retention_scheduler: LocalRetentionScheduler
    legacy_migrator: LegacySecretMigrator

    @property
    def deployment_epoch(self) -> int:
        mirror = self.epoch_service.current()
        assert mirror is not None
        return mirror.deployment_epoch


def build_phase0c_kernel(
    *,
    phase0b: Phase0BKernel | None = None,
    monotonic_clock: MonotonicClock | None = None,
    result_delivery_mode: str = "provider_task",
) -> Phase0CKernel:
    kernel = phase0b if phase0b is not None else build_phase0b_kernel(result_delivery_mode=result_delivery_mode)
    db = kernel.phase0a.database
    ds = kernel.phase0a.digest_service
    clock = monotonic_clock if monotonic_clock is not None else ManualMonotonicClock(kernel.phase0a.clock.now())
    guard = WriteGuard()
    kernel.phase0a.mission_manager.bind_trust_recovery_guard(guard)
    clock_guard = ClockIntegrityGuard(clock)

    key_provider = InMemoryEnvelopeKeyProvider(digest_service=ds)
    quarantine_blobs = InMemoryQuarantineBlobStore()
    secret_blobs = InMemoryQuarantineBlobStore()
    artifact_blobs = InMemoryQuarantineBlobStore()
    wrapped_state_blobs = InMemoryQuarantineBlobStore()

    witness = InMemoryNvExtendWitness(digest_service=ds)
    auth_key = InMemoryRecordAuthenticationKey()
    generation_store = GenerationRecordStore(db, ds, auth_key)
    coordinator = AuthenticatedGenerationCoordinator(
        database=db, witness=witness, record_store=generation_store, digest_service=ds,
        digest_catalog_revision=CATALOG_REVISION,
    )
    audit_store = AuditStore(db, ds)
    epoch_service = DeploymentEpochService(db, ds, guard)
    lease_service = LeaseService(
        database=db, digest_service=ds, clock_guard=clock_guard, epoch_service=epoch_service,
        anchor_verifier=lambda: epoch_service.verify_against_tpm(coordinator),
        write_guard=guard, policy=LeasePolicy(),
    )
    quarantine_store = EncryptedQuarantineStore(
        database=db, blob_store=quarantine_blobs, key_provider=key_provider, digest_service=ds, clock=clock,
    )
    secret_store = SecretLifecycleStore(
        database=db, digest_service=ds, clock=clock, audit_store=audit_store, key_provider=key_provider,
        secret_blob_store=secret_blobs,
    )
    artifact_store = ArtifactStore(
        database=db, blob_store=artifact_blobs, key_provider=key_provider, digest_service=ds,
    )
    rule_catalog = OutputPublicationRuleCatalog(ds)
    rule_catalog.register(
        rule_id="pub-1", parser_id="json_object_v1",
        public_field_types={"host": "string", "status": "string", "port": "integer"},
        secret_field_pointers=("/credential",),
    )
    parser = OutputPublicationParser()

    collection_service = QuarantineCollectionService(
        database=db, digest_service=ds, clock=clock, exec_guard=kernel.execution_guard,
        context_resolver=kernel.phase0a.context_resolver, execution_repository=kernel.execution_repository,
        task_binding_repository=kernel.task_binding_repository,
        control_metadata_repository=kernel.control_metadata_repository,
        ingestion_repository=kernel.ingestion_repository,
        recovery_repository=kernel.recovery_authority_repository,
        quarantine_store=quarantine_store,
        lease_service=lease_service, audit_store=audit_store,
        quarantine_retention_seconds=DEFAULT_QUARANTINE_RETENTION_SECONDS,
    )
    ingestion_service = SecureIngestionService(
        database=db, digest_service=ds, clock=clock, exec_guard=kernel.execution_guard,
        context_resolver=kernel.phase0a.context_resolver, ingestion_repository=kernel.ingestion_repository,
        execution_repository=kernel.execution_repository, task_binding_repository=kernel.task_binding_repository,
        control_metadata_repository=kernel.control_metadata_repository,
        projection_repository=kernel.projection_repository, result_repository=kernel.result_repository,
        registry_repository=kernel.phase0a.registry_repository, registry_revision=kernel.phase0a.registry_revision,
        quarantine_store=quarantine_store, secret_store=secret_store, artifact_store=artifact_store,
        rule_catalog=rule_catalog, parser=parser, lease_service=lease_service, audit_store=audit_store,
    )
    eraser = VerifiedQuarantineEraser(
        database=db, digest_service=ds, clock=clock, exec_guard=kernel.execution_guard,
        ingestion_repository=kernel.ingestion_repository, execution_repository=kernel.execution_repository,
        projection_repository=kernel.projection_repository, result_repository=kernel.result_repository,
        quarantine_store=quarantine_store, key_provider=key_provider, audit_store=audit_store,
    )
    retention_scheduler = LocalRetentionScheduler(
        database=db, digest_service=ds, clock_guard=clock_guard, epoch_service=epoch_service,
        lease_service=lease_service, ingestion_repository=kernel.ingestion_repository,
        execution_repository=kernel.execution_repository, quarantine_store=quarantine_store,
        audit_store=audit_store, exec_guard=kernel.execution_guard,
    )
    legacy_migrator = LegacySecretMigrator(db, ds)

    # Bootstrap the anchors and the deployment-epoch mirror (a mini production bootstrap).
    coordinator.genesis(
        "audit_head", initial_state_digest=ds.compute("security_projection_digest", {"genesis": "audit_head"}),
        initial_content='{"heads": []}',
    )
    coordinator.genesis(
        "wrapped_key_state",
        initial_state_digest=ds.compute("security_projection_digest", {"genesis": "wrapped_key_state"}),
        initial_content='{"providers": []}',
    )
    critical_record_types = frozenset({
        "mission_authorization", "dispatch_claim", "cancel_attempt", "mission_execution_budget",
        "result_task_binding", "result_ingestion_state", "secure_ingestion_manifest",
        "secret_lifecycle_head", "quarantine_deletion_intent", "quarantine_erasure_claim",
        "knowledge_evidence_head", "audit_chain_head", "unresolved_item",
    })
    policy_fields = {
        "policy_revision": "generation-witness-policy-v5",
        "max_unwitnessed_events": 256,
        "max_unwitnessed_seconds": 300,
        "force_event_types": frozenset({
            "MISSION_AUTHORIZATION_CHANGED", "DISPATCH_CLAIM_CHANGED",
            "CANCEL_ATTEMPT_CHANGED", "MISSION_BUDGET_CHANGED", "RESULT_TASK_BOUND",
            "COLLECTION_COMMITTED", "INGESTION_STATE_CHANGED", "INGESTION_PUBLISHED",
            "SECRET_DETECTED", "SECRET_CONFIRMED",
            "SECRET_REVOKED", "SECRET_SUPERSEDED", "EVIDENCE_RETENTION_EXPIRED",
            "INCOMPLETE_COLLECTION_EXPIRED",
            "ERASURE_CLAIMED", "QUARANTINE_ERASED", "INGESTION_SUCCEEDED",
            "ERASURE_COMPLETED_UNRESOLVED",
            "KNOWLEDGE_EVIDENCE_CHANGED",
        }),
        "critical_state_catalog_revision": "critical-state-catalog-v1",
        "critical_state_catalog_digest": ds.compute("security_projection_digest", {
            "catalog_revision": "critical-state-catalog-v1",
            "record_types": tuple(sorted(critical_record_types)),
        }),
    }
    witness_policy = GenerationWitnessPolicy(
        **policy_fields,  # type: ignore[arg-type]
        policy_digest=ds.compute("generation_witness_policy_digest", policy_fields),
    )

    def current_binding(binding: SecurityStateBinding) -> tuple[int, str] | None:
        """Rebuild a binding from its owner record without a parallel state table."""
        if binding.record_type == "mission_authorization":
            return kernel.phase0a.mission_manager.current_security_projection(binding.record_id)
        if binding.record_type == "dispatch_claim":
            claim_record = kernel.claim_repository.get(binding.record_id)
            return None if claim_record is None else (
                claim_record.execution_state_version,
                claim_record.record_digest,
            )
        if binding.record_type == "cancel_attempt":
            cancel_record = kernel.cancel_attempt_repository.get(binding.record_id)
            return None if cancel_record is None else (
                cancel_record.post_transition_execution_state_version,
                cancel_record.record_digest,
            )
        if binding.record_type == "mission_execution_budget":
            mission_id, separator, revision = binding.record_id.rpartition("/")
            if not separator or not revision.isdecimal():
                return None
            budget_record = kernel.budget_repository.get(mission_id, int(revision))
            return None if budget_record is None else (
                budget_record.budget_version,
                budget_record.record_digest,
            )
        if binding.record_type == "result_task_binding":
            task_binding = kernel.task_binding_repository.get(binding.record_id)
            if task_binding is None or task_binding.binding_digest != binding.security_projection_digest:
                return None
            return binding.state_version, task_binding.binding_digest
        if binding.record_type == "result_ingestion_state":
            ingestion_record = kernel.ingestion_repository.get(binding.record_id)
            return None if ingestion_record is None else (
                ingestion_record.state_version,
                ingestion_record.record_digest,
            )
        if binding.record_type == "secure_ingestion_manifest":
            row = db.occ_get("secure_ingestion_manifest", binding.record_id)
            if row is None:
                return None
            manifest = SecureIngestionManifest.model_validate_json(row[1])
            ds.verify(
                "manifest_digest",
                {k: v for k, v in manifest.model_dump(mode="python").items() if k != "manifest_digest"},
                manifest.manifest_digest,
            )
            return binding.state_version, manifest.manifest_digest
        if binding.record_type == "secret_lifecycle_head":
            return secret_store.current_security_projection(binding.record_id)
        if binding.record_type == "quarantine_deletion_intent":
            row = db.occ_get("quarantine_deletion_intent", binding.record_id)
            if row is None:
                return None
            deletion_intent = QuarantineDeletionIntent.model_validate_json(row[1])
            ds.verify(
                "deletion_intent_digest",
                {
                    k: v
                    for k, v in deletion_intent.model_dump(mode="python").items()
                    if k != "intent_digest"
                },
                deletion_intent.intent_digest,
            )
            return binding.state_version, deletion_intent.intent_digest
        if binding.record_type == "quarantine_erasure_claim":
            row = db.occ_get("quarantine_erasure_claim", binding.record_id)
            if row is None:
                return None
            erasure_claim = QuarantineErasureClaim.model_validate_json(row[1])
            ds.verify(
                "erasure_claim_digest",
                {
                    k: v
                    for k, v in erasure_claim.model_dump(mode="python").items()
                    if k != "claim_digest"
                },
                erasure_claim.claim_digest,
            )
            return binding.state_version, erasure_claim.claim_digest
        if binding.record_type == "audit_chain_head":
            audit_store.verify_chain(binding.record_id)
            event = next(
                (
                    item
                    for item in audit_store.events(binding.record_id)
                    if item.sequence_number == binding.state_version
                ),
                None,
            )
            return None if event is None else (event.sequence_number, event.event_digest)
        # The record type is fixed in Phase 0C; Phase 1 may create the explicit
        # head, after which this generic owner read path verifies it.
        if binding.record_type == "knowledge_evidence_head":
            row = db.occ_get("knowledge_security_head", binding.record_id)
            if row is None:
                return None
            head = KnowledgeSecurityHead.model_validate_json(row[1])
            fields = head.model_dump(mode="python")
            ds.verify(
                "knowledge_security_head_digest",
                {k: v for k, v in fields.items() if k != "head_digest"},
                head.head_digest,
            )
            if head.mission_id != binding.record_id or head.security_version != row[0]:
                return None
            return head.security_version, head.head_digest
        return None

    critical_barrier = CriticalWitnessBarrier(
        database=db, digest_service=ds, coordinator=coordinator, policy=witness_policy,
        critical_record_types=critical_record_types, current_binding=current_binding,
    )
    audit_store.set_critical_witness_barrier(critical_barrier)

    def record_critical_mutation(mutation: CriticalMutation) -> None:
        audit_store.append_in_txn(
            mission_id=mutation.mission_id,
            event_type=mutation.event_type,
            payload_digest=mutation.security_projection_digest,
            actor_id=mutation.actor_id,
            occurred_at_iso=mutation.occurred_at_iso,
            record_type=mutation.record_type,
            record_id=mutation.record_id,
            state_version=mutation.state_version,
            security_projection_digest=mutation.security_projection_digest,
        )

    db.set_critical_mutation_recorder(record_critical_mutation)
    wrapped_key_state_service = WrappedKeyStateService(
        database=db, digest_service=ds, coordinator=coordinator, blob_store=wrapped_state_blobs,
    )
    def witness_provider_state(
        state_digest: str,
        domain_digests: tuple[str, ...],
        bindings_digest: str,
        envelope: EnvelopeCiphertext,
    ) -> bool:
        def commit_state() -> None:
            wrapped_key_state_service.commit(
                operation_id=f"provider-state-{state_digest}",
                provider_identity=key_provider.provider_identity,
                domain_key_metadata_digests=domain_digests,
                active_domain_key_bindings_digest=bindings_digest,
                wrapped_envelope=envelope,
            )
            key_provider.confirm_wrapped_state(state_digest)

        if db.in_transaction:
            db.register_after_commit(commit_state)
            return False
        commit_state()
        return True

    key_provider.connect_wrapped_state_witness(witness_provider_state)
    epoch = coordinator.initialize_deployment_epoch()
    epoch_service.establish(
        guard=guard, trust_epoch=coordinator.trust_epoch, deployment_epoch=epoch,
        nv_identity_digest=witness.identity("deployment_epoch").identity_digest,
        provider_identity=key_provider.provider_identity, established_at_iso="2026-01-15T12:00:00Z",
    )
    adapters: dict[str, ExecutionAdapter] = {
        kernel.mock_adapter.identity().adapter_id: kernel.mock_adapter,
    }
    collection_facade = _SecureCollectionFacade(collection_service, kernel, adapters)
    ingestion_facade = _SecureIngestionFacade(ingestion_service, kernel)
    secret_source = _SecretLifecycleSource(secret_store)
    legacy_collection = kernel.collection_coordinator
    legacy_ingestion = kernel.ingestion_coordinator
    legacy_collection.retire_for_phase0c(guard=kernel.execution_guard)
    legacy_ingestion.retire_for_phase0c(guard=kernel.execution_guard)
    kernel.executor.bind_phase0c_dependencies(
        guard=kernel.execution_guard,
        collection_coordinator=cast(ResultCollectionCoordinator, collection_facade),
        secret_source=cast(TrustedSecretSource, secret_source),
        secret_metadata_reader=secret_store,
    )
    kernel.collection_coordinator = cast(ResultCollectionCoordinator, collection_facade)
    kernel.ingestion_coordinator = cast(ResultIngestionCoordinator, ingestion_facade)
    return Phase0CKernel(
        phase0b=kernel, monotonic_clock=clock, clock_guard=clock_guard, data_guard=guard,
        key_provider_identity=key_provider.provider_identity, nv_witness=witness,
        generation_coordinator=coordinator,
        generation_store=generation_store, audit_store=audit_store, epoch_service=epoch_service,
        critical_witness_barrier=critical_barrier,
        wrapped_key_state_service=wrapped_key_state_service,
        wrapped_state_blobs=wrapped_state_blobs,
        lease_service=lease_service,
        quarantine_metadata=QuarantineMetadataView(quarantine_store),
        secret_metadata=SecretMetadataView(secret_store),
        artifact_metadata=ArtifactMetadataView(artifact_store),
        rule_catalog=rule_catalog, parser=parser,
        collection_service=collection_service, ingestion_service=ingestion_service, eraser=eraser,
        retention_scheduler=retention_scheduler, legacy_migrator=legacy_migrator,
    )
