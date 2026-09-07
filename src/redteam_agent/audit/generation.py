"""AuthenticatedGenerationCoordinator: content-bound TPM-witnessed commit (SystemDesign §34.2 / §34.2.1 / §34.2.2).

The current committed state is the pair (TPM current NV Extend digest, the exact
authenticated record + immutable blob that reproduces it). A commit persists the next
record/blob durably first, then extends the TPM outside the DB transaction, then
re-reads and confirms the predicted witness. A crash between persist and extend is
reconciled by re-reading the TPM: the same pending payload is completed, never a new
one. Any of {TPM reset, NV identity mismatch, current record missing, DB rolled back
below the witness, ambiguous state} stops as :class:`AnchorRecoveryRequiredError` with
no local re-seed.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from redteam_agent.audit.generation_store import GenerationRecordStore, blob_id_for
from redteam_agent.audit.models import (
    GenerationCommitRecord,
    GenerationNamespace,
    ImmutableGenerationBlob,
    NvRole,
    ProvisionedNvIdentity,
)
from redteam_agent.audit.nv_witness import NvExtendDigestWitness
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    AggregateConsistencyError,
    AnchorRecoveryRequiredError,
    GenerationWitnessError,
)
from redteam_agent.storage.database import Database
from redteam_agent.storage.unit_of_work import (
    ApplicationUnitOfWork,
    FaultInjector,
    NoFaultInjector,
    peek_operation,
)

_ZERO32 = "00" * 32
_COMMIT_DOMAIN = "redteam-generation-commit/nv_extend_sha256_v1"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AuthenticatedGenerationCoordinator:
    def __init__(
        self,
        *,
        database: Database,
        witness: NvExtendDigestWitness,
        record_store: GenerationRecordStore,
        digest_service: DigestService,
        trust_epoch: int = 1,
        schema_version: str = "generation-schema-v1",
        digest_catalog_revision: str,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._db = database
        self._witness = witness
        self._store = record_store
        self._ds = digest_service
        self._trust_epoch = trust_epoch
        self._schema_version = schema_version
        self._catalog_revision = digest_catalog_revision
        self._fault = fault_injector if fault_injector is not None else NoFaultInjector()

    @property
    def trust_epoch(self) -> int:
        return self._trust_epoch

    @property
    def database(self) -> Database:
        return self._db

    @property
    def witness(self) -> NvExtendDigestWitness:
        return self._witness

    @property
    def record_store(self) -> GenerationRecordStore:
        return self._store

    def record_at(self, namespace: GenerationNamespace, generation: int) -> GenerationCommitRecord | None:
        """Read and authenticate an exact logical generation for recovery checks."""
        return self._store.get_record(namespace, self._trust_epoch, generation)

    def record_content(self, record: GenerationCommitRecord) -> str:
        blob = self._store.get_blob(record.immutable_blob_id)
        if blob is None:
            raise AnchorRecoveryRequiredError("generation record content blob is missing")
        return blob.content

    def witness_identity(self, role: NvRole) -> ProvisionedNvIdentity:
        return self._witness.identity(role)

    def witness_is_written(self, role: NvRole) -> bool:
        return self._witness.public_area(role).written

    # --- content-bound digest helpers ------------------------------------

    def _commit_payload_digest(
        self, *, namespace: GenerationNamespace, generation: int, state_digest: str,
        immutable_blob_id: str, previous_anchor_digest: str | None, tpm_nv_index_identity: str,
        previous_witness_digest: str,
    ) -> str:
        payload = {
            "domain_separator": _COMMIT_DOMAIN, "namespace": namespace, "trust_epoch": self._trust_epoch,
            "generation": generation, "state_digest": state_digest, "immutable_blob_id": immutable_blob_id,
            "previous_anchor_digest": previous_anchor_digest, "schema_version": self._schema_version,
            "digest_catalog_revision": self._catalog_revision, "tpm_nv_index_identity": tpm_nv_index_identity,
            "witness_mode": "nv_extend_sha256_v1", "previous_witness_digest": previous_witness_digest,
        }
        return _sha256_hex(canonical_dumps(payload))

    @staticmethod
    def _witness_digest(previous_witness_digest: str, commit_payload_digest: str) -> str:
        return _sha256_hex(bytes.fromhex(previous_witness_digest) + bytes.fromhex(commit_payload_digest))

    def _build_blob(self, namespace: GenerationNamespace, content: str) -> ImmutableGenerationBlob:
        blob_digest = _sha256_hex(f"gen-blob-v1\x00{content}".encode())
        content_kind: Literal["audit_head_set", "wrapped_key_state"] = (
            "audit_head_set" if namespace == "audit_head" else "wrapped_key_state"
        )
        return ImmutableGenerationBlob(
            blob_id=blob_id_for(namespace, blob_digest), namespace=namespace,
            content_kind=content_kind, content=content, blob_digest=blob_digest,
        )

    def _build_record(
        self, *, namespace: GenerationNamespace, generation: int, blob: ImmutableGenerationBlob,
        state_digest: str, previous_anchor_digest: str | None, previous_witness_digest: str,
        identity_digest: str,
    ) -> GenerationCommitRecord:
        payload_digest = self._commit_payload_digest(
            namespace=namespace, generation=generation, state_digest=state_digest,
            immutable_blob_id=blob.blob_id, previous_anchor_digest=previous_anchor_digest,
            tpm_nv_index_identity=identity_digest, previous_witness_digest=previous_witness_digest,
        )
        witness = self._witness_digest(previous_witness_digest, payload_digest)
        fields: dict[str, object] = {
            "namespace": namespace, "trust_epoch": self._trust_epoch, "generation": generation,
            "immutable_blob_id": blob.blob_id, "state_digest": state_digest,
            "previous_anchor_digest": previous_anchor_digest, "schema_version": self._schema_version,
            "digest_catalog_revision": self._catalog_revision, "tpm_nv_index_identity": identity_digest,
            "witness_mode": "nv_extend_sha256_v1", "previous_witness_digest": previous_witness_digest,
            "commit_payload_digest": payload_digest, "witness_digest": witness,
        }
        record_digest = self._store.record_digest(fields)
        tag = self._store.authenticate(record_digest)
        return GenerationCommitRecord(
            **fields,  # type: ignore[arg-type]
            record_digest=record_digest, record_authentication_tag=tag,
        )

    # --- genesis ----------------------------------------------------------

    def _resolve_recorded(
        self, namespace: GenerationNamespace, operation_id: str, *, state_digest: str, content: str
    ) -> GenerationCommitRecord | None:
        """If ``operation_id`` was already recorded, verify the caller's inputs reproduce
        the recorded commit (idempotent replay) and complete any interrupted TPM extend;
        a different content for the same operation id fails closed."""
        recorded = peek_operation(self._db, "AnchorGenerationAggregate", operation_id)
        if recorded is None:
            return None
        record = self._store.get_by_witness(namespace, self._trust_epoch, recorded.result_digest)
        if record is None:
            raise AnchorRecoveryRequiredError(f"recorded operation {operation_id} has no matching record")
        blob = self._build_blob(namespace, content)
        expected_payload = self._commit_payload_digest(
            namespace=namespace, generation=record.generation, state_digest=state_digest,
            immutable_blob_id=blob.blob_id, previous_anchor_digest=record.previous_anchor_digest,
            tpm_nv_index_identity=record.tpm_nv_index_identity,
            previous_witness_digest=record.previous_witness_digest,
        )
        if expected_payload != record.commit_payload_digest:
            raise AggregateConsistencyError(
                f"generation operation {operation_id} replayed with different content"
            )
        self._confirm_or_extend(
            namespace, previous=record.previous_witness_digest, predicted=record.witness_digest,
            payload_digest=record.commit_payload_digest,
        )
        return record

    def genesis(
        self, namespace: GenerationNamespace, *, initial_state_digest: str, initial_content: str
    ) -> GenerationCommitRecord:
        op_id = f"genesis-{namespace}-{self._trust_epoch}"
        resolved = self._resolve_recorded(namespace, op_id, state_digest=initial_state_digest,
                                          content=initial_content)
        if resolved is not None:
            return resolved
        public = self._witness.public_area(namespace)
        if public.written:
            raise GenerationWitnessError(f"{namespace} NV index is already WRITTEN; not a fresh install")
        if self._witness.read_witness(namespace) != _ZERO32:
            raise GenerationWitnessError(f"{namespace} NV Extend value is not the fresh zero digest")
        if self._store.latest_generation(namespace, self._trust_epoch) is not None:
            raise AnchorRecoveryRequiredError(f"{namespace} has existing records but a fresh NV state")
        identity = self._witness.identity(namespace).identity_digest
        blob = self._build_blob(namespace, initial_content)
        record = self._build_record(
            namespace=namespace, generation=0, blob=blob, state_digest=initial_state_digest,
            previous_anchor_digest=None, previous_witness_digest=_ZERO32, identity_digest=identity,
        )
        with ApplicationUnitOfWork(
            self._db, aggregate_name="AnchorGenerationAggregate", operation_id=op_id,
            input_digest=record.commit_payload_digest, fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                self._store.store(record, blob)
                uow.record_result(record.witness_digest)
        self._confirm_or_extend(namespace, previous=_ZERO32, predicted=record.witness_digest,
                                payload_digest=record.commit_payload_digest)
        return record

    # --- commit -----------------------------------------------------------

    def commit(
        self, namespace: GenerationNamespace, *, new_state_digest: str, new_content: str,
        operation_id: str,
    ) -> GenerationCommitRecord:
        resolved = self._resolve_recorded(namespace, operation_id, state_digest=new_state_digest,
                                          content=new_content)
        if resolved is not None:
            return resolved
        current = self.current(namespace)
        if current is None:
            raise GenerationWitnessError(f"{namespace} has no genesis; cannot commit")
        identity = self._witness.identity(namespace).identity_digest
        blob = self._build_blob(namespace, new_content)
        record = self._build_record(
            namespace=namespace, generation=current.generation + 1, blob=blob, state_digest=new_state_digest,
            previous_anchor_digest=current.record_digest, previous_witness_digest=current.witness_digest,
            identity_digest=identity,
        )
        with ApplicationUnitOfWork(
            self._db, aggregate_name="AnchorGenerationAggregate", operation_id=operation_id,
            input_digest=record.commit_payload_digest, fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                self._store.store(record, blob)
                uow.record_result(record.witness_digest)
        self._confirm_or_extend(namespace, previous=current.witness_digest, predicted=record.witness_digest,
                                payload_digest=record.commit_payload_digest)
        return record

    def _confirm_or_extend(
        self, namespace: GenerationNamespace, *, previous: str, predicted: str, payload_digest: str
    ) -> None:
        # DB commit is durable; now extend the TPM outside any DB transaction. A crash
        # here is reconciled by re-reading the current witness: if it already equals the
        # predicted witness the extend happened (idempotent); if it still equals the
        # previous witness we complete the same pending payload; anything else stops.
        self._fault.check("before_extend")
        current_witness = self._witness.read_witness(namespace)
        if current_witness == predicted:
            return
        if current_witness != previous:
            raise AnchorRecoveryRequiredError(
                f"{namespace} witness is neither previous nor predicted; ambiguous extend"
            )
        actual = self._witness.extend(namespace, payload_digest)
        if actual != predicted:
            raise AnchorRecoveryRequiredError(f"{namespace} extend produced an unexpected witness")

    # --- current state / startup verification ----------------------------

    def current(self, namespace: GenerationNamespace) -> GenerationCommitRecord | None:
        witness = self._witness.read_witness(namespace)
        public = self._witness.public_area(namespace)
        latest = self._store.latest_generation(namespace, self._trust_epoch)
        if witness == _ZERO32:
            # Fresh: zero witness, unWRITTEN, and no records -> genesis is required next.
            if public.written or latest is not None:
                raise AnchorRecoveryRequiredError(
                    f"{namespace} NV Extend reset/cleared while records exist (rollback/reset)"
                )
            return None
        record = self._store.get_by_witness(namespace, self._trust_epoch, witness)
        if record is None:
            raise AnchorRecoveryRequiredError(
                f"{namespace} current witness has no matching record (DB rollback / missing record)"
            )
        identity = self._witness.identity(namespace).identity_digest
        if record.tpm_nv_index_identity != identity:
            raise AnchorRecoveryRequiredError(f"{namespace} NV identity mismatch")
        blob = self._store.get_blob(record.immutable_blob_id)
        if blob is None:
            raise AnchorRecoveryRequiredError(f"{namespace} current blob missing")
        return record

    def verify_startup(self) -> dict[str, GenerationCommitRecord | None]:
        return {
            "audit_head": self.current("audit_head"),
            "wrapped_key_state": self.current("wrapped_key_state"),
        }

    # --- deployment epoch (measured NV counter) ---------------------------

    def read_deployment_epoch(self) -> int:
        if not self._witness.public_area("deployment_epoch").written:
            raise GenerationWitnessError("deployment epoch counter is not explicitly initialized")
        return self._witness.read_counter("deployment_epoch")

    def initialize_deployment_epoch(self) -> int:
        """Perform the explicit first counter increment during provisioning.

        An unwritten counter is provisioning state, not a readable deployment epoch
        zero. Normal startup uses :meth:`advance_deployment_epoch` afterwards.
        """
        if self._witness.public_area("deployment_epoch").written:
            raise GenerationWitnessError("deployment epoch counter is already initialized")
        after = self._witness.increment_counter("deployment_epoch")
        public = self._witness.public_area("deployment_epoch")
        measured = self._witness.read_counter("deployment_epoch")
        if not public.written or measured != after:
            raise AnchorRecoveryRequiredError("deployment epoch initialization read-back mismatch")
        return measured

    def advance_deployment_epoch(self) -> int:
        """Increment the deployment NV counter and read back the measured value."""
        before = self.read_deployment_epoch()
        after = self._witness.increment_counter("deployment_epoch")
        if after <= before:
            raise AnchorRecoveryRequiredError("deployment epoch counter did not advance")
        return after
