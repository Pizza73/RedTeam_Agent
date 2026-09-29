"""TPM-witnessed encrypted provider-state root (SystemDesign §34.2).

Only an authenticated ``EnvelopeCiphertext`` is accepted.  The encrypted provider
blob is stored outside the normal application rows; SQLite keeps immutable metadata,
and the ``wrapped_key_state`` TPM generation selects the exact metadata/blob pair.
"""

from __future__ import annotations

import hashlib
import json

from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.models import WrappedKeyState
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto.models import EnvelopeCiphertext
from redteam_agent.errors import GenerationWitnessError, KeyDomainSeparationError
from redteam_agent.quarantine.blob_store import QuarantineBlobStore
from redteam_agent.storage.database import Database
from redteam_agent.storage.unit_of_work import (
    ApplicationUnitOfWork,
    FaultInjector,
    NoFaultInjector,
    compute_input_digest,
    peek_operation,
)

_STATE_NS = "wrapped_key_state"
_BLOB_PREFIX = "wrapped-key-state"


class WrappedKeyStateService:
    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        coordinator: AuthenticatedGenerationCoordinator,
        blob_store: QuarantineBlobStore,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._coordinator = coordinator
        self._blobs = blob_store
        self._fault = fault_injector if fault_injector is not None else NoFaultInjector()

    @property
    def database(self) -> Database:
        return self._db

    @property
    def coordinator(self) -> AuthenticatedGenerationCoordinator:
        return self._coordinator

    @property
    def blob_store_is_production(self) -> bool:
        return bool(getattr(self._blobs, "is_production", False))

    def commit(
        self,
        *,
        operation_id: str,
        provider_identity: str,
        domain_key_metadata_digests: tuple[str, ...],
        active_domain_key_bindings_digest: str,
        wrapped_envelope: EnvelopeCiphertext,
    ) -> WrappedKeyState:
        if wrapped_envelope.key_domain != "audit_signing":
            raise KeyDomainSeparationError("wrapped provider state requires the audit_signing key domain")
        if not domain_key_metadata_digests or len(set(domain_key_metadata_digests)) != len(
            domain_key_metadata_digests
        ):
            raise KeyDomainSeparationError("domain key metadata digests must be non-empty and unique")
        envelope_bytes = json.dumps(wrapped_envelope.model_dump(mode="json"), sort_keys=True).encode()
        envelope_digest = hashlib.sha256(envelope_bytes).hexdigest()
        blob_id = f"{_BLOB_PREFIX}/{envelope_digest}"
        prepared = peek_operation(
            self._db, "AnchorGenerationAggregate", f"wrapped-key-state-prepare-{operation_id}"
        )
        if prepared is not None:
            row = self._db.occ_get(_STATE_NS, prepared.result_digest)
            if row is None:
                raise GenerationWitnessError("prepared wrapped-key-state metadata is missing")
            prior = WrappedKeyState.model_validate_json(row[1])
            if (
                prior.provider_identity != provider_identity
                or prior.domain_key_metadata_digests != domain_key_metadata_digests
                or prior.active_domain_key_bindings_digest != active_domain_key_bindings_digest
                or prior.wrapped_provider_state_blob_id != blob_id
                or prior.wrapped_provider_state_digest != envelope_digest
            ):
                raise GenerationWitnessError("wrapped-key-state operation replayed with different input")
            self._coordinator.commit(
                "wrapped_key_state",
                new_state_digest=prior.state_digest,
                new_content=canonical_dumps(prior.model_dump(mode="json")).decode(),
                operation_id=f"wrapped-key-state-witness-{operation_id}",
            )
            return self.current()
        current = self._coordinator.current("wrapped_key_state")
        if current is None:
            raise GenerationWitnessError("wrapped-key-state genesis is missing")
        fields = {
            "state_revision": "wrapped-key-state-v1",
            "provider_identity": provider_identity,
            "domain_key_metadata_digests": domain_key_metadata_digests,
            "wrapped_provider_state_blob_id": blob_id,
            "wrapped_provider_state_digest": envelope_digest,
            "active_domain_key_bindings_digest": active_domain_key_bindings_digest,
            "previous_state_digest": current.state_digest,
        }
        state = WrappedKeyState(
            **fields,  # type: ignore[arg-type]
            state_digest=self._ds.compute("wrapped_key_state_digest", fields),
        )
        if self._blobs.exists(blob_id):
            if self._blobs.get(blob_id) != envelope_bytes:
                raise GenerationWitnessError("wrapped provider state blob id collision")
        else:
            self._blobs.put(blob_id, envelope_bytes)
        with ApplicationUnitOfWork(
            self._db,
            aggregate_name="AnchorGenerationAggregate",
            operation_id=f"wrapped-key-state-prepare-{operation_id}",
            input_digest=compute_input_digest(state.model_dump(mode="python")),
            fault_injector=self._fault,
        ) as uow:
            if not uow.already_applied:
                self._db.occ_insert_idempotent(
                    _STATE_NS,
                    state.state_digest,
                    1,
                    json.dumps(state.model_dump(mode="json"), sort_keys=True),
                )
                uow.record_result(state.state_digest)
        self._fault.check("before_wrapped_key_witness")
        record = self._coordinator.commit(
            "wrapped_key_state",
            new_state_digest=state.state_digest,
            new_content=canonical_dumps(state.model_dump(mode="json")).decode(),
            operation_id=f"wrapped-key-state-witness-{operation_id}",
        )
        if record.state_digest != state.state_digest:
            raise GenerationWitnessError("wrapped-key-state witness selected a different state")
        return self.current()

    def current(self) -> WrappedKeyState:
        record = self._coordinator.current("wrapped_key_state")
        if record is None:
            raise GenerationWitnessError("wrapped-key-state witness is empty")
        row = self._db.occ_get(_STATE_NS, record.state_digest)
        if row is None:
            raise GenerationWitnessError("witnessed wrapped-key-state metadata is missing")
        state = WrappedKeyState.model_validate_json(row[1])
        payload = state.model_dump(mode="python")
        self._ds.verify(
            "wrapped_key_state_digest",
            {k: v for k, v in payload.items() if k != "state_digest"},
            state.state_digest,
        )
        if not self._blobs.exists(state.wrapped_provider_state_blob_id):
            raise GenerationWitnessError("witnessed wrapped provider state blob is missing")
        actual = hashlib.sha256(self._blobs.get(state.wrapped_provider_state_blob_id)).hexdigest()
        if actual != state.wrapped_provider_state_digest:
            raise GenerationWitnessError("wrapped provider state blob digest mismatch")
        return state
