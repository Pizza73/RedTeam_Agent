"""Typed durable repositories for Phase 0B execution safety (SystemDesign §10 / §32).

Each repository wraps :class:`ExecutionStore` (database-enforced uniqueness / OCC)
with the same write/read integrity guarantees as the Phase 0A repositories:

* Write: strict schema revalidation (a ``model_construct`` bypass is rejected) and
  object-integrity/id-binding verification before storage; owner-only writes via
  the composition-issued :class:`WriteGuard` inside an active unit of work.
* Read: duplicate-key-rejecting load, object-integrity verification, and a
  row-key vs payload-identity binding check.

Uniqueness invariants are enforced by the database schema, not by the repository:
one policy decision yields at most one execution; at most one unconsumed dispatch
claim exists per execution; at most one cancel attempt per (execution, task).
"""

from __future__ import annotations

from pydantic import TypeAdapter, ValidationError

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import load_model_from_json, parse_json_no_duplicate_keys
from redteam_agent.errors import RepositoryIntegrityError, ResultTaskBindingError
from redteam_agent.execution.models import (
    CancelAttempt,
    DispatchClaim,
    ExecutionRecord,
    ExecutionRecoveryAuthority,
    ExecutionResult,
    ExecutionResultProjection,
    MissionExecutionBudget,
    RawControlMetadataRecord,
    ResultCollectionAuthority,
    ResultCollectionStateRecord,
    ResultIngestionStateRecord,
    ResultTaskBinding,
)
from redteam_agent.storage.database import Database
from redteam_agent.storage.execution_db import ExecutionStore
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.integrity import verify_object_integrity
from redteam_agent.storage.repositories import _GuardedRepository


class _ExecutionRepository(_GuardedRepository):
    def __init__(self, database: Database, digest_service: DigestService) -> None:
        super().__init__(database, digest_service)
        self._store = ExecutionStore(database)


class ExecutionRecordRepository(_ExecutionRepository):
    def create(self, record: ExecutionRecord, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_execution(
            execution_id=record.execution_id,
            policy_decision_id=record.policy_decision_id,
            mission_id=record.mission_id,
            execution_state_version=record.execution_state_version,
            provider_execution_state=record.provider_execution_state,
            json_text=self._dump(record),
        )

    def transition(self, record: ExecutionRecord, *, expected_version: int, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.update_execution(
            execution_id=record.execution_id,
            expected_version=expected_version,
            new_version=record.execution_state_version,
            provider_execution_state=record.provider_execution_state,
            json_text=self._dump(record),
        )

    def get(self, execution_id: str) -> ExecutionRecord | None:
        raw = self._store.get_execution(execution_id)
        if raw is None:
            return None
        model = load_model_from_json(ExecutionRecord, raw)
        return self._load(ExecutionRecord, raw, row_key=execution_id, payload_key=model.execution_id)

    def get_by_decision(self, policy_decision_id: str) -> ExecutionRecord | None:
        found = self._store.get_execution_by_decision(policy_decision_id)
        if found is None:
            return None
        row_key, raw = found
        model = load_model_from_json(ExecutionRecord, raw)
        return self._load(ExecutionRecord, raw, row_key=row_key, payload_key=model.execution_id)

    def all_for_mission(self, mission_id: str) -> tuple[ExecutionRecord, ...]:
        records = []
        for row_key, raw in self._store.get_executions_for_mission(mission_id):
            model = load_model_from_json(ExecutionRecord, raw)
            records.append(self._load(
                ExecutionRecord, raw, row_key=row_key, payload_key=model.execution_id
            ))
        return tuple(records)


class DispatchClaimRepository(_ExecutionRepository):
    def create(self, claim: DispatchClaim, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_claim(
            claim_id=claim.claim_id,
            execution_id=claim.execution_id,
            claim_state=claim.claim_state,
            json_text=self._dump(claim),
        )

    def update_state(self, claim: DispatchClaim, *, expected_state: str, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.update_claim_state(
            claim_id=claim.claim_id,
            expected_state=expected_state,
            new_state=claim.claim_state,
            json_text=self._dump(claim),
        )

    def get(self, claim_id: str) -> DispatchClaim | None:
        raw = self._store.get_claim(claim_id)
        if raw is None:
            return None
        model = load_model_from_json(DispatchClaim, raw)
        return self._load(DispatchClaim, raw, row_key=claim_id, payload_key=model.claim_id)

    def find_unconsumed(self, execution_id: str) -> DispatchClaim | None:
        found = self._store.find_unconsumed_claim(execution_id)
        if found is None:
            return None
        row_key, raw = found
        model = load_model_from_json(DispatchClaim, raw)
        return self._load(DispatchClaim, raw, row_key=row_key, payload_key=model.claim_id)

    def all_for(self, execution_id: str) -> tuple[DispatchClaim, ...]:
        claims = []
        for row_key, raw in self._store.claims_for(execution_id):
            model = load_model_from_json(DispatchClaim, raw)
            claims.append(self._load(DispatchClaim, raw, row_key=row_key, payload_key=model.claim_id))
        return tuple(claims)


class ResultCollectionAuthorityRepository(_ExecutionRepository):
    def create(self, authority: ResultCollectionAuthority, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_collection_authority(
            collection_id=authority.collection_id,
            execution_id=authority.execution_id,
            json_text=self._dump(authority),
        )

    def get(self, collection_id: str) -> ResultCollectionAuthority | None:
        raw = self._store.get_collection_authority(collection_id)
        if raw is None:
            return None
        model = load_model_from_json(ResultCollectionAuthority, raw)
        return self._load(ResultCollectionAuthority, raw, row_key=collection_id, payload_key=model.collection_id)

    def find_by_execution(self, execution_id: str) -> ResultCollectionAuthority | None:
        found = self._store.find_collection_authority_by_execution(execution_id)
        if found is None:
            return None
        row_key, raw = found
        model = load_model_from_json(ResultCollectionAuthority, raw)
        return self._load(ResultCollectionAuthority, raw, row_key=row_key, payload_key=model.collection_id)


class ResultCollectionStateRepository(_ExecutionRepository):
    def create(self, record: ResultCollectionStateRecord, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_collection_state(
            collection_state_id=record.collection_state_id,
            collection_id=record.collection_id,
            execution_id=record.execution_id,
            state_version=record.state_version,
            status=record.status,
            json_text=self._dump(record),
        )

    def update(self, record: ResultCollectionStateRecord, *, expected_version: int, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.update_collection_state(
            collection_state_id=record.collection_state_id,
            expected_version=expected_version,
            new_version=record.state_version,
            status=record.status,
            json_text=self._dump(record),
        )

    def get(self, collection_state_id: str) -> ResultCollectionStateRecord | None:
        raw = self._store.get_collection_state(collection_state_id)
        if raw is None:
            return None
        model = load_model_from_json(ResultCollectionStateRecord, raw)
        return self._load(
            ResultCollectionStateRecord, raw, row_key=collection_state_id, payload_key=model.collection_state_id
        )


class ResultTaskBindingRepository(_ExecutionRepository):
    """Immutable result-task-binding mapping. A changed mapping is an integrity stop
    (the row-key/execution unique constraints reject any second binding)."""

    def create(self, binding: ResultTaskBinding, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_task_binding(
            result_task_binding_id=binding.task_id,
            execution_id=binding.execution_id,
            json_text=self._dump(binding),
        )

    def get(self, result_task_binding_id: str) -> ResultTaskBinding | None:
        raw = self._store.get_task_binding(result_task_binding_id)
        if raw is None:
            return None
        model = _load_task_binding(raw)
        return self._load_binding(raw, row_key=result_task_binding_id, payload_key=model.task_id)

    def find_by_execution(self, execution_id: str) -> ResultTaskBinding | None:
        found = self._store.find_task_binding_by_execution(execution_id)
        if found is None:
            return None
        row_key, raw = found
        model = _load_task_binding(raw)
        return self._load_binding(raw, row_key=row_key, payload_key=model.task_id)

    def _load_binding(self, raw: str, *, row_key: str, payload_key: str) -> ResultTaskBinding:
        model = _load_task_binding(raw)
        verify_object_integrity(model, self._digests)
        if row_key != payload_key:
            raise RepositoryIntegrityError("stored row key does not match payload identity")
        return model


class RawControlMetadataRepository(_ExecutionRepository):
    def create(self, record: RawControlMetadataRecord, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_control_metadata(
            control_record_id=record.control_record_id,
            execution_id=record.execution_id,
            json_text=self._dump(record),
        )

    def get(self, control_record_id: str) -> RawControlMetadataRecord | None:
        raw = self._store.get_control_metadata(control_record_id)
        if raw is None:
            return None
        model = load_model_from_json(RawControlMetadataRecord, raw)
        return self._load(
            RawControlMetadataRecord, raw, row_key=control_record_id, payload_key=model.control_record_id
        )

    def find_by_execution(self, execution_id: str) -> RawControlMetadataRecord | None:
        found = self._store.find_control_metadata_by_execution(execution_id)
        if found is None:
            return None
        row_key, raw = found
        model = load_model_from_json(RawControlMetadataRecord, raw)
        return self._load(RawControlMetadataRecord, raw, row_key=row_key, payload_key=model.control_record_id)


class ExecutionResultProjectionRepository(_ExecutionRepository):
    def create(self, projection: ExecutionResultProjection, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_projection(
            projection_id=projection.projection_id,
            execution_id=projection.execution_id,
            json_text=self._dump(projection),
        )

    def get(self, projection_id: str) -> ExecutionResultProjection | None:
        raw = self._store.get_projection(projection_id)
        if raw is None:
            return None
        model = load_model_from_json(ExecutionResultProjection, raw)
        return self._load(ExecutionResultProjection, raw, row_key=projection_id, payload_key=model.projection_id)

    def find_by_execution(self, execution_id: str) -> ExecutionResultProjection | None:
        found = self._store.find_projection_by_execution(execution_id)
        if found is None:
            return None
        row_key, raw = found
        model = load_model_from_json(ExecutionResultProjection, raw)
        return self._load(ExecutionResultProjection, raw, row_key=row_key, payload_key=model.projection_id)


class ExecutionResultRepository(_ExecutionRepository):
    def upsert(self, result: ExecutionResult, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.upsert_execution_result(execution_id=result.execution_id, json_text=self._dump(result))

    def get(self, execution_id: str) -> ExecutionResult | None:
        raw = self._store.get_execution_result(execution_id)
        if raw is None:
            return None
        model = load_model_from_json(ExecutionResult, raw)
        return self._load(ExecutionResult, raw, row_key=execution_id, payload_key=model.execution_id)


class ResultIngestionStateRepository(_ExecutionRepository):
    def create(self, record: ResultIngestionStateRecord, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_ingestion_state(
            ingestion_id=record.ingestion_id,
            execution_id=record.execution_id,
            state_version=record.state_version,
            status=record.status,
            json_text=self._dump(record),
        )

    def update(self, record: ResultIngestionStateRecord, *, expected_version: int, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.update_ingestion_state(
            ingestion_id=record.ingestion_id,
            expected_version=expected_version,
            new_version=record.state_version,
            status=record.status,
            json_text=self._dump(record),
        )

    def get(self, ingestion_id: str) -> ResultIngestionStateRecord | None:
        raw = self._store.get_ingestion_state(ingestion_id)
        if raw is None:
            return None
        model = load_model_from_json(ResultIngestionStateRecord, raw)
        return self._load(ResultIngestionStateRecord, raw, row_key=ingestion_id, payload_key=model.ingestion_id)

    def find_by_execution(self, execution_id: str) -> ResultIngestionStateRecord | None:
        found = self._store.find_ingestion_state_by_execution(execution_id)
        if found is None:
            return None
        row_key, raw = found
        model = load_model_from_json(ResultIngestionStateRecord, raw)
        return self._load(ResultIngestionStateRecord, raw, row_key=row_key, payload_key=model.ingestion_id)


class ExecutionRecoveryAuthorityRepository(_ExecutionRepository):
    def create(self, authority: ExecutionRecoveryAuthority, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_recovery_authority(
            authority_id=authority.authority_id,
            execution_id=authority.execution_id,
            allowed_operation=authority.allowed_operation,
            json_text=self._dump(authority),
        )

    def get(self, authority_id: str) -> ExecutionRecoveryAuthority | None:
        raw = self._store.get_recovery_authority(authority_id)
        if raw is None:
            return None
        model = load_model_from_json(ExecutionRecoveryAuthority, raw)
        return self._load(ExecutionRecoveryAuthority, raw, row_key=authority_id, payload_key=model.authority_id)


class CancelAttemptRepository(_ExecutionRepository):
    def create(self, attempt: CancelAttempt, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_cancel_attempt(
            cancel_attempt_id=attempt.cancel_attempt_id,
            execution_id=attempt.execution_id,
            provider_task_id=attempt.provider_task_id,
            json_text=self._dump(attempt),
        )

    def update(self, attempt: CancelAttempt, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.update_cancel_attempt(
            cancel_attempt_id=attempt.cancel_attempt_id, json_text=self._dump(attempt)
        )

    def get(self, cancel_attempt_id: str) -> CancelAttempt | None:
        raw = self._store.get_cancel_attempt(cancel_attempt_id)
        if raw is None:
            return None
        model = load_model_from_json(CancelAttempt, raw)
        return self._load(CancelAttempt, raw, row_key=cancel_attempt_id, payload_key=model.cancel_attempt_id)

    def find(self, execution_id: str, provider_task_id: str) -> CancelAttempt | None:
        found = self._store.find_cancel_attempt(execution_id, provider_task_id)
        if found is None:
            return None
        row_key, raw = found
        model = load_model_from_json(CancelAttempt, raw)
        return self._load(CancelAttempt, raw, row_key=row_key, payload_key=model.cancel_attempt_id)


class MissionExecutionBudgetRepository(_ExecutionRepository):
    def create(self, budget: MissionExecutionBudget, *, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.insert_budget(
            mission_id=budget.mission_id,
            mission_revision=budget.mission_revision,
            budget_version=budget.budget_version,
            json_text=self._dump(budget),
        )

    def update(self, budget: MissionExecutionBudget, *, expected_version: int, guard: WriteGuard) -> None:
        self._authorize_write(guard, require_transaction=True)
        self._store.update_budget(
            mission_id=budget.mission_id,
            mission_revision=budget.mission_revision,
            expected_version=expected_version,
            new_version=budget.budget_version,
            json_text=self._dump(budget),
        )

    def get(self, mission_id: str, mission_revision: int) -> MissionExecutionBudget | None:
        raw = self._store.get_budget(mission_id, mission_revision)
        if raw is None:
            return None
        key = f"{mission_id}/{mission_revision}"
        model = load_model_from_json(MissionExecutionBudget, raw)
        payload_key = f"{model.mission_id}/{model.mission_revision}"
        return self._load(MissionExecutionBudget, raw, row_key=key, payload_key=payload_key)


_BINDING_ADAPTER: TypeAdapter[ResultTaskBinding] = TypeAdapter(ResultTaskBinding)


def _load_task_binding(raw: str) -> ResultTaskBinding:
    """Load a provider_task|local_result binding through the strict boundary.

    Duplicate keys are rejected before validation; the discriminated union then
    rejects an unknown discriminant, a missing branch field, and ``local_capture``
    (SystemDesign §10.5). Error text stays content-free.
    """
    parse_json_no_duplicate_keys(raw)
    try:
        return _BINDING_ADAPTER.validate_json(raw)
    except ValidationError as exc:
        raise ResultTaskBindingError(f"result task binding failed strict validation ({exc.error_count()} errors)") \
            from None
