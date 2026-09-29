"""Result ingestion: independent state, durable milestone, bounded same-input retry."""

from __future__ import annotations

import support_phase0b as p0b
from redteam_agent.execution.records import finalize_object_digest


def _to_complete(kernel: object):  # type: ignore[no-untyped-def]
    seeded = p0b.seed_authorized(kernel)  # type: ignore[arg-type]
    p0b.authorize(seeded)
    kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)  # type: ignore[attr-defined]
    kernel.collection_coordinator.start_collection(execution_id="exec-1")  # type: ignore[attr-defined]
    kernel.collection_coordinator.collect(execution_id="exec-1")  # type: ignore[attr-defined]
    return seeded


def _force_state(kernel: object, *, status: str, attempt_count: int) -> None:  # type: ignore[no-untyped-def]
    current = kernel.ingestion_repository.get("ingestion-exec-1")  # type: ignore[attr-defined]
    updated = finalize_object_digest(
        current.model_copy(
            update={"state_version": current.state_version + 1, "status": status, "attempt_count": attempt_count}
        ),
        digest_field="record_digest", digest_name="result_ingestion_state_digest",
        digest_service=kernel.phase0a.digest_service,  # type: ignore[attr-defined]
    )
    from redteam_agent.storage.database import UnitOfWork

    with UnitOfWork(kernel.phase0a.database):  # type: ignore[attr-defined]
        kernel.ingestion_repository.update(  # type: ignore[attr-defined]
            updated, expected_version=current.state_version, guard=kernel.execution_guard  # type: ignore[attr-defined]
        )


def test_ingest_reaches_durable_milestone_and_builds_result() -> None:
    kernel = p0b.make_kernel()
    _to_complete(kernel)
    result = kernel.ingestion_coordinator.ingest(execution_id="exec-1")
    assert result.status == "DELETE_PENDING"
    assert result.execution_result_present is True
    ingestion = kernel.ingestion_repository.get("ingestion-exec-1")
    assert ingestion is not None and ingestion.manifest_id is not None
    assert ingestion.ingested_durable_at is not None
    execution_result = kernel.result_repository.get("exec-1")
    assert execution_result is not None
    assert execution_result.status == "SUCCEEDED"
    assert execution_result.provider_task_id is not None  # provider_task mode
    projection = kernel.projection_repository.find_by_execution("exec-1")
    assert projection is not None


def test_reingest_is_create_or_verify_idempotent() -> None:
    kernel = p0b.make_kernel()
    _to_complete(kernel)
    first = kernel.ingestion_coordinator.ingest(execution_id="exec-1")
    projection = kernel.projection_repository.find_by_execution("exec-1")
    second = kernel.ingestion_coordinator.ingest(execution_id="exec-1")  # resume/re-run
    assert first.status == second.status == "DELETE_PENDING"
    # The projection is not duplicated or changed.
    projection2 = kernel.projection_repository.find_by_execution("exec-1")
    assert projection is not None and projection2 is not None
    assert projection.projection_digest == projection2.projection_digest


def test_failed_ingestion_retries_to_pending_within_budget() -> None:
    kernel = p0b.make_kernel()
    _to_complete(kernel)
    _force_state(kernel, status="INGESTING", attempt_count=1)
    _force_state(kernel, status="FAILED", attempt_count=1)
    result = kernel.ingestion_coordinator.retry(execution_id="exec-1")
    assert result.status == "PENDING"


def test_retry_exhaustion_quarantines() -> None:
    kernel = p0b.make_kernel()
    _to_complete(kernel)
    # attempt_count at the retry-policy max -> QUARANTINED, not PENDING.
    _force_state(kernel, status="INGESTING", attempt_count=kernel.retry_policy.max_attempts_per_ingestion)
    _force_state(kernel, status="FAILED", attempt_count=kernel.retry_policy.max_attempts_per_ingestion)
    result = kernel.ingestion_coordinator.retry(execution_id="exec-1")
    assert result.status == "QUARANTINED"


def test_ingestion_state_is_independent_of_provider_state() -> None:
    kernel = p0b.make_kernel()
    _to_complete(kernel)
    kernel.ingestion_coordinator.ingest(execution_id="exec-1")
    record = kernel.execution_repository.get("exec-1")
    ingestion = kernel.ingestion_repository.get("ingestion-exec-1")
    # Provider terminal (SUCCEEDED) and ingestion (DELETE_PENDING) are distinct.
    assert record is not None and record.provider_execution_state == "SUCCEEDED"
    assert ingestion is not None and ingestion.status == "DELETE_PENDING"


def test_ingestion_at_retention_deadline_expires_without_provider_call() -> None:
    kernel = p0b.make_kernel()
    _to_complete(kernel)
    state = kernel.ingestion_repository.get("ingestion-exec-1")
    assert state is not None
    provider_reads = kernel.mock_adapter.collect_calls + kernel.mock_adapter.get_control_calls
    kernel.phase0a.clock.set(state.evidence_retention_until)
    result = kernel.ingestion_coordinator.ingest(execution_id="exec-1")
    assert result.status == "EVIDENCE_RETENTION_EXPIRED"
    assert result.execution_result_present is False
    assert kernel.mock_adapter.collect_calls + kernel.mock_adapter.get_control_calls == provider_reads
