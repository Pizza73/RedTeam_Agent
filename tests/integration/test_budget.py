"""Durable mission execution budget: OCC reservation, exhaustion, persistence."""

from __future__ import annotations

import pytest

import support_phase0b as p0b
from redteam_agent.errors import ExecutionStateConflictError, MissionExecutionBudgetError


def test_reserve_consumes_and_bumps_version() -> None:
    kernel = p0b.make_kernel()
    service = kernel.budget_service
    service.create_budget(mission_id="m1", mission_revision=1, max_dispatch_claims=2)
    first = service.reserve(mission_id="m1", mission_revision=1)
    assert first.consumed_dispatch_claims == 1
    assert first.budget_version == 2
    second = service.reserve(mission_id="m1", mission_revision=1)
    assert second.consumed_dispatch_claims == 2
    # Persisted durably.
    assert service.get("m1", 1).consumed_dispatch_claims == 2


def test_reserve_beyond_budget_fails_closed() -> None:
    kernel = p0b.make_kernel()
    service = kernel.budget_service
    service.create_budget(mission_id="m1", mission_revision=1, max_dispatch_claims=1)
    service.reserve(mission_id="m1", mission_revision=1)
    with pytest.raises(MissionExecutionBudgetError):
        service.reserve(mission_id="m1", mission_revision=1)


def test_reserve_without_budget_fails_closed() -> None:
    kernel = p0b.make_kernel()
    with pytest.raises(MissionExecutionBudgetError):
        kernel.budget_service.reserve(mission_id="m1", mission_revision=1)


def test_stale_budget_version_conflicts() -> None:
    kernel = p0b.make_kernel()
    service = kernel.budget_service
    budget = service.create_budget(mission_id="m1", mission_revision=1, max_dispatch_claims=5)
    service.reserve(mission_id="m1", mission_revision=1)  # bumps to version 2
    # A stale update against the original version 1 conflicts (OCC).
    stale = budget.model_copy(update={"consumed_dispatch_claims": 4, "budget_version": 2})
    from redteam_agent.execution.records import finalize_object_digest
    from redteam_agent.storage.database import UnitOfWork

    stale = finalize_object_digest(
        stale, digest_field="record_digest", digest_name="mission_execution_budget_digest",
        digest_service=kernel.phase0a.digest_service,
    )
    with pytest.raises(ExecutionStateConflictError), UnitOfWork(kernel.phase0a.database):
        kernel.budget_repository.update(stale, expected_version=1, guard=kernel.execution_guard)


def test_dispatch_reserves_budget_in_claim_transaction() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, seed_budget=False)
    p0b.authorize(seeded)
    kernel.budget_service.create_budget(
        mission_id=seeded.seeded.revision.mission_id,
        mission_revision=seeded.seeded.revision.mission_revision,
        max_dispatch_claims=1,
    )
    kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    budget = kernel.budget_service.get(
        seeded.seeded.revision.mission_id, seeded.seeded.revision.mission_revision
    )
    assert budget is not None and budget.consumed_dispatch_claims == 1


def test_exhausted_dispatch_budget_creates_no_claim_or_provider_call() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, seed_budget=False)
    p0b.authorize(seeded)
    mission_id = seeded.seeded.revision.mission_id
    revision = seeded.seeded.revision.mission_revision
    kernel.budget_service.create_budget(
        mission_id=mission_id, mission_revision=revision, max_dispatch_claims=1
    )
    kernel.budget_service.reserve(mission_id=mission_id, mission_revision=revision)
    with pytest.raises(MissionExecutionBudgetError):
        kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    record = kernel.execution_repository.get("exec-1")
    assert record is not None and record.provider_execution_state == "AUTHORIZED"
    assert kernel.claim_repository.get("claim-exec-1") is None
    assert kernel.mock_adapter.submit_calls == 0


def test_dispatch_without_budget_fails_closed_before_claim() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, seed_budget=False)
    p0b.authorize(seeded)
    with pytest.raises(MissionExecutionBudgetError):
        kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    record = kernel.execution_repository.get("exec-1")
    assert record is not None and record.provider_execution_state == "AUTHORIZED"
    assert kernel.claim_repository.get("claim-exec-1") is None
    assert kernel.mock_adapter.submit_calls == 0
