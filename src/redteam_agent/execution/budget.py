"""Durable mission execution budget (SystemDesign §27.1).

A per-mission dispatch budget is persisted and consumed with OCC, never counted
in memory. Reservation increments the consumed count against an expected budget
version; a stale version conflicts and an exhausted budget fails closed. This is
the durable substrate the agent loop uses for bounded execution (Phase 1); Phase
0B provides and verifies the record, OCC and reservation semantics.
"""

from __future__ import annotations

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import MissionExecutionBudgetError
from redteam_agent.execution.models import MissionExecutionBudget
from redteam_agent.execution.records import finalize_object_digest
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.execution_repositories import MissionExecutionBudgetRepository
from redteam_agent.storage.guard import WriteGuard


class MissionExecutionBudgetService:
    def __init__(
        self,
        *,
        database: Database,
        repository: MissionExecutionBudgetRepository,
        clock: Clock,
        digest_service: DigestService,
        write_guard: WriteGuard,
    ) -> None:
        self._db = database
        self._repo = repository
        self._clock = clock
        self._ds = digest_service
        self._guard = write_guard

    def create_budget(
        self, *, mission_id: str, mission_revision: int, max_dispatch_claims: int
    ) -> MissionExecutionBudget:
        budget = self._finalize(
            MissionExecutionBudget(
                mission_id=mission_id, mission_revision=mission_revision, budget_version=1,
                max_dispatch_claims=max_dispatch_claims, consumed_dispatch_claims=0,
                updated_at=self._clock.now(), record_digest="pending",
            )
        )
        with UnitOfWork(self._db):
            self._repo.create(budget, guard=self._guard)
        return budget

    def reserve(self, *, mission_id: str, mission_revision: int) -> MissionExecutionBudget:
        with UnitOfWork(self._db):
            return self.reserve_in_txn(mission_id=mission_id, mission_revision=mission_revision)

    def reserve_in_txn(self, *, mission_id: str, mission_revision: int) -> MissionExecutionBudget:
        """Reserve one dispatch claim; the caller supplies the active transaction."""
        current = self._repo.get(mission_id, mission_revision)
        if current is None:
            raise MissionExecutionBudgetError("no execution budget for this mission revision")
        if current.consumed_dispatch_claims >= current.max_dispatch_claims:
            raise MissionExecutionBudgetError("mission execution budget exhausted")
        updated = self._finalize(
            current.model_copy(
                update={
                    "budget_version": current.budget_version + 1,
                    "consumed_dispatch_claims": current.consumed_dispatch_claims + 1,
                    "updated_at": self._clock.now(),
                }
            )
        )
        self._repo.update(updated, expected_version=current.budget_version, guard=self._guard)
        return updated

    def get(self, mission_id: str, mission_revision: int) -> MissionExecutionBudget | None:
        return self._repo.get(mission_id, mission_revision)

    def _finalize(self, budget: MissionExecutionBudget) -> MissionExecutionBudget:
        return finalize_object_digest(
            budget, digest_field="record_digest", digest_name="mission_execution_budget_digest",
            digest_service=self._ds,
        )
