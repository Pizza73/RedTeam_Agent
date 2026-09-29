"""Durable mission execution budget (SystemDesign §27.1).

A per-mission dispatch budget is persisted and consumed with OCC, never counted
in memory. Reservation increments the consumed count against an expected budget
version; a stale version conflicts and an exhausted budget fails closed. This is
the durable substrate the agent loop uses for bounded execution (Phase 1); Phase
0B provides and verifies the record, OCC and reservation semantics.
"""

from __future__ import annotations

import json
from datetime import datetime

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import ClockIntegrityError, MissionExecutionBudgetError
from redteam_agent.execution.models import MissionExecutionBudget, RuntimeSegment
from redteam_agent.execution.records import finalize_object_digest
from redteam_agent.runtime.clock import Clock, ClockIntegrityGuard
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork
from redteam_agent.storage.execution_repositories import MissionExecutionBudgetRepository
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import MissionLifecycleEventRepository

_RUNTIME_SEGMENT_NS = "mission_runtime_segment"


class MissionExecutionBudgetService:
    def __init__(
        self,
        *,
        database: Database,
        repository: MissionExecutionBudgetRepository,
        clock: Clock,
        digest_service: DigestService,
        write_guard: WriteGuard,
        lifecycle_event_repository: MissionLifecycleEventRepository,
    ) -> None:
        self._db = database
        self._repo = repository
        self._clock = clock
        self._ds = digest_service
        self._guard = write_guard
        self._lifecycle_events = lifecycle_event_repository
        self._runtime_clock: ClockIntegrityGuard | None = None
        self._boot_identity: str | None = None

    def bind_runtime_clock(
        self, *, clock_guard: ClockIntegrityGuard, boot_identity: str,
    ) -> None:
        if self._runtime_clock is clock_guard and self._boot_identity == boot_identity:
            return
        if self._runtime_clock is not None or not boot_identity:
            raise MissionExecutionBudgetError("mission runtime clock is already or invalidly bound")
        self._runtime_clock = clock_guard
        self._boot_identity = boot_identity

    def create_budget(
        self, *, mission_id: str, mission_revision: int, max_dispatch_claims: int
    ) -> MissionExecutionBudget:
        budget = self._finalize(
            MissionExecutionBudget(
                mission_id=mission_id, mission_revision=mission_revision, budget_version=1,
                max_dispatch_claims=max_dispatch_claims, consumed_dispatch_claims=0,
                updated_at=self._trusted_now(), record_digest="pending",
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
                    "updated_at": self._trusted_now(),
                }
            )
        )
        self._repo.update(updated, expected_version=current.budget_version, guard=self._guard)
        self._db.record_critical_mutation(
            CriticalMutation(
                mission_id=updated.mission_id,
                event_type="MISSION_BUDGET_CHANGED",
                actor_id="mission-budget-service",
                occurred_at_iso=updated.updated_at.isoformat(),
                record_type="mission_execution_budget",
                record_id=f"{updated.mission_id}/{updated.mission_revision}",
                state_version=updated.budget_version,
                security_projection_digest=updated.record_digest,
            )
        )
        return updated

    def get(self, mission_id: str, mission_revision: int) -> MissionExecutionBudget | None:
        return self._repo.get(mission_id, mission_revision)

    def reserve_planner_in_txn(
        self, *, mission_id: str, mission_revision: int, max_iterations: int,
    ) -> MissionExecutionBudget:
        """Reserve a logical Planner call with its gateway input identity transaction.

        Dispatch and Planner counters are independent. A crash never refunds this
        reservation, and a gateway replay must use its already reserved identity.
        """
        current = self._repo.get(mission_id, mission_revision)
        if current is None or current.consumed_planner_invocations >= max_iterations:
            raise MissionExecutionBudgetError("mission Planner iteration budget exhausted")
        updated = self._finalize(current.model_copy(update={
            "budget_version": current.budget_version + 1,
            "consumed_planner_invocations": current.consumed_planner_invocations + 1,
            "updated_at": self._trusted_now(),
        }))
        self._repo.update(updated, expected_version=current.budget_version, guard=self._guard)
        self._db.record_critical_mutation(CriticalMutation(
            mission_id=mission_id, event_type="MISSION_BUDGET_CHANGED",
            actor_id="mission-budget-service", occurred_at_iso=updated.updated_at.isoformat(),
            record_type="mission_execution_budget", record_id=f"{mission_id}/{mission_revision}",
            state_version=updated.budget_version, security_projection_digest=updated.record_digest,
        ))
        return updated

    def reserve_analyzer_in_txn(
        self, *, mission_id: str, mission_revision: int,
    ) -> MissionExecutionBudget:
        """Reserve one Analyzer call, bounded by the external execution budget."""
        current = self._repo.get(mission_id, mission_revision)
        if (
            current is None
            or current.consumed_analyzer_invocations >= current.max_dispatch_claims
        ):
            raise MissionExecutionBudgetError("mission Analyzer invocation budget exhausted")
        updated = self._finalize(current.model_copy(update={
            "budget_version": current.budget_version + 1,
            "consumed_analyzer_invocations": current.consumed_analyzer_invocations + 1,
            "updated_at": self._trusted_now(),
        }))
        self._repo.update(updated, expected_version=current.budget_version, guard=self._guard)
        self._record_mutation(updated)
        return updated

    def account_runtime(
        self, *, mission_id: str, mission_revision: int, active: bool,
    ) -> MissionExecutionBudget:
        """Durably account the current active interval and open/close its segment."""
        with UnitOfWork(self._db):
            return self._account_runtime_in_txn(
                mission_id=mission_id, mission_revision=mission_revision, active=active,
            )

    def _account_runtime_in_txn(
        self, *, mission_id: str, mission_revision: int, active: bool,
    ) -> MissionExecutionBudget:
        if self._runtime_clock is None or self._boot_identity is None:
            raise MissionExecutionBudgetError("mission runtime clock is not bound")
        current = self._repo.get(mission_id, mission_revision)
        if current is None:
            raise MissionExecutionBudgetError("no execution budget for this mission revision")
        reading = self._runtime_clock.read()
        segments = self._segments(mission_id, mission_revision)
        open_segments = tuple(item for item in segments if item.closed_at is None)
        if len(open_segments) > 1:
            raise ClockIntegrityError("mission has overlapping active runtime segments")
        open_segment = open_segments[0] if open_segments else None
        changed = False
        delta_seconds = 0.0
        updated_segment: RuntimeSegment | None = None
        new_segment = False

        if open_segment is not None:
            if reading.utc < open_segment.accounted_until:
                raise ClockIntegrityError("runtime UTC moved behind its durable boundary")
            same_boot = (
                open_segment.boot_identity == self._boot_identity
                and reading.monotonic_ns >= open_segment.accounted_monotonic_ns
            )
            if same_boot:
                delta_seconds = (
                    reading.monotonic_ns - open_segment.accounted_monotonic_ns
                ) / 1_000_000_000
            else:
                # A process/host restart loses the earlier monotonic origin. The
                # trusted UTC boundary is used conservatively and is never allowed
                # to move backwards.
                delta_seconds = (reading.utc - open_segment.accounted_until).total_seconds()
            updated_segment = self._finalize_segment(open_segment.model_copy(update={
                "accounted_until": reading.utc,
                "accounted_monotonic_ns": (
                    reading.monotonic_ns
                    if same_boot else open_segment.accounted_monotonic_ns
                ),
                "closed_at": None if active else reading.utc,
                "accounted_seconds": open_segment.accounted_seconds + delta_seconds,
            }))
            changed = delta_seconds > 0 or not active
        elif active:
            prior_exists = bool(segments)
            started_at = reading.utc if prior_exists else self._running_started_at(
                mission_id, reading.utc
            )
            elapsed = (reading.utc - started_at).total_seconds()
            if elapsed < 0:
                # The Phase 0C clock guard permits at most five seconds of
                # wall/monotonic skew. Mission start and the first runtime read
                # are separate trusted reads, so normalize only that bounded
                # construction skew; a larger future start remains a failure.
                if elapsed < -5.0:
                    raise ClockIntegrityError("runtime segment starts in the future")
                started_at = reading.utc
                elapsed = 0.0
            elapsed_ns = int(elapsed * 1_000_000_000)
            if elapsed_ns <= reading.monotonic_ns:
                segment_boot = self._boot_identity
                started_monotonic_ns = reading.monotonic_ns - elapsed_ns
            else:
                # The active interval began before the current boot. Keep that
                # fact explicit so subsequent accounting continues by trusted UTC.
                segment_boot = f"utc-recovered:{self._boot_identity}"
                started_monotonic_ns = 0
            sequence = len(segments) + 1
            updated_segment = self._finalize_segment(RuntimeSegment(
                segment_id=f"runtime-{mission_id}-{mission_revision}-{sequence}",
                mission_id=mission_id, mission_revision=mission_revision,
                boot_identity=segment_boot, started_at=started_at,
                started_monotonic_ns=started_monotonic_ns,
                accounted_until=reading.utc, accounted_monotonic_ns=reading.monotonic_ns,
                closed_at=None, accounted_seconds=elapsed, record_digest="pending",
            ))
            delta_seconds = elapsed
            changed = True
            new_segment = True

        if not changed or updated_segment is None:
            return current
        updated = self._finalize(current.model_copy(update={
            "budget_version": current.budget_version + 1,
            "active_runtime_seconds": current.active_runtime_seconds + delta_seconds,
            "updated_at": reading.utc,
        }))
        self._repo.update(updated, expected_version=current.budget_version, guard=self._guard)
        text = json.dumps(updated_segment.model_dump(mode="json"), sort_keys=True)
        if new_segment:
            self._db.occ_insert(_RUNTIME_SEGMENT_NS, updated_segment.segment_id, 1, text)
        else:
            row = self._db.occ_get(_RUNTIME_SEGMENT_NS, updated_segment.segment_id)
            if row is None:
                raise ClockIntegrityError("open runtime segment disappeared")
            self._db.occ_update(
                _RUNTIME_SEGMENT_NS, updated_segment.segment_id,
                expected_version=row[0], new_version=row[0] + 1, json_text=text,
            )
        self._record_mutation(updated)
        return updated

    def _segments(self, mission_id: str, mission_revision: int) -> tuple[RuntimeSegment, ...]:
        segments: list[RuntimeSegment] = []
        for row_key, _version, raw in self._db.occ_get_all(_RUNTIME_SEGMENT_NS):
            segment = RuntimeSegment.model_validate_json(raw)
            payload = segment.model_dump(mode="python")
            expected = payload.pop("record_digest")
            self._ds.verify("runtime_segment_digest", payload, expected)
            if segment.segment_id != row_key:
                raise ClockIntegrityError("runtime segment row identity mismatch")
            if segment.mission_id == mission_id and segment.mission_revision == mission_revision:
                segments.append(segment)
        return tuple(sorted(segments, key=lambda item: (item.started_at, item.segment_id)))

    def _running_started_at(
        self, mission_id: str, fallback: datetime,
    ) -> datetime:
        events = self._lifecycle_events.events_for(mission_id)
        starts = tuple(
            item.occurred_at for item in events
            if item.to_state == "RUNNING" and item.mission_state_version >= 1
        )
        return starts[-1] if starts else fallback

    def _finalize_segment(self, segment: RuntimeSegment) -> RuntimeSegment:
        return finalize_object_digest(
            segment, digest_field="record_digest", digest_name="runtime_segment_digest",
            digest_service=self._ds,
        )

    def _record_mutation(self, updated: MissionExecutionBudget) -> None:
        self._db.record_critical_mutation(CriticalMutation(
            mission_id=updated.mission_id, event_type="MISSION_BUDGET_CHANGED",
            actor_id="mission-budget-service", occurred_at_iso=updated.updated_at.isoformat(),
            record_type="mission_execution_budget",
            record_id=f"{updated.mission_id}/{updated.mission_revision}",
            state_version=updated.budget_version,
            security_projection_digest=updated.record_digest,
        ))

    def _finalize(self, budget: MissionExecutionBudget) -> MissionExecutionBudget:
        return finalize_object_digest(
            budget, digest_field="record_digest", digest_name="mission_execution_budget_digest",
            digest_service=self._ds,
        )

    def _trusted_now(self) -> datetime:
        if self._runtime_clock is not None:
            return self._runtime_clock.read().utc
        return self._clock.now()
