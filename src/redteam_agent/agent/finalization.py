"""Goal-gated FINALIZING workflow with audit and witness verification."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from redteam_agent.agent.outcome_accounting import ExecutionOutcomeAccountingService
from redteam_agent.agent.unresolved import UnresolvedItemService
from redteam_agent.audit.critical_witness import CriticalWitnessBarrier
from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AgentLoopError
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.mission.manager import MissionManager
from redteam_agent.mission.models import MissionState
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionResultRepository,
    RawControlMetadataRepository,
)
from redteam_agent.storage.repositories import MissionStateRepository

_ACTIVE = frozenset({
    "PLANNED", "AUTHORIZED", "DISPATCH_CLAIMED", "DISPATCHED", "RUNNING",
    "CANCEL_REQUESTED", "RECONCILING", "OUTCOME_UNKNOWN",
})
_INTENT_NS = "mission_finalization_intent"


class FinalizationIntent(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    target_state: Literal["COMPLETED", "ABORTED"]
    reason_code: Literal["GOAL_ACHIEVED", "HARD_LIMIT"]
    intent_digest: str = Field(min_length=1)


class FinalizationService:
    def __init__(
        self, *, goal_service: GoalEvaluationService, mission_manager: MissionManager,
        state_repository: MissionStateRepository,
        execution_repository: ExecutionRecordRepository,
        result_repository: ExecutionResultRepository,
        outcome_accounting: ExecutionOutcomeAccountingService,
        control_metadata_repository: RawControlMetadataRepository,
        database: Database, unresolved_items: UnresolvedItemService,
        audit_store: AuditStore, witness_barrier: CriticalWitnessBarrier,
        operator_actor_token: str, digest_service: DigestService,
    ) -> None:
        self._goals = goal_service
        self._manager = mission_manager
        self._states = state_repository
        self._executions = execution_repository
        self._results = result_repository
        self._outcomes = outcome_accounting
        self._control = control_metadata_repository
        self._db = database
        self._unresolved = unresolved_items
        self._audit = audit_store
        self._witness = witness_barrier
        self._operator_actor_token = operator_actor_token
        self._ds = digest_service

    def finalize(self, mission_id: str) -> MissionState:
        self.begin_completion(mission_id)
        return self._finish(mission_id)

    def abort(self, mission_id: str) -> MissionState:
        self.begin_abort(mission_id)
        return self._finish(mission_id)

    def resume(self, mission_id: str) -> MissionState | None:
        state = self._states.get(mission_id)
        if state is None or state.state != "FINALIZING":
            return None
        return self._finish(mission_id)

    def begin_completion(self, mission_id: str) -> MissionState:
        goal = self._goals.refresh_for_finalization(mission_id=mission_id)
        if goal.status.status != "achieved":
            raise AgentLoopError("mission cannot finalize before its current goal is achieved")
        return self._begin(mission_id, target_state="COMPLETED", reason_code="GOAL_ACHIEVED")

    def begin_abort(self, mission_id: str) -> MissionState:
        self._goals.refresh_for_finalization(mission_id=mission_id)
        return self._begin(mission_id, target_state="ABORTED", reason_code="HARD_LIMIT")

    def active_execution_ids(self, mission_id: str) -> tuple[str, ...]:
        return tuple(
            item.execution_id
            for item in self._executions.all_for_mission(mission_id)
            if item.provider_execution_state in _ACTIVE
        )

    def is_finalizing(self, mission_id: str) -> bool:
        state = self._states.get(mission_id)
        return state is not None and state.state == "FINALIZING"

    def wait_for_human_review(self, mission_id: str) -> MissionState:
        state = self._states.get(mission_id)
        if state is None or state.state != "FINALIZING":
            raise AgentLoopError("human review requires a FINALIZING mission")
        return self._manager.wait_for_human_review(
            mission_id,
            expected_version=state.mission_state_version,
            actor_token=self._operator_actor_token,
        )

    def _begin(
        self,
        mission_id: str,
        *,
        target_state: Literal["COMPLETED", "ABORTED"],
        reason_code: Literal["GOAL_ACHIEVED", "HARD_LIMIT"],
    ) -> MissionState:
        state = self._states.get(mission_id)
        if state is None or state.state not in {"RUNNING", "PAUSED", "FINALIZING"}:
            raise AgentLoopError("mission is not ready to enter FINALIZING")
        fields = {
            "mission_id": mission_id,
            "target_state": target_state,
            "reason_code": reason_code,
        }
        intent = FinalizationIntent.model_validate(
            {
                **fields,
                "intent_digest": self._ds.compute("mission_finalization_intent_digest", fields),
            }
        )
        with UnitOfWork(self._db):
            self._db.occ_insert_idempotent(
                _INTENT_NS,
                mission_id,
                1,
                json.dumps(intent.model_dump(mode="json"), sort_keys=True),
            )
        if state.state == "FINALIZING":
            return state
        return self._manager.begin_finalization(
            mission_id,
            expected_version=state.mission_state_version,
            actor_token=self._operator_actor_token,
        )

    def _finish(self, mission_id: str) -> MissionState:
        intent = self._intent(mission_id)
        goal = self._goals.refresh_for_finalization(mission_id=mission_id)
        if intent.target_state == "COMPLETED" and goal.status.status != "achieved":
            raise AgentLoopError("mission cannot complete before its current goal is achieved")
        executions = self._executions.all_for_mission(mission_id)
        for item in executions:
            if item.provider_execution_state in _ACTIVE:
                raise AgentLoopError("mission cannot finalize with an active execution")
            if item.provider_execution_state != "BLOCKED" and self._results.get(item.execution_id) is None:
                raise AgentLoopError("mission cannot finalize before result ingestion completes")
            if item.provider_execution_state != "BLOCKED" and item.result_ingestion_state != "SUCCEEDED":
                raise AgentLoopError("mission cannot finalize before verified erasure completes")
            if item.provider_execution_state != "BLOCKED":
                control = self._control.find_by_execution(item.execution_id)
                if control is None:
                    raise AgentLoopError("mission cannot finalize before result collection completes")
        if any(item.status != "RESOLVED" for item in self._unresolved.current(mission_id)):
            raise AgentLoopError("mission cannot finalize with unresolved items")
        state = self._states.get(mission_id)
        if state is None or state.state != "FINALIZING":
            raise AgentLoopError("mission finalization was not started")
        self._outcomes.reconcile(
            mission_id=mission_id, mission_revision=state.mission_revision
        )
        finalizing = state
        refreshed_goal = self._goals.refresh_for_finalization(mission_id=mission_id)
        if intent.target_state == "COMPLETED" and refreshed_goal.status.status != "achieved":
            raise AgentLoopError("mission goal changed while entering FINALIZING")
        if any(
            item.provider_execution_state in _ACTIVE
            or (
                item.provider_execution_state != "BLOCKED"
                and item.result_ingestion_state != "SUCCEEDED"
            )
            for item in self._executions.all_for_mission(mission_id)
        ):
            raise AgentLoopError("mission execution state changed while entering FINALIZING")
        if any(item.status != "RESOLVED" for item in self._unresolved.current(mission_id)):
            raise AgentLoopError("unresolved items changed while entering FINALIZING")
        self._outcomes.reconcile(
            mission_id=mission_id, mission_revision=finalizing.mission_revision
        )
        self._audit.verify_chain(mission_id)
        self._witness.verify_current_security_state()
        terminal = (
            self._manager.complete_mission(
                mission_id,
                expected_version=finalizing.mission_state_version,
                actor_token=self._operator_actor_token,
            )
            if intent.target_state == "COMPLETED"
            else self._manager.abort_mission(
                mission_id,
                expected_version=finalizing.mission_state_version,
                actor_token=self._operator_actor_token,
            )
        )
        self._audit.verify_chain(mission_id)
        self._witness.verify_current_security_state()
        return terminal

    def _intent(self, mission_id: str) -> FinalizationIntent:
        row = self._db.occ_get(_INTENT_NS, mission_id)
        if row is None or row[0] != 1:
            raise AgentLoopError("mission finalization intent is missing")
        intent = FinalizationIntent.model_validate_json(row[1])
        if intent.mission_id != mission_id:
            raise AgentLoopError("mission finalization intent identity mismatch")
        payload = intent.model_dump(mode="python")
        expected = payload.pop("intent_digest")
        self._ds.verify("mission_finalization_intent_digest", payload, expected)
        return intent
