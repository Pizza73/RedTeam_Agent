"""Goal-gated FINALIZING workflow with audit and witness verification."""

from __future__ import annotations

from redteam_agent.agent.outcome_accounting import ExecutionOutcomeAccountingService
from redteam_agent.agent.unresolved import UnresolvedItemService
from redteam_agent.audit.critical_witness import CriticalWitnessBarrier
from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.errors import AgentLoopError
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.mission.manager import MissionManager
from redteam_agent.mission.models import MissionState
from redteam_agent.storage.database import Database
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
        operator_actor_token: str,
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

    def finalize(self, mission_id: str) -> MissionState:
        goal = self._goals.evaluate(mission_id=mission_id)
        if goal.status.status != "achieved":
            raise AgentLoopError("mission cannot finalize before its current goal is achieved")
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
        if state is None or state.state not in {"RUNNING", "FINALIZING"}:
            raise AgentLoopError("mission is not ready to enter FINALIZING")
        self._outcomes.reconcile(
            mission_id=mission_id, mission_revision=state.mission_revision
        )
        finalizing = state
        if state.state == "RUNNING":
            finalizing = self._manager.begin_finalization(
                mission_id, expected_version=state.mission_state_version,
                actor_token=self._operator_actor_token,
            )
        refreshed_goal = self._goals.evaluate(mission_id=mission_id)
        if refreshed_goal.status.status != "achieved":
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
        completed = self._manager.complete_mission(
            mission_id, expected_version=finalizing.mission_state_version,
            actor_token=self._operator_actor_token,
        )
        self._audit.verify_chain(mission_id)
        self._witness.verify_current_security_state()
        return completed
