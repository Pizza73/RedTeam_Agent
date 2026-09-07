"""Goal-gated FINALIZING workflow with audit and witness verification."""

from __future__ import annotations

from redteam_agent.audit.critical_witness import CriticalWitnessBarrier
from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.errors import AgentLoopError
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.mission.manager import MissionManager
from redteam_agent.mission.models import MissionState
from redteam_agent.storage.execution_repositories import ExecutionRecordRepository
from redteam_agent.storage.repositories import MissionStateRepository

_ACTIVE = frozenset({
    "PLANNED", "AUTHORIZED", "DISPATCH_CLAIMED", "DISPATCHED", "RUNNING",
    "CANCEL_REQUESTED", "RECONCILING",
})


class FinalizationService:
    def __init__(
        self, *, goal_service: GoalEvaluationService, mission_manager: MissionManager,
        state_repository: MissionStateRepository,
        execution_repository: ExecutionRecordRepository,
        audit_store: AuditStore, witness_barrier: CriticalWitnessBarrier,
        operator_actor_token: str,
    ) -> None:
        self._goals = goal_service
        self._manager = mission_manager
        self._states = state_repository
        self._executions = execution_repository
        self._audit = audit_store
        self._witness = witness_barrier
        self._operator_actor_token = operator_actor_token

    def finalize(self, mission_id: str) -> MissionState:
        goal = self._goals.evaluate(mission_id=mission_id)
        if goal.status.status != "achieved":
            raise AgentLoopError("mission cannot finalize before its current goal is achieved")
        if any(
            item.provider_execution_state in _ACTIVE
            for item in self._executions.all_for_mission(mission_id)
        ):
            raise AgentLoopError("mission cannot finalize with an active execution")
        state = self._states.get(mission_id)
        if state is None or state.state != "RUNNING":
            raise AgentLoopError("mission is not ready to enter FINALIZING")
        finalizing = self._manager.begin_finalization(
            mission_id, expected_version=state.mission_state_version,
            actor_token=self._operator_actor_token,
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
