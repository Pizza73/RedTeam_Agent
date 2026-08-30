"""Phase 0B finalization entry point; goal completion can never skip FINALIZING."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.mission.manager import MissionManager
from redteam_agent.models.mission import Mission
from redteam_agent.repositories.execution import ExecutionRepository


class FinalizationCoordinator:
    """Begins the common lifecycle before any later completion decision."""

    def __init__(
        self,
        *,
        missions: MissionManager,
        executions: ExecutionRepository,
    ) -> None:
        self.missions = missions
        self.executions = executions

    def begin_for_goal(self, mission_id: str, *, now: datetime) -> Mission:
        """Goal achievement requests FINALIZING, never COMPLETED."""

        return self.missions.finalize(mission_id, now=now)

    def request_finalizing(self, mission_id: str, *, now: datetime) -> None:
        self.missions.finalize(mission_id, now=now)

    def pause_for_result_ingestion_failure(
        self, mission_id: str, *, now: datetime
    ) -> Mission:
        """Route ingestion-failure lifecycle changes through the Mission Manager."""

        return self.missions.pause_for_result_ingestion_failure(mission_id, now=now)

    def pause_for_raw_result_failure(self, mission_id: str, *, now: datetime) -> Mission:
        """Route quarantine/streaming failure lifecycle changes through Mission Manager."""

        return self.missions.pause_for_raw_result_failure(mission_id, now=now)

    def unresolved_execution_ids(self, mission_id: str) -> tuple[str, ...]:
        return tuple(
            record.execution_id for record in self.executions.list_unresolved(mission_id)
        )
