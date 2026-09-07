"""Priority-ordered Phase 1 controller (AI Control §6)."""

from __future__ import annotations

import json

from redteam_agent.agent.models import (
    AgentCheckpoint,
    ControllerAction,
    ControllerDecision,
    ControllerReason,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AgentLoopError
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.mission.models import Mission
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.execution_repositories import MissionExecutionBudgetRepository

_CHECKPOINT_NS = "agent_checkpoint"


class AgentController:
    def __init__(
        self, *, database: Database, digest_service: DigestService, clock: Clock,
        context_resolver: AuthorizationContextResolver, goal_service: GoalEvaluationService,
        budget_repository: MissionExecutionBudgetRepository,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._resolver = context_resolver
        self._goals = goal_service
        self._budgets = budget_repository

    def step(
        self, *, mission_id: str, operation_id: str, candidate_ids: tuple[str, ...] = (),
        active_execution_id: str | None = None, source_refresh_pending: bool = False,
        planning_search_limited: bool = False,
    ) -> ControllerDecision:
        mission = self._resolver.resolve(mission_id, now=self._clock.now()).mission
        if mission.state != "RUNNING":
            return self._save(
                mission=mission, operation_id=operation_id,
                decision=ControllerDecision(
                    action="STOP", reason_code="MISSION_NOT_RUNNING", goal_evaluation_id=None,
                    candidate_ids=(),
                ), active_execution_id=active_execution_id,
            )
        budget = self._budgets.get(mission_id, mission.mission_revision)
        if budget is None:
            raise AgentLoopError("mission execution budget is missing")
        if active_execution_id is not None:
            return self._save(
                mission=mission, operation_id=operation_id,
                decision=ControllerDecision(
                    action="RECOVER", reason_code="EXECUTION_IN_PROGRESS", goal_evaluation_id=None,
                    candidate_ids=(),
                ), active_execution_id=active_execution_id,
            )
        evaluation = self._goals.evaluate(mission_id=mission_id)
        if evaluation.status.status == "achieved":
            action: ControllerAction = "FINALIZE"
            reason: ControllerReason = "GOAL_ACHIEVED"
            selected: tuple[str, ...] = ()
        elif budget.consumed_dispatch_claims >= min(budget.max_dispatch_claims, mission.max_iterations):
            action, reason, selected = "PAUSE", "BUDGET_EXHAUSTED", ()
        elif candidate_ids:
            action, reason, selected = "PLAN", "CANDIDATES_READY", tuple(sorted(set(candidate_ids)))
        elif source_refresh_pending:
            action, reason, selected = "WAIT", "SOURCE_REFRESH_PENDING", ()
        elif planning_search_limited:
            action, reason, selected = "PAUSE", "PLANNING_SEARCH_LIMIT", ()
        else:
            action, reason, selected = "PAUSE", "NO_ACTION_IN_SUPPORTED_MODEL", ()
        return self._save(
            mission=mission, operation_id=operation_id,
            decision=ControllerDecision(
                action=action, reason_code=reason, goal_evaluation_id=evaluation.evaluation_id,
                candidate_ids=selected,
            ), active_execution_id=None,
        )

    def checkpoint(self, mission_id: str) -> AgentCheckpoint | None:
        row = self._db.occ_get(_CHECKPOINT_NS, mission_id)
        if row is None:
            return None
        checkpoint = AgentCheckpoint.model_validate_json(row[1])
        payload = checkpoint.model_dump(mode="python")
        expected = payload.pop("checkpoint_digest")
        self._ds.verify("agent_checkpoint_digest", payload, expected)
        if checkpoint.mission_id != mission_id:
            raise AgentLoopError("checkpoint row identity mismatch")
        return checkpoint

    def _save(self, *, mission: Mission, operation_id: str, decision: ControllerDecision,
              active_execution_id: str | None) -> ControllerDecision:
        budget = self._budgets.get(mission.mission_id, mission.mission_revision)
        iteration = 0 if budget is None else budget.consumed_dispatch_claims
        updated_at = self._clock.now()
        fields = {
            "checkpoint_id": f"checkpoint-{mission.mission_id}", "mission_id": mission.mission_id,
            "mission_revision": mission.mission_revision, "authorization_epoch": mission.authorization_epoch,
            "goal_evaluation_id": decision.goal_evaluation_id, "planner_context_id": None,
            "active_execution_id": active_execution_id, "operation_id": operation_id,
            "iteration_cache": iteration, "updated_at": updated_at,
        }
        checkpoint = AgentCheckpoint(
            checkpoint_id=f"checkpoint-{mission.mission_id}", mission_id=mission.mission_id,
            mission_revision=mission.mission_revision, authorization_epoch=mission.authorization_epoch,
            goal_evaluation_id=decision.goal_evaluation_id, planner_context_id=None,
            active_execution_id=active_execution_id, operation_id=operation_id,
            iteration_cache=iteration, updated_at=updated_at,
            checkpoint_digest=self._ds.compute("agent_checkpoint_digest", fields),
        )
        row = self._db.occ_get(_CHECKPOINT_NS, mission.mission_id)
        text = json.dumps(checkpoint.model_dump(mode="json"), sort_keys=True)
        with UnitOfWork(self._db):
            if row is None:
                self._db.occ_insert(_CHECKPOINT_NS, mission.mission_id, 1, text)
            else:
                self._db.occ_update(
                    _CHECKPOINT_NS, mission.mission_id, expected_version=row[0],
                    new_version=row[0] + 1, json_text=text,
                )
        return decision
