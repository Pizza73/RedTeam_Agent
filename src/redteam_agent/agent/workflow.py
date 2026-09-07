"""Coarse, checkpoint-safe Phase 1 Agent workflow caller."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from redteam_agent.agent.application import ActionTransitionResult, PlannerActionApplicationService
from redteam_agent.agent.controller import AgentController
from redteam_agent.agent.llm_gateway import SharedLLMGateway
from redteam_agent.agent.models import ControllerDecision, PlannerContextEnvelope
from redteam_agent.agent.planner_context import PlannerContextService
from redteam_agent.errors import AgentLoopError
from redteam_agent.knowledge.models import KnowledgeObservation
from redteam_agent.knowledge.reducer import KnowledgeReducer
from redteam_agent.plan.models import PlannerActionOutput, PlannerContextRequest, PlannerOutput


@dataclass(frozen=True)
class PlanningOperationIds:
    operation_id: str
    plan_id: str
    run_id: str
    thread_id: str
    decision_id: str
    execution_id: str
    task_id: str


@dataclass(frozen=True)
class WorkflowStepResult:
    controller_decision: ControllerDecision
    planner_output: PlannerOutput | None
    action_transition: ActionTransitionResult | None


class Phase1AgentWorkflow:
    """Runs one bounded coarse node; repositories remain the only source of truth."""

    def __init__(
        self, *, controller: AgentController, llm_gateway: SharedLLMGateway,
        planner_context_service: PlannerContextService,
        action_service: PlannerActionApplicationService,
        knowledge_reducer: KnowledgeReducer,
    ) -> None:
        self._controller = controller
        self._gateway = llm_gateway
        self._contexts = planner_context_service
        self._actions = action_service
        self._reducer = knowledge_reducer

    def run_planning_iteration(
        self, *, envelope: PlannerContextEnvelope, ids: PlanningOperationIds,
        invoke_planner: Callable[[], object],
    ) -> WorkflowStepResult:
        decision = self._controller.step(
            mission_id=envelope.mission_id, operation_id=ids.operation_id,
            projection=envelope.action_candidate_projection,
        )
        if decision.action != "PLAN":
            return WorkflowStepResult(decision, None, None)
        output = self._gateway.invoke_planner(
            operation_id=ids.operation_id, envelope=envelope, invoke=invoke_planner
        )
        if isinstance(output, PlannerContextRequest):
            self._contexts.accept_context_request(
                planner_context_id=envelope.planner_context_id, output=output
            )
            return WorkflowStepResult(decision, output, None)
        if not isinstance(output, PlannerActionOutput):
            raise AgentLoopError("Planner returned an unsupported output type")
        transition = self._actions.execute(
            planner_context_id=envelope.planner_context_id, output=output,
            plan_id=ids.plan_id, run_id=ids.run_id, thread_id=ids.thread_id,
            decision_id=ids.decision_id, execution_id=ids.execution_id,
            task_id=ids.task_id,
        )
        return WorkflowStepResult(decision, output, transition)

    def run_analysis(
        self, *, mission_id: str, mission_revision: int, operation_id: str,
        execution_id: str, result_digest: str, invoke_analyzer: Callable[[], object],
    ) -> KnowledgeObservation:
        candidate = self._gateway.invoke_analyzer(
            mission_id=mission_id, mission_revision=mission_revision,
            operation_id=operation_id, execution_id=execution_id,
            result_digest=result_digest, invoke=invoke_analyzer,
        )
        return self._reducer.reduce(candidate)
