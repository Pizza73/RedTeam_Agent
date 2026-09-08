"""Coarse, checkpoint-safe Phase 1 Agent workflow caller."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TypedDict, cast

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.runtime import Runtime

from redteam_agent.agent.application import (
    ActionTransitionResult,
    PlannerActionApplicationService,
)
from redteam_agent.agent.controller import AgentController
from redteam_agent.agent.finalization import FinalizationService
from redteam_agent.agent.llm_gateway import SharedLLMGateway
from redteam_agent.agent.models import ControllerDecision, PlannerContextEnvelope
from redteam_agent.agent.planner_context import PlannerContextService
from redteam_agent.agent.retry_budget import AgentRetryBudgetService
from redteam_agent.agent.unresolved import UnresolvedItemService, UnresolvedReason
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.context.authorization import ContextAuthorizationService
from redteam_agent.context.builder import ContextBuilder
from redteam_agent.context.selector import ContextSelector
from redteam_agent.erasure.service import VerifiedQuarantineEraser
from redteam_agent.errors import (
    AgentLoopError,
    MissionRevisionConflictError,
    OutputPublicationError,
    RawResultQuarantineError,
    SecureIngestionError,
    VerifiedErasureError,
)
from redteam_agent.execution.adapter import ExecutionAdapter
from redteam_agent.execution.executor import Executor
from redteam_agent.execution.models import AdapterCollectionControl, ProviderTaskBinding
from redteam_agent.execution.reconcile import ReconcileOutcome, ReconciliationService
from redteam_agent.execution.recovery import ExecutionRecoveryService
from redteam_agent.execution.thread import verify_run_thread_binding
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.ingestion.service import SecureIngestionService
from redteam_agent.knowledge.models import (
    AnalyzerCandidateObservation,
    KnowledgeObservation,
    VerifiedFinding,
)
from redteam_agent.knowledge.reducer import KnowledgeReducer
from redteam_agent.knowledge.verified_facts import VerifiedFindingProjector
from redteam_agent.mission.models import MissionLifecycleState, MissionState
from redteam_agent.plan.models import (
    PlannerActionOutput,
    PlannerContextRequest,
    PlannerOutput,
)
from redteam_agent.quarantine.collection import (
    QuarantineCollectionResult,
    QuarantineCollectionService,
)
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.execution_repositories import (
    CancelAttemptRepository,
    ExecutionRecordRepository,
    ExecutionResultRepository,
    RawControlMetadataRepository,
    ResultIngestionStateRepository,
    ResultTaskBindingRepository,
)


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


class _PlanningGraphState(TypedDict, total=False):
    mission_id: str
    operation_id: str
    planner_context_id: str
    goal_evaluation_id: str
    controller_action: str
    controller_reason: str
    planner_output_kind: str


@dataclass
class _PlanningResultSink:
    controller_decision: ControllerDecision | None = None
    planner_output: PlannerOutput | None = None
    action_transition: ActionTransitionResult | None = None


@dataclass(frozen=True)
class _PlanningRuntime:
    envelope: PlannerContextEnvelope
    ids: PlanningOperationIds
    invoke_planner: Callable[[PlannerContextEnvelope], object]
    sink: _PlanningResultSink


class _AnalysisGraphState(TypedDict, total=False):
    mission_id: str
    operation_id: str
    execution_id: str
    context_grant_id: str
    selected_resource_ids: tuple[str, ...]
    context_grant_digest: str
    observation_id: str
    goal_evaluation_id: str


@dataclass
class _AnalysisResultSink:
    authorized_context: CanonicalJsonObject | None = None
    candidate: AnalyzerCandidateObservation | None = None
    observation: KnowledgeObservation | None = None


@dataclass(frozen=True)
class _AnalysisRuntime:
    mission_id: str
    mission_revision: int
    operation_id: str
    execution_id: str
    result_digest: str
    context_grant_id: str
    invoke_analyzer: Callable[[], object]
    sink: _AnalysisResultSink


# Provider execution states that a durable resume still reconciles. Terminal
# states (including OUTCOME_UNKNOWN and BLOCKED) are never re-read or re-sent.
_RESUME_RECONCILE_STATES = frozenset(
    {
        "AUTHORIZED",
        "DISPATCH_CLAIMED",
        "DISPATCHED",
        "RUNNING",
        "CANCEL_REQUESTED",
        "RECONCILING",
    }
)

# Graph State / Mission State mapping (SystemDesign §17.3). A durable resume
# reports the graph state that corresponds to the *current* mission, never the
# state captured when reconciliation began.
_GRAPH_STATE_BY_MISSION_STATE: dict[MissionLifecycleState, str] = {
    "PAUSED": "PAUSED",
    "WAITING_HUMAN_REVIEW": "WAITING_HUMAN_REVIEW",
    "FINALIZING": "FINALIZING",
    "COMPLETED": "COMPLETED",
    "COMPLETED_WITH_UNRESOLVED_ITEMS": "COMPLETED_WITH_UNRESOLVED_ITEMS",
    "ABORTED": "ABORTED",
    "FAILED": "FAILED",
    "RUNNING": "RUNNING",
}


@dataclass(frozen=True)
class DurableResumeOutcome:
    """Result of a durable resume reconciliation (no new persisted record)."""

    mission_state: MissionLifecycleState
    graph_state: str
    entry_mission_state: MissionLifecycleState
    reconciled: tuple[tuple[str, str], ...]
    advanced_to_finalizing: bool


class Phase1AgentWorkflow:
    """Runs one bounded coarse node; repositories remain the only source of truth."""

    def __init__(
        self, *, controller: AgentController, llm_gateway: SharedLLMGateway,
        planner_context_service: PlannerContextService,
        action_service: PlannerActionApplicationService,
        knowledge_reducer: KnowledgeReducer,
        collection_service: QuarantineCollectionService,
        ingestion_service: SecureIngestionService,
        eraser: VerifiedQuarantineEraser,
        reconciliation: ReconciliationService,
        recovery_service: ExecutionRecoveryService,
        retry_budget_service: AgentRetryBudgetService,
        execution_repository: ExecutionRecordRepository,
        result_repository: ExecutionResultRepository,
        task_binding_repository: ResultTaskBindingRepository,
        cancel_attempt_repository: CancelAttemptRepository,
        ingestion_repository: ResultIngestionStateRepository,
        control_metadata_repository: RawControlMetadataRepository,
        unresolved_items: UnresolvedItemService,
        adapters: Mapping[str, ExecutionAdapter],
        executor: Executor,
        finalization: FinalizationService,
        goal_service: GoalEvaluationService,
        context_selector: ContextSelector,
        context_authorization_service: ContextAuthorizationService,
        context_builder: ContextBuilder,
        digest_service: DigestService,
        checkpointer: SqliteSaver,
        verified_finding_projector: VerifiedFindingProjector,
        context_resolver: AuthorizationContextResolver,
        clock: Clock,
    ) -> None:
        self._controller = controller
        self._gateway = llm_gateway
        self._contexts = planner_context_service
        self._actions = action_service
        self._reducer = knowledge_reducer
        self._collection, self._ingestion = collection_service, ingestion_service
        self._eraser, self._reconciliation = eraser, reconciliation
        self._recovery = recovery_service
        self._retry_budgets = retry_budget_service
        self._executions = execution_repository
        self._results = result_repository
        self._bindings = task_binding_repository
        self._cancel_attempts = cancel_attempt_repository
        self._ingestion_states = ingestion_repository
        self._control = control_metadata_repository
        self._unresolved = unresolved_items
        self._adapters = dict(adapters)
        self._executor = executor
        self._finalization = finalization
        self._goals = goal_service
        self._context_selector = context_selector
        self._context_authorization = context_authorization_service
        self._context_builder = context_builder
        self._digests = digest_service
        self._checkpointer = checkpointer
        self._verified_findings = verified_finding_projector
        self._resolver = context_resolver
        self._clock = clock
        self.graph = self._build_planning_graph()
        self.analysis_graph = self._build_analysis_graph()

    def run_planning_iteration(
        self, *, envelope: PlannerContextEnvelope, ids: PlanningOperationIds,
        invoke_planner: Callable[[PlannerContextEnvelope], object],
    ) -> WorkflowStepResult:
        current_revision = self._contexts.current_mission_revision(envelope.mission_id)
        if envelope.mission_revision != current_revision:
            raise MissionRevisionConflictError(
                "planner context mission revision is not current"
            )
        verify_run_thread_binding(
            thread_id=ids.thread_id,
            run_id=ids.run_id,
            mission_id=envelope.mission_id,
            mission_revision=current_revision,
        )
        sink = _PlanningResultSink()
        cast(
            _PlanningGraphState,
            self.graph.invoke(
                {
                    "mission_id": envelope.mission_id,
                    "operation_id": ids.operation_id,
                    "planner_context_id": envelope.planner_context_id,
                },
                config={"configurable": {"thread_id": ids.thread_id}},
                context=_PlanningRuntime(
                    envelope=envelope, ids=ids, invoke_planner=invoke_planner, sink=sink
                ),
            ),
        )
        decision = sink.controller_decision
        if decision is None:
            raise AgentLoopError("agent graph returned no controller decision")
        return WorkflowStepResult(
            decision,
            sink.planner_output,
            sink.action_transition,
        )

    def run_analysis(
        self, *, mission_id: str, mission_revision: int, operation_id: str,
        execution_id: str, result_digest: str, invoke_analyzer: Callable[[], object],
        context_grant_id: str, run_id: str, thread_id: str,
    ) -> KnowledgeObservation:
        current_revision = self._contexts.current_mission_revision(mission_id)
        if mission_revision != current_revision:
            raise MissionRevisionConflictError("Analyzer mission revision is not current")
        verify_run_thread_binding(
            thread_id=thread_id,
            run_id=run_id,
            mission_id=mission_id,
            mission_revision=current_revision,
        )
        sink = _AnalysisResultSink()
        cast(
            _AnalysisGraphState,
            self.analysis_graph.invoke(
                {
                    "mission_id": mission_id,
                    "operation_id": operation_id,
                    "execution_id": execution_id,
                    "context_grant_id": context_grant_id,
                },
                config={"configurable": {"thread_id": thread_id}},
                context=_AnalysisRuntime(
                    mission_id=mission_id,
                    mission_revision=mission_revision,
                    operation_id=operation_id,
                    execution_id=execution_id,
                    result_digest=result_digest,
                    context_grant_id=context_grant_id,
                    invoke_analyzer=invoke_analyzer,
                    sink=sink,
                ),
            ),
        )
        observation = sink.observation
        if observation is None:
            raise AgentLoopError("analysis graph returned no observation")
        return observation

    def _build_planning_graph(
        self,
    ) -> CompiledStateGraph[
        _PlanningGraphState, _PlanningRuntime, _PlanningGraphState, _PlanningGraphState
    ]:
        builder = StateGraph(_PlanningGraphState, context_schema=_PlanningRuntime)
        builder.add_node("session_refresh", self._graph_session_refresh)  # type: ignore[call-overload]
        builder.add_node("controller", self._graph_controller)  # type: ignore[call-overload]
        builder.add_node("context_rebuild", self._graph_context_rebuild)
        builder.add_node("context_selector", self._graph_context_selector)
        builder.add_node("context_authorization", self._graph_context_authorization)
        builder.add_node("context_builder", self._graph_context_builder)
        builder.add_node("tool_availability", self._graph_tool_availability)
        builder.add_node("planner", self._graph_planner)
        builder.add_node("context_request", self._graph_context_request)
        builder.add_node("action_application", self._graph_action_application)
        builder.add_node("reconciliation", self._graph_reconciliation)  # type: ignore[call-overload]
        builder.add_node("finalization", self._graph_finalization)
        builder.add_edge(START, "session_refresh")
        builder.add_edge("session_refresh", "controller")
        builder.add_conditional_edges(
            "controller",
            self._planning_route,
            {
                "plan": "context_rebuild",
                "recover": "reconciliation",
                "finalize": "finalization",
                "stop": "finalization",
                "end": END,
            },
        )
        builder.add_edge("context_rebuild", "context_selector")
        builder.add_edge("context_selector", "context_authorization")
        builder.add_edge("context_authorization", "context_builder")
        builder.add_edge("context_builder", "tool_availability")
        builder.add_edge("tool_availability", "planner")
        builder.add_conditional_edges(
            "planner",
            self._planner_output_route,
            {"context_request": "context_request", "action": "action_application"},
        )
        builder.add_edge("context_request", END)
        builder.add_edge("action_application", END)
        builder.add_edge("reconciliation", END)
        builder.add_edge("finalization", END)
        return cast(
            CompiledStateGraph[
                _PlanningGraphState,
                _PlanningRuntime,
                _PlanningGraphState,
                _PlanningGraphState,
            ],
            builder.compile(checkpointer=self._checkpointer),
        )

    def _build_analysis_graph(
        self,
    ) -> CompiledStateGraph[
        _AnalysisGraphState, _AnalysisRuntime, _AnalysisGraphState, _AnalysisGraphState
    ]:
        builder = StateGraph(_AnalysisGraphState, context_schema=_AnalysisRuntime)
        builder.add_node("analysis_source_binding", self._graph_analysis_source_binding)  # type: ignore[call-overload]
        builder.add_node("analyzer_context_selector", self._graph_analyzer_context_selector)  # type: ignore[call-overload]
        builder.add_node(
            "analyzer_context_authorization", self._graph_analyzer_context_authorization
        )
        builder.add_node("analyzer_context_builder", self._graph_analyzer_context_builder)  # type: ignore[call-overload]
        builder.add_node("analyzer", self._graph_analyzer)
        builder.add_node("knowledge_reducer", self._graph_knowledge_reducer)
        builder.add_node(  # type: ignore[call-overload]
            "post_analysis_session_refresh", self._graph_analysis_session_refresh
        )
        builder.add_node("goal_evaluation", self._graph_goal_evaluation)
        builder.add_edge(START, "analysis_source_binding")
        builder.add_edge("analysis_source_binding", "analyzer_context_selector")
        builder.add_edge("analyzer_context_selector", "analyzer_context_authorization")
        builder.add_edge("analyzer_context_authorization", "analyzer_context_builder")
        builder.add_edge("analyzer_context_builder", "analyzer")
        builder.add_edge("analyzer", "knowledge_reducer")
        builder.add_edge("knowledge_reducer", "post_analysis_session_refresh")
        builder.add_edge("post_analysis_session_refresh", "goal_evaluation")
        builder.add_edge("goal_evaluation", END)
        return cast(
            CompiledStateGraph[
                _AnalysisGraphState,
                _AnalysisRuntime,
                _AnalysisGraphState,
                _AnalysisGraphState,
            ],
            builder.compile(checkpointer=self._checkpointer),
        )

    def _graph_analysis_source_binding(
        self, _state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> _AnalysisGraphState:
        context = runtime.context
        execution = self._executions.get(context.execution_id)
        result = self._results.get(context.execution_id)
        if (
            execution is None
            or result is None
            or execution.mission_id != context.mission_id
            or execution.mission_revision != context.mission_revision
            or result.execution_id != execution.execution_id
            or result.status != "SUCCEEDED"
        ):
            raise AgentLoopError("Analyzer source is not the requested current successful result")
        expected = self._digests.compute(
            "execution_outcome_source_digest", result.model_dump(mode="python")
        )
        if context.result_digest != expected:
            raise AgentLoopError("Analyzer result digest is not bound to the requested execution")
        return {}

    def _graph_analyzer_context_selector(
        self, _state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> _AnalysisGraphState:
        selected = self._context_selector.select_authorizable_resource_ids(
            runtime.context.mission_id, frozenset()
        )
        return {"selected_resource_ids": selected}

    def _graph_analyzer_context_authorization(
        self, state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> _AnalysisGraphState:
        context = runtime.context
        grant = self._context_authorization.verify_grant(
            grant_id=context.context_grant_id,
            mission_id=context.mission_id,
        )
        if grant.service_identity != "analyzer_context":
            raise AgentLoopError("Analyzer requires an analyzer_context grant")
        selected = frozenset(state["selected_resource_ids"])
        granted = frozenset(item.resource.resource_id for item in grant.resources)
        if not granted <= selected:
            raise AgentLoopError("Analyzer grant contains a resource outside current selection")
        return {"context_grant_digest": grant.grant_digest}

    def _graph_analyzer_context_builder(
        self, _state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> _AnalysisGraphState:
        context = runtime.context
        body = self._context_builder.build(
            grant_id=context.context_grant_id,
            mission_id=context.mission_id,
        )
        runtime.context.sink.authorized_context = body
        return {}

    def _graph_session_refresh(
        self, _state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        evaluation = self._goals.evaluate(mission_id=runtime.context.envelope.mission_id)
        return {"goal_evaluation_id": evaluation.evaluation_id}

    def _graph_controller(
        self, _state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        envelope, ids = runtime.context.envelope, runtime.context.ids
        decision = self._controller.step(
            mission_id=envelope.mission_id,
            operation_id=ids.operation_id,
            projection=envelope.action_candidate_projection,
        )
        runtime.context.sink.controller_decision = decision
        return {
            "controller_action": decision.action,
            "controller_reason": decision.reason_code,
        }

    @staticmethod
    def _planning_route(state: _PlanningGraphState) -> str:
        action = state["controller_action"]
        if action == "PLAN":
            return "plan"
        if action == "RECOVER":
            return "recover"
        if action == "FINALIZE":
            return "finalize"
        if action == "STOP":
            return "stop"
        return "end"

    def _graph_context_rebuild(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        del runtime
        planner_context_id = state["planner_context_id"]
        current = self._contexts.revalidate_or_rebuild(planner_context_id)
        return {"planner_context_id": current.planner_context_id}

    def _graph_context_selector(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        del runtime
        self._contexts.revalidate_selection(state["planner_context_id"])
        return {}

    def _graph_context_authorization(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        del runtime
        self._contexts.revalidate_authorization(state["planner_context_id"])
        return {}

    def _graph_context_builder(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        del runtime
        self._contexts.revalidate_context_body(state["planner_context_id"])
        return {}

    def _graph_tool_availability(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        del runtime
        self._contexts.revalidate_tool_availability(state["planner_context_id"])
        return {}

    def _graph_planner(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        envelope = self._contexts.revalidate(state["planner_context_id"])
        output = self._gateway.invoke_planner(
            operation_id=runtime.context.ids.operation_id,
            envelope=envelope,
            invoke=runtime.context.invoke_planner,
        )
        runtime.context.sink.planner_output = output
        return {
            "planner_output_kind": (
                "context_request" if isinstance(output, PlannerContextRequest) else "action"
            )
        }

    @staticmethod
    def _planner_output_route(state: _PlanningGraphState) -> str:
        return state["planner_output_kind"]

    def _current_planner_output(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> PlannerOutput:
        output = runtime.context.sink.planner_output
        if output is None:
            envelope = self._contexts.revalidate(state["planner_context_id"])
            output = self._gateway.invoke_planner(
                operation_id=runtime.context.ids.operation_id,
                envelope=envelope,
                invoke=runtime.context.invoke_planner,
            )
            runtime.context.sink.planner_output = output
        return output

    def _graph_context_request(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        output = cast(PlannerContextRequest, self._current_planner_output(state, runtime))
        self._contexts.accept_context_request(
            planner_context_id=state["planner_context_id"],
            output=output,
        )
        return {}

    def _graph_action_application(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        output = cast(PlannerActionOutput, self._current_planner_output(state, runtime))
        ids = runtime.context.ids
        transition = self._actions.execute(
            planner_context_id=state["planner_context_id"],
            output=output,
            plan_id=ids.plan_id,
            run_id=ids.run_id,
            thread_id=ids.thread_id,
            decision_id=ids.decision_id,
            execution_id=ids.execution_id,
            task_id=ids.task_id,
        )
        runtime.context.sink.action_transition = transition
        return {}

    def _graph_reconciliation(
        self, _state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        mission_id = runtime.context.envelope.mission_id
        checkpoint = self._controller.checkpoint(mission_id)
        if checkpoint is None or checkpoint.active_execution_id is None:
            raise AgentLoopError("recovery decision has no active execution binding")
        try:
            self._reconcile(mission_id, checkpoint.active_execution_id)
        except AgentLoopError as exc:
            if str(exc) != "reconciliation retry budget exhausted":
                raise
            self._finalization.begin_abort(mission_id)
            self._hold_for_review(
                mission_id,
                checkpoint.active_execution_id,
                "EXECUTION_RECONCILED",
            )
        return {}

    def _graph_finalization(
        self, state: _PlanningGraphState, runtime: Runtime[_PlanningRuntime]
    ) -> _PlanningGraphState:
        mission_id = runtime.context.envelope.mission_id
        action = state["controller_action"]
        if action == "FINALIZE":
            if state["controller_reason"] == "GOAL_ACHIEVED":
                self._finalization.begin_completion(mission_id)
            else:
                self._finalization.begin_abort(mission_id)
            self._drive_finalization(mission_id)
        elif self._finalization.is_finalizing(mission_id):
            self._drive_finalization(mission_id)
        return {}

    def _graph_analyzer(
        self, state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> _AnalysisGraphState:
        self._current_analyzer_candidate(state, runtime)
        return {}

    def _current_analyzer_candidate(
        self, state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> AnalyzerCandidateObservation:
        context = runtime.context
        if context.sink.candidate is not None:
            return context.sink.candidate
        authorized_context = context.sink.authorized_context
        if authorized_context is None:
            authorized_context = self._context_builder.build(
                grant_id=context.context_grant_id,
                mission_id=context.mission_id,
            )
            context.sink.authorized_context = authorized_context
        candidate = self._gateway.invoke_analyzer(
            mission_id=context.mission_id,
            mission_revision=context.mission_revision,
            operation_id=context.operation_id,
            execution_id=context.execution_id,
            result_digest=context.result_digest,
            context_grant_id=context.context_grant_id,
            context_grant_digest=state["context_grant_digest"],
            authorized_context=authorized_context,
            invoke=context.invoke_analyzer,
        )
        if candidate.source_execution_id != context.execution_id:
            raise AgentLoopError("Analyzer candidate changed its bound source execution")
        context.sink.candidate = candidate
        return candidate

    def _graph_knowledge_reducer(
        self, state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> _AnalysisGraphState:
        candidate = self._current_analyzer_candidate(state, runtime)
        observation = self._reducer.reduce(candidate)
        runtime.context.sink.observation = observation
        return {"observation_id": observation.observation_id}

    def _graph_analysis_session_refresh(
        self, _state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> _AnalysisGraphState:
        # Session state remains Session Manager-owned; this node is the explicit
        # read boundary and never promotes an Analyzer candidate to runtime state.
        evaluation = self._goals.evaluate(mission_id=runtime.context.mission_id)
        return {"goal_evaluation_id": evaluation.evaluation_id}

    def _graph_goal_evaluation(
        self, state: _AnalysisGraphState, runtime: Runtime[_AnalysisRuntime]
    ) -> _AnalysisGraphState:
        evaluation = self._goals.verify_current(
            state["goal_evaluation_id"], mission_id=runtime.context.mission_id
        )
        return {"goal_evaluation_id": evaluation.evaluation_id}

    def reconcile_execution(
        self, *, execution_id: str, recovery_authority_id: str | None = None,
    ) -> ReconcileOutcome:
        return self._reconciliation.reconcile(
            execution_id=execution_id, recovery_authority_id=recovery_authority_id
        )

    def collect_ingest_and_erase(
        self, *, execution_id: str, stdout: bytes, stderr: bytes,
        control: AdapterCollectionControl,
    ) -> QuarantineCollectionResult:
        collected = self._collection.collect(
            execution_id=execution_id, stdout=stdout, stderr=stderr, control=control
        )
        published = self._ingestion.ingest(ingestion_id=collected.ingestion_id)
        if published.deletion_intent_id is None:
            raise AgentLoopError("secure ingestion did not issue a deletion intent")
        self._eraser.run(deletion_intent_id=published.deletion_intent_id)
        return collected

    def finalize(self, mission_id: str) -> MissionState:
        return self._finalization.finalize(mission_id)

    def durable_resume(self, *, mission_id: str) -> DurableResumeOutcome:
        """Reconcile a PAUSED / WAITING_HUMAN_REVIEW mission without resuming it.

        This is the durable-resume reconciliation of SystemDesign §17.3 / §21.1.1.
        It reuses the existing RECONCILING recovery path and Current Recovery
        Authority only: it dispatches nothing, calls no Planner/Analyzer, and never
        moves the mission to RUNNING. Reconciliation consults, in order, the durable
        **checkpoint**, then the **Application DB** execution record, then the
        **Adapter** (through ``ReconciliationService``), so an uncertain provider
        outcome becomes ``OUTCOME_UNKNOWN`` and a non-idempotent action is never
        auto-resent. The mission lifecycle state is preserved; the only permitted
        progression is the documented ``WAITING_HUMAN_REVIEW -> FINALIZING`` edge
        (§21.1.3), taken exactly when every unresolved item is already RESOLVED.
        """
        now = self._clock.now()
        mission = self._resolver.resolve(mission_id, now=now).mission
        if mission.state not in ("PAUSED", "WAITING_HUMAN_REVIEW"):
            raise AgentLoopError(
                "durable resume reconciles only a PAUSED or WAITING_HUMAN_REVIEW mission"
            )
        entry_state: MissionLifecycleState = mission.state
        # 1) Checkpoint (durable) — its active execution is reconciled first.
        checkpoint = self._controller.checkpoint(mission_id)
        within_recovery = now < mission.recovery_until
        reconciled: list[tuple[str, str]] = []
        for execution_id in self._durable_resume_targets(mission_id, checkpoint):
            if not within_recovery:
                # After recovery_until no provider read is permitted (§21.3); the
                # unconfirmed execution stays as-is for human review.
                reconciled.append((execution_id, "RECOVERY_WINDOW_CLOSED"))
                continue
            reconciled.append((execution_id, self._durable_resume_reconcile_one(mission_id, execution_id)))
        # Re-read the *current* mission; reconciliation must not have changed its
        # lifecycle state, and the graph state is derived from the repository, not
        # from the entry snapshot.
        mission = self._resolver.resolve(mission_id, now=self._clock.now()).mission
        if mission.state != entry_state:
            raise AgentLoopError("durable resume must not change the mission lifecycle state")
        advanced = False
        if entry_state == "WAITING_HUMAN_REVIEW" and self._all_items_resolved(mission_id):
            # §21.1.3: the Mission Manager takes the existing WAITING_HUMAN_REVIEW ->
            # FINALIZING edge, preserving the original terminal reason. The ordinary
            # FINALIZING workflow (not durable resume) then drives to the terminal;
            # durable resume never implies a normal resume of its own.
            self._finalization.advance_from_human_review(mission_id)
            advanced = True
            mission = self._resolver.resolve(mission_id, now=self._clock.now()).mission
        return DurableResumeOutcome(
            mission_state=mission.state,
            graph_state=_GRAPH_STATE_BY_MISSION_STATE[mission.state],
            entry_mission_state=entry_state,
            reconciled=tuple(reconciled),
            advanced_to_finalizing=advanced,
        )

    def _durable_resume_targets(
        self, mission_id: str, checkpoint: object | None
    ) -> tuple[str, ...]:
        ordered: list[str] = []
        seen: set[str] = set()
        active_id = getattr(checkpoint, "active_execution_id", None)
        if isinstance(active_id, str):
            record = self._executions.get(active_id)
            if record is not None and record.provider_execution_state in _RESUME_RECONCILE_STATES:
                ordered.append(active_id)
                seen.add(active_id)
        for record in self._executions.all_for_mission(mission_id):
            if (
                record.provider_execution_state in _RESUME_RECONCILE_STATES
                and record.execution_id not in seen
            ):
                ordered.append(record.execution_id)
                seen.add(record.execution_id)
        return tuple(ordered)

    def _durable_resume_reconcile_one(self, mission_id: str, execution_id: str) -> str:
        try:
            return self._reconcile(mission_id, execution_id).reason_code
        except AgentLoopError as exc:
            if str(exc) == "reconciliation retry budget exhausted":
                # Preserve the stopped/review mission state; the operator decides.
                return "RECONCILE_BUDGET_EXHAUSTED"
            raise

    def _all_items_resolved(self, mission_id: str) -> bool:
        items = self._unresolved.current(mission_id)
        return bool(items) and all(item.status == "RESOLVED" for item in items)

    def project_verified_execution(self, execution_id: str) -> VerifiedFinding:
        return self._verified_findings.project_success(execution_id)

    def _drive_finalization(self, mission_id: str) -> None:
        for execution_id in self._finalization.active_execution_ids(mission_id):
            try:
                outcome = self._reconcile(mission_id, execution_id)
            except AgentLoopError as exc:
                if str(exc) != "reconciliation retry budget exhausted":
                    raise
                self._hold_for_review(
                    mission_id, execution_id, "EXECUTION_RECONCILED"
                )
                return
            if outcome.provider_execution_state in {"DISPATCHED", "RUNNING"}:
                self._cancel_for_finalization(execution_id)
            elif (
                outcome.provider_execution_state in {"SUCCEEDED", "FAILED", "CANCELLED"}
                and not self._settle_result(mission_id, execution_id)
            ):
                return
        for record in self._executions.all_for_mission(mission_id):
            if (
                record.provider_execution_state in {"SUCCEEDED", "FAILED", "CANCELLED"}
                and record.result_ingestion_state != "SUCCEEDED"
                and not self._settle_result(mission_id, record.execution_id)
            ):
                return
        if not self._finalization.active_execution_ids(mission_id):
            self._finalization.resume(mission_id)

    def _reconcile(self, mission_id: str, execution_id: str) -> ReconcileOutcome:
        current = self._executions.get(execution_id)
        if current is None:
            raise AgentLoopError("recovery execution is missing")
        if current.provider_execution_state == "AUTHORIZED":
            blocked = self._executor.abandon_pre_dispatch(execution_id=execution_id)
            return ReconcileOutcome(
                execution_id, blocked.provider_execution_state, "PRE_DISPATCH_ABANDONED"
            )
        if current.provider_execution_state == "PLANNED":
            raise AgentLoopError(
                "durable PLANNED execution violates the create transaction boundary"
            )
        reserved = self._retry_budgets.reserve(
            mission_id=mission_id,
            operation_id=f"reconcile-{execution_id}",
            retry_kind="reconciliation",
        )
        authority = self._recovery.issue_authority(
            authority_id=f"agent-reconcile-{execution_id}-{reserved.consumed_attempts}",
            execution_id=execution_id,
            allowed_operation="reconcile",
            reason="phase1_existing_execution_recovery",
        )
        return self._reconciliation.reconcile(
            execution_id=execution_id,
            recovery_authority_id=authority.authority_id,
        )

    def _cancel_for_finalization(self, execution_id: str) -> None:
        record = self._executions.get(execution_id)
        binding = self._bindings.find_by_execution(execution_id)
        if record is None or not isinstance(binding, ProviderTaskBinding):
            return
        if self._cancel_attempts.find(execution_id, binding.provider_task_id) is not None:
            return
        authority = self._recovery.issue_authority(
            authority_id=f"agent-cancel-{execution_id}-v{record.execution_state_version}",
            execution_id=execution_id,
            allowed_operation="cancel",
            reason="phase1_finalization_cancel",
        )
        self._recovery.request_cancel(
            cancel_attempt_id=f"agent-cancel-{execution_id}",
            execution_id=execution_id,
            recovery_authority_id=authority.authority_id,
            reason="phase1_finalization_cancel",
        )

    def _settle_result(self, mission_id: str, execution_id: str) -> bool:
        record = self._executions.get(execution_id)
        if record is None:
            raise AgentLoopError("finalization result execution is missing")
        control = self._control.find_by_execution(execution_id)
        try:
            if control is None:
                reserved = self._retry_budgets.reserve(
                    mission_id=mission_id,
                    operation_id=f"collection-{execution_id}",
                    retry_kind="collection",
                )
                adapter = self._adapters.get(record.resolved_adapter_id)
                if adapter is None:
                    raise RawResultQuarantineError("trusted collection adapter is unavailable")
                authority = self._recovery.issue_authority(
                    authority_id=(
                        f"agent-collection-{execution_id}-{reserved.consumed_attempts}"
                    ),
                    execution_id=execution_id,
                    allowed_operation="collect_result",
                    reason="phase1_finalization_collection",
                )
                collected = self._collection.collect_from_adapter(
                    execution_id=execution_id,
                    adapter=adapter,
                    recovery_authority_id=authority.authority_id,
                )
                ingestion_id = collected.ingestion_id
            else:
                ingestion = self._ingestion_states.find_by_execution(execution_id)
                if ingestion is None:
                    raise SecureIngestionError("collection has no ingestion state")
                ingestion_id = ingestion.ingestion_id
            self._retry_budgets.reserve(
                mission_id=mission_id,
                operation_id=f"ingestion-{execution_id}",
                retry_kind="ingestion",
            )
            published = self._ingestion.ingest(ingestion_id=ingestion_id)
            if published.deletion_intent_id is not None:
                self._eraser.run(deletion_intent_id=published.deletion_intent_id)
        except RawResultQuarantineError:
            self._hold_for_review(mission_id, execution_id, "COLLECTION_COMPLETE")
            return False
        except (OutputPublicationError, SecureIngestionError, VerifiedErasureError):
            self._hold_for_review(mission_id, execution_id, "INGESTION_COMPLETE")
            return False
        except AgentLoopError as exc:
            if str(exc) == "collection retry budget exhausted":
                self._hold_for_review(mission_id, execution_id, "COLLECTION_COMPLETE")
                return False
            if str(exc) == "ingestion retry budget exhausted":
                self._hold_for_review(mission_id, execution_id, "INGESTION_COMPLETE")
                return False
            raise
        return True

    def _hold_for_review(
        self, mission_id: str, execution_id: str, reason_code: UnresolvedReason
    ) -> None:
        self._unresolved.open(
            unresolved_id=f"unresolved-{reason_code.lower()}-{execution_id}",
            mission_id=mission_id,
            source_execution_id=execution_id,
            reason_code=reason_code,
        )
        self._finalization.wait_for_human_review(mission_id)
