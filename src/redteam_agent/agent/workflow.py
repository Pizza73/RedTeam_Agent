"""Coarse, checkpoint-safe Phase 1 Agent workflow caller."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from redteam_agent.agent.application import ActionTransitionResult, PlannerActionApplicationService
from redteam_agent.agent.controller import AgentController
from redteam_agent.agent.finalization import FinalizationService
from redteam_agent.agent.llm_gateway import SharedLLMGateway
from redteam_agent.agent.models import ControllerDecision, PlannerContextEnvelope
from redteam_agent.agent.planner_context import PlannerContextService
from redteam_agent.agent.retry_budget import AgentRetryBudgetService
from redteam_agent.erasure.service import VerifiedQuarantineEraser
from redteam_agent.errors import AgentLoopError
from redteam_agent.execution.executor import Executor
from redteam_agent.execution.models import AdapterCollectionControl, ProviderTaskBinding
from redteam_agent.execution.reconcile import ReconcileOutcome, ReconciliationService
from redteam_agent.execution.recovery import ExecutionRecoveryService
from redteam_agent.ingestion.service import SecureIngestionService
from redteam_agent.knowledge.models import KnowledgeObservation, VerifiedFinding
from redteam_agent.knowledge.reducer import KnowledgeReducer
from redteam_agent.knowledge.verified_facts import VerifiedFindingProjector
from redteam_agent.mission.models import MissionState
from redteam_agent.plan.models import PlannerActionOutput, PlannerContextRequest, PlannerOutput
from redteam_agent.quarantine.collection import QuarantineCollectionResult, QuarantineCollectionService
from redteam_agent.storage.execution_repositories import (
    CancelAttemptRepository,
    ExecutionRecordRepository,
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
        task_binding_repository: ResultTaskBindingRepository,
        cancel_attempt_repository: CancelAttemptRepository,
        executor: Executor,
        finalization: FinalizationService,
        verified_finding_projector: VerifiedFindingProjector,
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
        self._bindings = task_binding_repository
        self._cancel_attempts = cancel_attempt_repository
        self._executor = executor
        self._finalization = finalization
        self._verified_findings = verified_finding_projector

    def run_planning_iteration(
        self, *, envelope: PlannerContextEnvelope, ids: PlanningOperationIds,
        invoke_planner: Callable[[], object],
    ) -> WorkflowStepResult:
        decision = self._controller.step(
            mission_id=envelope.mission_id, operation_id=ids.operation_id,
            projection=envelope.action_candidate_projection,
        )
        if decision.action == "RECOVER":
            checkpoint = self._controller.checkpoint(envelope.mission_id)
            if checkpoint is None or checkpoint.active_execution_id is None:
                raise AgentLoopError("recovery decision has no active execution binding")
            self._reconcile(envelope.mission_id, checkpoint.active_execution_id)
            return WorkflowStepResult(decision, None, None)
        if decision.action == "FINALIZE":
            if decision.reason_code == "GOAL_ACHIEVED":
                self._finalization.begin_completion(envelope.mission_id)
            else:
                self._finalization.begin_abort(envelope.mission_id)
            self._drive_finalization(envelope.mission_id)
            return WorkflowStepResult(decision, None, None)
        if decision.action == "STOP":
            if self._finalization.is_finalizing(envelope.mission_id):
                self._drive_finalization(envelope.mission_id)
            return WorkflowStepResult(decision, None, None)
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

    def project_verified_execution(self, execution_id: str) -> VerifiedFinding:
        return self._verified_findings.project_success(execution_id)

    def _drive_finalization(self, mission_id: str) -> None:
        for execution_id in self._finalization.active_execution_ids(mission_id):
            outcome = self._reconcile(mission_id, execution_id)
            if outcome.provider_execution_state in {"DISPATCHED", "RUNNING"}:
                self._cancel_for_finalization(execution_id)
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
