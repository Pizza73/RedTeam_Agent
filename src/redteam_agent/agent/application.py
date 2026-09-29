"""Application-owned Planner proposal to Policy/Executor transition."""

from __future__ import annotations

import json
from dataclasses import dataclass

from redteam_agent.agent.planner_context import PlannerContextService
from redteam_agent.agent.prerequisites import FinitePrerequisiteSearch, PredicateSnapshot
from redteam_agent.approval.service import ApprovalService
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.contracts.catalog import (
    ActionContractCatalog,
    compute_execution_precondition_digest,
)
from redteam_agent.errors import AgentLoopError
from redteam_agent.execution.budget import MissionExecutionBudgetService
from redteam_agent.execution.executor import DispatchOutcome, Executor
from redteam_agent.execution.thread import verify_run_thread_binding
from redteam_agent.executor.authorization_gate import GateResult
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.plan.models import ExecutionPlan, PlannerActionOutput, compute_proposal_digest
from redteam_agent.policy.authorization_service import ExecutionAuthorizationService
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.execution_repositories import ExecutionRecordRepository
from redteam_agent.storage.repositories import (
    ApprovalRecordRepository,
    ApprovalRequestRepository,
    AvailableToolSnapshotRepository,
    PolicyDecisionRepository,
)


@dataclass(frozen=True)
class ActionTransitionResult:
    plan: ExecutionPlan
    decision: PolicyDecision
    dispatch: DispatchOutcome | None


@dataclass(frozen=True)
class ExecutionPlanContinuation:
    plan_id: str
    decision_id: str
    execution_id: str
    task_id: str


class PlannerActionApplicationService:
    """The sole Phase 1 transition from a Planner action into existing gates."""

    def __init__(
        self,
        *,
        planner_context_service: PlannerContextService,
        goal_service: GoalEvaluationService,
        context_resolver: AuthorizationContextResolver,
        snapshot_repository: AvailableToolSnapshotRepository,
        contract_catalog: ActionContractCatalog,
        authorization_service: ExecutionAuthorizationService,
        executor: Executor,
        digest_service: DigestService,
        clock: Clock,
        prerequisite_search: FinitePrerequisiteSearch,
        database: Database,
        approval_service: ApprovalService,
        approval_requests: ApprovalRequestRepository,
        approval_records: ApprovalRecordRepository,
        decisions: PolicyDecisionRepository,
        executions: ExecutionRecordRepository,
        budget_service: MissionExecutionBudgetService,
    ) -> None:
        self._contexts = planner_context_service
        self._goals = goal_service
        self._resolver = context_resolver
        self._snapshots = snapshot_repository
        self._contracts = contract_catalog
        self._authorization = authorization_service
        self._executor = executor
        self._ds = digest_service
        self._clock = clock
        self._prerequisites = prerequisite_search
        self._db, self._approvals, self._requests = database, approval_service, approval_requests
        self._approval_records = approval_records
        self._decisions, self._executions = decisions, executions
        self._budget_service = budget_service

    def saved_plan(self, plan_id: str) -> ExecutionPlan | None:
        raw = self._db.get("execution_plans", plan_id)
        return None if raw is None else ExecutionPlan.model_validate_json(raw)

    def _saved_continuation(self, plan_id: str) -> ExecutionPlanContinuation | None:
        raw = self._db.get("execution_plan_continuations", plan_id)
        if raw is None:
            return None
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {
            "plan_id", "decision_id", "execution_id", "task_id"
        } or not all(isinstance(value, str) and value for value in payload.values()):
            raise AgentLoopError("stored execution continuation is malformed")
        continuation = ExecutionPlanContinuation(**payload)
        if continuation.plan_id != plan_id:
            raise AgentLoopError("stored execution continuation identity mismatch")
        return continuation

    def continue_plan(
        self,
        *,
        plan_id: str,
        decision_id: str,
        execution_id: str,
        task_id: str,
    ) -> ActionTransitionResult:
        """Use the stored exact intent; an existing Execution is never re-submitted."""
        plan = self.saved_plan(plan_id)
        if plan is None:
            raise AgentLoopError("stored execution plan is missing")
        continuation = self._saved_continuation(plan_id)
        if continuation is None:
            raise AgentLoopError("stored execution continuation is missing")
        if (
            continuation.decision_id != decision_id
            or continuation.execution_id != execution_id
            or continuation.task_id != task_id
        ):
            raise AgentLoopError("execution continuation changed its system identities")
        decision = self._decisions.get(decision_id)
        if decision is None:
            decision = self._authorization.issue(decision_id=decision_id, plan=plan)
        if decision.plan_id != plan.plan_id or decision.proposal_digest != plan.proposal_digest:
            raise AgentLoopError("stored decision does not match its plan")
        if decision.decision == "DENY":
            return ActionTransitionResult(plan, decision, None)
        if decision.decision == "REQUIRE_APPROVAL" and self._requests.find_by_decision(decision_id) is None:
            self._approvals.issue_request(
                approval_request_id=f"approval-{decision_id}", decision_id=decision_id, plan=plan,
            )
        if decision.decision == "REQUIRE_APPROVAL":
            mission = self._resolver.resolve(plan.mission_id, now=self._clock.now()).mission
            self._budget_service.account_runtime(
                mission_id=mission.mission_id,
                mission_revision=mission.mission_revision,
                active=mission.approval_policy.count_approval_wait_in_runtime,
            )
        existing = self._executions.get_by_decision(decision_id)
        if existing is not None:
            return ActionTransitionResult(plan, decision, None)
        # The Executor revalidates approval, source freshness and current Goal.
        # Waiting is represented by the existing request, never by a new Plan.
        if not self._executor.can_execute(decision_id=decision_id, plan=plan).authorized:
            return ActionTransitionResult(plan, decision, None)
        self._executor.create_execution(execution_id=execution_id, task_id=task_id,
                                        decision_id=decision_id, plan=plan)
        dispatch = self._executor.dispatch(execution_id=execution_id, plan=plan)
        return ActionTransitionResult(plan, decision, dispatch)

    def continue_approved(self, mission_id: str) -> ActionTransitionResult:
        """Dispatch the newest unexecuted approved exact Plan without replanning."""
        for decision in reversed(self._decisions.all_for_mission(mission_id)):
            if decision.decision != "REQUIRE_APPROVAL":
                continue
            if self._executions.get_by_decision(decision.decision_id) is not None:
                continue
            request = self._requests.find_by_decision(decision.decision_id)
            if request is None:
                continue
            record = self._approval_records.find_by_request(request.approval_request_id)
            if record is None or record.decision != "APPROVED":
                continue
            continuation = self._saved_continuation(decision.plan_id)
            if continuation is None or continuation.decision_id != decision.decision_id:
                raise AgentLoopError("approved Plan continuation is missing or mismatched")
            return self.continue_plan(
                plan_id=continuation.plan_id,
                decision_id=continuation.decision_id,
                execution_id=continuation.execution_id,
                task_id=continuation.task_id,
            )
        raise AgentLoopError("Controller selected no approved executable Plan")

    def plan_gate(self, plan_id: str, decision_id: str) -> GateResult:
        plan = self.saved_plan(plan_id)
        if plan is None:
            raise AgentLoopError("stored execution plan is missing")
        return self._executor.can_execute(decision_id=decision_id, plan=plan)

    def execute(
        self,
        *,
        planner_context_id: str,
        output: PlannerActionOutput,
        plan_id: str,
        run_id: str,
        thread_id: str,
        decision_id: str,
        execution_id: str,
        task_id: str,
        predicate_snapshot: PredicateSnapshot | None = None,
    ) -> ActionTransitionResult:
        saved = self.saved_plan(plan_id)
        if saved is not None:
            if saved.proposal != output.proposal or saved.run_id != run_id or saved.thread_id != thread_id:
                raise AgentLoopError("execution plan replay changed its intent")
            return self.continue_plan(
                plan_id=plan_id,
                decision_id=decision_id,
                execution_id=execution_id,
                task_id=task_id,
            )
        envelope = self._contexts.revalidate(planner_context_id)
        verify_run_thread_binding(
            thread_id=thread_id,
            run_id=run_id,
            mission_id=envelope.mission_id,
            mission_revision=envelope.mission_revision,
        )
        candidate = self._contexts.accept_action(planner_context_id=planner_context_id, output=output)
        envelope = self._contexts.revalidate(planner_context_id)
        current_goal = self._goals.evaluate(mission_id=envelope.mission_id)
        if current_goal.status.status == "achieved":
            raise AgentLoopError("goal became achieved before dispatch")
        runtime = self._resolver.resolve(envelope.mission_id, now=self._clock.now())
        snapshot = self._snapshots.get(envelope.available_tool_snapshot_id)
        contract = self._contracts.get(candidate.action_contract_ref.contract_id)
        if snapshot is None or contract is None or contract.reference() != candidate.action_contract_ref:
            raise AgentLoopError("planner action binding is unavailable")
        if contract.preconditions:
            if predicate_snapshot is None:
                raise AgentLoopError("current prerequisite snapshot is required")
            self._prerequisites.verify_executable(
                candidate=candidate,
                predicate_snapshot=predicate_snapshot,
                mission_id=envelope.mission_id,
                mission_revision=runtime.mission.mission_revision,
                authorization_epoch=runtime.mission.authorization_epoch,
            )
        if predicate_snapshot is None:
            snapshot_fields = {
                "mission_id": envelope.mission_id,
                "mission_revision": runtime.mission.mission_revision,
                "authorization_epoch": runtime.mission.authorization_epoch,
                "evaluations": (),
            }
            predicate_snapshot_digest = self._ds.compute(
                "security_projection_digest", snapshot_fields
            )
            predicate_evidence: tuple[dict[str, object], ...] = ()
        else:
            predicate_snapshot_digest = predicate_snapshot.snapshot_digest
            predicate_evidence = tuple(
                item.model_dump(mode="python") for item in predicate_snapshot.evaluations
                if item.predicate_id in contract.preconditions
            )
        precondition_digest = compute_execution_precondition_digest(
            definition=contract,
            requested_targets=output.proposal.requested_targets,
            predicate_snapshot_digest=predicate_snapshot_digest,
            predicate_evidence=predicate_evidence,
            digest_service=self._ds,
        )
        plan = ExecutionPlan(
            plan_id=plan_id,
            mission_id=envelope.mission_id,
            mission_revision=runtime.mission.mission_revision,
            observed_mission_state_version=runtime.mission.mission_state_version,
            observed_authorization_epoch=runtime.mission.authorization_epoch,
            run_id=run_id,
            thread_id=thread_id,
            proposal=output.proposal,
            proposal_digest=compute_proposal_digest(output.proposal, self._ds),
            goal_evaluation_id=current_goal.evaluation_id,
            goal_evaluation_digest=current_goal.evaluation_digest,
            action_contract_ref=candidate.action_contract_ref,
            execution_precondition_digest=precondition_digest,
            execution_precondition_snapshot_digest=predicate_snapshot_digest,
            execution_precondition_evidence=predicate_evidence,
            available_tool_snapshot_id=snapshot.snapshot_id,
            available_tool_snapshot_digest=snapshot.snapshot_digest,
            session_security_context_digest=snapshot.session_security_context_digest,
            adapter_capabilities_digest=snapshot.adapter_capabilities_digest,
            sandbox_capabilities_digest=snapshot.sandbox_capabilities_digest,
            remote_mcp_trust_policy_digest=snapshot.remote_mcp_trust_policy_digest,
            created_at=self._clock.now(),
        )
        with UnitOfWork(self._db):
            self._db.put_idempotent(
                "execution_plans", plan_id,
                json.dumps(plan.model_dump(mode="json"), sort_keys=True),
            )
            self._db.put_idempotent(
                "execution_plan_continuations", plan_id,
                json.dumps(
                    {
                        "plan_id": plan_id,
                        "decision_id": decision_id,
                        "execution_id": execution_id,
                        "task_id": task_id,
                    },
                    sort_keys=True,
                ),
            )
        decision = self._authorization.issue(decision_id=decision_id, plan=plan)
        if decision.decision == "DENY":
            self._contexts.authorize_denied_action_replan(planner_context_id)
            return ActionTransitionResult(plan=plan, decision=decision, dispatch=None)
        return self.continue_plan(
            plan_id=plan_id,
            decision_id=decision_id,
            execution_id=execution_id,
            task_id=task_id,
        )
