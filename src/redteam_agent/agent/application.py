"""Application-owned Planner proposal to Policy/Executor transition."""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.agent.planner_context import PlannerContextService
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.contracts.catalog import ActionContractCatalog
from redteam_agent.errors import AgentLoopError
from redteam_agent.execution.executor import DispatchOutcome, Executor
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.plan.models import ExecutionPlan, PlannerActionOutput, compute_proposal_digest
from redteam_agent.policy.authorization_service import ExecutionAuthorizationService
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.repositories import AvailableToolSnapshotRepository


@dataclass(frozen=True)
class ActionTransitionResult:
    plan: ExecutionPlan
    decision: PolicyDecision
    dispatch: DispatchOutcome | None


class PlannerActionApplicationService:
    """The sole Phase 1 transition from a Planner action into existing gates."""

    def __init__(
        self, *, planner_context_service: PlannerContextService,
        goal_service: GoalEvaluationService,
        context_resolver: AuthorizationContextResolver,
        snapshot_repository: AvailableToolSnapshotRepository,
        contract_catalog: ActionContractCatalog,
        authorization_service: ExecutionAuthorizationService,
        executor: Executor, digest_service: DigestService, clock: Clock,
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

    def execute(
        self, *, planner_context_id: str, output: PlannerActionOutput,
        plan_id: str, run_id: str, thread_id: str, decision_id: str,
        execution_id: str, task_id: str,
    ) -> ActionTransitionResult:
        candidate = self._contexts.accept_action(
            planner_context_id=planner_context_id, output=output
        )
        envelope = self._contexts.revalidate(planner_context_id)
        current_goal = self._goals.evaluate(mission_id=envelope.mission_id)
        if current_goal.status.status == "achieved":
            raise AgentLoopError("goal became achieved before dispatch")
        runtime = self._resolver.resolve(envelope.mission_id, now=self._clock.now())
        snapshot = self._snapshots.get(envelope.available_tool_snapshot_id)
        contract = self._contracts.get(candidate.action_contract_ref.contract_id)
        if snapshot is None or contract is None or contract.reference() != candidate.action_contract_ref:
            raise AgentLoopError("planner action binding is unavailable")
        plan = ExecutionPlan(
            plan_id=plan_id, mission_id=envelope.mission_id,
            mission_revision=runtime.mission.mission_revision,
            observed_mission_state_version=runtime.mission.mission_state_version,
            observed_authorization_epoch=runtime.mission.authorization_epoch,
            run_id=run_id, thread_id=thread_id, proposal=output.proposal,
            proposal_digest=compute_proposal_digest(output.proposal, self._ds),
            goal_evaluation_id=current_goal.evaluation_id,
            goal_evaluation_digest=current_goal.evaluation_digest,
            action_contract_ref=candidate.action_contract_ref,
            execution_precondition_digest=contract.execution_precondition_digest,
            available_tool_snapshot_id=snapshot.snapshot_id,
            available_tool_snapshot_digest=snapshot.snapshot_digest,
            session_security_context_digest=snapshot.session_security_context_digest,
            adapter_capabilities_digest=snapshot.adapter_capabilities_digest,
            sandbox_capabilities_digest=snapshot.sandbox_capabilities_digest,
            remote_mcp_trust_policy_digest=snapshot.remote_mcp_trust_policy_digest,
            created_at=self._clock.now(),
        )
        decision = self._authorization.issue(decision_id=decision_id, plan=plan)
        if decision.decision != "ALLOW":
            return ActionTransitionResult(plan=plan, decision=decision, dispatch=None)
        self._executor.create_execution(
            execution_id=execution_id, task_id=task_id,
            decision_id=decision.decision_id, plan=plan,
        )
        dispatch = self._executor.dispatch(execution_id=execution_id, plan=plan)
        return ActionTransitionResult(plan=plan, decision=decision, dispatch=dispatch)
