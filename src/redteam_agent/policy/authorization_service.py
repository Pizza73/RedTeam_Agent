"""Execution authorization issuing service (owner of policy_decisions).

This is the only path that persists a PolicyDecision. It resolves the tool,
adapter, session context and evaluation context from trusted repositories for
the plan's mission, runs the policy engine, and saves the decision with the
write guard. A caller cannot raw-save a forged decision (the repository requires
the guard held only here).
"""

from __future__ import annotations

from redteam_agent.errors import PolicyEvaluationIndeterminateError
from redteam_agent.plan.models import ExecutionPlan
from redteam_agent.policy.engine import PolicyEngine, context_from_mission
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    AdapterCapabilityRepository,
    PolicyDecisionRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)


class ExecutionAuthorizationService:
    def __init__(
        self,
        *,
        engine: PolicyEngine,
        context_resolver: AuthorizationContextResolver,
        registry_repository: ToolRegistryRepository,
        adapter_repository: AdapterCapabilityRepository,
        session_repository: SessionSecurityContextSnapshotRepository,
        decision_repository: PolicyDecisionRepository,
        clock: Clock,
        write_guard: WriteGuard,
        registry_revision: int,
    ) -> None:
        self._engine = engine
        self._resolver = context_resolver
        self._registry_repo = registry_repository
        self._adapters = adapter_repository
        self._sessions = session_repository
        self._decisions = decision_repository
        self._clock = clock
        self._guard = write_guard
        self._registry_revision = registry_revision
        decision_repository.bind_owner(write_guard)

    def issue(self, *, decision_id: str, plan: ExecutionPlan) -> PolicyDecision:
        now = self._clock.now()
        runtime = self._resolver.resolve(plan.mission_id, now=now)
        mission = runtime.mission
        if mission.state != "RUNNING":
            raise PolicyEvaluationIndeterminateError("decisions may only be issued while the mission is RUNNING")
        if not (mission.valid_from <= now < mission.valid_until):
            raise PolicyEvaluationIndeterminateError("mission is outside its validity window")

        registry = self._registry_repo.get(self._registry_revision)
        if registry is None:
            raise PolicyEvaluationIndeterminateError("tool registry not found")
        tool = registry.by_ref(plan.proposal.tool_ref.tool_id, plan.proposal.tool_ref.registry_revision)
        if tool is None:
            raise PolicyEvaluationIndeterminateError("proposed tool is not in the registry")
        adapter = self._adapters.get(tool.adapter_id)
        if adapter is None:
            raise PolicyEvaluationIndeterminateError("tool adapter capabilities not found")
        session_context = None
        if plan.proposal.session_id is not None:
            snap = self._sessions.get(plan.proposal.session_id)
            session_context = snap.context if snap is not None else None

        decision = self._engine.authorize(
            decision_id=decision_id,
            plan=plan,
            context=context_from_mission(mission),
            tool=tool,
            adapter=adapter,
            session_context=session_context,
            registry_digest=runtime.registry_digest,
            now=now,
        )
        self._decisions.save(decision, guard=self._guard)
        return decision
