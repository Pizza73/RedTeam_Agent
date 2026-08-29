"""Trusted application service for PolicyDecision issuance."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.authorization_runtime import AuthorizationRuntimeContextResolver
from redteam_agent.errors import CurrentAuthorizationStateError
from redteam_agent.models.context import DataAccessGrant, ResourceBinding
from redteam_agent.models.policy import PolicyDecision
from redteam_agent.repositories.context import ContextResourceIndexRepository
from redteam_agent.repositories.plans import PlanRepository
from redteam_agent.repositories.policy import PolicyDecisionRepository
from redteam_agent.tools.target_extractors import TrustedTargetExtractorRegistry

from .engine import PolicyEngine

_POLICY_ENGINE_ISSUER_TOKEN = object()


class PolicyDecisionIssuanceService:
    """Caller supplies IDs/requests; trusted current state and plan come from repositories."""

    def __init__(
        self,
        *,
        runtime_resolver: AuthorizationRuntimeContextResolver,
        plans: PlanRepository,
        decisions: PolicyDecisionRepository,
        resources: ContextResourceIndexRepository,
    ) -> None:
        self.runtime_resolver = runtime_resolver
        self.plans = plans
        self.decisions = decisions
        self.resources = resources

    def issue(
        self,
        *,
        plan_id: str,
        requested_data_access: tuple[DataAccessGrant, ...] = (),
        issued_at: datetime,
        expires_at: datetime,
    ) -> PolicyDecision:
        plan = self.plans.get(plan_id)
        if plan is None:
            raise CurrentAuthorizationStateError("execution plan is not persisted")
        runtime = self.runtime_resolver.resolve(plan.mission_id)
        bindings: dict[str, ResourceBinding] = {}
        for grant in requested_data_access:
            current = self.resources.current_binding(
                plan.mission_id, grant.resource.resource_id
            )
            if current is not None:
                bindings[grant.resource.resource_id] = current.binding
        engine = PolicyEngine(
            policy_version=runtime.policy_state.policy_version,
            extractors=TrustedTargetExtractorRegistry(),
        )
        decision = engine.authorize(
            mission=runtime.mission,
            plan=plan,
            snapshot=runtime.snapshot,
            registry=runtime.registry,
            requested_data_access=requested_data_access,
            current_resource_bindings=bindings,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return self.decisions._store_issued(
            decision, issuer_token=_POLICY_ENGINE_ISSUER_TOKEN
        )
