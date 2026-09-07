"""Phase 1 composition: Knowledge current state, goal evaluator and controller."""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.agent.controller import AgentController
from redteam_agent.agent.planner_context import ActionCandidateProjector, PlannerContextService
from redteam_agent.composition.phase0c import Phase0CKernel, build_phase0c_kernel
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.knowledge.service import KnowledgeService


@dataclass(frozen=True)
class Phase1Kernel:
    phase0c: Phase0CKernel
    knowledge_service: KnowledgeService
    goal_service: GoalEvaluationService
    controller: AgentController
    candidate_projector: ActionCandidateProjector
    planner_context_service: PlannerContextService


def build_phase1_kernel(*, phase0c: Phase0CKernel | None = None) -> Phase1Kernel:
    kernel = phase0c if phase0c is not None else build_phase0c_kernel()
    phase0b = kernel.phase0b
    phase0a = phase0b.phase0a
    ds = phase0a.digest_service
    evidence_catalog_digest = ds.compute(
        "security_projection_digest",
        {"catalog_revision": "knowledge-evidence-rules-v1", "rule_ids": ("session-current-v1",)},
    )
    knowledge = KnowledgeService(
        database=phase0a.database, digest_service=ds,
        evidence_rule_catalog_digest=evidence_catalog_digest,
    )
    goals = GoalEvaluationService(
        database=phase0a.database, digest_service=ds, clock=kernel.monotonic_clock,
        context_resolver=phase0a.context_resolver,
        session_repository=phase0a.session_repository, knowledge_service=knowledge,
    )
    controller = AgentController(
        database=phase0a.database, digest_service=ds, clock=kernel.monotonic_clock,
        context_resolver=phase0a.context_resolver, goal_service=goals,
        budget_repository=phase0b.budget_repository,
    )
    candidate_projector = ActionCandidateProjector(
        snapshot_repository=phase0a.snapshot_repository,
        registry_repository=phase0a.registry_repository,
        contract_catalog=phase0a.contract_catalog,
        digest_service=ds,
        registry_revision=phase0a.registry_revision,
    )
    planner_context = PlannerContextService(
        database=phase0a.database,
        digest_service=ds,
        clock=kernel.monotonic_clock,
        context_resolver=phase0a.context_resolver,
        context_authorization_service=phase0a.context_authorization_service,
        snapshot_repository=phase0a.snapshot_repository,
        session_repository=phase0a.session_repository,
        goal_service=goals,
        candidate_projector=candidate_projector,
    )
    return Phase1Kernel(
        phase0c=kernel, knowledge_service=knowledge, goal_service=goals, controller=controller,
        candidate_projector=candidate_projector, planner_context_service=planner_context,
    )
