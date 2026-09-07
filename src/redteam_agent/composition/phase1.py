"""Phase 1 composition: Knowledge current state, goal evaluator and controller."""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.agent.application import PlannerActionApplicationService
from redteam_agent.agent.controller import AgentController
from redteam_agent.agent.finalization import FinalizationService
from redteam_agent.agent.llm_gateway import SharedLLMGateway
from redteam_agent.agent.outcome_accounting import ExecutionOutcomeAccountingService
from redteam_agent.agent.planner_context import ActionCandidateProjector, PlannerContextService
from redteam_agent.agent.prerequisites import FinitePrerequisiteSearch
from redteam_agent.agent.retry_budget import AgentRetryBudgetService
from redteam_agent.agent.unresolved import UnresolvedItemService
from redteam_agent.agent.workflow import Phase1AgentWorkflow
from redteam_agent.agent.working_state import PlannerStateManager
from redteam_agent.composition.phase0c import Phase0CKernel, build_phase0c_kernel
from redteam_agent.composition.testing import OPERATOR_ACTOR_TOKEN
from redteam_agent.context.builder import ContextBodyStore, ContextBuilder
from redteam_agent.context.selector import ContextSelector
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.knowledge.entities import EntityResolver
from redteam_agent.knowledge.reducer import KnowledgeReducer
from redteam_agent.knowledge.semantic_catalog import SemanticCatalog, build_phase1_semantic_catalog
from redteam_agent.knowledge.service import KnowledgeService
from redteam_agent.knowledge.verified_facts import VerifiedFindingProjector


@dataclass(frozen=True)
class Phase1Kernel:
    phase0c: Phase0CKernel
    knowledge_service: KnowledgeService
    goal_service: GoalEvaluationService
    controller: AgentController
    candidate_projector: ActionCandidateProjector
    planner_context_service: PlannerContextService
    context_body_store: ContextBodyStore
    action_service: PlannerActionApplicationService
    knowledge_reducer: KnowledgeReducer
    finalization_service: FinalizationService
    retry_budget_service: AgentRetryBudgetService
    planner_state_manager: PlannerStateManager
    entity_resolver: EntityResolver
    semantic_catalog: SemanticCatalog
    llm_gateway: SharedLLMGateway
    outcome_accounting: ExecutionOutcomeAccountingService
    prerequisite_search: FinitePrerequisiteSearch
    workflow: Phase1AgentWorkflow
    verified_finding_projector: VerifiedFindingProjector
    unresolved_items: UnresolvedItemService


def build_phase1_kernel(*, phase0c: Phase0CKernel | None = None) -> Phase1Kernel:
    kernel = phase0c if phase0c is not None else build_phase0c_kernel()
    phase0b = kernel.phase0b
    phase0a = phase0b.phase0a
    phase0a.contract_catalog.enable_typed_predicates()
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
    entity_resolver = EntityResolver(database=phase0a.database, digest_service=ds)
    semantic_catalog = build_phase1_semantic_catalog(ds)
    verified_findings = VerifiedFindingProjector(
        knowledge_service=knowledge, execution_repository=phase0b.execution_repository,
        result_repository=phase0b.result_repository, digest_service=ds,
    )
    reducer = KnowledgeReducer(
        knowledge_service=knowledge,
        execution_repository=phase0b.execution_repository,
        result_repository=phase0b.result_repository,
        context_resolver=phase0a.context_resolver,
        digest_service=ds, clock=kernel.monotonic_clock, entity_resolver=entity_resolver,
        semantic_catalog=semantic_catalog,
    )
    candidate_projector = ActionCandidateProjector(
        snapshot_repository=phase0a.snapshot_repository,
        registry_repository=phase0a.registry_repository,
        contract_catalog=phase0a.contract_catalog,
        digest_service=ds,
        registry_revision=phase0a.registry_revision,
    )
    outcome_accounting = ExecutionOutcomeAccountingService(
        database=phase0a.database, digest_service=ds,
        execution_repository=phase0b.execution_repository,
        result_repository=phase0b.result_repository,
    )
    controller = AgentController(
        database=phase0a.database, digest_service=ds, clock=kernel.monotonic_clock,
        context_resolver=phase0a.context_resolver, goal_service=goals,
        budget_repository=phase0b.budget_repository,
        execution_repository=phase0b.execution_repository,
        snapshot_repository=phase0a.snapshot_repository,
        candidate_projector=candidate_projector,
        outcome_accounting=outcome_accounting,
    )
    planner_state = PlannerStateManager(
        database=phase0a.database, digest_service=ds,
        context_resolver=phase0a.context_resolver, clock=kernel.monotonic_clock,
    )
    retry_budgets = AgentRetryBudgetService(
        database=phase0a.database, digest_service=ds, clock=kernel.monotonic_clock
    )
    llm_gateway = SharedLLMGateway(
        database=phase0a.database, digest_service=ds, clock=kernel.monotonic_clock
    )
    unresolved_items = UnresolvedItemService(
        database=phase0a.database, digest_service=ds, clock=kernel.monotonic_clock,
        execution_repository=phase0b.execution_repository,
        result_repository=phase0b.result_repository,
        control_metadata_repository=phase0b.control_metadata_repository,
        ingestion_repository=phase0b.ingestion_repository,
        audit_store=kernel.audit_store,
    )
    context_body_store = ContextBodyStore(ds)
    context_builder = ContextBuilder(
        authorization_service=phase0a.context_authorization_service,
        body_store=context_body_store,
    )
    context_selector = ContextSelector(phase0a.index_repository)
    planner_context = PlannerContextService(
        database=phase0a.database,
        digest_service=ds,
        clock=kernel.monotonic_clock,
        context_resolver=phase0a.context_resolver,
        context_authorization_service=phase0a.context_authorization_service,
        context_builder=context_builder,
        context_selector=context_selector,
        snapshot_repository=phase0a.snapshot_repository,
        session_repository=phase0a.session_repository,
        goal_service=goals,
        candidate_projector=candidate_projector,
        planner_state_manager=planner_state,
        retry_budget_service=retry_budgets,
        mission_budget_repository=phase0b.budget_repository,
    )
    llm_gateway.bind_planner_context_revalidator(planner_context.revalidate)
    prerequisite_search = FinitePrerequisiteSearch(catalog=phase0a.contract_catalog, digest_service=ds)
    action_service = PlannerActionApplicationService(
        planner_context_service=planner_context, goal_service=goals,
        context_resolver=phase0a.context_resolver,
        snapshot_repository=phase0a.snapshot_repository,
        contract_catalog=phase0a.contract_catalog,
        authorization_service=phase0a.execution_authorization_service,
        executor=phase0b.executor, digest_service=ds, clock=kernel.monotonic_clock,
        prerequisite_search=prerequisite_search,
    )
    finalization = FinalizationService(
        goal_service=goals, mission_manager=phase0a.mission_manager,
        state_repository=phase0a.state_repository,
        execution_repository=phase0b.execution_repository,
        result_repository=phase0b.result_repository,
        outcome_accounting=outcome_accounting,
        control_metadata_repository=phase0b.control_metadata_repository,
        database=phase0a.database,
        unresolved_items=unresolved_items,
        audit_store=kernel.audit_store, witness_barrier=kernel.critical_witness_barrier,
        operator_actor_token=OPERATOR_ACTOR_TOKEN, digest_service=ds,
    )
    workflow = Phase1AgentWorkflow(
        controller=controller, llm_gateway=llm_gateway,
        planner_context_service=planner_context, action_service=action_service,
        knowledge_reducer=reducer,
        collection_service=kernel.collection_service,
        ingestion_service=kernel.ingestion_service, eraser=kernel.eraser,
        reconciliation=phase0b.reconciliation, finalization=finalization,
        recovery_service=phase0b.recovery_service,
        retry_budget_service=retry_budgets,
        execution_repository=phase0b.execution_repository,
        task_binding_repository=phase0b.task_binding_repository,
        cancel_attempt_repository=phase0b.cancel_attempt_repository,
        ingestion_repository=phase0b.ingestion_repository,
        control_metadata_repository=phase0b.control_metadata_repository,
        unresolved_items=unresolved_items,
        adapters={phase0b.mock_adapter.identity().adapter_id: phase0b.mock_adapter},
        executor=phase0b.executor,
        goal_service=goals,
        verified_finding_projector=verified_findings,
    )
    return Phase1Kernel(
        phase0c=kernel, knowledge_service=knowledge, goal_service=goals, controller=controller,
        candidate_projector=candidate_projector, planner_context_service=planner_context,
        context_body_store=context_body_store,
        action_service=action_service,
        knowledge_reducer=reducer,
        finalization_service=finalization,
        retry_budget_service=retry_budgets, planner_state_manager=planner_state,
        entity_resolver=entity_resolver,
        semantic_catalog=semantic_catalog,
        llm_gateway=llm_gateway,
        outcome_accounting=outcome_accounting,
        prerequisite_search=prerequisite_search,
        workflow=workflow,
        verified_finding_projector=verified_findings,
        unresolved_items=unresolved_items,
    )
