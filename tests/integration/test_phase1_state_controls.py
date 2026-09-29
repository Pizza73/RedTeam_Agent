"""Phase 1 durable working-state, entity and retry controls."""

from __future__ import annotations

import pytest

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.agent.prerequisites import (
    FinitePrerequisiteSearch,
    PredicateEvaluation,
    PredicateSnapshot,
)
from redteam_agent.composition.phase1 import build_phase1_kernel
from redteam_agent.contracts.catalog import ActionContractCatalog, ActionContractDefinition
from redteam_agent.errors import AgentLoopError, KnowledgeStateIntegrityError
from redteam_agent.models.common import ToolRef
from redteam_agent.plan.models import HypothesisCreateProposal, PlanThreadUpdateProposal
from redteam_agent.tools.availability import AvailableToolSnapshot, AvailableToolView


def _kernel():
    kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
    p0b.seed_authorized(kernel.phase0c.phase0b)
    return kernel


def test_retry_budgets_are_durable_and_separate_by_operation_kind() -> None:
    kernel = _kernel()
    first = kernel.retry_budget_service.reserve(
        mission_id=support.MISSION_ID, operation_id="op-1", retry_kind="dispatch"
    )
    assert first.consumed_attempts == 1
    with pytest.raises(AgentLoopError):
        kernel.retry_budget_service.reserve(
            mission_id=support.MISSION_ID, operation_id="op-1", retry_kind="dispatch"
        )
    collection = kernel.retry_budget_service.reserve(
        mission_id=support.MISSION_ID, operation_id="op-1", retry_kind="collection"
    )
    assert collection.consumed_attempts == 1 and collection.max_attempts == 3


def test_plan_thread_updates_use_occ_and_remain_unconfirmed() -> None:
    kernel = _kernel()
    created = kernel.planner_state_manager.apply(
        mission_id=support.MISSION_ID,
        proposal=PlanThreadUpdateProposal(
            operation="replace", objective="verify service",
            expected_thread_version=None,
            hypothesis_updates=(HypothesisCreateProposal(
                statement="service may be exposed", basis_reference_ids=(),
                next_verification_objective="scan",
            ),),
        ),
    )
    assert created.thread_version == 1
    assert created.hypotheses[0].status == "investigating"
    with pytest.raises(AgentLoopError):
        kernel.planner_state_manager.apply(
            mission_id=support.MISSION_ID,
            proposal=PlanThreadUpdateProposal(
                operation="continue", objective="stale", expected_thread_version=99,
                hypothesis_updates=(),
            ),
        )
    with pytest.raises(AgentLoopError):
        kernel.planner_state_manager.apply(
            mission_id=support.MISSION_ID,
            proposal=PlanThreadUpdateProposal(
                operation="replace", objective="unbound reference",
                expected_thread_version=created.thread_version,
                hypothesis_updates=(HypothesisCreateProposal(
                    statement="untrusted", basis_reference_ids=("unknown-record",),
                    next_verification_objective="verify",
                ),),
            ),
        )


def test_entity_auto_merge_requires_same_registered_strong_key() -> None:
    kernel = _kernel()
    first = kernel.entity_resolver.resolve_strong(
        mission_id=support.MISSION_ID, entity_type="host",
        strong_key_type="machine_sid", strong_key_value="S-1-5-21-host",
        source_reference_ids=("session:sess-1",),
    )
    again = kernel.entity_resolver.resolve_strong(
        mission_id=support.MISSION_ID, entity_type="host",
        strong_key_type="machine_sid", strong_key_value="S-1-5-21-host",
        source_reference_ids=("session:sess-1",),
    )
    assert again.entity_id == first.entity_id
    alias = kernel.entity_resolver.record_alias_candidate(
        mission_id=support.MISSION_ID, left_ref="hostname:server",
        right_ref=first.entity_id, evidence_reference_ids=(),
    )
    assert alias.status == "candidate_match"
    with pytest.raises(KnowledgeStateIntegrityError):
        kernel.entity_resolver.resolve_strong(
            mission_id=support.MISSION_ID, entity_type="host",
            strong_key_type="hostname", strong_key_value="server",
            source_reference_ids=(),
        )


def test_semantic_catalog_rejects_unknown_analyzer_predicate() -> None:
    kernel = _kernel()
    with pytest.raises(KnowledgeStateIntegrityError):
        kernel.semantic_catalog.validate(
            observation_type="finding", predicate="model_invented_predicate"
        )


def test_finite_prerequisite_search_uses_observer_for_unknown_predicate() -> None:
    ds = build_phase1_kernel(phase0c=p0c.make_phase0c()).phase0c.phase0b.phase0a.digest_service
    observer = ActionContractDefinition(
        contract_id="observe-session", revision="1", tool_id="observe", registry_revision=1,
        parameter_schema_digest="schema", target_extractor_id=None, evidence_rule_ids=(),
        output_publication_rule_id="pub", minimum_risk_level="read", side_effect="read_only",
        observes=("session_exists",),
    )
    action = ActionContractDefinition(
        contract_id="use-session", revision="1", tool_id="use", registry_revision=1,
        parameter_schema_digest="schema", target_extractor_id=None, evidence_rule_ids=(),
        output_publication_rule_id="pub", minimum_risk_level="low", side_effect="state_change",
        preconditions=("session_exists",),
    )
    catalog = ActionContractCatalog((observer, action), allow_typed_predicates=True)
    views = tuple(AvailableToolView(
        tool_ref=ToolRef(tool_id=tool_id, registry_revision=1), display_name=tool_id,
        version="1", description="", parameter_schema={}, requires_session=False,
        eligible_session_ids=(),
    ) for tool_id in ("observe", "use"))
    snapshot = AvailableToolSnapshot(
        snapshot_id="tools", snapshot_digest="tools-digest", mission_id=support.MISSION_ID,
        mission_revision=1, authorization_epoch=0, registry_digest="registry",
        policy_version="policy", execution_scope_digest="scope",
        session_security_context_digest="sessions", adapter_capabilities_digest="adapters",
        sandbox_capabilities_digest="sandbox", remote_mcp_trust_policy_digest="remote",
        tools=views, created_at=support.T0, expires_at=support.T0.replace(year=support.T0.year + 1),
    )
    evaluation = PredicateEvaluation(
        predicate_id="session_exists", truth="unknown", source_digest="source"
    )
    fields = {
        "mission_id": support.MISSION_ID, "mission_revision": 1, "authorization_epoch": 0,
        "evaluations": (evaluation.model_dump(mode="python"),),
    }
    predicates = PredicateSnapshot(
        mission_id=support.MISSION_ID, mission_revision=1, authorization_epoch=0,
        evaluations=(evaluation,), snapshot_digest=ds.compute("security_projection_digest", fields)
    )
    seeds, limited = FinitePrerequisiteSearch(catalog=catalog, digest_service=ds).search(
        tool_snapshot=snapshot, predicate_snapshot=predicates, target_bindings={},
    )
    assert [seed.tool_ref.tool_id for seed in seeds] == ["observe"]
    assert not limited
