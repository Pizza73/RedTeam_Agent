"""Finite registered ActionContract prerequisite search."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from redteam_agent.agent.models import ActionCandidate, ActionCandidateSeed
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.contracts.catalog import ActionContractCatalog, ActionContractDefinition
from redteam_agent.errors import PlannerCandidateError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ToolRef
from redteam_agent.policy.scope_models import TargetReference
from redteam_agent.tools.availability import AvailableToolSnapshot


class PredicateEvaluation(StrictImmutableBoundaryModel):
    predicate_id: str = Field(min_length=1)
    truth: Literal["true", "false", "unknown"]
    source_digest: str = Field(min_length=1)


class PredicateSnapshot(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    evaluations: tuple[PredicateEvaluation, ...]
    snapshot_digest: str = Field(min_length=1)


class FinitePrerequisiteSearch:
    MAX_DEPTH = 8
    MAX_VISITED_CONTRACTS = 64

    def __init__(self, *, catalog: ActionContractCatalog, digest_service: DigestService) -> None:
        self._catalog, self._ds = catalog, digest_service

    def search(
        self, *, tool_snapshot: AvailableToolSnapshot, predicate_snapshot: PredicateSnapshot,
        target_bindings: dict[ToolRef, tuple[TargetReference, ...]],
    ) -> tuple[tuple[ActionCandidateSeed, ...], bool]:
        payload = predicate_snapshot.model_dump(mode="python")
        expected = payload.pop("snapshot_digest")
        self._ds.verify("security_projection_digest", payload, expected)
        if (
            predicate_snapshot.mission_id != tool_snapshot.mission_id
            or predicate_snapshot.mission_revision != tool_snapshot.mission_revision
            or predicate_snapshot.authorization_epoch != tool_snapshot.authorization_epoch
        ):
            raise PlannerCandidateError("predicate and tool snapshots do not share a current binding")
        truth = {item.predicate_id: item.truth for item in predicate_snapshot.evaluations}
        visible = {item.tool_ref for item in tool_snapshot.tools}
        contracts = tuple(
            item for item in self._catalog.all()
            if ToolRef(tool_id=item.tool_id, registry_revision=item.registry_revision) in visible
        )
        visited = 0
        selected: dict[str, ActionContractDefinition] = {}

        def executable(contract: ActionContractDefinition, branch: frozenset[str], depth: int) -> bool:
            nonlocal visited
            if depth > self.MAX_DEPTH or visited >= self.MAX_VISITED_CONTRACTS:
                return False
            if contract.contract_id in branch:
                return False
            visited += 1
            missing = tuple(p for p in contract.preconditions if truth.get(p, "unknown") != "true")
            if not missing:
                selected[contract.contract_id] = contract
                return True
            next_branch = branch | {contract.contract_id}
            for predicate in missing:
                required_relation = "may_change" if truth.get(predicate) == "false" else "observes"
                helpers = tuple(
                    item for item in contracts
                    if predicate in getattr(item, required_relation)
                )
                if not any(executable(item, next_branch, depth + 1) for item in helpers):
                    return False
            return False

        for contract in contracts:
            executable(contract, frozenset(), 0)
        limited = visited >= self.MAX_VISITED_CONTRACTS
        seeds = []
        for contract_id in sorted(selected):
            contract = selected[contract_id]
            tool_ref = ToolRef(tool_id=contract.tool_id, registry_revision=contract.registry_revision)
            seeds.append(ActionCandidateSeed(
                tool_ref=tool_ref,
                canonical_target_binding=target_bindings.get(tool_ref, ()),
                satisfied_precondition_refs=tuple(sorted(contract.preconditions)),
                objective_dependency_ids=(contract.contract_id,),
            ))
        return tuple(seeds[:32]), limited or len(seeds) > 32

    def verify_executable(
        self, *, candidate: ActionCandidate, predicate_snapshot: PredicateSnapshot,
        mission_id: str, mission_revision: int, authorization_epoch: int,
    ) -> None:
        payload = predicate_snapshot.model_dump(mode="python")
        expected = payload.pop("snapshot_digest")
        self._ds.verify("security_projection_digest", payload, expected)
        if (
            predicate_snapshot.mission_id != mission_id
            or predicate_snapshot.mission_revision != mission_revision
            or predicate_snapshot.authorization_epoch != authorization_epoch
        ):
            raise PlannerCandidateError("prerequisite snapshot is stale")
        contract = self._catalog.get(candidate.action_contract_ref.contract_id)
        if contract is None or contract.reference() != candidate.action_contract_ref:
            raise PlannerCandidateError("candidate contract is unavailable")
        truth = {item.predicate_id: item.truth for item in predicate_snapshot.evaluations}
        if any(truth.get(item, "unknown") != "true" for item in contract.preconditions):
            raise PlannerCandidateError("candidate prerequisite is no longer true")
