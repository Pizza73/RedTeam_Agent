"""Finite action candidates and current-bound Planner context envelopes."""

from __future__ import annotations

import json
from datetime import timedelta

from redteam_agent.agent.models import (
    ActionCandidate,
    ActionCandidateProjection,
    ActionCandidateSeed,
    PlannerContextEnvelope,
    PlannerFeedback,
    RecentExecutionSummary,
)
from redteam_agent.agent.retry_budget import AgentRetryBudgetService
from redteam_agent.agent.working_state import PlannerStateManager
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.context.authorization import ContextAuthorizationService
from redteam_agent.context.builder import ContextBuilder
from redteam_agent.context.models import ContextDataAccessGrant, RankedContextCandidate
from redteam_agent.context.selector import ContextSelector, target_reference_value
from redteam_agent.contracts.catalog import ActionContractCatalog
from redteam_agent.errors import PlannerCandidateError, PlannerContextError, RepositoryIntegrityError
from redteam_agent.goal.service import GoalEvaluationService
from redteam_agent.plan.models import OperationalPhase, PlannerActionOutput, PlannerContextRequest
from redteam_agent.policy.scope_models import TargetReference
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.execution_repositories import MissionExecutionBudgetRepository
from redteam_agent.storage.repositories import (
    AvailableToolSnapshotRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.tools.availability import AvailableToolSnapshot, revalidate_snapshot

_ENVELOPE_NS = "planner_context_envelope"
_CONTEXT_REQUEST_NS = "planner_context_request"
_CONTEXT_CHILD_NS = "planner_context_child"
_CONTEXT_ROOT_NS = "planner_context_root"
_CONTEXT_ACTION_NS = "planner_context_action"
MAX_ACTION_CANDIDATES = 32
MAX_RANKED_METADATA = 100
MAX_ENVELOPE_TTL_SECONDS = 300


def _target_key(targets: tuple[TargetReference, ...]) -> bytes:
    values = [target.model_dump(mode="python") for target in targets]
    return canonical_dumps(sorted(values, key=canonical_dumps))


class ActionCandidateProjector:
    """Restrict application seeds to exact visible tools and registered contracts."""

    def __init__(
        self, *, snapshot_repository: AvailableToolSnapshotRepository,
        registry_repository: ToolRegistryRepository, contract_catalog: ActionContractCatalog,
        digest_service: DigestService, registry_revision: int,
    ) -> None:
        self._snapshots = snapshot_repository
        self._registries = registry_repository
        self._contracts = contract_catalog
        self._ds = digest_service
        self._registry_revision = registry_revision

    def build(
        self, *, snapshot_id: str, seeds: tuple[ActionCandidateSeed, ...],
        source_version_digests: tuple[str, ...],
    ) -> ActionCandidateProjection:
        snapshot = self._snapshots.get(snapshot_id)
        registry = self._registries.get(self._registry_revision)
        if snapshot is None or registry is None:
            raise PlannerCandidateError("tool snapshot or registry is unavailable")
        visible = {view.tool_ref: view for view in snapshot.tools}
        definitions = {tool.tool_ref: tool for tool in registry.tools}
        candidates: dict[str, ActionCandidate] = {}
        for seed in seeds:
            view = visible.get(seed.tool_ref)
            tool = definitions.get(seed.tool_ref)
            if view is None or tool is None:
                raise PlannerCandidateError("candidate tool is not visible in the current snapshot")
            contract = self._contracts.get(tool.action_contract_ref.contract_id)
            if contract is None or contract.reference() != tool.action_contract_ref:
                raise PlannerCandidateError("candidate action contract is not exact and registered")
            if tuple(sorted(set(seed.satisfied_precondition_refs))) != tuple(
                sorted(contract.preconditions)
            ):
                raise PlannerCandidateError("candidate does not bind every registered precondition")
            targets = tuple(sorted(seed.canonical_target_binding, key=lambda item: canonical_dumps(
                item.model_dump(mode="python")
            )))
            if len(targets) != len({_target_key((target,)) for target in targets}):
                raise PlannerCandidateError("candidate target binding contains duplicates")
            fields = {
                "tool_ref": seed.tool_ref.model_dump(mode="python"),
                "action_contract_ref": tool.action_contract_ref.model_dump(mode="python"),
                "canonical_target_binding": [item.model_dump(mode="python") for item in targets],
                "satisfied_precondition_refs": sorted(set(seed.satisfied_precondition_refs)),
                "objective_dependency_ids": sorted(set(seed.objective_dependency_ids)),
                "eligible_session_ids": list(view.eligible_session_ids),
                "requires_session": view.requires_session,
            }
            candidate_digest = self._ds.compute("action_candidate_digest", fields)
            satisfied = tuple(sorted(set(seed.satisfied_precondition_refs)))
            dependencies = tuple(sorted(set(seed.objective_dependency_ids)))
            candidate = ActionCandidate(
                candidate_id=f"candidate-{candidate_digest[:24]}",
                tool_ref=seed.tool_ref,
                action_contract_ref=tool.action_contract_ref,
                canonical_target_binding=targets,
                satisfied_precondition_refs=satisfied,
                objective_dependency_ids=dependencies,
                eligible_session_ids=view.eligible_session_ids,
                requires_session=view.requires_session,
            )
            candidates[candidate.candidate_id] = candidate
        ordered = sorted(
            candidates.values(),
            key=lambda item: (item.tool_ref.tool_id, item.tool_ref.registry_revision,
                              _target_key(item.canonical_target_binding), item.candidate_id),
        )
        limited = len(ordered) > MAX_ACTION_CANDIDATES
        fields = {
            "schema_version": "action-candidate-projection-v1",
            "available_tool_snapshot_id": snapshot.snapshot_id,
            "available_tool_snapshot_digest": snapshot.snapshot_digest,
            "source_version_digests": sorted(set(source_version_digests)),
            "candidates": [item.model_dump(mode="python") for item in ordered[:MAX_ACTION_CANDIDATES]],
            "search_limited": limited,
        }
        return ActionCandidateProjection(
            schema_version="action-candidate-projection-v1",
            available_tool_snapshot_id=snapshot.snapshot_id,
            available_tool_snapshot_digest=snapshot.snapshot_digest,
            source_version_digests=tuple(sorted(set(source_version_digests))),
            candidates=tuple(ordered[:MAX_ACTION_CANDIDATES]),
            search_limited=limited,
            projection_digest=self._ds.compute("action_candidate_digest", fields),
        )

    def verify(
        self, projection: ActionCandidateProjection, *, snapshot: AvailableToolSnapshot,
    ) -> None:
        payload = projection.model_dump(mode="python")
        expected = payload.pop("projection_digest")
        self._ds.verify("action_candidate_digest", payload, expected)
        if (
            projection.available_tool_snapshot_id != snapshot.snapshot_id
            or projection.available_tool_snapshot_digest != snapshot.snapshot_digest
        ):
            raise PlannerCandidateError("candidate projection is bound to another tool snapshot")
        visible = {view.tool_ref: view for view in snapshot.tools}
        registry = self._registries.get(self._registry_revision)
        if registry is None:
            raise PlannerCandidateError("tool registry is unavailable")
        definitions = {tool.tool_ref: tool for tool in registry.tools}
        for candidate in projection.candidates:
            view = visible.get(candidate.tool_ref)
            tool = definitions.get(candidate.tool_ref)
            if view is None or tool is None:
                raise PlannerCandidateError("candidate projection contains a non-visible tool")
            contract = self._contracts.get(candidate.action_contract_ref.contract_id)
            if (
                contract is None
                or contract.reference() != candidate.action_contract_ref
                or tool.action_contract_ref != candidate.action_contract_ref
                or tuple(sorted(candidate.satisfied_precondition_refs))
                != tuple(sorted(contract.preconditions))
                or candidate.eligible_session_ids != view.eligible_session_ids
                or candidate.requires_session != view.requires_session
            ):
                raise PlannerCandidateError("candidate projection contract or capability binding drift")
            fields = {
                "tool_ref": candidate.tool_ref.model_dump(mode="python"),
                "action_contract_ref": candidate.action_contract_ref.model_dump(mode="python"),
                "canonical_target_binding": [
                    item.model_dump(mode="python") for item in candidate.canonical_target_binding
                ],
                "satisfied_precondition_refs": list(candidate.satisfied_precondition_refs),
                "objective_dependency_ids": list(candidate.objective_dependency_ids),
                "eligible_session_ids": list(candidate.eligible_session_ids),
                "requires_session": candidate.requires_session,
            }
            expected_id = f"candidate-{self._ds.compute('action_candidate_digest', fields)[:24]}"
            if candidate.candidate_id != expected_id:
                raise PlannerCandidateError("candidate identity digest mismatch")

    def match_action(
        self, *, output: PlannerActionOutput, projection: ActionCandidateProjection,
    ) -> ActionCandidate:
        requested = _target_key(output.proposal.requested_targets)
        matches = [
            candidate for candidate in projection.candidates
            if candidate.tool_ref == output.proposal.tool_ref
            and _target_key(candidate.canonical_target_binding) == requested
            and (
                (candidate.requires_session and output.proposal.session_id in candidate.eligible_session_ids)
                or (not candidate.requires_session and output.proposal.session_id is None)
            )
        ]
        if len(matches) != 1:
            raise PlannerCandidateError("planner action does not uniquely match a current candidate")
        return matches[0]


class PlannerContextService:
    """Build and revalidate prompt snapshots without making them authority."""

    def __init__(
        self, *, database: Database, digest_service: DigestService, clock: Clock,
        context_resolver: AuthorizationContextResolver,
        context_authorization_service: ContextAuthorizationService,
        context_builder: ContextBuilder,
        context_selector: ContextSelector,
        snapshot_repository: AvailableToolSnapshotRepository,
        session_repository: SessionSecurityContextSnapshotRepository,
        goal_service: GoalEvaluationService, candidate_projector: ActionCandidateProjector,
        planner_state_manager: PlannerStateManager,
        retry_budget_service: AgentRetryBudgetService,
        mission_budget_repository: MissionExecutionBudgetRepository,
    ) -> None:
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._resolver = context_resolver
        self._context_auth = context_authorization_service
        self._context_builder = context_builder
        self._context_selector = context_selector
        self._snapshots = snapshot_repository
        self._sessions = session_repository
        self._goals = goal_service
        self._projector = candidate_projector
        self._planner_state = planner_state_manager
        self._retry_budgets = retry_budget_service
        self._mission_budgets = mission_budget_repository

    def build(
        self, *, planner_context_id: str, mission_id: str, goal_evaluation_id: str,
        projection: ActionCandidateProjection, context_grant_id: str,
        available_tool_snapshot_id: str, iteration: int,
        ranked_candidate_metadata: tuple[RankedContextCandidate, ...] = (),
        recent_execution_summaries: tuple[RecentExecutionSummary, ...] = (),
        feedback: tuple[PlannerFeedback, ...] = (), working_state_id: str | None = None,
        operational_phase: OperationalPhase = "INITIAL_ACCESS",
        truncation_reason_codes: tuple[str, ...] = (), parent_context_id: str | None = None,
    ) -> PlannerContextEnvelope:
        now = self._clock.now()
        context_rebuild_count = 0
        if parent_context_id is not None:
            parent = self.revalidate(parent_context_id)
            if parent.mission_id != mission_id or parent.iteration != iteration:
                raise PlannerContextError("context rebuild parent belongs to another loop iteration")
            if parent.context_rebuild_count >= 2:
                raise PlannerContextError("context rebuild limit reached")
            context_rebuild_count = parent.context_rebuild_count + 1
        current = self._resolver.resolve(mission_id, now=now)
        selected_metadata = self._context_selector.select(
            mission_id, _projection_target_values(projection)
        )
        if ranked_candidate_metadata != selected_metadata:
            raise PlannerContextError("ranked context metadata is not the current deterministic selection")
        mission_budget = self._mission_budgets.get(
            mission_id, current.mission.mission_revision
        )
        if mission_budget is None or iteration != mission_budget.consumed_dispatch_claims:
            raise PlannerContextError("planner iteration does not match the durable mission budget")
        goal = self._goals.verify_current(goal_evaluation_id, mission_id=mission_id)
        grant = self._context_auth.verify_grant(grant_id=context_grant_id, mission_id=mission_id)
        authorized_context = self._context_builder.build(
            grant_id=context_grant_id, mission_id=mission_id
        )
        snapshot = self._snapshots.get(available_tool_snapshot_id)
        if snapshot is None:
            raise PlannerContextError("available tool snapshot not found")
        revalidate_snapshot(
            snapshot, current=current.bindings,
            session_snapshots=self._sessions.all_snapshots(), now=now,
        )
        self._projector.verify(projection, snapshot=snapshot)
        if len(ranked_candidate_metadata) > MAX_RANKED_METADATA:
            raise PlannerContextError("ranked context metadata exceeds its fixed bound")
        if (
            goal.mission_revision != current.mission.mission_revision
            or goal.authorization_epoch != current.mission.authorization_epoch
            or grant.mission_revision != current.mission.mission_revision
            or grant.authorization_epoch != current.mission.authorization_epoch
            or snapshot.mission_revision != current.mission.mission_revision
            or snapshot.authorization_epoch != current.mission.authorization_epoch
        ):
            raise PlannerContextError("planner inputs do not share one current mission binding")
        required_sources = {goal.evaluation_digest, goal.knowledge_head_digest}
        if not required_sources <= set(projection.source_version_digests):
            raise PlannerContextError("candidate projection omits current goal or Knowledge source")
        visible = {view.tool_ref for view in snapshot.tools}
        if any(item.visible_tool_ref is not None and item.visible_tool_ref not in visible for item in feedback):
            raise PlannerContextError("feedback reveals a tool outside the visible snapshot")
        expires_at = min(grant.expires_at, snapshot.expires_at, now + timedelta(
            seconds=MAX_ENVELOPE_TTL_SECONDS
        ))
        if not now < expires_at:
            raise PlannerContextError("planner context has no positive lifetime")
        draft = PlannerContextEnvelope(
            planner_context_id=planner_context_id, envelope_revision=1,
            parent_context_id=parent_context_id,
            context_rebuild_count=context_rebuild_count,
            goal_evaluation_id=goal.evaluation_id,
            goal_evaluation_digest=goal.evaluation_digest,
            action_candidate_projection=projection,
            action_candidate_digest=projection.projection_digest,
            mission_id=mission_id, mission_revision=current.mission.mission_revision,
            authorization_epoch=current.mission.authorization_epoch, iteration=iteration,
            context_grant_id=grant.grant_id, context_grant_digest=grant.grant_digest,
            available_tool_snapshot_id=snapshot.snapshot_id,
            available_tool_snapshot_digest=snapshot.snapshot_digest,
            authorized_context=authorized_context,
            ranked_candidate_metadata=ranked_candidate_metadata,
            recent_execution_summaries=recent_execution_summaries,
            feedback=feedback, working_state_id=working_state_id,
            operational_phase=operational_phase,
            truncation_reason_codes=tuple(sorted(set(truncation_reason_codes))),
            created_at=now, expires_at=expires_at, envelope_digest="pending",
        )
        fields = draft.model_dump(mode="python")
        fields.pop("envelope_digest")
        envelope = draft.model_copy(update={
            "envelope_digest": self._ds.compute("planner_context_envelope_digest", fields)
        })
        try:
            with UnitOfWork(self._db):
                if parent_context_id is None:
                    self._db.occ_insert(
                        _CONTEXT_ROOT_NS, f"{mission_id}:{iteration}", 1,
                        json.dumps({"planner_context_id": planner_context_id}, sort_keys=True),
                    )
                else:
                    if self._db.occ_get(_CONTEXT_REQUEST_NS, parent_context_id) is None:
                        raise PlannerContextError("context rebuild parent has no accepted request")
                    self._db.occ_insert(
                        _CONTEXT_CHILD_NS, parent_context_id, 1,
                        json.dumps({"child_context_id": planner_context_id}, sort_keys=True),
                    )
                self._db.occ_insert_idempotent(
                    _ENVELOPE_NS, planner_context_id, 1,
                    json.dumps(envelope.model_dump(mode="json"), sort_keys=True),
                )
        except RepositoryIntegrityError:
            raise PlannerContextError("planner context lineage already advanced") from None
        return envelope

    def get(self, planner_context_id: str) -> PlannerContextEnvelope | None:
        row = self._db.occ_get(_ENVELOPE_NS, planner_context_id)
        if row is None:
            return None
        envelope = PlannerContextEnvelope.model_validate_json(row[1])
        if envelope.planner_context_id != planner_context_id or row[0] != envelope.envelope_revision:
            raise PlannerContextError("planner context identity or revision mismatch")
        payload = envelope.model_dump(mode="python")
        expected = payload.pop("envelope_digest")
        self._ds.verify("planner_context_envelope_digest", payload, expected)
        return envelope

    def revalidate(self, planner_context_id: str) -> PlannerContextEnvelope:
        envelope = self.get(planner_context_id)
        if envelope is None:
            raise PlannerContextError("planner context not found")
        now = self._clock.now()
        if not now < envelope.expires_at:
            raise PlannerContextError("planner context expired")
        current = self._resolver.resolve(envelope.mission_id, now=now)
        goal = self._goals.verify_current(
            envelope.goal_evaluation_id, mission_id=envelope.mission_id
        )
        self.revalidate_selection(planner_context_id)
        grant = self.revalidate_authorization(planner_context_id)
        self.revalidate_context_body(planner_context_id)
        snapshot = self.revalidate_tool_availability(planner_context_id)
        if (
            envelope.goal_evaluation_digest != goal.evaluation_digest
            or envelope.context_grant_digest != grant.grant_digest
            or envelope.available_tool_snapshot_digest != snapshot.snapshot_digest
            or envelope.mission_revision != current.mission.mission_revision
            or envelope.authorization_epoch != current.mission.authorization_epoch
        ):
            raise PlannerContextError("planner context binding drift")
        return envelope

    def revalidate_selection(self, planner_context_id: str) -> PlannerContextEnvelope:
        """Re-run the read-only metadata selector for the stored target set."""
        envelope = self._require(planner_context_id)
        selected = self._context_selector.select(
            envelope.mission_id,
            _projection_target_values(envelope.action_candidate_projection),
        )
        if selected != envelope.ranked_candidate_metadata:
            raise PlannerContextError("ranked context metadata changed")
        return envelope

    def revalidate_authorization(self, planner_context_id: str) -> ContextDataAccessGrant:
        """Verify the persisted grant against the current mission binding."""
        envelope = self._require(planner_context_id)
        grant = self._context_auth.verify_grant(
            grant_id=envelope.context_grant_id, mission_id=envelope.mission_id
        )
        if grant.grant_digest != envelope.context_grant_digest:
            raise PlannerContextError("context grant binding drift")
        return grant

    def revalidate_context_body(self, planner_context_id: str) -> CanonicalJsonObject:
        """Rebuild only the bodies named by the verified grant."""
        envelope = self._require(planner_context_id)
        body = self._context_builder.build(
            grant_id=envelope.context_grant_id, mission_id=envelope.mission_id
        )
        if canonical_dumps(body) != canonical_dumps(envelope.authorized_context):
            raise PlannerContextError("authorized context body changed")
        return body

    def revalidate_tool_availability(self, planner_context_id: str) -> AvailableToolSnapshot:
        """Revalidate the persisted tool snapshot and its finite projection."""
        envelope = self._require(planner_context_id)
        now = self._clock.now()
        current = self._resolver.resolve(envelope.mission_id, now=now)
        snapshot = self._snapshots.get(envelope.available_tool_snapshot_id)
        if snapshot is None:
            raise PlannerContextError("available tool snapshot not found")
        revalidate_snapshot(
            snapshot, current=current.bindings,
            session_snapshots=self._sessions.all_snapshots(), now=now,
        )
        self._projector.verify(envelope.action_candidate_projection, snapshot=snapshot)
        return snapshot

    def _require(self, planner_context_id: str) -> PlannerContextEnvelope:
        envelope = self.get(planner_context_id)
        if envelope is None:
            raise PlannerContextError("planner context not found")
        if not self._clock.now() < envelope.expires_at:
            raise PlannerContextError("planner context expired")
        return envelope

    def accept_action(
        self, *, planner_context_id: str, output: PlannerActionOutput,
    ) -> ActionCandidate:
        """Revalidate all sources before accepting one exact Planner proposal."""
        envelope = self.revalidate(planner_context_id)
        candidate = self._projector.match_action(
            output=output, projection=envelope.action_candidate_projection
        )
        if self._db.occ_get(_CONTEXT_ACTION_NS, planner_context_id) is not None:
            raise PlannerContextError("planner action context already consumed") from None
        try:
            with UnitOfWork(self._db):
                if output.working_state_update is not None:
                    self._planner_state.apply(
                        mission_id=envelope.mission_id,
                        proposal=output.working_state_update,
                        allowed_reference_ids=_allowed_working_state_references(envelope),
                        use_existing_transaction=True,
                    )
                self._db.occ_insert(
                    _CONTEXT_ACTION_NS, planner_context_id, 1,
                    json.dumps(output.model_dump(mode="json"), sort_keys=True),
                )
        except RepositoryIntegrityError:
            raise PlannerContextError("planner action context already consumed") from None
        return candidate

    def accept_context_request(
        self, *, planner_context_id: str, output: PlannerContextRequest,
    ) -> PlannerContextRequest:
        """Authorize only a bounded rebuild; this creates no execution artifact."""
        envelope = self.revalidate(planner_context_id)
        if envelope.context_rebuild_count >= 2:
            raise PlannerContextError("context rebuild limit reached")
        if not output.retrieval_hints:
            raise PlannerContextError("context request must contain a typed retrieval hint")
        if self._db.occ_get(_CONTEXT_REQUEST_NS, planner_context_id) is not None:
            raise PlannerContextError("context request already consumed")
        root_context_id = envelope.planner_context_id
        ancestor = envelope
        while ancestor.parent_context_id is not None:
            root_context_id = ancestor.parent_context_id
            loaded_ancestor = self.get(root_context_id)
            if loaded_ancestor is None:
                raise PlannerContextError("context request lineage is incomplete")
            ancestor = loaded_ancestor
        self._retry_budgets.reserve(
            mission_id=envelope.mission_id,
            operation_id=f"{envelope.iteration}:{root_context_id}",
            retry_kind="context",
        )
        if output.working_state_update is not None:
            self._planner_state.apply(
                mission_id=envelope.mission_id, proposal=output.working_state_update,
                allowed_reference_ids=_allowed_working_state_references(envelope),
            )
        try:
            with UnitOfWork(self._db):
                self._db.occ_insert(
                    _CONTEXT_REQUEST_NS, planner_context_id, 1,
                    json.dumps(output.model_dump(mode="json"), sort_keys=True),
                )
        except RepositoryIntegrityError:
            raise PlannerContextError("context request already consumed") from None
        return output


def _allowed_working_state_references(envelope: PlannerContextEnvelope) -> frozenset[str]:
    references = {
        envelope.goal_evaluation_id,
        envelope.context_grant_id,
        envelope.available_tool_snapshot_id,
        *(item.execution_id for item in envelope.recent_execution_summaries),
        *(
            reference
            for item in envelope.recent_execution_summaries
            for reference in item.result_reference_ids
        ),
    }

    def collect(value: object, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                collect(child, str(child_key))
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect(child, key)
        elif isinstance(value, str) and (key.endswith("_id") or key.endswith("_ids")):
            references.add(value)

    collect(envelope.authorized_context)
    return frozenset(references)


def _projection_target_values(projection: ActionCandidateProjection) -> frozenset[str]:
    return frozenset(
        target_reference_value(target)
        for candidate in projection.candidates
        for target in candidate.canonical_target_binding
    )
