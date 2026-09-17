"""Advisory local-LLM selection of the next read-only AD inspection."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Literal

from pydantic import Field

from redteam_agent.ad_assessment.catalog import (
    AD_ASSESSMENT_CATALOG_REVISION,
    AD_ASSESSMENT_OPERATIONS,
    AD_ASSESSMENT_PARAMETER_SCHEMA,
)
from redteam_agent.ad_assessment.models import ADAssessmentCategory
from redteam_agent.ad_assessment.planner import (
    build_ad_assessment_candidate_seeds,
    validate_ad_assessment_planner_selection,
)
from redteam_agent.agent.models import (
    ActionCandidate,
    ActionCandidateProjection,
    ActionCandidateSeed,
    PlannerContextEnvelope,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMOutputValidationError, PlannerCandidateError
from redteam_agent.llm.adapters import LocalLLMPlanner
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ActionContractReference
from redteam_agent.policy.scope_models import HostTargetReference
from redteam_agent.runtime.clock import Clock


class ADAssessmentRecommendation(StrictImmutableBoundaryModel):
    operation_id: str = Field(pattern=r"^ad\.audit\.[a-z0-9_.-]+$")
    category: ADAssessmentCategory
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    output_schema: Literal["planner_output"] = "planner_output"
    authority: Literal["recommendation_only"] = "recommendation_only"
    candidate_count: int = Field(gt=0, le=5)
    generated_at: datetime


CapabilityChecker = Callable[[], None]


class ADAssessmentReasoner:
    """Run the qualified Planner, then reduce its output to trusted catalog metadata."""

    MAX_OUTPUT_RETRIES = 3

    def __init__(
        self,
        *,
        planner: LocalLLMPlanner,
        capability_checker: CapabilityChecker,
        clock: Clock,
        digest_service: DigestService,
    ) -> None:
        self._planner = planner
        self._check_capability = capability_checker
        self._clock = clock
        self._digests = digest_service

    def recommend(
        self,
        *,
        completed_operation_ids: frozenset[str] = frozenset(),
    ) -> ADAssessmentRecommendation:
        self._check_capability()
        host = HostTargetReference(type="host", host_id="ad-assessment-simulator-dc")
        seeds = build_ad_assessment_candidate_seeds(
            host_target=host,
            registry_revision=1,
            completed_operation_ids=completed_operation_ids,
        )
        if not seeds:
            raise PlannerCandidateError("all AD assessment inspections are already complete")
        envelope = self._build_envelope(seeds=seeds)
        invocation = self._planner.build_invocation(
            envelope,
            deadline=self._clock.now() + timedelta(seconds=60),
            seed=0,
        )
        selected_id: str | None = None
        for attempt in range(self.MAX_OUTPUT_RETRIES + 1):
            invocation.before_attempt(attempt)
            try:
                output = invocation(envelope)
                selected_id = validate_ad_assessment_planner_selection(output, candidates=seeds)
            except (LLMOutputValidationError, PlannerCandidateError):
                continue
            break
        if selected_id is None:
            raise PlannerCandidateError("local LLM produced no exact AD assessment candidate")
        operation = next(item for item in AD_ASSESSMENT_OPERATIONS if item.operation_id == selected_id)
        return ADAssessmentRecommendation(
            operation_id=operation.operation_id,
            category=operation.category,
            title=operation.title,
            description=operation.description,
            candidate_count=len(seeds),
            generated_at=self._clock.now(),
        )

    def _build_envelope(
        self,
        *,
        seeds: tuple[ActionCandidateSeed, ...],
    ) -> PlannerContextEnvelope:
        operation_by_id = {item.operation_id: item for item in AD_ASSESSMENT_OPERATIONS}
        catalog_digest = self._digests.compute(
            "security_projection_digest",
            {
                "catalog_revision": AD_ASSESSMENT_CATALOG_REVISION,
                "operation_ids": [seed.tool_ref.tool_id for seed in seeds],
            },
        )
        candidates: list[ActionCandidate] = []
        for seed in seeds:
            operation = operation_by_id[seed.tool_ref.tool_id]
            contract_digest = self._digests.compute(
                "security_projection_digest",
                {"catalog_revision": AD_ASSESSMENT_CATALOG_REVISION, "operation_id": operation.operation_id},
            )
            candidates.append(
                ActionCandidate(
                    candidate_id=f"candidate-{contract_digest[:24]}",
                    tool_ref=seed.tool_ref,
                    action_contract_ref=ActionContractReference(
                        contract_id=f"ad-assessment:{operation.operation_id}",
                        revision=AD_ASSESSMENT_CATALOG_REVISION,
                        digest=contract_digest,
                    ),
                    display_name=operation.title,
                    description=operation.description,
                    parameter_schema=AD_ASSESSMENT_PARAMETER_SCHEMA,
                    canonical_target_binding=seed.canonical_target_binding,
                    satisfied_precondition_refs=(),
                    objective_dependency_ids=seed.objective_dependency_ids,
                    eligible_session_ids=(),
                    requires_session=False,
                    suggested_arguments=seed.suggested_arguments,
                )
            )
        projection_draft = ActionCandidateProjection(
            available_tool_snapshot_id="ad-assessment-advisory-tools",
            available_tool_snapshot_digest=catalog_digest,
            source_version_digests=(catalog_digest,),
            candidates=tuple(candidates),
            search_limited=False,
            projection_digest="pending",
        )
        projection_fields = projection_draft.model_dump(mode="python")
        projection_fields.pop("projection_digest")
        projection = projection_draft.model_copy(
            update={"projection_digest": self._digests.compute("action_candidate_digest", projection_fields)}
        )
        now = self._clock.now()
        envelope_draft = PlannerContextEnvelope(
            planner_context_id="ad-assessment-advisory-context",
            envelope_revision=1,
            parent_context_id=None,
            context_rebuild_count=0,
            goal_evaluation_id="ad-assessment-advisory-goal",
            goal_evaluation_digest=catalog_digest,
            action_candidate_projection=projection,
            action_candidate_digest=projection.projection_digest,
            mission_id="ad-assessment-advisory",
            mission_revision=1,
            authorization_epoch=0,
            iteration=0,
            context_grant_id="ad-assessment-advisory-public-context",
            context_grant_digest=catalog_digest,
            available_tool_snapshot_id=projection.available_tool_snapshot_id,
            available_tool_snapshot_digest=projection.available_tool_snapshot_digest,
            authorized_context={
                "assessment_mode": "read_only_configuration_assessment",
                "finding_authority": "deterministic_verifier",
                "prohibited": [
                    "ticket_acquisition",
                    "credential_cracking",
                    "certificate_enrollment",
                    "delegation_impersonation",
                    "directory_changes",
                ],
            },
            ranked_candidate_metadata=(),
            recent_execution_summaries=(),
            feedback=(),
            working_state_id=None,
            operational_phase="DISCOVERY",
            truncation_reason_codes=(),
            created_at=now,
            expires_at=now + timedelta(seconds=120),
            envelope_digest="pending",
        )
        envelope_fields = envelope_draft.model_dump(mode="python")
        envelope_fields.pop("envelope_digest")
        return envelope_draft.model_copy(
            update={"envelope_digest": self._digests.compute("planner_context_envelope_digest", envelope_fields)}
        )


__all__ = ["ADAssessmentReasoner", "ADAssessmentRecommendation"]
