"""Bounded local-LLM classification with deterministic consensus enforcement."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import timedelta

from redteam_agent.ad_assessment.catalog import (
    AD_ASSESSMENT_CATALOG_REVISION,
    AD_ASSESSMENT_OPERATIONS,
    ADAssessmentOperation,
)
from redteam_agent.ad_assessment.models import (
    ADAssessmentCategoryConsensus,
    ADAssessmentConsensusResult,
    ADAssessmentSnapshot,
    ADAssessmentStatus,
)
from redteam_agent.ad_assessment.service import ADAssessmentVerifier
from redteam_agent.agent.models import ActionCandidate, ActionCandidateProjection, PlannerContextEnvelope
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMOutputValidationError, PlannerCandidateError
from redteam_agent.llm.adapters import LocalLLMPlanner
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.plan.models import PlannerActionOutput
from redteam_agent.policy.scope_models import HostTargetReference
from redteam_agent.runtime.clock import Clock

CapabilityChecker = Callable[[], None]

_CLASSIFICATION_STATUSES: tuple[ADAssessmentStatus, ...] = (
    "misconfiguration_detected",
    "no_misconfiguration_detected",
    "indeterminate",
)
_CLASSIFICATION_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "operation_id": {"type": "string"},
        "evidence_digest": {"type": "string"},
        "classification": {"enum": list(_CLASSIFICATION_STATUSES)},
    },
    "required": ["operation_id", "evidence_digest", "classification"],
    "additionalProperties": False,
}
_CLASSIFICATION_DESCRIPTIONS: Mapping[ADAssessmentStatus, str] = {
    "misconfiguration_detected": (
        "Select only when normalized evidence is present and risk_signal_count is greater than zero."
    ),
    "no_misconfiguration_detected": (
        "Select only when normalized evidence is present and risk_signal_count equals zero."
    ),
    "indeterminate": "Select only when normalized evidence is not present.",
}


class ADAssessmentLLMConsensusEvaluator:
    """Classify every closed-catalog category and fail closed on disagreement.

    The model selects from three finite status candidates. Its free-form objective
    and hints are discarded. Deterministic rules independently produce all findings.
    """

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

    def evaluate(self, snapshot: ADAssessmentSnapshot) -> ADAssessmentConsensusResult:
        self._check_capability()
        verifier_result = ADAssessmentVerifier(clock=self._clock.now).evaluate(snapshot)
        verifier_by_operation = {item.operation_id: item for item in verifier_result.checks}
        category_results: list[ADAssessmentCategoryConsensus] = []
        for operation in AD_ASSESSMENT_OPERATIONS:
            evidence_summary = self._evidence_summary(snapshot, operation)
            evidence_digest = self._digests.compute(
                "security_projection_digest",
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "operation_id": operation.operation_id,
                    "evidence_summary": evidence_summary,
                },
            )
            candidates = self._build_candidates(operation, evidence_digest)
            envelope = self._build_envelope(
                operation=operation,
                candidates=candidates,
                evidence_summary=evidence_summary,
                evidence_digest=evidence_digest,
            )
            llm_status = self._select_status(envelope, candidates)
            verifier_check = verifier_by_operation[operation.operation_id]
            category_results.append(
                ADAssessmentCategoryConsensus(
                    operation_id=operation.operation_id,
                    category=operation.category,
                    llm_status=llm_status,
                    verifier_status=verifier_check.status,
                    consensus="agreed" if llm_status == verifier_check.status else "disagreed",
                    verified_rule_ids=verifier_check.finding_rule_ids,
                )
            )
        complete = all(
            item.consensus == "agreed" and item.verifier_status != "indeterminate" for item in category_results
        )
        return ADAssessmentConsensusResult(
            result_id=f"ad-assessment-consensus-{snapshot.snapshot_id}",
            snapshot_id=snapshot.snapshot_id,
            domain_ref=snapshot.domain_ref,
            evidence_source_type=snapshot.source_type,
            status="completed" if complete else "blocked",
            evaluated_at=self._clock.now(),
            category_results=tuple(category_results),
            findings=verifier_result.findings,
        )

    def _select_status(
        self,
        envelope: PlannerContextEnvelope,
        candidates: tuple[ActionCandidate, ...],
    ) -> ADAssessmentStatus:
        invocation = self._planner.build_invocation(
            envelope,
            deadline=self._clock.now() + timedelta(seconds=60),
            seed=0,
        )
        for attempt in range(self.MAX_OUTPUT_RETRIES + 1):
            invocation.before_attempt(attempt)
            try:
                output = invocation(envelope)
                return self._validate_selection(output, candidates)
            except (LLMOutputValidationError, PlannerCandidateError):
                continue
        raise PlannerCandidateError("local LLM produced no exact AD assessment classification")

    @staticmethod
    def _validate_selection(
        output: object,
        candidates: tuple[ActionCandidate, ...],
    ) -> ADAssessmentStatus:
        if not isinstance(output, PlannerActionOutput):
            raise PlannerCandidateError("AD assessment classification did not select an action")
        proposal = output.proposal
        if proposal.phase != "DISCOVERY" or proposal.session_id is not None:
            raise PlannerCandidateError("AD assessment classification must be session-free discovery")
        for candidate, status in zip(candidates, _CLASSIFICATION_STATUSES, strict=True):
            if (
                proposal.tool_ref == candidate.tool_ref
                and canonical_dumps([item.model_dump(mode="python") for item in proposal.requested_targets])
                == canonical_dumps([item.model_dump(mode="python") for item in candidate.canonical_target_binding])
                and canonical_dumps(proposal.arguments) == canonical_dumps(candidate.suggested_arguments)
            ):
                return status
        raise PlannerCandidateError("AD assessment classification is not an exact current candidate")

    def _build_candidates(
        self,
        operation: ADAssessmentOperation,
        evidence_digest: str,
    ) -> tuple[ActionCandidate, ...]:
        target = HostTargetReference(type="host", host_id="ad-assessment-simulator-dc")
        candidates: list[ActionCandidate] = []
        for status in _CLASSIFICATION_STATUSES:
            tool_id = f"ad.classify.{status}"
            contract_digest = self._digests.compute(
                "security_projection_digest",
                {
                    "catalog_revision": AD_ASSESSMENT_CATALOG_REVISION,
                    "operation_id": operation.operation_id,
                    "classification": status,
                    "evidence_digest": evidence_digest,
                },
            )
            candidates.append(
                ActionCandidate(
                    candidate_id=f"classification-{contract_digest[:24]}",
                    tool_ref=ToolRef(tool_id=tool_id, registry_revision=1),
                    action_contract_ref=ActionContractReference(
                        contract_id=f"ad-assessment-classification:{operation.operation_id}:{status}",
                        revision=AD_ASSESSMENT_CATALOG_REVISION,
                        digest=contract_digest,
                    ),
                    display_name=status.replace("_", " ").title(),
                    description=_CLASSIFICATION_DESCRIPTIONS[status],
                    parameter_schema=_CLASSIFICATION_SCHEMA,
                    canonical_target_binding=(target,),
                    satisfied_precondition_refs=(operation.operation_id,),
                    objective_dependency_ids=(operation.category,),
                    eligible_session_ids=(),
                    requires_session=False,
                    suggested_arguments={
                        "operation_id": operation.operation_id,
                        "evidence_digest": evidence_digest,
                        "classification": status,
                    },
                )
            )
        return tuple(candidates)

    def _build_envelope(
        self,
        *,
        operation: ADAssessmentOperation,
        candidates: tuple[ActionCandidate, ...],
        evidence_summary: dict[str, object],
        evidence_digest: str,
    ) -> PlannerContextEnvelope:
        projection_digest = self._digests.compute(
            "action_candidate_digest",
            {
                "operation_id": operation.operation_id,
                "evidence_digest": evidence_digest,
                "candidates": [item.model_dump(mode="python") for item in candidates],
            },
        )
        projection = ActionCandidateProjection(
            available_tool_snapshot_id=f"ad-assessment-classification-{operation.evidence_field}",
            available_tool_snapshot_digest=evidence_digest,
            source_version_digests=(evidence_digest,),
            candidates=candidates,
            search_limited=False,
            projection_digest=projection_digest,
        )
        now = self._clock.now()
        envelope_draft = PlannerContextEnvelope(
            planner_context_id=f"ad-assessment-classification-{operation.evidence_field}",
            envelope_revision=1,
            parent_context_id=None,
            context_rebuild_count=0,
            goal_evaluation_id=f"ad-assessment-classify-{operation.evidence_field}",
            goal_evaluation_digest=evidence_digest,
            action_candidate_projection=projection,
            action_candidate_digest=projection.projection_digest,
            mission_id="ad-assessment-read-only",
            mission_revision=1,
            authorization_epoch=0,
            iteration=0,
            context_grant_id="ad-assessment-normalized-evidence-only",
            context_grant_digest=evidence_digest,
            available_tool_snapshot_id=projection.available_tool_snapshot_id,
            available_tool_snapshot_digest=projection.available_tool_snapshot_digest,
            authorized_context={
                "assessment_mode": "read_only_configuration_classification",
                "operation_id": operation.operation_id,
                "category": operation.category,
                "normalized_evidence": evidence_summary,
                "classification_rule": {
                    "evidence_missing": "indeterminate",
                    "risk_signal_count_greater_than_zero": "misconfiguration_detected",
                    "risk_signal_count_equals_zero": "no_misconfiguration_detected",
                },
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

    @staticmethod
    def _evidence_summary(
        snapshot: ADAssessmentSnapshot,
        operation: ADAssessmentOperation,
    ) -> dict[str, object]:
        evidence = getattr(snapshot, operation.evidence_field)
        if evidence is None:
            return {"present": False, "risk_signal_count": 0, "counts": {}}
        counts = evidence.model_dump(mode="json")
        if operation.operation_id == "ad.audit.kerberos_service_accounts":
            risk_count = sum(
                counts[field]
                for field in (
                    "weak_encryption_service_account_count",
                    "stale_password_service_account_count",
                    "unmanaged_service_account_count",
                )
            )
        elif operation.operation_id == "ad.audit.adcs_esc":
            risk_count = sum(item["affected_object_count"] for item in counts["exposure_counts"])
        else:
            risk_count = sum(counts.values())
        return {"present": True, "risk_signal_count": risk_count, "counts": counts}


__all__ = ["ADAssessmentLLMConsensusEvaluator"]
