"""Finite Planner candidate construction and post-LLM selection guard."""

from __future__ import annotations

from redteam_agent.ad_assessment.catalog import AD_ASSESSMENT_OPERATIONS
from redteam_agent.agent.models import ActionCandidateSeed
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.errors import PlannerCandidateError
from redteam_agent.models.common import ToolRef
from redteam_agent.plan.models import PlannerActionOutput, PlannerOutput
from redteam_agent.policy.scope_models import HostTargetReference


def build_ad_assessment_candidate_seeds(
    *,
    host_target: HostTargetReference,
    registry_revision: int,
    completed_operation_ids: frozenset[str] = frozenset(),
) -> tuple[ActionCandidateSeed, ...]:
    """Offer only incomplete, registered read-only inspections to the LLM Planner."""

    known = {item.operation_id for item in AD_ASSESSMENT_OPERATIONS}
    if not completed_operation_ids <= known:
        raise PlannerCandidateError("completed AD assessment operation is not registered")
    arguments = {"host_ids": [host_target.host_id], "timeout_seconds": 30}
    return tuple(
        ActionCandidateSeed(
            tool_ref=ToolRef(tool_id=item.operation_id, registry_revision=registry_revision),
            canonical_target_binding=(host_target,),
            satisfied_precondition_refs=(),
            objective_dependency_ids=(item.category,),
            suggested_arguments=arguments,
        )
        for item in AD_ASSESSMENT_OPERATIONS
        if item.operation_id not in completed_operation_ids
    )


def validate_ad_assessment_planner_selection(
    output: PlannerOutput,
    *,
    candidates: tuple[ActionCandidateSeed, ...],
) -> str:
    """Return the selected ID only when the LLM exactly copied one finite candidate.

    This validates selection, not evidence and not a finding.  The deterministic
    verifier remains the sole decision authority.
    """

    if not isinstance(output, PlannerActionOutput):
        raise PlannerCandidateError("AD assessment planning did not select an action")
    proposal = output.proposal
    if proposal.phase != "DISCOVERY" or proposal.session_id is not None:
        raise PlannerCandidateError("AD assessment selection must be session-free discovery")
    for candidate in candidates:
        if (
            proposal.tool_ref == candidate.tool_ref
            and canonical_dumps([item.model_dump(mode="python") for item in proposal.requested_targets])
            == canonical_dumps([item.model_dump(mode="python") for item in candidate.canonical_target_binding])
            and canonical_dumps(proposal.arguments) == canonical_dumps(candidate.suggested_arguments)
        ):
            return proposal.tool_ref.tool_id
    raise PlannerCandidateError("AD assessment selection is not an exact current candidate")


__all__ = [
    "build_ad_assessment_candidate_seeds",
    "validate_ad_assessment_planner_selection",
]
