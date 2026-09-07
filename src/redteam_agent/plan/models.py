"""Planner output and execution plan models (SystemDesign §6 / §25).

The planner only ever emits a typed ``PlannerOutput``. Only its ``action``
branch carries an ``ExecutionPlanProposal`` that may proceed to the policy
engine; the ``context_request`` branch never yields an execution/decision/
approval. Risk, approval and adapter are never planner-supplied. System ids are
issued by the application, not the model.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.policy.scope_models import TargetReference

OperationalPhase = Literal[
    "INITIAL_ACCESS",
    "DISCOVERY",
    "PRIVILEGE_ESCALATION",
    "CREDENTIAL_ACCESS",
    "LATERAL_MOVEMENT",
    "DOMAIN_CONTROL",
    "LINUX_PRIVILEGE_ESCALATION",
    "OBJECTIVE",
]


class ExecutionPlanProposal(StrictImmutableBoundaryModel):
    objective: str
    phase: OperationalPhase
    tool_ref: ToolRef
    requested_targets: tuple[TargetReference, ...]
    session_id: str | None
    arguments: CanonicalJsonObject


class RetrievalHint(StrictImmutableBoundaryModel):
    resource_types: tuple[
        Literal["artifact", "secret_reference", "local_artifact", "report", "internal_knowledge"], ...
    ]
    related_entity_refs: tuple[str, ...]
    requested_fact_types: tuple[
        Literal["identity", "service", "relationship", "finding", "execution_outcome"], ...
    ]
    recency_class: Literal["current", "recent", "any_authorized"]
    purpose_code: Literal["verify_hypothesis", "resolve_entity", "explain_failure", "prepare_next_action"]

    @model_validator(mode="after")
    def _bounded_canonical_references(self) -> RetrievalHint:
        groups = (self.resource_types, self.related_entity_refs, self.requested_fact_types)
        if any(len(group) != len(set(group)) for group in groups):
            raise ValueError("retrieval hint values must be unique")
        if len(self.related_entity_refs) > 20:
            raise ValueError("retrieval hint entity references exceed the fixed bound")
        if any(
            not ref or len(ref) > 128 or any(char in ref for char in ("/", "\\", "?", "\n", "\r"))
            for ref in self.related_entity_refs
        ):
            raise ValueError("retrieval hint requires canonical entity references")
        return self


class HypothesisCreateProposal(StrictImmutableBoundaryModel):
    operation: Literal["create"] = "create"
    statement: str
    basis_reference_ids: tuple[str, ...]
    next_verification_objective: str | None

    @model_validator(mode="after")
    def _bounded(self) -> HypothesisCreateProposal:
        _validate_hypothesis_text(self.statement, self.basis_reference_ids)
        return self


class HypothesisUpdateProposal(StrictImmutableBoundaryModel):
    operation: Literal["update"] = "update"
    hypothesis_id: str
    expected_hypothesis_version: int = Field(ge=1)
    statement: str
    proposed_status: Literal["investigating", "supported"]
    basis_reference_ids: tuple[str, ...]
    next_verification_objective: str | None

    @model_validator(mode="after")
    def _bounded(self) -> HypothesisUpdateProposal:
        _validate_hypothesis_text(self.statement, self.basis_reference_ids)
        if self.proposed_status == "supported" and not self.basis_reference_ids:
            raise ValueError("supported hypothesis requires a basis reference")
        return self


class HypothesisCloseProposal(StrictImmutableBoundaryModel):
    operation: Literal["close"] = "close"
    hypothesis_id: str
    expected_hypothesis_version: int = Field(ge=1)
    proposed_status: Literal["refuted", "abandoned"]
    reason_code: str
    basis_reference_ids: tuple[str, ...]

    @model_validator(mode="after")
    def _bounded(self) -> HypothesisCloseProposal:
        _validate_hypothesis_text(self.reason_code, self.basis_reference_ids)
        return self


HypothesisProposal = Annotated[
    HypothesisCreateProposal | HypothesisUpdateProposal | HypothesisCloseProposal,
    Field(discriminator="operation"),
]


class PlanThreadUpdateProposal(StrictImmutableBoundaryModel):
    operation: Literal["continue", "replace", "abandon"]
    objective: str
    expected_thread_version: int | None = Field(default=None, ge=1)
    hypothesis_updates: tuple[HypothesisProposal, ...] = Field(max_length=20)

    @model_validator(mode="after")
    def _bounded(self) -> PlanThreadUpdateProposal:
        if not self.objective or len(self.objective) > 4096:
            raise ValueError("Plan Thread objective must contain at most 4096 characters")
        identities = [
            f"new:{index}" if item.operation == "create" else item.hypothesis_id
            for index, item in enumerate(self.hypothesis_updates)
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("a hypothesis may be changed only once per proposal")
        if self.operation == "abandon" and self.hypothesis_updates:
            raise ValueError("abandon cannot also update hypotheses")
        return self


def _validate_hypothesis_text(text: str, references: tuple[str, ...]) -> None:
    if not text or len(text) > 4096:
        raise ValueError("hypothesis text must contain at most 4096 characters")
    if len(references) > 20 or len(references) != len(set(references)):
        raise ValueError("hypothesis basis references must be unique and bounded")
    if any(not reference or len(reference) > 256 for reference in references):
        raise ValueError("hypothesis basis reference is invalid")


class PlannerActionOutput(StrictImmutableBoundaryModel):
    output_type: Literal["action"] = "action"
    proposal: ExecutionPlanProposal
    working_state_update: PlanThreadUpdateProposal | None
    next_iteration_hints: tuple[RetrievalHint, ...] = Field(max_length=20)


class PlannerContextRequest(StrictImmutableBoundaryModel):
    output_type: Literal["context_request"] = "context_request"
    objective: str
    retrieval_hints: tuple[RetrievalHint, ...] = Field(max_length=20)
    working_state_update: PlanThreadUpdateProposal | None


PlannerOutput = Annotated[
    PlannerActionOutput | PlannerContextRequest,
    Field(discriminator="output_type"),
]


class ExecutionPlan(StrictImmutableBoundaryModel):
    plan_id: str
    mission_id: str
    mission_revision: int
    observed_mission_state_version: int
    observed_authorization_epoch: int
    run_id: str
    thread_id: str
    proposal: ExecutionPlanProposal
    proposal_digest: str
    # Audit reference only, never an authorization basis (SystemDesign §6). Goal
    # evaluation is a later phase; Phase 0A carries an explicit unevaluated
    # marker rather than a fabricated result.
    goal_evaluation_id: str
    goal_evaluation_digest: str
    action_contract_ref: ActionContractReference
    execution_precondition_digest: str
    available_tool_snapshot_id: str
    available_tool_snapshot_digest: str
    session_security_context_digest: str
    adapter_capabilities_digest: str
    sandbox_capabilities_digest: str
    remote_mcp_trust_policy_digest: str
    created_at: datetime


def _target_reference_payload(reference: TargetReference) -> dict[str, object]:
    return reference.model_dump(mode="python")


def compute_proposal_digest(proposal: ExecutionPlanProposal, digest_service: DigestService) -> str:
    """proposal_digest over the proposal only (SystemDesign §22.1).

    ``requested_targets`` are order-independent and are sorted; ``arguments``
    retain their (semantically meaningful) structure.
    """
    sorted_targets = sorted(
        (_target_reference_payload(target) for target in proposal.requested_targets),
        key=lambda payload: (payload.get("type", ""), str(sorted(payload.items()))),
    )
    payload = {
        "schema_version": "execution-plan-proposal-v1",
        "objective": proposal.objective,
        "phase": proposal.phase,
        "tool_ref": proposal.tool_ref.model_dump(mode="python"),
        "requested_targets": sorted_targets,
        "session_id": proposal.session_id,
        "arguments": proposal.arguments,
    }
    return digest_service.compute("proposal_digest", payload)
