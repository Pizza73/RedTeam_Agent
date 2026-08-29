"""Approval request/record factories; no UI or external service is included."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.authorization_runtime import AuthorizationRuntimeContextResolver
from redteam_agent.canonical import canonicalize, digest_model, sha256_digest, stable_id
from redteam_agent.canonical.models import CanonicalJsonObject
from redteam_agent.errors import ApprovalBindingError, MissionTTLExceededError
from redteam_agent.models.approval import (
    ApprovalPresentation,
    ApprovalRecord,
    ApprovalRequest,
    HumanApprovalDecision,
)
from redteam_agent.models.mission import Mission
from redteam_agent.models.plans import ExecutionPlan
from redteam_agent.models.policy import PolicyDecision
from redteam_agent.models.tools import ToolDefinition
from redteam_agent.repositories.approval import ApprovalRecordRepository, ApprovalRequestRepository
from redteam_agent.repositories.plans import PlanRepository
from redteam_agent.repositories.policy import PolicyDecisionRepository

_APPROVAL_BUILDER_TOKEN = object()


def _redacted_arguments(plan: ExecutionPlan, tool: ToolDefinition) -> CanonicalJsonObject:
    value = plan.proposal.arguments.to_dict()
    for path in tool.secret_argument_paths:
        segments = tuple(
            segment for segment in path.strip("/.").replace("/", ".").split(".") if segment
        )
        current: object = value
        for segment in segments[:-1]:
            if not isinstance(current, dict) or segment not in current:
                current = None
                break
            current = current[segment]
        if segments and isinstance(current, dict) and segments[-1] in current:
            current[segments[-1]] = "[REDACTED]"
    return CanonicalJsonObject(value)


def build_approval_presentation(
    *, plan: ExecutionPlan, decision: PolicyDecision, tool: ToolDefinition
) -> ApprovalPresentation:
    return ApprovalPresentation(
        tool_ref=decision.tool_ref,
        tool_display_name=tool.display_name,
        normalized_targets=decision.normalized_targets,
        redacted_arguments=_redacted_arguments(plan, tool),
        effective_risk=decision.effective_risk,
        side_effect=decision.side_effect,
        resolved_adapter_id=decision.resolved_adapter_id,
    )


def create_approval_request(
    *,
    mission: Mission,
    decision: PolicyDecision,
    plan: ExecutionPlan,
    tool: ToolDefinition,
    issued_at: datetime,
    expires_at: datetime,
) -> ApprovalRequest:
    if decision.decision != "REQUIRE_APPROVAL":
        raise ApprovalBindingError("approval requests require REQUIRE_APPROVAL decisions")
    if expires_at > mission.valid_until or expires_at > decision.expires_at:
        raise MissionTTLExceededError("approval request violates TTL invariant")
    if decision.plan_id != plan.plan_id:
        raise ApprovalBindingError("approval decision/plan binding mismatch")
    presentation = build_approval_presentation(plan=plan, decision=decision, tool=tool)
    redacted_arguments_summary = canonicalize(presentation.redacted_arguments).decode("utf-8")
    presentation_digest = sha256_digest(
        {"schema_version": "approval-presentation-v1", "presentation": presentation}
    )
    identity = {
        "schema_version": "approval-request-v1",
        "policy_decision_id": decision.decision_id,
        "authorization_digest": decision.authorization_digest,
        "approval_presentation_digest": presentation_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    provisional = ApprovalRequest(
        approval_request_id=stable_id("approvalrequest", identity),
        request_digest="pending",
        mission_id=mission.mission_id,
        mission_revision=mission.mission_revision,
        authorization_epoch=mission.authorization_epoch,
        policy_decision_id=decision.decision_id,
        authorization_digest=decision.authorization_digest,
        approval_presentation_digest=presentation_digest,
        presentation=presentation,
        redacted_arguments_summary=redacted_arguments_summary,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return provisional.model_copy(
        update={"request_digest": digest_model(provisional, exclude={"request_digest"})}
    )


def create_approval_record(
    *,
    request: ApprovalRequest,
    decision: PolicyDecision,
    human_decision: HumanApprovalDecision,
    approver_id: str,
    approver_role: str,
    issued_at: datetime,
    expires_at: datetime,
) -> ApprovalRecord:
    if human_decision not in {"APPROVED", "REJECTED"}:
        raise ApprovalBindingError("unknown human approval decision")
    if expires_at > request.expires_at or expires_at > decision.expires_at:
        raise MissionTTLExceededError("approval record violates TTL invariant")
    identity = {
        "schema_version": "approval-record-v1",
        "approval_request_id": request.approval_request_id,
        "request_digest": request.request_digest,
        "human_decision": human_decision,
        "approver_id": approver_id,
        "issued_at": issued_at,
    }
    provisional = ApprovalRecord(
        approval_id=stable_id("approval", identity),
        record_digest="pending",
        approval_request_id=request.approval_request_id,
        approval_request_digest=request.request_digest,
        approval_presentation_digest=request.approval_presentation_digest,
        mission_id=request.mission_id,
        mission_revision=request.mission_revision,
        authorization_epoch=request.authorization_epoch,
        policy_decision_id=decision.decision_id,
        authorization_digest=decision.authorization_digest,
        decision=human_decision,
        approver_id=approver_id,
        approver_role=approver_role,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return provisional.model_copy(
        update={"record_digest": digest_model(provisional, exclude={"record_digest"})}
    )


class ApprovalService:
    """Application-owned construction/persistence path for human approval artifacts."""

    def __init__(
        self,
        *,
        runtime_resolver: AuthorizationRuntimeContextResolver,
        plans: PlanRepository,
        decisions: PolicyDecisionRepository,
        requests: ApprovalRequestRepository,
        records: ApprovalRecordRepository,
    ) -> None:
        self.runtime_resolver = runtime_resolver
        self.plans = plans
        self.decisions = decisions
        self.requests = requests
        self.records = records

    def request(
        self,
        *,
        plan_id: str,
        policy_decision_id: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> ApprovalRequest:
        plan = self.plans.get(plan_id)
        decision = self.decisions.get(policy_decision_id)
        if plan is None or decision is None or decision.plan_id != plan_id:
            raise ApprovalBindingError("approval source plan/decision is unavailable")
        runtime = self.runtime_resolver.resolve(plan.mission_id)
        tool = next(
            (item for item in runtime.registry.tools if item.tool_ref == decision.tool_ref),
            None,
        )
        if tool is None:
            raise ApprovalBindingError("approval tool is not registered")
        request = create_approval_request(
            mission=runtime.mission,
            decision=decision,
            plan=plan,
            tool=tool,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return self.requests._store_built(request, builder_token=_APPROVAL_BUILDER_TOKEN)

    def record(
        self,
        *,
        approval_request_id: str,
        human_decision: HumanApprovalDecision,
        approver_id: str,
        approver_role: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> ApprovalRecord:
        request = self.requests.get(approval_request_id)
        if request is None:
            raise ApprovalBindingError("approval request is unavailable")
        decision = self.decisions.get(request.policy_decision_id)
        if decision is None:
            raise ApprovalBindingError("policy decision is unavailable")
        record = create_approval_record(
            request=request,
            decision=decision,
            human_decision=human_decision,
            approver_id=approver_id,
            approver_role=approver_role,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return self.records._store_built(record, builder_token=_APPROVAL_BUILDER_TOKEN)
