"""Repository-backed Phase 0A authorization gate; no dispatch capability exists."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from redteam_agent.authorization_runtime import AuthorizationRuntimeContextResolver
from redteam_agent.canonical import canonicalize, sha256_digest
from redteam_agent.errors import (
    CurrentAuthorizationStateError,
    DigestIntegrityError,
    PolicyDecisionProvenanceError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.context import ResourceBinding
from redteam_agent.policy.approval import build_approval_presentation
from redteam_agent.policy.engine import PolicyEngine
from redteam_agent.repositories.approval import (
    ApprovalRecordRepository,
    ApprovalRequestRepository,
)
from redteam_agent.repositories.context import ContextResourceIndexRepository
from redteam_agent.repositories.plans import PlanRepository
from redteam_agent.repositories.policy import PolicyDecisionRepository
from redteam_agent.tools.availability import ToolAvailabilityResolver, execution_scope_digest
from redteam_agent.tools.target_extractors import TrustedTargetExtractorRegistry


class AuthorizationGateResult(StrictImmutableBoundaryModel):
    status: Literal["AUTHORIZED", "DENIED", "STALE", "INVALID", "WAITING_APPROVAL"]
    reason_codes: tuple[str, ...]
    dispatch_performed: Literal[False] = False


def _result(status: str, *reasons: str) -> AuthorizationGateResult:
    return AuthorizationGateResult(
        status=status,
        reason_codes=tuple(sorted(set(reasons))),
        dispatch_performed=False,
    )


def authorize_execution(
    *,
    plan_id: str,
    policy_decision_id: str,
    runtime_resolver: AuthorizationRuntimeContextResolver,
    plans: PlanRepository,
    decisions: PolicyDecisionRepository,
    resources: ContextResourceIndexRepository,
    approval_requests: ApprovalRequestRepository | None = None,
    approvals: ApprovalRecordRepository | None = None,
    approval_request_id: str | None = None,
    approval_record_id: str | None = None,
    now: datetime,
) -> AuthorizationGateResult:
    """Validate trusted IDs and current Source of Truth; never invoke an adapter."""

    try:
        plan = plans.get(plan_id)
        decision = decisions.get(policy_decision_id)
    except (DigestIntegrityError, PolicyDecisionProvenanceError):
        return _result("INVALID", "SECURITY_ARTIFACT_INTEGRITY_FAILURE")
    if plan is None:
        return _result("INVALID", "PLAN_NOT_PERSISTED")
    if decision is None:
        return _result("DENIED", "POLICY_DECISION_NOT_ISSUED")
    if decision.plan_id != plan.plan_id:
        return _result("INVALID", "PLAN_BINDING_MISMATCH")
    try:
        runtime = runtime_resolver.resolve(plan.mission_id)
    except (CurrentAuthorizationStateError, DigestIntegrityError):
        return _result("STALE", "CURRENT_AUTHORIZATION_STATE_INVALID")
    mission = runtime.mission
    if mission.state != "RUNNING":
        return _result("STALE", "MISSION_NOT_RUNNING")
    if not (mission.valid_from <= now < mission.valid_until):
        return _result("STALE", "MISSION_EXPIRED")
    if (
        plan.mission_revision != mission.mission_revision
        or decision.mission_revision != mission.mission_revision
        or decision.mission_id != mission.mission_id
    ):
        return _result("STALE", "MISSION_REVISION_MISMATCH")
    if (
        plan.authorization_epoch != mission.authorization_epoch
        or decision.authorization_epoch != mission.authorization_epoch
    ):
        return _result("STALE", "AUTHORIZATION_EPOCH_MISMATCH")
    if now >= runtime.snapshot.expires_at or now >= decision.expires_at:
        return _result("STALE", "AUTHORIZATION_EXPIRED")
    try:
        ToolAvailabilityResolver.revalidate(
            runtime.snapshot,
            mission=mission,
            registry_digest=runtime.registry.registry_digest,
            policy_version=runtime.policy_state.policy_version,
            execution_scope_digest_value=execution_scope_digest(mission),
            session_security_context_digest=runtime.session_snapshot.snapshot_digest,
            adapter_capabilities_digest=runtime.adapter_snapshot.snapshot_digest,
            sandbox_capabilities_digest=runtime.sandbox_snapshot.snapshot_digest,
            remote_mcp_trust_policy_digest=runtime.remote_trust_snapshot.snapshot_digest,
            now=now,
        )
    except Exception:
        return _result("STALE", "AVAILABLE_TOOL_SNAPSHOT_STALE")
    if not (
        plan.available_tool_snapshot_id == runtime.snapshot.snapshot_id
        and plan.available_tool_snapshot_digest == runtime.snapshot.snapshot_digest
        and decision.available_tool_snapshot_id == runtime.snapshot.snapshot_id
        and decision.available_tool_snapshot_digest == runtime.snapshot.snapshot_digest
    ):
        return _result("INVALID", "SNAPSHOT_BINDING_MISMATCH")

    current_bindings: dict[str, ResourceBinding] = {}
    for grant in decision.authorized_data_access:
        current = resources.current_binding(mission.mission_id, grant.resource.resource_id)
        if current is not None:
            current_bindings[grant.resource.resource_id] = current.binding
    try:
        expected = PolicyEngine(
            policy_version=runtime.policy_state.policy_version,
            extractors=TrustedTargetExtractorRegistry(),
        ).authorize(
            mission=mission,
            plan=plan,
            snapshot=runtime.snapshot,
            registry=runtime.registry,
            requested_data_access=decision.authorized_data_access,
            current_resource_bindings=current_bindings,
            issued_at=decision.issued_at,
            expires_at=decision.expires_at,
        )
    except Exception:
        return _result("INVALID", "POLICY_REEVALUATION_FAILED")
    if expected != decision:
        return _result("INVALID", "POLICY_DECISION_INCOMPLETE_OR_MODIFIED")
    if decision.decision == "DENY":
        return _result("DENIED", "POLICY_DENY")
    if decision.decision == "ALLOW":
        return _result("AUTHORIZED", "POLICY_ALLOW")

    if (
        approval_requests is None
        or approvals is None
        or approval_request_id is None
        or approval_record_id is None
    ):
        return _result("WAITING_APPROVAL", "MATCHING_APPROVAL_REQUIRED")
    try:
        request = approval_requests.get(approval_request_id)
        record = approvals.get(approval_record_id)
    except DigestIntegrityError:
        return _result("INVALID", "APPROVAL_DIGEST_INVALID")
    if request is None or record is None:
        return _result("WAITING_APPROVAL", "MATCHING_APPROVAL_REQUIRED")
    if now >= request.expires_at or now >= record.expires_at:
        return _result("STALE", "APPROVAL_EXPIRED")
    tool = next(
        (item for item in runtime.registry.tools if item.tool_ref == decision.tool_ref), None
    )
    if tool is None:
        return _result("INVALID", "APPROVAL_TOOL_UNAVAILABLE")
    expected_presentation = build_approval_presentation(
        plan=plan, decision=decision, tool=tool
    )
    expected_presentation_digest = sha256_digest(
        {
            "schema_version": "approval-presentation-v1",
            "presentation": expected_presentation,
        }
    )
    common_match = (
        request.presentation == expected_presentation
        and request.redacted_arguments_summary
        == canonicalize(expected_presentation.redacted_arguments).decode("utf-8")
        and request.approval_presentation_digest == expected_presentation_digest
        and request.mission_id == mission.mission_id
        and record.mission_id == mission.mission_id
        and request.mission_revision == mission.mission_revision
        and record.mission_revision == mission.mission_revision
        and request.authorization_epoch == mission.authorization_epoch
        and record.authorization_epoch == mission.authorization_epoch
        and request.policy_decision_id == decision.decision_id
        and record.policy_decision_id == decision.decision_id
        and request.authorization_digest == decision.authorization_digest
        and record.authorization_digest == decision.authorization_digest
        and record.approval_request_id == request.approval_request_id
        and record.approval_request_digest == request.request_digest
        and record.approval_presentation_digest == request.approval_presentation_digest
    )
    if not common_match:
        return _result("INVALID", "APPROVAL_PRESENTATION_OR_BINDING_MISMATCH")
    if record.decision != "APPROVED":
        return _result("DENIED", "APPROVAL_REJECTED")
    return _result("AUTHORIZED", "APPROVAL_APPROVED")
