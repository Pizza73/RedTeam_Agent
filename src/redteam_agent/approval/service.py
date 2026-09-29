"""Approval binding verification and the executable predicate (SystemDesign §23).

Two independent guarantees:

* The human-visible presentation must be re-derivable exactly from the decision,
  tool and arguments (B-05). Verification rebuilds it deterministically and
  rejects any divergence.
* An execution is executable only if the decision is ALLOW, or it is
  REQUIRE_APPROVAL with a matching, unexpired, approved request/record whose
  bindings (authorization digest, policy decision id, mission revision, epoch)
  all match (B-02).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from redteam_agent.approval.models import ApprovalPresentation, ApprovalRecord, ApprovalRequest
from redteam_agent.approval.presentation import build_presentation
from redteam_agent.auth.principal import PrincipalResolver
from redteam_agent.auth.rbac import APPROVER_ROLE, RbacPolicy
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import ApprovalAuthorityError, MisleadingApprovalPresentationError
from redteam_agent.mission.models import Mission
from redteam_agent.plan.models import ExecutionPlan, compute_proposal_digest
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.policy.ttl import enforce_ttl
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    ApprovalRecordRepository,
    ApprovalRequestRepository,
    PolicyDecisionRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.tools.models import ToolDefinition


def verify_presentation_matches_intent(
    *,
    presentation: ApprovalPresentation,
    decision: PolicyDecision,
    tool: ToolDefinition,
    arguments: Any,
    session_id: str | None,
    current_principal_ref: str | None,
    current_principal_display: str | None,
    timeout_seconds: int,
    digest_service: DigestService,
) -> None:
    """Rebuild the presentation from the intent and require an exact match."""
    expected = build_presentation(
        decision=decision,
        tool=tool,
        arguments=arguments,
        current_principal_ref=current_principal_ref,
        current_principal_display=current_principal_display,
        timeout_seconds=timeout_seconds,
        digest_service=digest_service,
        session_id=session_id,
    )
    if expected.presentation_digest != presentation.presentation_digest or expected != presentation:
        raise MisleadingApprovalPresentationError(
            "approval presentation does not match the executable intent"
        )


@dataclass(frozen=True)
class ExecutableResult:
    executable: bool
    reason_code: str


def evaluate_executable(
    *,
    decision: PolicyDecision,
    request: ApprovalRequest | None,
    record: ApprovalRecord | None,
    now: datetime,
) -> ExecutableResult:
    """The Executable predicate (SystemDesign §23)."""
    if decision.decision == "DENY":
        return ExecutableResult(False, "DECISION_DENY")
    if decision.decision == "ALLOW":
        return ExecutableResult(True, "ALLOW")

    # REQUIRE_APPROVAL
    if request is None or record is None:
        return ExecutableResult(False, "APPROVAL_MISSING")
    if record.decision != "APPROVED":
        return ExecutableResult(False, "APPROVAL_NOT_APPROVED")
    if not (now < request.expires_at) or not (now < record.expires_at):
        return ExecutableResult(False, "APPROVAL_EXPIRED")
    # TTL invariants re-checked at use: approval never outlives the decision or
    # its request (SystemDesign §21).
    if request.expires_at > decision.expires_at or record.expires_at > request.expires_at:
        return ExecutableResult(False, "APPROVAL_TTL_EXCEEDS_PARENT")
    checks = (
        record.approval_request_id == request.approval_request_id,
        record.approval_request_digest == request.request_digest,
        request.policy_decision_id == decision.decision_id,
        record.policy_decision_id == decision.decision_id,
        request.authorization_digest == decision.authorization_digest,
        record.authorization_digest == decision.authorization_digest,
        request.mission_revision == decision.mission_revision,
        record.mission_revision == decision.mission_revision,
        request.authorization_epoch == decision.authorization_epoch,
        record.authorization_epoch == decision.authorization_epoch,
    )
    if not all(checks):
        return ExecutableResult(False, "APPROVAL_BINDING_MISMATCH")
    return ExecutableResult(True, "APPROVED")


# --- builders -------------------------------------------------------------


def _object_digest(name: str, model_fields: dict[str, Any], digest_service: DigestService) -> str:
    return digest_service.compute(name, model_fields)


def build_approval_request(
    *,
    approval_request_id: str,
    decision: PolicyDecision,
    presentation: ApprovalPresentation,
    issued_at: datetime,
    expires_at: datetime,
    digest_service: DigestService,
) -> ApprovalRequest:
    draft = {
        "approval_request_id": approval_request_id,
        "mission_id": decision.mission_id,
        "mission_revision": decision.mission_revision,
        "authorization_epoch": decision.authorization_epoch,
        "policy_decision_id": decision.decision_id,
        "authorization_digest": decision.authorization_digest,
        "presentation": presentation.model_dump(mode="python"),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    request_digest = _object_digest("request_digest", draft, digest_service)
    return ApprovalRequest(
        approval_request_id=approval_request_id,
        request_digest=request_digest,
        mission_id=decision.mission_id,
        mission_revision=decision.mission_revision,
        authorization_epoch=decision.authorization_epoch,
        policy_decision_id=decision.decision_id,
        authorization_digest=decision.authorization_digest,
        presentation=presentation,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def record_approval_decision(
    *,
    approval_id: str,
    request: ApprovalRequest,
    decision: PolicyDecision,
    mission_id: str,
    actor_token: str,
    verdict: str,
    issued_at: datetime,
    expires_at: datetime,
    digest_service: DigestService,
    principal_resolver: PrincipalResolver,
    rbac: RbacPolicy,
) -> ApprovalRecord:
    """Build an approval record from an *authenticated* approver (E).

    The approver id and role come from the authenticated principal and its
    mission RBAC, never from caller-supplied strings. A principal that is not
    authenticated, or lacks the approver role for this mission, is rejected.
    """
    principal = principal_resolver.authenticate(actor_token)
    if principal is None:
        raise ApprovalAuthorityError("actor is not authenticated")
    if verdict not in ("APPROVED", "REJECTED"):
        raise ApprovalAuthorityError("invalid approval verdict")
    if not rbac.principal_can_approve(mission_id, principal):
        raise ApprovalAuthorityError("principal lacks the approver role for this mission")
    if decision.mission_id != mission_id:
        raise ApprovalAuthorityError("decision does not belong to the mission")
    # Record TTL must not outlive its request.
    enforce_ttl(
        label="approval_record",
        issued_at=issued_at,
        expires_at=expires_at,
        mission_valid_until=request.expires_at,
    )
    return build_approval_record(
        approval_id=approval_id,
        request=request,
        decision=decision,
        approver_id=principal.principal_id,
        approver_role=APPROVER_ROLE,
        verdict=verdict,
        issued_at=issued_at,
        expires_at=expires_at,
        digest_service=digest_service,
    )


def build_approval_record(
    *,
    approval_id: str,
    request: ApprovalRequest,
    decision: PolicyDecision,
    approver_id: str,
    approver_role: str,
    verdict: str,
    issued_at: datetime,
    expires_at: datetime,
    digest_service: DigestService,
) -> ApprovalRecord:
    draft = {
        "approval_id": approval_id,
        "approval_request_id": request.approval_request_id,
        "approval_request_digest": request.request_digest,
        "mission_id": decision.mission_id,
        "mission_revision": decision.mission_revision,
        "authorization_epoch": decision.authorization_epoch,
        "policy_decision_id": decision.decision_id,
        "authorization_digest": decision.authorization_digest,
        "decision": verdict,
        "approver_id": approver_id,
        "approver_role": approver_role,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    record_digest = _object_digest("record_digest", draft, digest_service)
    return ApprovalRecord(
        approval_id=approval_id,
        record_digest=record_digest,
        approval_request_id=request.approval_request_id,
        approval_request_digest=request.request_digest,
        mission_id=decision.mission_id,
        mission_revision=decision.mission_revision,
        authorization_epoch=decision.authorization_epoch,
        policy_decision_id=decision.decision_id,
        authorization_digest=decision.authorization_digest,
        decision=verdict,  # type: ignore[arg-type]
        approver_id=approver_id,
        approver_role=approver_role,
        issued_at=issued_at,
        expires_at=expires_at,
    )


class ApprovalService:
    """Owner of approval requests and records (authenticated issuance).

    Presentations are derived from the trusted decision/tool/plan; records are
    built only from an authenticated approver that holds the mission approver
    role. Both are persisted with the write guard, so a caller cannot raw-save a
    forged request or record (Codex #2 / E).
    """

    def __init__(
        self,
        *,
        request_repository: ApprovalRequestRepository,
        record_repository: ApprovalRecordRepository,
        decision_repository: PolicyDecisionRepository,
        registry_repository: ToolRegistryRepository,
        session_repository: SessionSecurityContextSnapshotRepository,
        context_resolver: AuthorizationContextResolver,
        principal_resolver: PrincipalResolver,
        rbac: RbacPolicy,
        digest_service: DigestService,
        clock: Clock,
        write_guard: WriteGuard,
        registry_revision: int,
        max_approval_ttl_seconds: int,
    ) -> None:
        self._requests = request_repository
        self._records = record_repository
        self._decisions = decision_repository
        self._registry_repo = registry_repository
        self._sessions = session_repository
        self._resolver = context_resolver
        self._principal_resolver = principal_resolver
        self._rbac = rbac
        self._digests = digest_service
        self._clock = clock
        self._guard = write_guard
        self._registry_revision = registry_revision
        self._max_approval_ttl_seconds = max_approval_ttl_seconds
        request_repository.bind_owner(write_guard)
        record_repository.bind_owner(write_guard)

    def issue_request(
        self, *, approval_request_id: str, decision_id: str, plan: ExecutionPlan
    ) -> ApprovalRequest:
        now = self._clock.now()
        decision = self._decisions.get(decision_id)
        if decision is None:
            raise ApprovalAuthorityError("decision not found")
        if decision.decision != "REQUIRE_APPROVAL":
            raise ApprovalAuthorityError("decision does not require approval")
        if plan.plan_id != decision.plan_id or plan.proposal_digest != decision.proposal_digest:
            raise ApprovalAuthorityError("plan does not match decision")
        if compute_proposal_digest(plan.proposal, self._digests) != decision.proposal_digest:
            raise ApprovalAuthorityError("plan proposal digest invalid")
        registry = self._registry_repo.get(self._registry_revision)
        if registry is None:
            raise ApprovalAuthorityError("registry not found")
        tool = registry.by_ref(decision.tool_ref.tool_id, decision.tool_ref.registry_revision)
        if tool is None:
            raise ApprovalAuthorityError("tool not found")
        # The mission's approval policy and validity window bound the request TTL,
        # alongside a global maximum and the parent decision expiry (R09).
        runtime = self._resolver.resolve(decision.mission_id, now=now)
        mission = runtime.mission
        if decision.mission_revision != mission.mission_revision:
            raise ApprovalAuthorityError("decision mission revision is stale")
        if decision.authorization_epoch != mission.authorization_epoch:
            raise ApprovalAuthorityError("decision authorization epoch is stale")
        principal_ref = None
        if plan.proposal.session_id is not None:
            snap = self._sessions.get(plan.proposal.session_id)
            principal_ref = snap.context.current_principal if snap is not None else None
        presentation = build_presentation(
            decision=decision,
            tool=tool,
            arguments=plan.proposal.arguments,
            current_principal_ref=principal_ref,
            current_principal_display=principal_ref,
            timeout_seconds=tool.default_timeout_seconds,
            digest_service=self._digests,
            session_id=plan.proposal.session_id,
        )
        expires_at = self._bounded_request_expiry(now=now, decision=decision, mission=mission)
        enforce_ttl(
            label="approval_request", issued_at=now, expires_at=expires_at,
            mission_valid_until=mission.valid_until, parent_expires_at=decision.expires_at,
        )
        request = build_approval_request(
            approval_request_id=approval_request_id,
            decision=decision,
            presentation=presentation,
            issued_at=now,
            expires_at=expires_at,
            digest_service=self._digests,
        )
        self._requests.save(request, guard=self._guard)
        return request

    def _bounded_request_expiry(
        self, *, now: datetime, decision: PolicyDecision, mission: Mission
    ) -> datetime:
        """Smallest of the mission approval TTL, global max, decision and validity."""
        candidates = (
            now + timedelta(seconds=mission.approval_policy.approval_ttl_seconds),
            now + timedelta(seconds=self._max_approval_ttl_seconds),
            decision.expires_at,
            mission.valid_until,
        )
        return min(candidates)

    def submit_decision(
        self, *, approval_id: str, approval_request_id: str, actor_token: str, verdict: str
    ) -> ApprovalRecord:
        now = self._clock.now()
        request = self._requests.get(approval_request_id)
        if request is None:
            raise ApprovalAuthorityError("approval request not found")
        decision = self._decisions.get(request.policy_decision_id)
        if decision is None:
            raise ApprovalAuthorityError("decision not found")
        record = record_approval_decision(
            approval_id=approval_id,
            request=request,
            decision=decision,
            mission_id=decision.mission_id,
            actor_token=actor_token,
            verdict=verdict,
            issued_at=now,
            expires_at=request.expires_at,
            digest_service=self._digests,
            principal_resolver=self._principal_resolver,
            rbac=self._rbac,
        )
        self._records.save(record, guard=self._guard)
        return record
