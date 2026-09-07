"""Executor authorization gate — validate only, never dispatch (Phase 0A).

The gate is the trust boundary for execution authorization. Its public entry
point accepts only identifiers and the plan; it never accepts a caller-supplied
runtime context or ``now``. It resolves the current mission/registry/capability
state from trusted repositories and reads time from an injected clock (A/H-01).

It then: verifies the decision against current state (mission RUNNING, matching
revision/epoch/policy/registry, unexpired, within the mission validity window);
re-derives the authorization digest from current trusted inputs and rejects any
binding drift or stale approval (B); enforces the executable predicate; re-checks
the approver's RBAC at use time (E); and confirms the approval presentation
matches the executable intent (B-05). A DENY decision is never executable. It
performs no dispatch and creates no execution (External Tool Dispatch = 0).
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.approval.service import evaluate_executable, verify_presentation_matches_intent
from redteam_agent.auth.rbac import RbacPolicy
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AuthorizationKernelError, MisleadingApprovalPresentationError
from redteam_agent.plan.models import ExecutionPlan, compute_proposal_digest
from redteam_agent.policy.engine import PolicyEngine, context_from_mission
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.repositories import (
    AdapterCapabilityRepository,
    ApprovalRecordRepository,
    ApprovalRequestRepository,
    AvailableToolSnapshotRepository,
    MissionRoleAssignmentRepository,
    PolicyDecisionRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.tools.availability import revalidate_snapshot


@dataclass(frozen=True)
class GateResult:
    authorized: bool
    reason_code: str


class ExecutorAuthorizationGate:
    def __init__(
        self,
        *,
        decision_repository: PolicyDecisionRepository,
        request_repository: ApprovalRequestRepository,
        record_repository: ApprovalRecordRepository,
        snapshot_repository: AvailableToolSnapshotRepository,
        registry_repository: ToolRegistryRepository,
        session_repository: SessionSecurityContextSnapshotRepository,
        adapter_repository: AdapterCapabilityRepository,
        role_assignment_repository: MissionRoleAssignmentRepository,
        context_resolver: AuthorizationContextResolver,
        policy_engine: PolicyEngine,
        clock: Clock,
        digest_service: DigestService,
        registry_revision: int,
    ) -> None:
        self._decisions = decision_repository
        self._requests = request_repository
        self._records = record_repository
        self._snapshots = snapshot_repository
        self._registry_repo = registry_repository
        self._sessions = session_repository
        self._adapters = adapter_repository
        self._rbac = RbacPolicy(role_assignment_repository)
        self._resolver = context_resolver
        self._policy_engine = policy_engine
        self._clock = clock
        self._digests = digest_service
        self._registry_revision = registry_revision

    def authorize_execution(self, *, decision_id: str, plan: ExecutionPlan) -> GateResult:
        try:
            return self._authorize(decision_id, plan)
        except MisleadingApprovalPresentationError:
            return GateResult(False, "MISLEADING_PRESENTATION")
        except AuthorizationKernelError:
            return GateResult(False, "INTEGRITY_ERROR")

    def _authorize(self, decision_id: str, plan: ExecutionPlan) -> GateResult:
        now = self._clock.now()
        decision = self._decisions.get(decision_id)  # digest-verified on load
        if decision is None:
            return GateResult(False, "DECISION_NOT_FOUND")

        # Resolve current trusted state for the decision's mission.
        runtime = self._resolver.resolve(decision.mission_id, now=now)
        mission = runtime.mission

        if mission.state != "RUNNING":
            return GateResult(False, "MISSION_NOT_RUNNING")
        if not (mission.valid_from <= now < mission.valid_until):
            return GateResult(False, "MISSION_OUTSIDE_VALIDITY_WINDOW")
        if decision.mission_id != mission.mission_id:
            return GateResult(False, "MISSION_MISMATCH")
        if decision.mission_revision != mission.mission_revision:
            return GateResult(False, "MISSION_REVISION_STALE")
        if decision.authorization_epoch != mission.authorization_epoch:
            return GateResult(False, "AUTHORIZATION_EPOCH_STALE")
        if decision.policy_version != runtime.policy_version:
            return GateResult(False, "POLICY_VERSION_STALE")
        if decision.registry_digest != runtime.registry_digest:
            return GateResult(False, "REGISTRY_STALE")
        if not (now < decision.expires_at):
            return GateResult(False, "DECISION_EXPIRED")
        if decision.expires_at > mission.valid_until:
            return GateResult(False, "DECISION_TTL_EXCEEDS_VALIDITY")

        # The plan must be the one that was authorized: identity, revision,
        # observed epoch/state, tool ref, snapshot binding and declared
        # capability digests are all checked against the decision and the
        # current trusted state (Codex #3).
        if plan.plan_id != decision.plan_id:
            return GateResult(False, "PLAN_MISMATCH")
        if plan.mission_id != decision.mission_id or plan.mission_id != mission.mission_id:
            return GateResult(False, "PLAN_MISSION_MISMATCH")
        if plan.mission_revision != decision.mission_revision:
            return GateResult(False, "PLAN_MISSION_REVISION_MISMATCH")
        if plan.observed_authorization_epoch != mission.authorization_epoch:
            return GateResult(False, "PLAN_EPOCH_STALE")
        if plan.observed_mission_state_version != mission.mission_state_version:
            return GateResult(False, "PLAN_STATE_VERSION_STALE")
        if plan.proposal.tool_ref != decision.tool_ref:
            return GateResult(False, "PLAN_TOOL_REF_MISMATCH")
        if plan.available_tool_snapshot_id != decision.available_tool_snapshot_id:
            return GateResult(False, "PLAN_SNAPSHOT_ID_MISMATCH")
        if plan.available_tool_snapshot_digest != decision.available_tool_snapshot_digest:
            return GateResult(False, "PLAN_SNAPSHOT_DIGEST_MISMATCH")
        if compute_proposal_digest(plan.proposal, self._digests) != plan.proposal_digest:
            return GateResult(False, "PROPOSAL_DIGEST_INVALID")
        if plan.proposal_digest != decision.proposal_digest:
            return GateResult(False, "PROPOSAL_MISMATCH")
        # Plan-declared capability digests must equal the current trusted ones.
        if plan.adapter_capabilities_digest != runtime.bindings.adapter_capabilities_digest:
            return GateResult(False, "PLAN_ADAPTER_DIGEST_STALE")
        if plan.sandbox_capabilities_digest != runtime.bindings.sandbox_capabilities_digest:
            return GateResult(False, "PLAN_SANDBOX_DIGEST_STALE")
        if plan.session_security_context_digest != runtime.bindings.session_security_context_digest:
            return GateResult(False, "PLAN_SESSION_DIGEST_STALE")
        if plan.remote_mcp_trust_policy_digest != runtime.bindings.remote_mcp_trust_policy_digest:
            return GateResult(False, "PLAN_REMOTE_TRUST_DIGEST_STALE")

        # Snapshot binding + revalidation.
        snapshot = self._snapshots.get(decision.available_tool_snapshot_id)
        if snapshot is None:
            return GateResult(False, "SNAPSHOT_NOT_FOUND")
        if snapshot.snapshot_digest != decision.available_tool_snapshot_digest:
            return GateResult(False, "SNAPSHOT_DIGEST_MISMATCH")
        revalidate_snapshot(
            snapshot,
            current=runtime.bindings,
            session_snapshots=self._sessions.all_snapshots(),
            now=now,
            selected_tool_ref=decision.tool_ref,
            selected_session_id=plan.proposal.session_id,
        )

        # Resolve the tool/adapter/session and re-derive the authorization digest.
        registry = self._registry_repo.get(self._registry_revision)
        if registry is None:
            return GateResult(False, "REGISTRY_NOT_FOUND")
        tool = registry.by_ref(decision.tool_ref.tool_id, decision.tool_ref.registry_revision)
        if tool is None:
            return GateResult(False, "TOOL_NOT_IN_REGISTRY")
        # The plan's action contract reference must match the registered tool's.
        if plan.action_contract_ref != tool.action_contract_ref:
            return GateResult(False, "ACTION_CONTRACT_MISMATCH")
        adapter = self._adapters.get(tool.adapter_id)
        if adapter is None:
            return GateResult(False, "ADAPTER_NOT_FOUND")
        session_context = None
        principal_ref = None
        if plan.proposal.session_id is not None:
            snap = self._sessions.get(plan.proposal.session_id)
            if snap is not None:
                session_context = snap.context
                principal_ref = snap.context.current_principal

        context = context_from_mission(mission)
        binding_ok, binding_reason = self._policy_engine.verify_authorization_binding(
            decision=decision,
            plan=plan,
            context=context,
            tool=tool,
            adapter=adapter,
            session_context=session_context,
            registry_digest=runtime.registry_digest,
            now=now,
        )
        if not binding_ok:
            return GateResult(False, binding_reason)

        # Executable predicate (ALLOW, or approved REQUIRE_APPROVAL).
        request = self._requests.find_by_decision(decision.decision_id)
        record = self._records.find_by_request(request.approval_request_id) if request is not None else None
        result = evaluate_executable(decision=decision, request=request, record=record, now=now)
        if not result.executable:
            return GateResult(False, result.reason_code)

        if decision.decision == "REQUIRE_APPROVAL" and request is not None and record is not None:
            # Re-check approver authority against current RBAC (E).
            if not self._rbac.has_role(mission.mission_id, record.approver_id, record.approver_role):
                return GateResult(False, "APPROVAL_AUTHORITY_REVOKED")
            if record.approver_role != "approver":
                return GateResult(False, "APPROVAL_ROLE_INVALID")
            verify_presentation_matches_intent(
                presentation=request.presentation,
                decision=decision,
                tool=tool,
                arguments=plan.proposal.arguments,
                session_id=plan.proposal.session_id,
                current_principal_ref=principal_ref,
                current_principal_display=principal_ref,
                timeout_seconds=tool.default_timeout_seconds,
                digest_service=self._digests,
            )

        return GateResult(True, "AUTHORIZED")
