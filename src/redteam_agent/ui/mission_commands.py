"""Owner-service adapters for authoritative UI mission and approval commands."""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Callable
from datetime import timedelta
from urllib.parse import urlsplit
from uuid import uuid4

from redteam_agent.auth.models import AuthenticatedPrincipal, MissionRoleAssignment
from redteam_agent.auth.rbac import APPROVER_ROLE
from redteam_agent.composition.testing import Phase0AKernel
from redteam_agent.errors import MissionValidationError
from redteam_agent.llm.profile import AgentModelProfile
from redteam_agent.mission.manager import MISSION_ADMIN_ROLE, MISSION_OPERATOR_ROLE
from redteam_agent.mission.models import (
    ApprovalPolicy,
    ExactSessionSelector,
    MissionRevision,
    MissionState,
    SessionExistsCondition,
    compute_mission_revision_digest,
)
from redteam_agent.policy.data_access import DataAccessPolicy, DataAccessRule
from redteam_agent.policy.risk_policy import RiskLevel
from redteam_agent.policy.scope_models import (
    DomainScopeRule,
    ExecutionScopeRule,
    HostnameScopeRule,
    HostScopeRule,
    NetworkScopeRule,
    SessionScopeRule,
    UrlScopeRule,
)
from redteam_agent.ui.models import MissionDraftInput, MissionDraftTarget

_ADMIN_TOKEN = "internal:local-product:mission-admin"  # noqa: S105 - private capability label
_OPERATOR_TOKEN = "internal:local-product:mission-operator"  # noqa: S105 - private capability label
_APPROVER_TOKEN = "internal:local-product:mission-approver"  # noqa: S105 - private capability label

MissionBudgetInitializer = Callable[[str, int, int], None]
KnowledgeInitializer = Callable[[str, int], None]


class MissionCommandOwner:
    """Convert a reviewed UI draft into the existing Mission owner aggregate."""

    def __init__(
        self,
        *,
        kernel: Phase0AKernel,
        profile: AgentModelProfile,
        principal_id: str = "redteam-operator",
        initialize_budget: MissionBudgetInitializer | None = None,
        initialize_knowledge: KnowledgeInitializer | None = None,
        execution_enabled: bool = False,
    ) -> None:
        if not principal_id or principal_id != principal_id.strip():
            raise ValueError("mission command principal is invalid")
        self._kernel = kernel
        self._profile = profile
        self._principal_id = principal_id
        self._initialize_budget = initialize_budget
        self._initialize_knowledge = initialize_knowledge
        self._execution_enabled = execution_enabled
        principal = AuthenticatedPrincipal(
            principal_id=principal_id,
            roles=frozenset({MISSION_ADMIN_ROLE, MISSION_OPERATOR_ROLE, APPROVER_ROLE}),
        )
        for actor_token in (_ADMIN_TOKEN, _OPERATOR_TOKEN, _APPROVER_TOKEN):
            kernel.principal_resolver.register(actor_token, principal)
        kernel.profile_repository.save(profile)

    @property
    def execution_enabled(self) -> bool:
        return self._execution_enabled

    def create_from_draft(self, *, draft_id: str, draft: MissionDraftInput) -> MissionState:
        mission_id = self._mission_id(draft_id)
        current = self._kernel.state_repository.get(mission_id)
        if current is not None:
            self._ensure_initialized(current)
            return current
        self._provision_roles(mission_id)
        revision = self._revision(mission_id, draft)
        state = self._kernel.mission_manager.create_mission(
            revision,
            actor_token=_ADMIN_TOKEN,
        )
        self._ensure_initialized(state)
        return state

    def transition(self, *, mission_id: str, expected_version: int, action: str) -> MissionState:
        manager = self._kernel.mission_manager
        actions = {
            "validate": manager.validate_mission,
            "start": manager.start_mission,
            "pause": manager.pause_mission,
            "resume": manager.resume_mission,
            "finalize": manager.begin_finalization,
            "complete": manager.complete_mission,
            "abort": manager.abort_mission,
        }
        selected = actions.get(action)
        if selected is None:
            raise MissionValidationError("mission transition is unsupported")
        if action in {"start", "resume"} and not self._execution_enabled:
            raise MissionValidationError("mission execution runtime is not attached")
        if action in {"validate", "start"}:
            current = self._kernel.state_repository.get(mission_id)
            if current is None:
                raise MissionValidationError("mission does not exist")
            self._ensure_initialized(current)
        return selected(mission_id, expected_version, actor_token=_OPERATOR_TOKEN)

    def submit_approval(self, approval_request_id: str, verdict: str) -> None:
        self._kernel.approval_service.submit_decision(
            approval_id=f"approval-{uuid4()}",
            approval_request_id=approval_request_id,
            actor_token=_APPROVER_TOKEN,
            verdict=verdict,
        )

    @staticmethod
    def _mission_id(draft_id: str) -> str:
        suffix = hashlib.sha256(draft_id.encode("utf-8")).hexdigest()[:24]
        return f"mission-ui-{suffix}"

    def _provision_roles(self, mission_id: str) -> None:
        for role in (MISSION_ADMIN_ROLE, MISSION_OPERATOR_ROLE, APPROVER_ROLE):
            self._kernel.role_assignment_repository.save(
                MissionRoleAssignment(
                    mission_id=mission_id,
                    principal_id=self._principal_id,
                    role=role,
                    active=True,
                )
            )

    def _ensure_initialized(self, state: MissionState) -> None:
        if self._initialize_budget is not None:
            self._initialize_budget(
                state.mission_id,
                state.mission_revision,
                self._revision_for(state).max_iterations,
            )
        if self._initialize_knowledge is not None:
            self._initialize_knowledge(state.mission_id, state.mission_revision)

    def _revision_for(self, state: MissionState) -> MissionRevision:
        revision = self._kernel.revision_repository.get(state.mission_id, state.mission_revision)
        if revision is None:
            raise MissionValidationError("mission revision is unavailable")
        return revision

    def _revision(self, mission_id: str, draft: MissionDraftInput) -> MissionRevision:
        now = self._kernel.clock.now()
        valid_until = draft.validUntil.astimezone(now.tzinfo)
        if valid_until <= now:
            raise MissionValidationError("mission validity must end in the future")
        if timedelta(minutes=draft.maxRuntimeMinutes) > valid_until - now:
            raise MissionValidationError("mission runtime exceeds its validity window")
        if draft.successType != "session_exists":
            raise MissionValidationError(
                "authoritative activation currently requires a session_exists success condition"
            )
        recovery_until = valid_until + timedelta(hours=1)
        evidence_retention_until = recovery_until + timedelta(days=14)
        risk_order: tuple[RiskLevel, ...] = ("low", "medium", "high")
        require_for_risk: frozenset[RiskLevel] = frozenset(
            risk_order[risk_order.index(draft.approvalRisk) :]
        )
        fields: dict[str, object] = {
            "mission_id": mission_id,
            "mission_revision": 1,
            "llm_profile_revision": self._profile.profile_revision,
            "llm_profile_digest": self._profile.profile_digest,
            "description": f"{draft.name}: {draft.description}",
            "authorization_reference": draft.authorizationReference,
            "authorized_by": self._principal_id,
            "valid_from": now,
            "valid_until": valid_until,
            "recovery_until": recovery_until,
            "evidence_retention_until": evidence_retention_until,
            "allowed_execution_scope": tuple(self._scope(target) for target in draft.targets),
            "prohibited_execution_scope": (),
            "data_access_policy": DataAccessPolicy(
                allowed=(
                    DataAccessRule(
                        resource_type="internal_knowledge",
                        resource_pattern=f"prefix:{mission_id}",
                        operations=frozenset({"read"}),
                    ),
                ),
                prohibited=(),
            ),
            "objectives": (draft.successValue,),
            "success_conditions": (
                SessionExistsCondition(
                    condition_id="objective-session-exists",
                    session_selector=ExactSessionSelector(session_ref=draft.successValue),
                ),
            ),
            "success_mode": "all",
            "max_iterations": draft.maxIterations,
            "max_runtime_minutes": draft.maxRuntimeMinutes,
            "approval_policy": ApprovalPolicy(
                require_for_risk=require_for_risk,
                require_for_side_effect=frozenset({"state_change", "destructive"}),
                approval_ttl_seconds=900,
                count_approval_wait_in_runtime=False,
            ),
        }
        revision = MissionRevision(**fields, mission_revision_digest="pending")  # type: ignore[arg-type]
        digest_fields = revision.model_dump(mode="python")
        digest_fields.pop("mission_revision_digest")
        digest = compute_mission_revision_digest(digest_fields, self._kernel.digest_service)
        return revision.model_copy(update={"mission_revision_digest": digest})

    @staticmethod
    def _scope(target: MissionDraftTarget) -> ExecutionScopeRule:
        target_type = target.type
        value = target.value
        if target_type == "network":
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise MissionValidationError("network target is invalid") from exc
            if str(network) != value:
                raise MissionValidationError("network target must be canonical CIDR")
            port = target.port
            protocol = target.protocol
            return NetworkScopeRule(
                type="network",
                cidrs=(value,),
                ports=None if port is None else (port,),
                protocols=None if protocol is None else (protocol,),
            )
        if target_type == "host":
            return HostScopeRule(type="host", host_id=value)
        if target_type == "session":
            return SessionScopeRule(type="session", session_id=value)
        if target_type == "hostname":
            return HostnameScopeRule(type="hostname", hostname=value)
        if target_type == "domain":
            return DomainScopeRule(type="domain", domain=value, include_subdomains=False)
        if target_type == "url":
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
                raise MissionValidationError("URL target is invalid")
            return UrlScopeRule(
                type="url",
                scheme=parsed.scheme,  # type: ignore[arg-type]
                hostname=parsed.hostname,
                port=parsed.port,
                path_prefix=parsed.path or "/",
            )
        raise MissionValidationError("target type cannot be activated by the current runtime")


__all__ = ["MissionCommandOwner"]
