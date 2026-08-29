"""Deterministic Phase 0A authorization kernel."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from redteam_agent.canonical import digest_model, sha256_digest, stable_id
from redteam_agent.errors import (
    AvailableToolSnapshotStaleError,
    MissionTTLExceededError,
    TargetExtractorResolutionError,
)
from redteam_agent.json_schema import is_json_schema_instance_valid
from redteam_agent.models.common import RiskLevel
from redteam_agent.models.context import DataAccessGrant, ResourceBinding
from redteam_agent.models.mission import Mission
from redteam_agent.models.plans import ExecutionPlan
from redteam_agent.models.policy import PolicyDecision
from redteam_agent.models.scope import NormalizedTarget, SessionTargetReference
from redteam_agent.models.tools import AvailableToolSnapshot, ToolDefinition, ToolRegistryRevision
from redteam_agent.tools.availability import ToolAvailabilityResolver, execution_scope_digest
from redteam_agent.tools.registry import registry_payload
from redteam_agent.tools.target_extractors import TrustedTargetExtractorRegistry

from .data_access import DataAccessEvaluator
from .digests import authorization_digest, proposal_digest
from .scope import ScopeEvaluator, TargetNormalizer, UnsupportedScopeTypeError


class PolicyEngine:
    """Only this component may issue ALLOW/REQUIRE_APPROVAL/DENY."""

    _risk_rank = {"read": 0, "low": 1, "medium": 2, "high": 3}

    def __init__(
        self,
        *,
        policy_version: str,
        extractors: TrustedTargetExtractorRegistry,
        normalizer: TargetNormalizer | None = None,
        scope_evaluator: ScopeEvaluator | None = None,
        data_access_evaluator: DataAccessEvaluator | None = None,
    ) -> None:
        if not policy_version:
            raise ValueError("policy_version is required")
        self.policy_version = policy_version
        self.extractors = extractors
        self.normalizer = normalizer or TargetNormalizer()
        self.scope_evaluator = scope_evaluator or ScopeEvaluator()
        self.data_access_evaluator = data_access_evaluator or DataAccessEvaluator()

    def authorize(
        self,
        *,
        mission: Mission,
        plan: ExecutionPlan,
        snapshot: AvailableToolSnapshot,
        registry: ToolRegistryRevision,
        requested_data_access: tuple[DataAccessGrant, ...] = (),
        current_resource_bindings: dict[str, ResourceBinding] | None = None,
        issued_at: datetime,
        expires_at: datetime,
    ) -> PolicyDecision:
        if issued_at >= expires_at or expires_at > mission.valid_until:
            raise MissionTTLExceededError("policy decision TTL violates mission validity")
        if (
            not (mission.valid_from <= issued_at < mission.valid_until)
            or mission.state != "RUNNING"
        ):
            raise MissionTTLExceededError("mission is not currently executable")
        if (
            plan.mission_id != mission.mission_id
            or plan.mission_revision != mission.mission_revision
        ):
            raise AvailableToolSnapshotStaleError("plan mission revision is stale")
        if plan.authorization_epoch != mission.authorization_epoch:
            raise AvailableToolSnapshotStaleError("plan authorization epoch is stale")
        actual_registry_digest = sha256_digest(
            registry_payload(registry.tools, registry.registry_revision)
        )
        if actual_registry_digest != registry.registry_digest:
            raise AvailableToolSnapshotStaleError("tool registry digest is invalid")
        ToolAvailabilityResolver.revalidate(
            snapshot,
            mission=mission,
            registry_digest=registry.registry_digest,
            policy_version=self.policy_version,
            execution_scope_digest_value=execution_scope_digest(mission),
            session_security_context_digest=plan.session_security_context_digest,
            adapter_capabilities_digest=plan.adapter_capabilities_digest,
            sandbox_capabilities_digest=plan.sandbox_capabilities_digest,
            remote_mcp_trust_policy_digest=plan.remote_mcp_trust_policy_digest,
            now=issued_at,
        )
        if plan.available_tool_snapshot_id != snapshot.snapshot_id or (
            plan.available_tool_snapshot_digest != snapshot.snapshot_digest
        ):
            raise AvailableToolSnapshotStaleError("plan/snapshot binding mismatch")
        if proposal_digest(plan.proposal) != plan.proposal_digest:
            raise AvailableToolSnapshotStaleError("proposal digest mismatch")
        tool = self._resolve_tool(plan, registry, snapshot)

        reasons: set[str] = set()
        normalized: list[NormalizedTarget] = []
        self._validate_arguments(tool, plan, reasons)
        self._validate_session(tool, plan, snapshot, mission, normalized, reasons)
        self._extract_and_authorize_targets(tool, plan, mission, normalized, reasons)
        authorized_data = self._authorize_data_access(
            tool,
            mission,
            requested_data_access,
            current_resource_bindings or {},
            reasons,
        )
        normalized_tuple = self._sorted_targets(normalized)
        data_tuple = self._sorted_grants(authorized_data)
        effective_risk = self._effective_risk(tool, len(normalized_tuple))

        decision_name: Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
        if reasons:
            decision_name = "DENY"
        elif self._requires_approval(tool, mission, effective_risk):
            decision_name = "REQUIRE_APPROVAL"
            reasons.add("HUMAN_APPROVAL_REQUIRED")
        else:
            decision_name = "ALLOW"
            reasons.add("POLICY_ALLOW")

        auth_digest = authorization_digest(
            plan=plan,
            tool=tool,
            normalized_targets=normalized_tuple,
            authorized_data_access=data_tuple,
            effective_risk=effective_risk,
            policy_version=self.policy_version,
            registry_digest=registry.registry_digest,
        )
        decision_id = stable_id(
            "decision",
            {
                "authorization_digest": auth_digest,
                "decision": decision_name,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )
        provisional = PolicyDecision(
            decision_id=decision_id,
            decision_digest="pending",
            mission_id=mission.mission_id,
            mission_revision=mission.mission_revision,
            authorization_epoch=mission.authorization_epoch,
            plan_id=plan.plan_id,
            tool_ref=tool.tool_ref,
            proposal_digest=plan.proposal_digest,
            authorization_digest=auth_digest,
            policy_version=self.policy_version,
            registry_digest=registry.registry_digest,
            available_tool_snapshot_id=snapshot.snapshot_id,
            available_tool_snapshot_digest=snapshot.snapshot_digest,
            session_security_context_digest=plan.session_security_context_digest,
            adapter_capabilities_digest=plan.adapter_capabilities_digest,
            sandbox_capabilities_digest=plan.sandbox_capabilities_digest,
            remote_mcp_trust_policy_digest=plan.remote_mcp_trust_policy_digest,
            resolved_adapter=tool.adapter,
            resolved_adapter_id=tool.adapter_id,
            decision=decision_name,
            normalized_targets=normalized_tuple,
            authorized_data_access=data_tuple,
            validated_arguments_digest=sha256_digest(plan.proposal.arguments),
            effective_risk=RiskLevel(effective_risk),
            side_effect=tool.side_effect,
            approval_rule=tool.approval_rule,
            reason_codes=tuple(sorted(reasons)),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return provisional.model_copy(
            update={"decision_digest": digest_model(provisional, exclude={"decision_digest"})}
        )

    @staticmethod
    def _resolve_tool(
        plan: ExecutionPlan,
        registry: ToolRegistryRevision,
        snapshot: AvailableToolSnapshot,
    ) -> ToolDefinition:
        if not any(view.tool_ref == plan.proposal.tool_ref for view in snapshot.tools):
            raise AvailableToolSnapshotStaleError("proposal tool is not available")
        tool = next(
            (item for item in registry.tools if item.tool_ref == plan.proposal.tool_ref), None
        )
        if tool is None:
            raise AvailableToolSnapshotStaleError("proposal tool is not registered")
        return tool

    @staticmethod
    def _validate_arguments(tool: ToolDefinition, plan: ExecutionPlan, reasons: set[str]) -> None:
        if not is_json_schema_instance_valid(
            tool.parameter_schema.to_dict(), plan.proposal.arguments.to_dict()
        ):
            reasons.add("ARGUMENT_SCHEMA_INVALID")

    def _validate_session(
        self,
        tool: ToolDefinition,
        plan: ExecutionPlan,
        snapshot: AvailableToolSnapshot,
        mission: Mission,
        normalized: list[NormalizedTarget],
        reasons: set[str],
    ) -> None:
        view = next(item for item in snapshot.tools if item.tool_ref == tool.tool_ref)
        if tool.requires_session:
            if plan.proposal.session_id is None:
                reasons.add("SESSION_REQUIRED")
            elif plan.proposal.session_id not in view.eligible_session_ids:
                reasons.add("SESSION_NOT_ELIGIBLE")
            else:
                session_target = self.normalizer.normalize(
                    SessionTargetReference(type="session", session_id=plan.proposal.session_id)
                )
                normalized.append(session_target)
                evaluation = self.scope_evaluator.evaluate(
                    session_target,
                    mission.allowed_execution_scope,
                    mission.prohibited_execution_scope,
                )
                if not evaluation.allowed:
                    reasons.add("EXECUTION_SESSION_SCOPE_DENIED")
        elif plan.proposal.session_id is not None:
            reasons.add("UNEXPECTED_SESSION")

    def _extract_and_authorize_targets(
        self,
        tool: ToolDefinition,
        plan: ExecutionPlan,
        mission: Mission,
        normalized: list[NormalizedTarget],
        reasons: set[str],
    ) -> None:
        if tool.target_mode == "none":
            if plan.proposal.requested_targets:
                reasons.add("TARGET_NOT_ALLOWED")
            return
        try:
            if tool.target_extractor_id is None:
                raise TargetExtractorResolutionError("missing target extractor")
            targets = self.extractors.extract(tool.target_extractor_id, plan.proposal, tool)
            if tool.target_mode == "required" and not targets:
                raise TargetExtractorResolutionError("required target could not be extracted")
            for target in targets:
                normalized_target = self.normalizer.normalize(target)
                normalized.append(normalized_target)
                evaluation = self.scope_evaluator.evaluate(
                    normalized_target,
                    mission.allowed_execution_scope,
                    mission.prohibited_execution_scope,
                )
                if not evaluation.allowed:
                    reasons.add(evaluation.reason_code)
        except UnsupportedScopeTypeError:
            reasons.add("SCOPE_TYPE_NOT_IMPLEMENTED")
        except (TargetExtractorResolutionError, ValueError, TypeError):
            reasons.add("TARGET_EXTRACTION_FAILED")

    def _authorize_data_access(
        self,
        tool: ToolDefinition,
        mission: Mission,
        requests: tuple[DataAccessGrant, ...],
        current_bindings: dict[str, ResourceBinding],
        reasons: set[str],
    ) -> list[DataAccessGrant]:
        authorized: list[DataAccessGrant] = []
        for request in requests:
            current = current_bindings.get(request.resource.resource_id)
            if current != request.resource:
                reasons.add("DATA_RESOURCE_BINDING_STALE")
                continue
            if not self.data_access_evaluator.allows(request, mission.data_access_policy):
                reasons.add("DATA_ACCESS_DENIED")
                continue
            authorized.append(request)
        granted_types = {grant.resource_type for grant in authorized}
        if not tool.required_data_access_types.issubset(granted_types):
            reasons.add("REQUIRED_DATA_ACCESS_MISSING")
        return authorized

    def _effective_risk(self, tool: ToolDefinition, target_count: int) -> str:
        risk = tool.minimum_risk_level.value
        floors = [risk]
        if tool.side_effect.value == "state_change":
            floors.append("medium")
        if tool.side_effect.value == "destructive":
            floors.append("high")
        if target_count > 1:
            floors.append("medium")
        return max(floors, key=self._risk_rank.__getitem__)

    @staticmethod
    def _requires_approval(tool: ToolDefinition, mission: Mission, effective_risk: str) -> bool:
        return (
            tool.approval_rule == "always"
            or effective_risk == "high"
            or tool.side_effect.value == "destructive"
            or effective_risk in mission.approval_policy.require_for_risk
            or tool.side_effect.value in mission.approval_policy.require_for_side_effect
        )

    @staticmethod
    def _sorted_targets(targets: list[NormalizedTarget]) -> tuple[NormalizedTarget, ...]:
        unique = {sha256_digest(target.model_dump(mode="python")): target for target in targets}
        return tuple(
            sorted(
                unique.values(),
                key=lambda item: (
                    item.type,
                    item.canonical_value,
                    item.host_ref or "",
                    item.port or 0,
                    item.protocol or "",
                ),
            )
        )

    @staticmethod
    def _sorted_grants(grants: list[DataAccessGrant]) -> tuple[DataAccessGrant, ...]:
        return tuple(
            sorted(
                grants,
                key=lambda item: (
                    item.resource_type,
                    item.resource.resource_id,
                    item.resource.resource_version,
                    tuple(sorted(item.operations)),
                ),
            )
        )
