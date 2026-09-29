"""Policy Engine (SystemDesign §22).

Given a resolved execution plan, the engine deterministically produces an
immutable ``PolicyDecision``. It extracts the *actual* targets (not just planner
hints) via a trusted extractor, enforces scope (including the execution
session), resolves data-access bindings from the trusted metadata source of
truth, computes effective risk from the versioned policy table, decides
ALLOW / REQUIRE_APPROVAL / DENY, and binds the whole resolved intent into an
authorization digest. It never dispatches or resolves secret values.

The same resolution is exposed via :meth:`resolve` and
:meth:`verify_authorization_binding` so the executor gate can re-derive the
authorization digest from *current* trusted inputs and reject a decision whose
binding (contract, precondition, adapter, targets, data access, risk) no longer
matches, or a stale approval.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import (
    DataAccessPatternError,
    ParameterSchemaError,
    PolicyEvaluationIndeterminateError,
    TargetExtractorResolutionError,
)
from redteam_agent.models.base import strict_revalidate
from redteam_agent.models.common import ResourceBinding
from redteam_agent.plan.models import ExecutionPlan
from redteam_agent.policy.data_access import DataAccessOperation, DataAccessPolicy, ResourceType, evaluate_data_access
from redteam_agent.policy.models import DataAccessGrant, PolicyDecision
from redteam_agent.policy.risk_policy import EffectiveRiskPolicy, RiskLevel, approval_required, compute_effective_risk
from redteam_agent.policy.scope_engine import evaluate_targets
from redteam_agent.policy.scope_models import ExecutionScopeRule, NormalizedTarget
from redteam_agent.policy.target_binding import (
    TargetDispatchBinding,
    build_target_dispatch_binding,
    select_binding_mode,
)
from redteam_agent.policy.ttl import enforce_ttl
from redteam_agent.resources.resource_metadata import ResourceMetadataReader
from redteam_agent.resources.secret_metadata import SecretMetadataReader
from redteam_agent.session.models import SessionSecurityContextSnapshot
from redteam_agent.tools.models import ToolDefinition
from redteam_agent.tools.parameter_schema import validate_arguments
from redteam_agent.tools.secret_argument_path import (
    parse_json_pointer,
    resolve_pointer,
    validate_secret_argument_paths,
    validate_secret_reference,
)
from redteam_agent.tools.target_extractors import (
    DEFAULT_TARGET_EXTRACTOR_REGISTRY,
    TargetExtractionInput,
    TrustedTargetExtractorRegistry,
)

_RESOURCE_ID_FIELD: dict[str, str] = {
    "artifact": "artifact_ids",
    "report": "report_ids",
    "local_artifact": "local_artifact_ids",
    "internal_knowledge": "internal_knowledge_ids",
}

Decision = Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]


def context_from_mission(mission: object) -> PolicyEvaluationContext:
    """Build a policy evaluation context from a trusted Mission read model."""
    from redteam_agent.mission.models import Mission

    if not isinstance(mission, Mission):
        raise TypeError("context_from_mission requires a Mission read model")
    return PolicyEvaluationContext(
        mission_id=mission.mission_id,
        mission_revision=mission.mission_revision,
        authorization_epoch=mission.authorization_epoch,
        allowed_execution_scope=mission.allowed_execution_scope,
        prohibited_execution_scope=mission.prohibited_execution_scope,
        data_access_policy=mission.data_access_policy,
        mission_require_for_risk=mission.approval_policy.require_for_risk,
        mission_require_for_side_effect=mission.approval_policy.require_for_side_effect,
        valid_until=mission.valid_until,
    )


@dataclass(frozen=True)
class _DataAccessRequest:
    resource_type: ResourceType
    resource_id: str
    resource_version: str
    resource_digest: str
    authorization_state_digest: str
    operations: frozenset[DataAccessOperation]


@dataclass(frozen=True)
class PolicyEvaluationContext:
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    allowed_execution_scope: tuple[ExecutionScopeRule, ...]
    prohibited_execution_scope: tuple[ExecutionScopeRule, ...]
    data_access_policy: DataAccessPolicy
    mission_require_for_risk: frozenset[RiskLevel]
    mission_require_for_side_effect: frozenset[Literal["read_only", "state_change", "destructive"]]
    valid_until: datetime


@dataclass(frozen=True)
class ResolvedAuthorization:
    decision: Decision
    targets: tuple[NormalizedTarget, ...]
    bindings: tuple[TargetDispatchBinding, ...]
    grants: tuple[DataAccessGrant, ...]
    effective_risk: RiskLevel
    authorization_digest: str
    reason_codes: tuple[str, ...]


class PolicyEngine:
    def __init__(
        self,
        *,
        digest_service: DigestService,
        risk_policy: EffectiveRiskPolicy,
        secret_metadata_reader: SecretMetadataReader | None = None,
        resource_metadata_reader: ResourceMetadataReader | None = None,
        extractors: TrustedTargetExtractorRegistry | None = None,
        decision_ttl_seconds: int = 900,
    ) -> None:
        self._digests = digest_service
        self._risk_policy = risk_policy
        self._secret_metadata = secret_metadata_reader
        self._resource_metadata = resource_metadata_reader
        self._extractors = extractors if extractors is not None else DEFAULT_TARGET_EXTRACTOR_REGISTRY
        self._decision_ttl_seconds = decision_ttl_seconds

    # --- intent resolution ------------------------------------------------

    def _normalized_targets(
        self,
        plan: ExecutionPlan,
        tool: ToolDefinition,
        session_snapshots: Mapping[str, SessionSecurityContextSnapshot],
        now: datetime,
    ) -> tuple[NormalizedTarget, ...]:
        if tool.target_extractor_id is None:
            targets: tuple[NormalizedTarget, ...] = ()
        else:
            targets = self._extractors.extract(
                tool.target_extractor_id,
                TargetExtractionInput(
                    requested_targets=plan.proposal.requested_targets,
                    arguments=plan.proposal.arguments,
                    session_id=plan.proposal.session_id,
                ),
            )
        if tool.requires_session:
            session_id = plan.proposal.session_id
            if session_id is None:
                raise TargetExtractorResolutionError("session-required tool has no session id")
            if not any(t.type == "session" and t.canonical_value == session_id for t in targets):
                targets = (*targets, NormalizedTarget(type="session", canonical_value=session_id, source="session"))
        # Every referenced session contributes its trusted current host to the
        # affected target set.  Checking only the execution session would let a
        # second argument session reach a prohibited host (Z05).
        host_ids: list[str] = []
        for target in targets:
            if target.type != "session":
                continue
            snapshot = session_snapshots.get(target.canonical_value)
            if snapshot is None or not (now < snapshot.session_fresh_until):
                raise TargetExtractorResolutionError("session target is missing or stale")
            session = snapshot.context
            if session.security_status != "ok":
                raise TargetExtractorResolutionError("session target security status is not usable")
            if session.os not in tool.supported_os or session.architecture not in tool.supported_architectures:
                raise TargetExtractorResolutionError("session target is incompatible with the tool")
            if not tool.required_session_capabilities <= session.session_capabilities:
                raise TargetExtractorResolutionError("session target lacks required capabilities")
            if session.host not in host_ids:
                host_ids.append(session.host)
        targets = (
            *targets,
            *(NormalizedTarget(type="host", canonical_value=host_id, source="session") for host_id in host_ids),
        )
        return targets

    def _derive_resource_requests(
        self, plan: ExecutionPlan, tool: ToolDefinition
    ) -> tuple[bool, list[_DataAccessRequest], tuple[str, ...]]:
        """Derive read data-access requests for declared non-secret resource types (R02)."""
        if not tool.required_data_access_types:
            return True, [], ()
        if self._resource_metadata is None:
            return False, [], ("RESOURCE_METADATA_UNAVAILABLE",)
        arguments = thaw(plan.proposal.arguments)
        requests: list[_DataAccessRequest] = []
        for resource_type in sorted(tool.required_data_access_types):
            if resource_type == "secret_reference":
                continue  # secret resolve is derived separately
            field = _RESOURCE_ID_FIELD.get(resource_type)
            if field is None:
                return False, [], ("UNSUPPORTED_DATA_ACCESS_TYPE",)
            resource_ids = arguments.get(field) if isinstance(arguments, dict) else None
            if not isinstance(resource_ids, list) or not resource_ids:
                return False, [], ("MISSING_RESOURCE_ARGUMENT",)
            for resource_id in resource_ids:
                if not isinstance(resource_id, str):
                    return False, [], ("RESOURCE_REFERENCE_INVALID",)
                metadata = self._resource_metadata.get(resource_id)
                if metadata is None or metadata.resource_type != resource_type:
                    return False, [], ("RESOURCE_NOT_FOUND",)
                state_digest = self._digests.compute(
                    "authorization_state_digest",
                    {
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "resource_version": metadata.version,
                        "resource_digest": metadata.metadata_digest,
                        "operations": ["read"],
                    },
                )
                requests.append(
                    _DataAccessRequest(
                        resource_type=resource_type,  # type: ignore[arg-type]
                        resource_id=resource_id,
                        resource_version=metadata.version,
                        resource_digest=metadata.metadata_digest,
                        authorization_state_digest=state_digest,
                        operations=frozenset({"read"}),
                    )
                )
        return True, requests, ()

    def _derive_secret_requests(
        self, plan: ExecutionPlan, tool: ToolDefinition, now: datetime
    ) -> tuple[bool, list[_DataAccessRequest], tuple[str, ...]]:
        try:
            validate_secret_argument_paths(tool.secret_argument_paths, plan.proposal.arguments)
        except Exception:
            return False, [], ("SECRET_PATH_INVALID",)
        if not tool.secret_argument_paths:
            return True, [], ()
        if self._secret_metadata is None:
            return False, [], ("SECRET_METADATA_UNAVAILABLE",)
        requests: list[_DataAccessRequest] = []
        for path in tool.secret_argument_paths:
            leaf = resolve_pointer(parse_json_pointer(path), plan.proposal.arguments)
            try:
                validate_secret_reference(leaf)
            except Exception:
                return False, [], ("SECRET_REFERENCE_INVALID",)
            assert isinstance(leaf, Mapping)
            version_id = leaf.get("secret_version_id")
            if not isinstance(version_id, str):
                return False, [], ("SECRET_REFERENCE_INVALID",)
            metadata = self._secret_metadata.get(version_id)
            if metadata is None:
                return False, [], ("SECRET_VERSION_NOT_FOUND",)
            if metadata.state != "CONFIRMED":
                return False, [], ("SECRET_NOT_CONFIRMED",)
            if metadata.expires_at is not None and now >= metadata.expires_at:
                return False, [], ("SECRET_EXPIRED",)
            claimed_version = leaf.get("secret_version")
            if claimed_version != metadata.version:
                return False, [], ("SECRET_VERSION_MISMATCH",)
            requests.append(
                _DataAccessRequest(
                    resource_type="secret_reference",
                    resource_id=metadata.secret_version_id,
                    resource_version=metadata.version,
                    resource_digest=metadata.metadata_digest,
                    authorization_state_digest=metadata.lifecycle_head_digest,
                    operations=frozenset({"resolve"}),
                )
            )
        return True, requests, ()

    def _build_grants(
        self, requests: list[_DataAccessRequest], policy: DataAccessPolicy
    ) -> tuple[bool, tuple[DataAccessGrant, ...], tuple[str, ...]]:
        grants: list[DataAccessGrant] = []
        for request in requests:
            for operation in sorted(request.operations):
                decision = evaluate_data_access(policy, request.resource_type, request.resource_id, operation)
                if not decision.allowed:
                    return False, (), (f"DATA_ACCESS_DENIED:{decision.reason_code}",)
            grants.append(
                DataAccessGrant(
                    resource_type=request.resource_type,
                    resource=ResourceBinding(
                        resource_id=request.resource_id,
                        resource_version=request.resource_version,
                        resource_digest=request.resource_digest,
                    ),
                    authorization_state_digest=request.authorization_state_digest,
                    operations=frozenset(request.operations),
                )
            )
        grants.sort(key=lambda g: (g.resource_type, g.resource.resource_id))
        return True, tuple(grants), ()

    def _build_bindings(
        self, targets: tuple[NormalizedTarget, ...], adapter: AdapterCapabilities, tool: ToolDefinition
    ) -> tuple[TargetDispatchBinding, ...]:
        bindings: list[TargetDispatchBinding] = []
        for target in targets:
            if target.type == "session":
                continue
            mode = select_binding_mode(tool.required_target_binding_modes, adapter.target_binding_modes) or "none"
            bindings.append(
                build_target_dispatch_binding(
                    normalized_target=target,
                    binding_mode=mode,
                    connection_addresses=target.resolved_addresses,
                    digest_service=self._digests,
                )
            )
        bindings.sort(key=lambda b: (b.normalized_target.type, b.normalized_target.canonical_value))
        return tuple(bindings)

    def _authorization_digest(
        self,
        *,
        context: PolicyEvaluationContext,
        plan: ExecutionPlan,
        tool: ToolDefinition,
        registry_digest: str,
        targets: tuple[NormalizedTarget, ...],
        bindings: tuple[TargetDispatchBinding, ...],
        grants: tuple[DataAccessGrant, ...],
        effective_risk: RiskLevel,
    ) -> str:
        payload = {
            "mission_id": context.mission_id,
            "mission_revision": context.mission_revision,
            "authorization_epoch": context.authorization_epoch,
            "proposal_digest": plan.proposal_digest,
            "tool_ref": tool.tool_ref.model_dump(mode="python"),
            "resolved_adapter": tool.adapter,
            "resolved_adapter_id": tool.adapter_id,
            "session_id": plan.proposal.session_id,
            "arguments": plan.proposal.arguments,
            "normalized_targets": sorted(
                (t.model_dump(mode="python") for t in targets),
                key=lambda p: (p["type"], p["canonical_value"]),
            ),
            "target_dispatch_bindings": sorted(
                (b.model_dump(mode="python") for b in bindings),
                key=lambda p: (p["normalized_target"]["type"], p["normalized_target"]["canonical_value"]),
            ),
            "authorized_data_access": sorted(
                (g.model_dump(mode="python") for g in grants),
                key=lambda p: (p["resource_type"], p["resource"]["resource_id"]),
            ),
            "effective_risk": effective_risk,
            "side_effect": tool.side_effect,
            "approval_rule": tool.approval_rule,
            "policy_version": self._risk_policy.policy_version,
            "registry_digest": registry_digest,
            "available_tool_snapshot_id": plan.available_tool_snapshot_id,
            "available_tool_snapshot_digest": plan.available_tool_snapshot_digest,
            "session_security_context_digest": plan.session_security_context_digest,
            "adapter_capabilities_digest": plan.adapter_capabilities_digest,
            "sandbox_capabilities_digest": plan.sandbox_capabilities_digest,
            "remote_mcp_trust_policy_digest": plan.remote_mcp_trust_policy_digest,
            "action_contract_ref": plan.action_contract_ref.model_dump(mode="python"),
            "execution_precondition_digest": plan.execution_precondition_digest,
        }
        return self._digests.compute("authorization_digest", payload)

    def resolve(
        self,
        *,
        plan: ExecutionPlan,
        context: PolicyEvaluationContext,
        tool: ToolDefinition,
        adapter: AdapterCapabilities,
        session_snapshots: Mapping[str, SessionSecurityContextSnapshot],
        registry_digest: str,
        now: datetime,
    ) -> ResolvedAuthorization:
        reason_codes: list[str] = []

        # Re-validate the plan against its strict schema and the arguments against
        # the tool's registered parameter schema before anything is trusted (R01).
        inputs_ok = True
        try:
            strict_revalidate(plan)
        except Exception:
            inputs_ok = False
            reason_codes.append("PLAN_SCHEMA_INVALID")
        if inputs_ok:
            try:
                validate_arguments(tool.parameter_schema, plan.proposal.arguments)
            except ParameterSchemaError:
                inputs_ok = False
                reason_codes.append("PARAMETER_SCHEMA_INVALID")

        if inputs_ok:
            try:
                targets = self._normalized_targets(plan, tool, session_snapshots, now)
                target_ok = True
            except TargetExtractorResolutionError:
                targets, target_ok = (), False
                reason_codes.append("TARGET_EXTRACTION_FAILED")
        else:
            targets, target_ok = (), False

        if not target_ok:
            scope_ok = False
        elif tool.target_mode == "none" and not targets:
            scope_ok = True
        else:
            scope_decision = evaluate_targets(
                context.allowed_execution_scope, context.prohibited_execution_scope, targets
            )
            scope_ok = scope_decision.allowed
            if not scope_ok:
                reason_codes.append(f"SCOPE_{scope_decision.reason_code}")

        secret_ok, secret_requests, secret_reasons = (
            self._derive_secret_requests(plan, tool, now) if inputs_ok else (False, [], ())
        )
        resource_ok, resource_requests, resource_reasons = (
            self._derive_resource_requests(plan, tool) if inputs_ok else (False, [], ())
        )
        reason_codes.extend(secret_reasons)
        reason_codes.extend(resource_reasons)
        requests = secret_requests + resource_requests
        grants: tuple[DataAccessGrant, ...] = ()
        grants_ok = True
        if secret_ok and resource_ok and requests:
            try:
                grants_ok, grants, grant_reasons = self._build_grants(requests, context.data_access_policy)
            except DataAccessPatternError:
                grants_ok, grants, grant_reasons = False, (), ("DATA_ACCESS_INDETERMINATE",)
            reason_codes.extend(grant_reasons)
        data_ok = inputs_ok and secret_ok and resource_ok and grants_ok

        has_secret_resolve = secret_ok and any(r.resource_type == "secret_reference" for r in secret_requests)
        selected_snapshot = (
            session_snapshots.get(plan.proposal.session_id) if plan.proposal.session_id is not None else None
        )
        privileged = bool(
            tool.requires_session and selected_snapshot is not None and selected_snapshot.context.privileged
        )
        effective_risk = compute_effective_risk(
            policy=self._risk_policy,
            tool_minimum_risk=tool.minimum_risk_level,
            side_effect=tool.side_effect,
            normalized_target_count=len([t for t in targets if t.type != "session"]),
            has_secret_resolve=has_secret_resolve,
            privileged_session=privileged,
        )
        bindings = self._build_bindings(targets, adapter, tool) if target_ok else ()

        if target_ok and scope_ok and data_ok:
            needs_approval = approval_required(
                policy=self._risk_policy,
                effective_risk=effective_risk,
                side_effect=tool.side_effect,
                tool_approval_rule=tool.approval_rule,
                mission_require_for_risk=context.mission_require_for_risk,
                mission_require_for_side_effect=context.mission_require_for_side_effect,
            )
            decision: Decision = "REQUIRE_APPROVAL" if needs_approval else "ALLOW"
            reason_codes.append(decision)
        else:
            decision = "DENY"

        authorization_digest = self._authorization_digest(
            context=context, plan=plan, tool=tool, registry_digest=registry_digest,
            targets=targets, bindings=bindings, grants=grants, effective_risk=effective_risk,
        )
        return ResolvedAuthorization(
            decision=decision,
            targets=targets,
            bindings=bindings,
            grants=grants,
            effective_risk=effective_risk,
            authorization_digest=authorization_digest,
            reason_codes=tuple(reason_codes),
        )

    # --- public API -------------------------------------------------------

    def authorize(
        self,
        *,
        decision_id: str,
        plan: ExecutionPlan,
        context: PolicyEvaluationContext,
        tool: ToolDefinition,
        adapter: AdapterCapabilities,
        session_snapshots: Mapping[str, SessionSecurityContextSnapshot],
        registry_digest: str,
        now: datetime,
    ) -> PolicyDecision:
        resolved = self.resolve(
            plan=plan, context=context, tool=tool, adapter=adapter,
            session_snapshots=session_snapshots, registry_digest=registry_digest, now=now,
        )
        expires_at = now + timedelta(seconds=self._decision_ttl_seconds)
        # Explicit rejection of an out-of-range TTL (no implicit clamp, §21).
        enforce_ttl(
            label="policy_decision", issued_at=now, expires_at=expires_at, mission_valid_until=context.valid_until
        )
        if not (now < context.valid_until):
            raise PolicyEvaluationIndeterminateError("mission validity window has ended")
        return self._finalize(
            decision_id=decision_id, plan=plan, context=context, tool=tool,
            registry_digest=registry_digest, resolved=resolved, issued_at=now, expires_at=expires_at,
        )

    def verify_authorization_binding(
        self,
        *,
        decision: PolicyDecision,
        plan: ExecutionPlan,
        context: PolicyEvaluationContext,
        tool: ToolDefinition,
        adapter: AdapterCapabilities,
        session_snapshots: Mapping[str, SessionSecurityContextSnapshot],
        registry_digest: str,
        now: datetime,
    ) -> tuple[bool, str]:
        """Re-derive the authorization from current trusted inputs and compare."""
        resolved = self.resolve(
            plan=plan, context=context, tool=tool, adapter=adapter,
            session_snapshots=session_snapshots, registry_digest=registry_digest, now=now,
        )
        if resolved.decision != decision.decision:
            return False, "DECISION_KIND_MISMATCH"
        if resolved.authorization_digest != decision.authorization_digest:
            return False, "AUTHORIZATION_DIGEST_MISMATCH"
        # Compare the re-resolved intent fields against the decision's stored
        # fields directly, so tampering with a stored field is caught even
        # independently of the digest (Codex #3).
        if resolved.targets != decision.normalized_targets:
            return False, "NORMALIZED_TARGETS_MISMATCH"
        if resolved.bindings != decision.target_dispatch_bindings:
            return False, "TARGET_BINDING_MISMATCH"
        if resolved.grants != decision.authorized_data_access:
            return False, "DATA_ACCESS_MISMATCH"
        if resolved.effective_risk != decision.effective_risk:
            return False, "EFFECTIVE_RISK_MISMATCH"
        return True, "OK"

    def _finalize(
        self,
        *,
        decision_id: str,
        plan: ExecutionPlan,
        context: PolicyEvaluationContext,
        tool: ToolDefinition,
        registry_digest: str,
        resolved: ResolvedAuthorization,
        issued_at: datetime,
        expires_at: datetime,
    ) -> PolicyDecision:
        fields = {
            "decision_id": decision_id,
            "mission_id": context.mission_id,
            "mission_revision": context.mission_revision,
            "authorization_epoch": context.authorization_epoch,
            "plan_id": plan.plan_id,
            "tool_ref": tool.tool_ref.model_dump(mode="python"),
            "proposal_digest": plan.proposal_digest,
            "authorization_digest": resolved.authorization_digest,
            "policy_version": self._risk_policy.policy_version,
            "registry_digest": registry_digest,
            "available_tool_snapshot_id": plan.available_tool_snapshot_id,
            "available_tool_snapshot_digest": plan.available_tool_snapshot_digest,
            "resolved_adapter": tool.adapter,
            "resolved_adapter_id": tool.adapter_id,
            "decision": resolved.decision,
            "normalized_targets": [t.model_dump(mode="python") for t in resolved.targets],
            "target_dispatch_bindings": [b.model_dump(mode="python") for b in resolved.bindings],
            "authorized_data_access": [g.model_dump(mode="python") for g in resolved.grants],
            "effective_risk": resolved.effective_risk,
            "reason_codes": list(resolved.reason_codes),
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        payload = dict(fields)
        payload.pop("decision_digest", None)
        decision_digest = self._digests.compute("decision_digest", payload)
        return PolicyDecision(
            decision_id=decision_id,
            decision_digest=decision_digest,
            mission_id=context.mission_id,
            mission_revision=context.mission_revision,
            authorization_epoch=context.authorization_epoch,
            plan_id=plan.plan_id,
            tool_ref=tool.tool_ref,
            proposal_digest=plan.proposal_digest,
            authorization_digest=resolved.authorization_digest,
            policy_version=self._risk_policy.policy_version,
            registry_digest=registry_digest,
            available_tool_snapshot_id=plan.available_tool_snapshot_id,
            available_tool_snapshot_digest=plan.available_tool_snapshot_digest,
            resolved_adapter=tool.adapter,
            resolved_adapter_id=tool.adapter_id,
            decision=resolved.decision,
            normalized_targets=resolved.targets,
            target_dispatch_bindings=resolved.bindings,
            authorized_data_access=resolved.grants,
            effective_risk=resolved.effective_risk,
            reason_codes=resolved.reason_codes,
            issued_at=issued_at,
            expires_at=expires_at,
        )
