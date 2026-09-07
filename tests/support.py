"""Reusable builders for authorization-kernel tests.

These helpers construct fully valid domain objects and seed a RUNNING mission
through the real Mission Manager and owner services, so tests exercise the
public entry points and then perturb a single input to assert a specific
fail-closed behaviour.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.auth.models import AuthenticatedPrincipal, MissionRoleAssignment
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition.testing import (
    ADMIN_ACTOR_TOKEN,
    ADMIN_PRINCIPAL_ID,
    OPERATOR_ACTOR_TOKEN,
    OPERATOR_PRINCIPAL_ID,
    Phase0AKernel,
)
from redteam_agent.contracts.catalog import (
    ActionContractCatalog,
    ActionContractDefinition,
    RuleCatalog,
    parameter_schema_digest,
)
from redteam_agent.llm.profile import AgentModelProfile, mock_agent_profile
from redteam_agent.mission.manager import MISSION_ADMIN_ROLE, MISSION_OPERATOR_ROLE
from redteam_agent.mission.models import (
    ApprovalPolicy,
    ExactSessionSelector,
    MissionRevision,
    MissionState,
    SessionExistsCondition,
)
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.plan.models import ExecutionPlan, ExecutionPlanProposal, compute_proposal_digest
from redteam_agent.policy.data_access import DataAccessPolicy, DataAccessRule
from redteam_agent.policy.scope_models import ExecutionScopeRule, NetworkScopeRule, TargetReference
from redteam_agent.resources.secret_metadata import SecretVersionMetadata
from redteam_agent.sandbox.models import SandboxCapabilities, build_sandbox_capabilities
from redteam_agent.session.models import SessionSecurityContext, SessionSecurityContextSnapshot
from redteam_agent.tools.availability import AvailableToolSnapshot
from redteam_agent.tools.models import ToolDefinition
from redteam_agent.tools.registry import ToolRegistryRevision, build_tool_registry

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
MISSION_ID = "mission-1"
ADAPTER_ID = "c2-main"

_PLACEHOLDER_CONTRACT = ActionContractReference(contract_id="pending", revision="1", digest="pending")

# Closed parameter schema for the network scan tool: every argument a proposal
# may carry is declared, and additional properties are rejected (R01). The
# credential object mirrors the secret-reference shape.
_SECRET_REFERENCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "credential_type": {"type": "string"},
        "secret_version_id": {"type": "string"},
        "secret_version": {"type": "string"},
        "principal_ref": {"type": "string"},
    },
    "required": ["credential_type", "secret_version_id", "secret_version", "principal_ref"],
    "additionalProperties": False,
}
_NETWORK_PARAMETER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "destinations": {"type": "array", "items": {"type": "string"}},
        "port": {"type": "integer"},
        "protocol": {"type": "string"},
        "timeout_seconds": {"type": "integer"},
        "credential": _SECRET_REFERENCE_SCHEMA,
    },
    "required": ["destinations"],
    "additionalProperties": False,
}


def make_profile(digest_service: DigestService) -> AgentModelProfile:
    return mock_agent_profile(digest_service)


def network_tool(
    *,
    tool_id: str = "net-scan",
    registry_revision: int = 1,
    side_effect: str = "read_only",
    minimum_risk: str = "low",
    approval_rule: str = "policy",
    secret_paths: tuple[str, ...] = (),
    requires_session: bool = False,
) -> ToolDefinition:
    parameter_schema = deepcopy(_NETWORK_PARAMETER_SCHEMA)
    if not secret_paths:
        del parameter_schema["properties"]["credential"]
    return ToolDefinition(
        tool_ref=ToolRef(tool_id=tool_id, registry_revision=registry_revision),
        display_name="Network Scan",
        version="1.0",
        description="scan",
        adapter="c2",
        adapter_id=ADAPTER_ID,
        provider_tool_name="scan",
        provider_definition_revision="1",
        provider_schema_digest="sd-1",
        minimum_risk_level=minimum_risk,  # type: ignore[arg-type]
        approval_rule=approval_rule,  # type: ignore[arg-type]
        side_effect=side_effect,  # type: ignore[arg-type]
        idempotency="idempotent",
        parameter_schema=parameter_schema,
        output_publication_rule_id="pub-1",
        evidence_rule_ids=("ev-1",),
        action_contract_ref=_PLACEHOLDER_CONTRACT,
        target_mode="required",
        target_extractor_id="network_target_v1",
        default_timeout_seconds=60,
        max_timeout_seconds=120,
        max_output_bytes=1_000_000,
        secret_argument_paths=secret_paths,
        requires_session=requires_session,
        supported_os=frozenset({"linux"}),
        supported_architectures=frozenset({"x86_64"}),
        required_adapter_capabilities=frozenset({"scan"}),
        required_session_capabilities=frozenset(),
        required_data_access_types=(
            frozenset({"secret_reference"}) if secret_paths else frozenset()
        ),
        required_target_binding_modes=frozenset({"exact_ip_enforced"}),
        sandbox_requirement=None,
    )


def _contract_for(tool: ToolDefinition) -> ActionContractDefinition:
    return ActionContractDefinition(
        contract_id=f"contract-{tool.tool_ref.tool_id}",
        revision="1",
        tool_id=tool.tool_ref.tool_id,
        registry_revision=tool.tool_ref.registry_revision,
        parameter_schema_digest=parameter_schema_digest(tool.parameter_schema),
        target_extractor_id=tool.target_extractor_id,
        evidence_rule_ids=tool.evidence_rule_ids,
        output_publication_rule_id=tool.output_publication_rule_id,
        minimum_risk_level=tool.minimum_risk_level,
        side_effect=tool.side_effect,
    )


def rule_catalog_for(tools: tuple[ToolDefinition, ...]) -> RuleCatalog:
    """Build a rule catalog that registers each tool's referenced rules."""
    catalog = RuleCatalog()
    register_rules_for(catalog, tools)
    return catalog


def register_rules_for(rule_catalog: RuleCatalog, tools: tuple[ToolDefinition, ...]) -> None:
    for tool in tools:
        rule_catalog.register_publication(tool.output_publication_rule_id)
        for rule_id in tool.evidence_rule_ids:
            rule_catalog.register_evidence(rule_id)


def register_contracts_for(catalog: ActionContractCatalog, tools: tuple[ToolDefinition, ...]) -> None:
    for tool in tools:
        catalog.register(_contract_for(tool))


def build_registered_registry(
    digest_service: DigestService,
    base_tools: tuple[ToolDefinition, ...],
    *,
    catalog: ActionContractCatalog | None = None,
    rule_catalog: RuleCatalog | None = None,
) -> tuple[ToolRegistryRevision, tuple[ToolDefinition, ...], ActionContractCatalog]:
    definitions = tuple(_contract_for(tool) for tool in base_tools)
    catalog = catalog if catalog is not None else ActionContractCatalog()
    for definition in definitions:
        catalog.register(definition)
    rule_catalog = rule_catalog if rule_catalog is not None else RuleCatalog()
    register_rules_for(rule_catalog, base_tools)
    rebound = tuple(
        tool.model_copy(update={"action_contract_ref": definition.reference()})
        for tool, definition in zip(base_tools, definitions, strict=True)
    )
    registry = build_tool_registry(
        registry_revision=1,
        tools=rebound,
        digest_service=digest_service,
        contract_catalog=catalog,
        rule_catalog=rule_catalog,
    )
    return registry, rebound, catalog


def contract_catalog_for(tools: tuple[ToolDefinition, ...]) -> ActionContractCatalog:
    return ActionContractCatalog(tuple(_contract_for(tool) for tool in tools))


def rebind_contract(tool: ToolDefinition) -> ToolDefinition:
    return tool.model_copy(update={"action_contract_ref": _contract_for(tool).reference()})


def contract_for(tool: ToolDefinition) -> ActionContractDefinition:
    return _contract_for(tool)


def empty_contract_catalog() -> ActionContractCatalog:
    return ActionContractCatalog(())


def adapter_capabilities(
    *, adapter_id: str = ADAPTER_ID, adapter_type: str = "c2", execution_location: str = "local_process"
) -> AdapterCapabilities:
    return AdapterCapabilities(
        adapter_id=adapter_id,
        adapter_type=adapter_type,  # type: ignore[arg-type]
        execution_location=execution_location,  # type: ignore[arg-type]
        capability_revision="1",
        capabilities=frozenset({"scan"}),
        supported_os=frozenset({"linux"}),
        supported_architectures=frozenset({"x86_64"}),
        reconciliation=True,
        cancellation=True,
        provider_deduplication=False,
        result_streaming=True,
        result_resume=True,
        durable_result_collection=True,
        result_delivery_mode="provider_task",
        target_binding_modes=frozenset({"exact_ip_enforced"}),
        redirect_disable_enforcement=True,
        policy_intercepted_redirect=False,
        max_output_bytes=1_000_000,
        provider_tool_catalog_digest=None,
        observed_at=T0,
    )


def sandbox_capabilities(
    digest_service: DigestService, *, adapter_id: str = ADAPTER_ID, location: str = "local_process", all_enabled: bool = True
) -> SandboxCapabilities:
    return build_sandbox_capabilities(
        sandbox_id=f"sandbox-{adapter_id}",
        adapter_id=adapter_id,
        execution_location=location,  # type: ignore[arg-type]
        digest_service=digest_service,
        all_enabled=all_enabled,
    )


def session_snapshot(
    *, session_id: str = "sess-1", privileged: bool = False, fresh_delta_hours: int = 6, security_status: str = "ok"
) -> SessionSecurityContextSnapshot:
    context = SessionSecurityContext(
        session_id=session_id,
        host="host-1",
        os="linux",
        architecture="x86_64",
        current_principal="root" if privileged else "user",
        effective_privilege_context="linux_uid0" if privileged else "standard",
        session_capabilities=frozenset({"shell"}),
        network_context="internal",
        security_status=security_status,
    )
    return SessionSecurityContextSnapshot(
        session_id=session_id,
        context=context,
        session_fresh_until=T0 + timedelta(hours=fresh_delta_hours),
        observed_at=T0,
    )


def default_scope() -> tuple[ExecutionScopeRule, ...]:
    return (NetworkScopeRule(type="network", cidrs=("10.0.0.0/8",), ports=(443,), protocols=("tcp",)),)


def secret_data_access_policy() -> DataAccessPolicy:
    return DataAccessPolicy(
        allowed=(
            DataAccessRule(resource_type="secret_reference", resource_pattern="exact:sv-1", operations=frozenset({"resolve"})),
        ),
        prohibited=(),
    )


def mission_revision(
    digest_service: DigestService,
    *,
    profile: AgentModelProfile,
    allowed_scope: tuple[ExecutionScopeRule, ...] | None = None,
    prohibited_scope: tuple[ExecutionScopeRule, ...] = (),
    data_access_policy: DataAccessPolicy | None = None,
    mission_revision_number: int = 1,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    require_for_risk: frozenset[str] = frozenset(),
    require_for_side_effect: frozenset[str] = frozenset(),
    success_conditions: tuple[Any, ...] | None = None,
) -> MissionRevision:
    valid_from = valid_from if valid_from is not None else T0 - timedelta(hours=1)
    valid_until = valid_until if valid_until is not None else T0 + timedelta(days=2)
    recovery_until = valid_until + timedelta(days=1)
    evidence_until = recovery_until + timedelta(days=1)
    conditions = success_conditions or (
        SessionExistsCondition(
            condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
        ),
    )
    stub = MissionRevision(
        mission_id=MISSION_ID,
        mission_revision=mission_revision_number,
        llm_profile_revision=profile.profile_revision,
        llm_profile_digest=profile.profile_digest,
        description="exercise",
        authorization_reference="AUTH-REF-1",
        authorized_by="operator-1",
        valid_from=valid_from,
        valid_until=valid_until,
        recovery_until=recovery_until,
        evidence_retention_until=evidence_until,
        allowed_execution_scope=allowed_scope if allowed_scope is not None else default_scope(),
        prohibited_execution_scope=prohibited_scope,
        data_access_policy=data_access_policy if data_access_policy is not None else DataAccessPolicy(allowed=(), prohibited=()),
        objectives=("enumerate",),
        success_conditions=conditions,
        success_mode="all",
        max_iterations=10,
        max_runtime_minutes=60,
        approval_policy=ApprovalPolicy(
            require_for_risk=require_for_risk,  # type: ignore[arg-type]
            require_for_side_effect=require_for_side_effect,  # type: ignore[arg-type]
            approval_ttl_seconds=3600,
            count_approval_wait_in_runtime=False,
        ),
        mission_revision_digest="pending",
    )
    payload = stub.model_dump(mode="python")
    payload.pop("mission_revision_digest", None)
    digest = digest_service.compute("mission_revision_digest", payload)
    return stub.model_copy(update={"mission_revision_digest": digest})


@dataclass
class SeededMission:
    kernel: Phase0AKernel
    revision: MissionRevision
    running_state: MissionState
    registry: ToolRegistryRevision
    tool: ToolDefinition
    tools: tuple[ToolDefinition, ...]
    snapshot: AvailableToolSnapshot


def seed_running_mission(
    kernel: Phase0AKernel,
    *,
    tool: ToolDefinition,
    revision: MissionRevision,
    extra_tools: tuple[ToolDefinition, ...] = (),
    session_ids: tuple[str, ...] = (),
    privileged_session: bool = False,
    seed_sandbox: bool = False,
    adapter_capability: AdapterCapabilities | None = None,
) -> SeededMission:
    ds = kernel.digest_service
    profile = mock_agent_profile(ds)
    kernel.profile_repository.save(profile)
    registry, rebound, _catalog = build_registered_registry(
        ds,
        (tool, *extra_tools),
        catalog=kernel.contract_catalog,
        rule_catalog=kernel.rule_catalog,
    )
    kernel.registry_repository.save(registry)
    kernel.adapter_repository.save(adapter_capability or adapter_capabilities())
    if seed_sandbox:
        kernel.sandbox_repository.save(sandbox_capabilities(ds))
    for session_id in session_ids:
        kernel.session_repository.save(session_snapshot(session_id=session_id, privileged=privileged_session))

    provision_lifecycle_roles(kernel, mission_id=revision.mission_id)
    kernel.mission_manager.create_mission(revision, actor_token=ADMIN_ACTOR_TOKEN)
    kernel.mission_manager.validate_mission(
        MISSION_ID, expected_version=0, actor_token=OPERATOR_ACTOR_TOKEN
    )
    running = kernel.mission_manager.start_mission(
        MISSION_ID, expected_version=1, actor_token=OPERATOR_ACTOR_TOKEN
    )

    snapshot = kernel.tool_availability_service.publish(snapshot_id="snap-1", mission_id=MISSION_ID)
    return SeededMission(
        kernel=kernel,
        revision=revision,
        running_state=running,
        registry=registry,
        tool=rebound[0],
        tools=rebound,
        snapshot=snapshot,
    )


def make_proposal(
    *,
    tool: ToolDefinition,
    arguments: dict[str, Any],
    requested_targets: tuple[TargetReference, ...] = (),
    session_id: str | None = None,
) -> ExecutionPlanProposal:
    return ExecutionPlanProposal(
        objective="scan target",
        phase="DISCOVERY",
        tool_ref=tool.tool_ref,
        requested_targets=requested_targets,
        session_id=session_id,
        arguments=arguments,
    )


def make_plan(
    kernel: Phase0AKernel,
    *,
    seeded: SeededMission,
    proposal: ExecutionPlanProposal,
    tool: ToolDefinition | None = None,
    plan_id: str = "plan-1",
) -> ExecutionPlan:
    ds = kernel.digest_service
    snapshot = seeded.snapshot
    tool = tool if tool is not None else seeded.tool
    return ExecutionPlan(
        plan_id=plan_id,
        mission_id=MISSION_ID,
        mission_revision=seeded.revision.mission_revision,
        observed_mission_state_version=seeded.running_state.mission_state_version,
        observed_authorization_epoch=seeded.running_state.authorization_epoch,
        run_id="run-1",
        thread_id="thread-1",
        proposal=proposal,
        proposal_digest=compute_proposal_digest(proposal, ds),
        goal_evaluation_id="phase0a-no-goal-eval",
        goal_evaluation_digest="phase0a-no-goal-eval-digest",
        action_contract_ref=tool.action_contract_ref,
        execution_precondition_digest=_contract_for(tool).execution_precondition_digest,
        available_tool_snapshot_id=snapshot.snapshot_id,
        available_tool_snapshot_digest=snapshot.snapshot_digest,
        session_security_context_digest=snapshot.session_security_context_digest,
        adapter_capabilities_digest=snapshot.adapter_capabilities_digest,
        sandbox_capabilities_digest=snapshot.sandbox_capabilities_digest,
        remote_mcp_trust_policy_digest=snapshot.remote_mcp_trust_policy_digest,
        created_at=T0,
    )


def issue_decision(kernel: Phase0AKernel, *, plan: ExecutionPlan, decision_id: str = "decision-1"):
    return kernel.execution_authorization_service.issue(decision_id=decision_id, plan=plan)


def provision_lifecycle_roles(kernel: Phase0AKernel, *, mission_id: str = MISSION_ID) -> None:
    """Grant the Root-fixed admin/operator principals their mission roles (R18)."""
    kernel.role_assignment_repository.save(
        MissionRoleAssignment(
            mission_id=mission_id, principal_id=ADMIN_PRINCIPAL_ID, role=MISSION_ADMIN_ROLE, active=True
        )
    )
    kernel.role_assignment_repository.save(
        MissionRoleAssignment(
            mission_id=mission_id, principal_id=OPERATOR_PRINCIPAL_ID, role=MISSION_OPERATOR_ROLE, active=True
        )
    )


def register_approver(kernel: Phase0AKernel, *, token: str = "tok-approver", principal_id: str = "op-approver") -> None:
    kernel.principal_resolver.register(
        token, AuthenticatedPrincipal(principal_id=principal_id, roles=frozenset({"approver"}))
    )
    kernel.role_assignment_repository.save(
        MissionRoleAssignment(mission_id=MISSION_ID, principal_id=principal_id, role="approver", active=True)
    )


def confirmed_secret_metadata(digest_service: DigestService, *, version_id: str = "sv-1") -> SecretVersionMetadata:
    return SecretVersionMetadata(
        secret_version_id=version_id,
        secret_id="secret-logical-1",
        version="1",
        metadata_digest=digest_service.compute("authorization_state_digest", {"kind": "meta", "id": version_id}),
        lifecycle_head_digest=digest_service.compute("authorization_state_digest", {"kind": "head", "id": version_id}),
        state="CONFIRMED",
    )


def secret_reference(version_id: str = "sv-1") -> dict[str, Any]:
    return {"credential_type": "password", "secret_version_id": version_id, "secret_version": "1", "principal_ref": "svc-acct"}
