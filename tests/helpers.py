from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from redteam_agent.canonical import CanonicalJsonObject
from redteam_agent.models.common import OperationalPhase
from redteam_agent.models.plans import ExecutionPlan, ExecutionPlanProposal
from redteam_agent.models.policy import PolicyDecision
from redteam_agent.models.tools import AvailableToolSnapshot, ToolDefinition, ToolRegistryRevision
from redteam_agent.policy.engine import PolicyEngine
from redteam_agent.policy.issuance import PolicyDecisionIssuanceService
from redteam_agent.policy.plans import create_execution_plan
from redteam_agent.repositories import (
    AdapterCapabilitySnapshotRepository,
    ApprovalRecordRepository,
    ApprovalRequestRepository,
    AuthorizationRuntimeBindingRepository,
    AvailableToolSnapshotRepository,
    ContextResourceIndexRepository,
    LLMProfileRepository,
    MissionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    PlanProposalRepository,
    PlanRepository,
    PolicyDecisionRepository,
    PolicyStateRepository,
    RemoteMCPTrustSnapshotRepository,
    SandboxCapabilitySnapshotRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.repositories.runtime import build_policy_state, build_runtime_binding
from redteam_agent.authorization_runtime import AuthorizationRuntimeContextResolver
from redteam_agent.mission import AuthorizationReferenceRegistry, MissionManager
from redteam_agent.seeds import (
    FIXED_TIME,
    mission_records,
    mock_capability_snapshots,
    mock_mission,
    mock_network_tool,
    mock_profile,
)
from redteam_agent.storage import Database
from redteam_agent.tools import (
    ToolAvailabilityResolver,
    TrustedTargetExtractorRegistry,
    build_registry_revision,
)


@dataclass(frozen=True)
class KernelEnvironment:
    mission: object
    tool: ToolDefinition
    extractors: TrustedTargetExtractorRegistry
    registry: ToolRegistryRevision
    session_snapshot: object
    adapter_snapshot: object
    sandbox_snapshot: object
    remote_snapshot: object
    availability_resolver: ToolAvailabilityResolver
    snapshot: AvailableToolSnapshot
    proposal: ExecutionPlanProposal
    plan: ExecutionPlan
    decision: PolicyDecision


@dataclass(frozen=True)
class PersistedKernel:
    environment: KernelEnvironment
    runtime_resolver: AuthorizationRuntimeContextResolver
    plans: PlanRepository
    decisions: PolicyDecisionRepository
    resources: ContextResourceIndexRepository
    approval_requests: ApprovalRequestRepository
    approvals: ApprovalRecordRepository
    decision: PolicyDecision


def build_environment(
    *,
    target: str = "10.0.0.10",
    approval_rule: str = "policy",
) -> KernelEnvironment:
    mission = mock_mission()
    tool = mock_network_tool(approval_rule=approval_rule)
    extractors = TrustedTargetExtractorRegistry()
    registry = build_registry_revision(
        registry_revision=1,
        tools=(tool,),
        created_at=FIXED_TIME,
        extractors=extractors,
    )
    session, adapter, sandbox, remote = mock_capability_snapshots(mission.mission_id)
    resolver = ToolAvailabilityResolver(extractors)
    calculation = resolver.calculate(
        mission=mission,
        registry=registry,
        session_snapshot=session,
        adapter_snapshot=adapter,
        sandbox_snapshot=sandbox,
        remote_trust_snapshot=remote,
        policy_version="policy-v1",
    )
    snapshot = resolver.persistable_snapshot(
        calculation,
        created_at=FIXED_TIME,
        expires_at=FIXED_TIME + timedelta(hours=1),
        mission_valid_until=mission.valid_until,
    )
    proposal = ExecutionPlanProposal(
        objective="Inspect an in-scope mock target",
        phase=OperationalPhase.DISCOVERY,
        tool_ref=tool.tool_ref,
        requested_targets=(),
        session_id=None,
        arguments=CanonicalJsonObject({"target": target}),
    )
    plan = create_execution_plan(
        mission=mission,
        proposal=proposal,
        snapshot=snapshot,
        created_at=FIXED_TIME,
    )
    decision = PolicyEngine(policy_version="policy-v1", extractors=extractors).authorize(
        mission=mission,
        plan=plan,
        snapshot=snapshot,
        registry=registry,
        issued_at=FIXED_TIME + timedelta(minutes=1),
        expires_at=FIXED_TIME + timedelta(minutes=30),
    )
    return KernelEnvironment(
        mission,
        tool,
        extractors,
        registry,
        session,
        adapter,
        sandbox,
        remote,
        resolver,
        snapshot,
        proposal,
        plan,
        decision,
    )


def gate_kwargs(environment: KernelEnvironment, *, now=None) -> dict[str, object]:
    raise RuntimeError("use persisted_gate_kwargs after trusted repository issuance")


def persist_environment(database: Database, environment: KernelEnvironment) -> PersistedKernel:
    roots = MissionRepository(database)
    revisions = MissionRevisionRepository(database)
    states = MissionStateRepository(database)
    profiles = LLMProfileRepository(database)
    profiles.add(mock_profile())
    manager = MissionManager(
        roots,
        revisions,
        states,
        profiles,
        authorization_references=AuthorizationReferenceRegistry(
            frozenset({environment.mission.authorization_reference})
        ),
    )
    root, revision, _ = mission_records(environment.mission)
    manager.create(root, revision, now=FIXED_TIME - timedelta(minutes=2))
    manager.transition_to_validated(environment.mission.mission_id, now=FIXED_TIME - timedelta(minutes=1))
    running = manager.start(environment.mission.mission_id, now=FIXED_TIME)
    assert running.mission_state_version == environment.mission.mission_state_version

    registries = ToolRegistryRepository(database)
    sessions = SessionSecurityContextSnapshotRepository(database)
    adapters = AdapterCapabilitySnapshotRepository(database)
    sandboxes = SandboxCapabilitySnapshotRepository(database)
    remote = RemoteMCPTrustSnapshotRepository(database)
    available = AvailableToolSnapshotRepository(database)
    registries.add(environment.registry)
    sessions.add(environment.session_snapshot)
    adapters.add(environment.adapter_snapshot)
    sandboxes.add(environment.sandbox_snapshot)
    remote.add(environment.remote_snapshot)
    available.add(environment.snapshot)

    proposal_repository = PlanProposalRepository(database)
    assert proposal_repository.add(environment.proposal) == environment.plan.proposal_digest
    plans = PlanRepository(database)
    plans.add(environment.plan)

    policies = PolicyStateRepository(database)
    policies.set_current(
        build_policy_state(
            mission_id=running.mission_id,
            state_version=0,
            policy_version="policy-v1",
            updated_at=FIXED_TIME,
        )
    )
    bindings = AuthorizationRuntimeBindingRepository(database)
    bindings.set_current(
        build_runtime_binding(
            mission_id=running.mission_id,
            binding_version=0,
            mission_revision=running.mission_revision,
            authorization_epoch=running.authorization_epoch,
            policy_version="policy-v1",
            registry_revision=environment.registry.registry_revision,
            registry_digest=environment.registry.registry_digest,
            available_tool_snapshot_id=environment.snapshot.snapshot_id,
            session_security_context_snapshot_id=environment.session_snapshot.snapshot_id,
            adapter_capability_snapshot_id=environment.adapter_snapshot.snapshot_id,
            sandbox_capability_snapshot_id=environment.sandbox_snapshot.snapshot_id,
            remote_mcp_trust_snapshot_id=environment.remote_snapshot.snapshot_id,
            updated_at=FIXED_TIME,
        )
    )
    runtime_resolver = AuthorizationRuntimeContextResolver(
        revisions=revisions,
        states=states,
        policies=policies,
        bindings=bindings,
        registries=registries,
        available_snapshots=available,
        sessions=sessions,
        adapters=adapters,
        sandboxes=sandboxes,
        remote_trust=remote,
    )
    decisions = PolicyDecisionRepository(database)
    resources = ContextResourceIndexRepository(database)
    issued = PolicyDecisionIssuanceService(
        runtime_resolver=runtime_resolver,
        plans=plans,
        decisions=decisions,
        resources=resources,
    ).issue(
        plan_id=environment.plan.plan_id,
        issued_at=environment.decision.issued_at,
        expires_at=environment.decision.expires_at,
    )
    return PersistedKernel(
        environment=environment,
        runtime_resolver=runtime_resolver,
        plans=plans,
        decisions=decisions,
        resources=resources,
        approval_requests=ApprovalRequestRepository(database),
        approvals=ApprovalRecordRepository(database),
        decision=issued,
    )


def persisted_gate_kwargs(kernel: PersistedKernel, *, now=None) -> dict[str, object]:
    return {
        "plan_id": kernel.environment.plan.plan_id,
        "policy_decision_id": kernel.decision.decision_id,
        "runtime_resolver": kernel.runtime_resolver,
        "plans": kernel.plans,
        "decisions": kernel.decisions,
        "resources": kernel.resources,
        "approval_requests": kernel.approval_requests,
        "approvals": kernel.approvals,
        "now": now or FIXED_TIME + timedelta(minutes=2),
    }
