"""Phase 0A test/local composition root.

Wires the deterministic authorization kernel over an in-memory (or file) SQLite
database. This is explicitly a test/local composition: there is no TPM witness,
no production key provider and no real adapter, and it dispatches nothing. The
trusted clock, principal authentication and secret metadata source are injected
here as fixed test doubles (never caller-supplied at an authorization entry).
Authorization artifacts are persisted only by their owner services, which hold
the single write guard created here.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.approval.service import ApprovalService
from redteam_agent.auth.principal import StaticPrincipalResolver
from redteam_agent.auth.rbac import RbacPolicy
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.context.authorization import ContextAuthorizationService
from redteam_agent.executor.authorization_gate import ExecutorAuthorizationGate
from redteam_agent.mission.manager import MissionManager
from redteam_agent.mission.models import EvidenceRetentionPolicy
from redteam_agent.mission.validation import MissionValidationPolicy
from redteam_agent.policy.authorization_service import ExecutionAuthorizationService
from redteam_agent.policy.engine import PolicyEngine
from redteam_agent.policy.risk_policy import EffectiveRiskPolicy, default_risk_policy
from redteam_agent.resources.secret_metadata import StaticSecretMetadataStore
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock, SystemUtcClock
from redteam_agent.storage.database import Database
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    AdapterCapabilityRepository,
    AgentProfileRepository,
    ApprovalRecordRepository,
    ApprovalRequestRepository,
    AvailableToolSnapshotRepository,
    ContextDataAccessGrantRepository,
    ContextResourceIndexRepository,
    MissionLifecycleEventRepository,
    MissionRevisionRepository,
    MissionRoleAssignmentRepository,
    MissionStateRepository,
    PolicyDecisionRepository,
    PolicyRevisionRepository,
    SandboxCapabilityRepository,
    SessionSecurityContextSnapshotRepository,
    ToolRegistryRepository,
)
from redteam_agent.tools.availability_service import ToolAvailabilityService

DEFAULT_REGISTRY_REVISION = 1
DEFAULT_EVIDENCE_RETENTION_SECONDS = 30 * 24 * 3600
DEFAULT_MAX_RECOVERY_WINDOW_SECONDS = 7 * 24 * 3600


def build_evidence_retention_policy(digest_service: DigestService) -> EvidenceRetentionPolicy:
    payload = {
        "policy_revision": "evidence-retention-v1",
        "max_evidence_retention_seconds": DEFAULT_EVIDENCE_RETENTION_SECONDS,
        "allow_local_reingestion_after_recovery": True,
        "require_erasure_at_expiry": True,
    }
    digest = digest_service.compute("policy_digest", payload)
    return EvidenceRetentionPolicy(
        policy_revision="evidence-retention-v1",
        max_evidence_retention_seconds=DEFAULT_EVIDENCE_RETENTION_SECONDS,
        policy_digest=digest,
    )


@dataclass
class Phase0AKernel:
    database: Database
    digest_service: DigestService
    clock: Clock
    risk_policy: EffectiveRiskPolicy
    remote_mcp_trust_policy_digest: str
    registry_revision: int
    policy_version: str
    principal_resolver: StaticPrincipalResolver
    secret_metadata_store: StaticSecretMetadataStore
    rbac: RbacPolicy
    # repositories
    revision_repository: MissionRevisionRepository
    state_repository: MissionStateRepository
    event_repository: MissionLifecycleEventRepository
    registry_repository: ToolRegistryRepository
    policy_repository: PolicyRevisionRepository
    snapshot_repository: AvailableToolSnapshotRepository
    decision_repository: PolicyDecisionRepository
    request_repository: ApprovalRequestRepository
    record_repository: ApprovalRecordRepository
    grant_repository: ContextDataAccessGrantRepository
    profile_repository: AgentProfileRepository
    session_repository: SessionSecurityContextSnapshotRepository
    adapter_repository: AdapterCapabilityRepository
    sandbox_repository: SandboxCapabilityRepository
    index_repository: ContextResourceIndexRepository
    role_assignment_repository: MissionRoleAssignmentRepository
    # services
    mission_manager: MissionManager
    policy_engine: PolicyEngine
    execution_authorization_service: ExecutionAuthorizationService
    tool_availability_service: ToolAvailabilityService
    approval_service: ApprovalService
    context_authorization_service: ContextAuthorizationService
    authorization_gate: ExecutorAuthorizationGate
    context_resolver: AuthorizationContextResolver


def build_test_kernel(
    *,
    db_path: str = ":memory:",
    registry_revision: int = DEFAULT_REGISTRY_REVISION,
    clock: Clock | None = None,
) -> Phase0AKernel:
    database = Database(db_path)
    digest_service = DigestService()
    clock = clock if clock is not None else SystemUtcClock()
    risk_policy = default_risk_policy(digest_service)
    remote_trust_digest = digest_service.compute("remote_mcp_trust_policy_digest", {"policies": []})
    principal_resolver = StaticPrincipalResolver()
    secret_metadata_store = StaticSecretMetadataStore()
    guard = WriteGuard()

    revision_repo = MissionRevisionRepository(database, digest_service)
    state_repo = MissionStateRepository(database, digest_service)
    event_repo = MissionLifecycleEventRepository(database, digest_service)
    registry_repo = ToolRegistryRepository(database, digest_service)
    policy_repo = PolicyRevisionRepository(database, digest_service)
    snapshot_repo = AvailableToolSnapshotRepository(database, digest_service)
    decision_repo = PolicyDecisionRepository(database, digest_service)
    request_repo = ApprovalRequestRepository(database, digest_service)
    record_repo = ApprovalRecordRepository(database, digest_service)
    grant_repo = ContextDataAccessGrantRepository(database, digest_service)
    profile_repo = AgentProfileRepository(database, digest_service)
    session_repo = SessionSecurityContextSnapshotRepository(database, digest_service)
    adapter_repo = AdapterCapabilityRepository(database, digest_service)
    sandbox_repo = SandboxCapabilityRepository(database, digest_service)
    index_repo = ContextResourceIndexRepository(database, digest_service)
    role_repo = MissionRoleAssignmentRepository(database, digest_service)

    policy_repo.save(risk_policy)
    rbac = RbacPolicy(role_repo)

    validation_policy = MissionValidationPolicy(
        max_recovery_window_seconds=DEFAULT_MAX_RECOVERY_WINDOW_SECONDS,
        evidence_retention_policy=build_evidence_retention_policy(digest_service),
    )
    mission_manager = MissionManager(
        database=database,
        revision_repository=revision_repo,
        state_repository=state_repo,
        event_repository=event_repo,
        profile_repository=profile_repo,
        digest_service=digest_service,
        validation_policy=validation_policy,
        clock=clock,
        write_guard=guard,
    )
    policy_engine = PolicyEngine(
        digest_service=digest_service,
        risk_policy=risk_policy,
        secret_metadata_reader=secret_metadata_store,
    )
    context_resolver = AuthorizationContextResolver(
        state_repository=state_repo,
        revision_repository=revision_repo,
        registry_repository=registry_repo,
        policy_repository=policy_repo,
        adapter_repository=adapter_repo,
        sandbox_repository=sandbox_repo,
        session_repository=session_repo,
        digest_service=digest_service,
        registry_revision=registry_revision,
        policy_version=risk_policy.policy_version,
        remote_mcp_trust_policy_digest=remote_trust_digest,
    )
    execution_authorization_service = ExecutionAuthorizationService(
        engine=policy_engine,
        context_resolver=context_resolver,
        registry_repository=registry_repo,
        adapter_repository=adapter_repo,
        session_repository=session_repo,
        decision_repository=decision_repo,
        clock=clock,
        write_guard=guard,
        registry_revision=registry_revision,
    )
    tool_availability_service = ToolAvailabilityService(
        state_repository=state_repo,
        revision_repository=revision_repo,
        registry_repository=registry_repo,
        adapter_repository=adapter_repo,
        sandbox_repository=sandbox_repo,
        session_repository=session_repo,
        snapshot_repository=snapshot_repo,
        digest_service=digest_service,
        clock=clock,
        write_guard=guard,
        registry_revision=registry_revision,
        remote_mcp_trust_policy_digest=remote_trust_digest,
        policy_version=risk_policy.policy_version,
    )
    approval_service = ApprovalService(
        request_repository=request_repo,
        record_repository=record_repo,
        decision_repository=decision_repo,
        registry_repository=registry_repo,
        session_repository=session_repo,
        principal_resolver=principal_resolver,
        rbac=rbac,
        digest_service=digest_service,
        clock=clock,
        write_guard=guard,
        registry_revision=registry_revision,
    )
    context_authorization_service = ContextAuthorizationService(
        state_repository=state_repo,
        revision_repository=revision_repo,
        index_repository=index_repo,
        session_repository=session_repo,
        grant_repository=grant_repo,
        digest_service=digest_service,
        clock=clock,
        write_guard=guard,
    )
    gate = ExecutorAuthorizationGate(
        decision_repository=decision_repo,
        request_repository=request_repo,
        record_repository=record_repo,
        snapshot_repository=snapshot_repo,
        registry_repository=registry_repo,
        session_repository=session_repo,
        adapter_repository=adapter_repo,
        role_assignment_repository=role_repo,
        context_resolver=context_resolver,
        policy_engine=policy_engine,
        clock=clock,
        digest_service=digest_service,
        registry_revision=registry_revision,
    )
    return Phase0AKernel(
        database=database,
        digest_service=digest_service,
        clock=clock,
        risk_policy=risk_policy,
        remote_mcp_trust_policy_digest=remote_trust_digest,
        registry_revision=registry_revision,
        policy_version=risk_policy.policy_version,
        principal_resolver=principal_resolver,
        secret_metadata_store=secret_metadata_store,
        rbac=rbac,
        revision_repository=revision_repo,
        state_repository=state_repo,
        event_repository=event_repo,
        registry_repository=registry_repo,
        policy_repository=policy_repo,
        snapshot_repository=snapshot_repo,
        decision_repository=decision_repo,
        request_repository=request_repo,
        record_repository=record_repo,
        grant_repository=grant_repo,
        profile_repository=profile_repo,
        session_repository=session_repo,
        adapter_repository=adapter_repo,
        sandbox_repository=sandbox_repo,
        index_repository=index_repo,
        role_assignment_repository=role_repo,
        mission_manager=mission_manager,
        policy_engine=policy_engine,
        execution_authorization_service=execution_authorization_service,
        tool_availability_service=tool_availability_service,
        approval_service=approval_service,
        context_authorization_service=context_authorization_service,
        authorization_gate=gate,
        context_resolver=context_resolver,
    )
