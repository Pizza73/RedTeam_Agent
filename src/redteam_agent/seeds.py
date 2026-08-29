"""Validated Phase 0A mock/seed objects; no validation bypasses or empty digests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from redteam_agent.canonical import CanonicalJsonObject, digest_model
from redteam_agent.models.capabilities import (
    AdapterCapabilities,
    RemoteMCPTrust,
    SandboxCapabilities,
    SessionSecurityContext,
)
from redteam_agent.models.common import RiskLevel, SideEffect
from redteam_agent.models.context import ContextResourceIndexRecord, ResourceBinding
from redteam_agent.models.goals import SessionExistsCondition
from redteam_agent.models.llm import MockAgentProfile
from redteam_agent.models.mission import Mission, MissionRevision, MissionRoot, MissionState
from redteam_agent.models.scope import (
    ApprovalPolicy,
    DataAccessPolicy,
    DataAccessRule,
    HostTargetReference,
    NetworkScopeRule,
    SessionScopeRule,
)
from redteam_agent.models.tools import ToolDefinition, ToolRef
from redteam_agent.tools.capability_snapshots import (
    build_adapter_snapshot,
    build_remote_trust_snapshot,
    build_sandbox_snapshot,
    build_session_snapshot,
)

UTC = timezone.utc
FIXED_TIME = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)


def mock_profile() -> MockAgentProfile:
    provisional = MockAgentProfile(
        profile_revision="mock-agent-v1",
        profile_digest="pending",
        planner_fixture_revision="planner-fixture-v1",
        analyzer_fixture_revision="analyzer-fixture-v1",
    )
    return provisional.model_copy(
        update={"profile_digest": digest_model(provisional, exclude={"profile_digest"})}
    )


def mock_mission(*, state: str = "RUNNING", revision: int = 1, epoch: int = 0) -> Mission:
    profile = mock_profile()
    return Mission(
        mission_id="mission-phase-0a",
        mission_revision=revision,
        mission_state_version=2,
        authorization_epoch=epoch,
        state=state,
        llm_profile_revision=profile.profile_revision,
        llm_profile_digest=profile.profile_digest,
        description="Authorized Phase 0A validation mission",
        authorization_reference="AUTH-TEST-001",
        authorized_by="operator-test",
        valid_from=FIXED_TIME - timedelta(hours=1),
        valid_until=FIXED_TIME + timedelta(hours=4),
        allowed_execution_scope=(
            NetworkScopeRule(type="network", cidrs=("10.0.0.0/24", "2001:db8::/64")),
            SessionScopeRule(type="session", session_id="session-1"),
        ),
        prohibited_execution_scope=(
            NetworkScopeRule(type="network", cidrs=("10.0.0.128/25",)),
        ),
        data_access_policy=DataAccessPolicy(
            allowed=(
                DataAccessRule(
                    resource_type="internal_knowledge",
                    resource_pattern="knowledge:*",
                    operations=frozenset({"read"}),
                ),
            ),
            prohibited=(),
        ),
        objectives=("Validate the authorization kernel",),
        success_conditions=(
            SessionExistsCondition(
                type="session_exists", condition_id="goal-1", host_ref="host-1"
            ),
        ),
        success_mode="all",
        max_iterations=10,
        max_runtime_minutes=30,
        max_indeterminate_retries=3,
        approval_policy=ApprovalPolicy(
            require_for_risk=frozenset({"high"}),
            require_for_side_effect=frozenset({"destructive"}),
            approval_ttl_seconds=300,
            count_approval_wait_in_runtime=False,
        ),
    )


def mission_records(mission: Mission) -> tuple[MissionRoot, MissionRevision, MissionState]:
    return (
        MissionRoot(
            mission_id=mission.mission_id,
            created_at=FIXED_TIME - timedelta(days=1),
            created_by="operator-test",
        ),
        mission.revision_record(),
        MissionState(
            mission_id=mission.mission_id,
            mission_state_version=mission.mission_state_version,
            authorization_epoch=mission.authorization_epoch,
            state=mission.state,
            updated_at=FIXED_TIME,
        ),
    )


def mock_network_tool(
    *,
    tool_id: str = "tool.network.inspect",
    revision: int = 1,
    risk: str = "read",
    approval_rule: str = "policy",
) -> ToolDefinition:
    return ToolDefinition(
        tool_ref=ToolRef(tool_id=tool_id, registry_revision=revision),
        display_name="Mock Network Inspect",
        version="1.0.0",
        description="A no-dispatch mock definition for authorization tests",
        adapter="local",
        adapter_id="mock-local-adapter",
        execution_runtime_id="mock-local-runtime",
        provider_tool_name="mock_network_inspect",
        provider_definition_revision="mock-provider-v1",
        provider_schema_digest="sha256:mock-provider-schema-v1",
        execution_location="not_applicable",
        minimum_risk_level=RiskLevel(risk),
        approval_rule=approval_rule,
        side_effect=SideEffect.READ_ONLY,
        idempotency="idempotent",
        parameter_schema=CanonicalJsonObject(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": False,
                "x-redteam-target-fields": ["target"],
            }
        ),
        target_mode="required",
        target_extractor_id="network_target_v1",
        default_timeout_seconds=10,
        max_timeout_seconds=30,
        max_output_bytes=1024,
        secret_argument_paths=(),
        requires_session=False,
        supported_os=frozenset({"linux"}),
        supported_architectures=frozenset({"x86_64"}),
        required_adapter_capabilities=frozenset({"mock_read"}),
        required_session_capabilities=frozenset(),
        required_data_access_types=frozenset(),
        sandbox_requirement=None,
    )


def mock_capability_snapshots(mission_id: str):
    session = build_session_snapshot(
        mission_id=mission_id,
        contexts=(
            SessionSecurityContext(
                session_id="session-1",
                host_id="host-1",
                os="linux",
                architecture="x86_64",
                current_principal="uid:1000",
                effective_privilege_context="uid=1000,gid=1000",
                capabilities=frozenset({"shell"}),
                network_context=("10.0.0.10",),
                status="active",
            ),
        ),
        source="mock-session-manager",
        created_at=FIXED_TIME,
    )
    adapter = build_adapter_snapshot(
        adapters=(
            AdapterCapabilities(
                adapter_type="local",
                adapter_id="mock-local-adapter",
                runtime_id="mock-local-runtime",
                capabilities=frozenset({"mock_read"}),
                provider_tool_catalog_digest="sha256:mock-catalog-v1",
                supported_os=frozenset({"linux"}),
                supported_architectures=frozenset({"x86_64"}),
                available=True,
            ),
        ),
        source="mock-adapter-manager",
        created_at=FIXED_TIME,
    )
    sandbox = build_sandbox_snapshot(
        sandboxes=(
            SandboxCapabilities(
                sandbox_id="mock-sandbox",
                runtime_id="mock-local-runtime",
                adapter_id="mock-local-adapter",
                execution_location="local_process",
                dedicated_os_user=True,
                process_isolation=True,
                container_or_namespace=True,
                filesystem_allowlist=True,
                network_egress_control=True,
                environment_allowlist=True,
                secret_injection_control=True,
                cpu_limit=True,
                memory_limit=True,
                process_limit=True,
            ),
        ),
        source="mock-sandbox-manager",
        created_at=FIXED_TIME,
    )
    remote = build_remote_trust_snapshot(
        policies=(
            RemoteMCPTrust(
                adapter_id="not_applicable",
                execution_location="not_applicable",
                stable_transport_identity=True,
                scope_enforcement=True,
                authentication_authorization=True,
                audit=True,
                network_egress_enforcement=True,
                sandbox_process_isolation=True,
            ),
        ),
        source="canonical-not-applicable",
        created_at=FIXED_TIME,
    )
    return session, adapter, sandbox, remote


def mock_context_index(mission_id: str) -> ContextResourceIndexRecord:
    return ContextResourceIndexRecord(
        index_id="index-knowledge-1-v1",
        binding=ResourceBinding(
            resource_id="knowledge:host-1",
            resource_version="1",
            resource_digest="sha256:knowledge-host-1-v1",
        ),
        resource_type="internal_knowledge",
        mission_id=mission_id,
        target_references=(HostTargetReference(type="host", host_id="host-1"),),
        verification_state="confirmed",
        observed_at=FIXED_TIME,
        classification="normal",
        size_bytes=128,
        summary_metadata=CanonicalJsonObject({"finding_type": "host_metadata"}),
    )
