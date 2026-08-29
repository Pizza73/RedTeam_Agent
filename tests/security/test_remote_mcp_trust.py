from __future__ import annotations

from redteam_agent.models.capabilities import AdapterCapabilities, RemoteMCPTrust
from redteam_agent.models.common import RiskLevel
from redteam_agent.models.tools import SandboxRequirement, ToolDefinition
from redteam_agent.seeds import FIXED_TIME, mock_capability_snapshots, mock_mission, mock_network_tool
from redteam_agent.tools import ToolAvailabilityResolver, TrustedTargetExtractorRegistry, build_registry_revision
from redteam_agent.tools.capability_snapshots import build_adapter_snapshot, build_remote_trust_snapshot


def remote_tool() -> ToolDefinition:
    data = mock_network_tool().model_dump(mode="python")
    data.update(
        {
            "adapter": "mcp",
            "adapter_id": "remote-mcp-1",
            "execution_runtime_id": "remote-mcp-runtime-1",
            "execution_location": "untrusted_remote",
            "minimum_risk_level": RiskLevel.HIGH,
            "sandbox_requirement": SandboxRequirement(
                dedicated_os_user=False,
                process_isolation=False,
                container_or_namespace=False,
                filesystem_allowlist_required=False,
                network_egress_control_required=False,
                environment_allowlist_required=False,
                secret_injection_control_required=False,
                cpu_limit_required=False,
                memory_limit_required=False,
                process_limit_required=False,
            ),
        }
    )
    return ToolDefinition.model_validate(data)


def calculate_for(trust: RemoteMCPTrust):
    mission = mock_mission()
    session, _, sandbox, _ = mock_capability_snapshots(mission.mission_id)
    tool = remote_tool()
    extractors = TrustedTargetExtractorRegistry()
    registry = build_registry_revision(
        registry_revision=1, tools=(tool,), created_at=FIXED_TIME, extractors=extractors
    )
    adapter = build_adapter_snapshot(
        adapters=(
            AdapterCapabilities(
                adapter_type="mcp",
                adapter_id="remote-mcp-1",
                runtime_id="remote-mcp-runtime-1",
                capabilities=frozenset({"mock_read"}),
                provider_tool_catalog_digest="sha256:remote-catalog",
                supported_os=frozenset({"linux"}),
                supported_architectures=frozenset({"x86_64"}),
                available=True,
            ),
        ),
        source="mock-mcp-capability",
        created_at=FIXED_TIME,
    )
    remote = build_remote_trust_snapshot(
        policies=(trust,), source="mock-remote-trust", created_at=FIXED_TIME
    )
    return ToolAvailabilityResolver(extractors).calculate(
        mission=mission,
        registry=registry,
        session_snapshot=session,
        adapter_snapshot=adapter,
        sandbox_snapshot=sandbox,
        remote_trust_snapshot=remote,
        policy_version="policy-v1",
    )


def test_untrusted_remote_high_risk_tool_is_default_denied() -> None:
    trust = RemoteMCPTrust(
        adapter_id="remote-mcp-1",
        execution_location="untrusted_remote",
        stable_transport_identity=True,
        scope_enforcement=True,
        authentication_authorization=True,
        audit=True,
        network_egress_enforcement=True,
        sandbox_process_isolation=True,
        explicitly_allowed_read_only=True,
    )
    assert calculate_for(trust).tools == ()


def test_managed_remote_missing_enforcement_is_unavailable() -> None:
    tool = remote_tool().model_copy(update={"execution_location": "managed_remote"})
    # The helper uses an untrusted location tool, so directly prove the trust predicate too.
    trust = RemoteMCPTrust(
        adapter_id="remote-mcp-1",
        execution_location="managed_remote",
        stable_transport_identity=True,
        scope_enforcement=False,
        authentication_authorization=True,
        audit=True,
        network_egress_enforcement=True,
        sandbox_process_isolation=True,
    )
    assert not ToolAvailabilityResolver._remote_trust_satisfies(
        tool,
        build_remote_trust_snapshot(
            policies=(trust,), source="mock", created_at=FIXED_TIME
        ),
    )
