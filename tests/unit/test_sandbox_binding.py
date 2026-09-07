"""Sandbox capability binding to runtime/adapter (H-04)."""

from __future__ import annotations

import support
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.sandbox.models import SandboxRequirement
from redteam_agent.tools.availability import ToolAvailabilityInputs, resolve_available_tools
from redteam_agent.tools.models import ToolDefinition


def _sandbox_tool(adapter_id: str = "local-x") -> ToolDefinition:
    return ToolDefinition(
        tool_ref=ToolRef(tool_id="analyze", registry_revision=1),
        display_name="Analyze",
        version="1.0",
        description="analysis",
        adapter="local",
        adapter_id=adapter_id,
        provider_tool_name="analyze",
        provider_definition_revision="1",
        provider_schema_digest="sd",
        minimum_risk_level="high",
        approval_rule="policy",
        side_effect="read_only",
        idempotency="idempotent",
        parameter_schema={"type": "object"},
        output_publication_rule_id="pub",
        evidence_rule_ids=("ev",),
        action_contract_ref=ActionContractReference(contract_id="c", revision="1", digest="d"),
        target_mode="none",
        target_extractor_id="artifact_target_v1",
        default_timeout_seconds=60,
        max_timeout_seconds=120,
        max_output_bytes=1000,
        secret_argument_paths=(),
        requires_session=False,
        supported_os=frozenset({"linux"}),
        supported_architectures=frozenset({"x86_64"}),
        required_adapter_capabilities=frozenset(),
        required_session_capabilities=frozenset(),
        required_data_access_types=frozenset(),
        required_target_binding_modes=frozenset({"none"}),
        sandbox_requirement=SandboxRequirement(
            dedicated_os_user=True,
            process_isolation=True,
            container_or_namespace=True,
            filesystem_allowlist_required=True,
            network_egress_control_required=True,
            environment_allowlist_required=True,
            secret_injection_control_required=True,
            cpu_limit_required=True,
            memory_limit_required=True,
            process_limit_required=True,
        ),
    )


def _registry(ds: DigestService):
    registry, tools, _catalog = support.build_registered_registry(ds, (_sandbox_tool(),))
    return registry, tools[0]


def _local_adapter(adapter_id: str = "local-x"):
    return support.adapter_capabilities(adapter_id=adapter_id, adapter_type="local")


def _inputs(ds, registry, *, sandbox_adapter_id: str | None):
    sandboxes = {}
    if sandbox_adapter_id is not None:
        sandbox = support.sandbox_capabilities(ds, adapter_id=sandbox_adapter_id)
        sandboxes[sandbox_adapter_id] = sandbox
    return ToolAvailabilityInputs(
        registry=registry,
        adapters={"local-x": _local_adapter("local-x")},
        sandbox_capabilities=sandboxes,
        session_snapshots={},
        remote_mcp_trust_policy_digest="rmt",
    )


def test_available_when_sandbox_bound_to_its_adapter() -> None:
    ds = DigestService()
    registry, _tool = _registry(ds)
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    views = resolve_available_tools(_inputs(ds, registry, sandbox_adapter_id="local-x"), revision)
    assert len(views) == 1


def test_not_available_when_sandbox_bound_to_other_adapter() -> None:
    ds = DigestService()
    registry, _tool = _registry(ds)
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    views = resolve_available_tools(_inputs(ds, registry, sandbox_adapter_id="other-adapter"), revision)
    assert views == ()


def test_not_available_without_sandbox() -> None:
    ds = DigestService()
    registry, _tool = _registry(ds)
    revision = support.mission_revision(ds, profile=support.make_profile(ds))
    views = resolve_available_tools(_inputs(ds, registry, sandbox_adapter_id=None), revision)
    assert views == ()
