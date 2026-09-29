"""Reusable builders for Phase 0B execution-safety tests.

These helpers seed a RUNNING mission through the real Phase 0A services, issue a
real PolicyDecision, and drive the executor to AUTHORIZED, so tests exercise the
public entry points and then perturb one input to assert a fail-closed behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import support
from redteam_agent.composition.execution_testing import Phase0BKernel, build_phase0b_kernel
from redteam_agent.composition.testing import Phase0AKernel
from redteam_agent.plan.models import ExecutionPlan
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.tools.models import ToolDefinition

SECRET_VALUE = b"s3cr3t-value-xyz"  # 16 bytes; length is the only non-secret metadata asserted


@dataclass
class SeededExecution:
    kernel: Phase0BKernel
    phase0a: Phase0AKernel
    seeded: support.SeededMission
    plan: ExecutionPlan
    decision: PolicyDecision
    execution_id: str


def make_kernel(*, result_delivery_mode: str = "provider_task", **adapter_kwargs: Any) -> Phase0BKernel:
    clock = ManualClock(support.T0)
    if adapter_kwargs:
        from redteam_agent.execution.adapter import MockExecutionAdapter

        adapter = MockExecutionAdapter(
            adapter_id="c2-main", result_delivery_mode=result_delivery_mode,  # type: ignore[arg-type]
            clock_value=support.T0, **adapter_kwargs,
        )
        return build_phase0b_kernel(clock=clock, result_delivery_mode=result_delivery_mode, mock_adapter=adapter)
    return build_phase0b_kernel(clock=clock, result_delivery_mode=result_delivery_mode)


def seed_authorized(
    kernel: Phase0BKernel,
    *,
    tool: ToolDefinition | None = None,
    with_secret: bool = False,
    require_for_side_effect: frozenset[str] = frozenset(),
    require_for_risk: frozenset[str] = frozenset(),
    side_effect: str = "read_only",
    minimum_risk: str = "low",
    execution_id: str = "exec-1",
    register_secret: bool = True,
    seed_budget: bool = True,
) -> SeededExecution:
    phase0a = kernel.phase0a
    ds = phase0a.digest_service
    secret_paths = ("/credential",) if with_secret else ()
    tool = tool if tool is not None else support.network_tool(
        secret_paths=secret_paths, side_effect=side_effect, minimum_risk=minimum_risk,
    )
    data_access = support.secret_data_access_policy() if with_secret else None
    revision = support.mission_revision(
        ds, profile=support.make_profile(ds), data_access_policy=data_access,
        require_for_side_effect=require_for_side_effect, require_for_risk=require_for_risk,
    )
    if with_secret and register_secret:
        phase0a.secret_metadata_store.put(support.confirmed_secret_metadata(ds, version_id="sv-1"))
        kernel.seed_secret_for_test("sv-1", SECRET_VALUE)
    adapter_capability = support.adapter_capabilities()
    if tool.adapter == "local":
        adapter_capability = adapter_capability.model_copy(
            update={"adapter_type": "local", "result_delivery_mode": "local_result"}
        )
    seeded = support.seed_running_mission(
        kernel.phase0a, tool=tool, revision=revision, adapter_capability=adapter_capability
    )
    if seed_budget:
        kernel.budget_service.create_budget(
            mission_id=revision.mission_id,
            mission_revision=revision.mission_revision,
            max_dispatch_claims=revision.max_iterations,
        )
    arguments: dict[str, Any] = {"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"}
    if with_secret:
        arguments["credential"] = support.secret_reference("sv-1")
    proposal = support.make_proposal(tool=seeded.tool, arguments=arguments)
    plan = support.make_plan(kernel.phase0a, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel.phase0a, plan=plan)
    return SeededExecution(
        kernel=kernel, phase0a=phase0a, seeded=seeded, plan=plan, decision=decision, execution_id=execution_id
    )


def authorize(seeded: SeededExecution) -> None:
    seeded.kernel.executor.create_execution(
        execution_id=seeded.execution_id, task_id=f"task-{seeded.execution_id}",
        decision_id=seeded.decision.decision_id, plan=seeded.plan,
    )


def build_execution_record(kernel: Phase0BKernel, *, execution_id: str, decision_id: str) -> Any:
    """Construct a valid, digest-finalized AUTHORIZED execution record for tests."""
    from redteam_agent.execution.models import ExecutionRecord
    from redteam_agent.execution.records import finalize_object_digest
    from redteam_agent.models.common import ToolRef

    record = ExecutionRecord(
        execution_id=execution_id, task_id=f"task-{execution_id}", execution_state_version=1, record_digest="pending",
        mission_id="mission-1", mission_revision=1, authorization_epoch=0, plan_id="plan-1",
        policy_decision_id=decision_id, proposal_digest="pd", authorization_digest="ad",
        tool_ref=ToolRef(tool_id="net-scan", registry_revision=1), resolved_adapter_id="c2-main",
        idempotency_key="ik", adapter_capabilities_digest="acd", sandbox_capabilities_digest="scd",
        remote_mcp_trust_policy_digest="rmtd", provider_execution_state="AUTHORIZED",
        pre_dispatch_block_reason=None, result_collection_state_id=None, result_ingestion_state="NOT_AVAILABLE",
        raw_result_quarantine_id=None, result_task_binding_id=None, dispatch_attempts=0,
        created_at=support.T0, updated_at=support.T0,
    )
    return finalize_object_digest(
        record, digest_field="record_digest", digest_name="execution_record_digest",
        digest_service=kernel.phase0a.digest_service,
    )
