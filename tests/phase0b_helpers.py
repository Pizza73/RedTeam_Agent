from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from redteam_agent.executor import (
    ExecutionAdapter,
    ExecutionAdapterRegistration,
    Executor,
    FinalizationCoordinator,
    MockExecutionAdapter,
    MockRawResultSinkFactory,
    PreDispatchCapabilityProbe,
    StaticPreDispatchCapabilityProbe,
    TrustedExecutionAdapterRegistry,
    create_workflow_run,
)
from redteam_agent.mission import MissionManager
from redteam_agent.models.execution import WorkflowRunBinding
from redteam_agent.policy.issuance import PolicyDecisionIssuanceService
from redteam_agent.policy.plans import create_execution_plan
from redteam_agent.repositories import (
    ExecutionRepository,
    ExecutionResultRepository,
    LLMProfileRepository,
    MissionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    PlanProposalRepository,
    RawResultReceiptRepository,
    RawResultRecoveryRepository,
    ResultIngestionRepository,
    WorkflowRunRepository,
)
from redteam_agent.seeds import FIXED_TIME
from redteam_agent.storage import Database

from .helpers import KernelEnvironment, PersistedKernel, build_environment, persist_environment


@dataclass
class ExecutionHarness:
    database: Database
    environment: KernelEnvironment
    kernel: PersistedKernel
    run: WorkflowRunBinding
    executor: Executor
    adapter: MockExecutionAdapter
    sink_factory: MockRawResultSinkFactory
    executions: ExecutionRepository
    receipts: RawResultReceiptRepository
    recovery: RawResultRecoveryRepository
    ingestions: ResultIngestionRepository
    results: ExecutionResultRepository
    capability_probe: PreDispatchCapabilityProbe
    finalization: FinalizationCoordinator
    adapter_registry: TrustedExecutionAdapterRegistry


def build_execution_harness(*, approval_rule: str = "policy") -> ExecutionHarness:
    database = Database()
    environment = build_environment(approval_rule=approval_rule)
    kernel = persist_environment(database, environment)
    run = create_workflow_run(
        mission_id=environment.plan.mission_id,
        mission_revision=environment.plan.mission_revision,
        run_seed="phase-0b-test-run",
        created_at=FIXED_TIME + timedelta(minutes=1),
    )
    WorkflowRunRepository(database).add(run)
    executions = ExecutionRepository(database)
    receipts = RawResultReceiptRepository(database)
    recovery = RawResultRecoveryRepository(database)
    ingestions = ResultIngestionRepository(database)
    results = ExecutionResultRepository(database)
    sink_factory = MockRawResultSinkFactory(
        now=FIXED_TIME + timedelta(minutes=3),
        max_bytes=environment.tool.max_output_bytes,
    )
    capabilities = environment.adapter_snapshot.adapters[0]
    adapter = MockExecutionAdapter(
        capabilities=capabilities,
        now=FIXED_TIME + timedelta(minutes=3),
    )
    capability_probe = StaticPreDispatchCapabilityProbe(
        session_digest=environment.session_snapshot.snapshot_digest,
        sandbox_digest=environment.sandbox_snapshot.snapshot_digest,
        remote_trust_digest=environment.remote_snapshot.snapshot_digest,
    )
    finalization = FinalizationCoordinator(
        missions=MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            LLMProfileRepository(database),
        ),
        executions=executions,
    )
    adapter_registry = TrustedExecutionAdapterRegistry(
        (
            ExecutionAdapterRegistration(
                adapter_type=capabilities.adapter_type,
                adapter_id=capabilities.adapter_id,
                adapter=adapter,
            ),
        )
    )
    executor = Executor(
        runtime_resolver=kernel.runtime_resolver,
        plans=kernel.plans,
        decisions=kernel.decisions,
        resources=kernel.resources,
        approval_requests=kernel.approval_requests,
        approvals=kernel.approvals,
        executions=executions,
        receipts=receipts,
        recovery=recovery,
        ingestions=ingestions,
        results=results,
        sink_factory=sink_factory,
        adapter_registry=adapter_registry,
        capability_probe=capability_probe,
        finalization_requester=finalization,
    )
    return ExecutionHarness(
        database=database,
        environment=environment,
        kernel=kernel,
        run=run,
        executor=executor,
        adapter=adapter,
        sink_factory=sink_factory,
        executions=executions,
        receipts=receipts,
        recovery=recovery,
        ingestions=ingestions,
        results=results,
        capability_probe=capability_probe,
        finalization=finalization,
        adapter_registry=adapter_registry,
    )


def executor_with_adapter(
    harness: ExecutionHarness,
    adapter: ExecutionAdapter,
    *,
    sink_factory: MockRawResultSinkFactory | None = None,
    capability_probe: PreDispatchCapabilityProbe | None = None,
) -> Executor:
    capabilities = harness.environment.adapter_snapshot.adapters[0]
    return Executor(
        runtime_resolver=harness.kernel.runtime_resolver,
        plans=harness.kernel.plans,
        decisions=harness.kernel.decisions,
        resources=harness.kernel.resources,
        approval_requests=harness.kernel.approval_requests,
        approvals=harness.kernel.approvals,
        executions=harness.executions,
        receipts=harness.receipts,
        recovery=harness.recovery,
        ingestions=harness.ingestions,
        results=harness.results,
        sink_factory=sink_factory or harness.sink_factory,
        adapter_registry=TrustedExecutionAdapterRegistry(
            (
                ExecutionAdapterRegistration(
                    adapter_type=capabilities.adapter_type,
                    adapter_id=capabilities.adapter_id,
                    adapter=adapter,
                ),
            )
        ),
        capability_probe=capability_probe or harness.capability_probe,
        finalization_requester=harness.finalization,
    )


def prepare_execution(harness: ExecutionHarness):
    return harness.executor.prepare(
        run=harness.run,
        plan_id=harness.environment.plan.plan_id,
        policy_decision_id=harness.kernel.decision.decision_id,
        now=FIXED_TIME + timedelta(minutes=2),
    )


def prepare_additional_execution(harness: ExecutionHarness):
    """Prepare another independently authorized action before a safety pause."""

    proposal = harness.environment.proposal.model_copy(
        update={"objective": "Inspect another in-scope mock target"}
    )
    PlanProposalRepository(harness.database).add(proposal)
    plan = create_execution_plan(
        mission=harness.environment.mission,
        proposal=proposal,
        snapshot=harness.environment.snapshot,
        created_at=FIXED_TIME + timedelta(seconds=1),
    )
    harness.kernel.plans.add(plan)
    decision = PolicyDecisionIssuanceService(
        runtime_resolver=harness.kernel.runtime_resolver,
        plans=harness.kernel.plans,
        decisions=harness.kernel.decisions,
        resources=harness.kernel.resources,
    ).issue(
        plan_id=plan.plan_id,
        issued_at=FIXED_TIME + timedelta(minutes=1),
        expires_at=FIXED_TIME + timedelta(minutes=30),
    )
    run = create_workflow_run(
        mission_id=plan.mission_id,
        mission_revision=plan.mission_revision,
        run_seed="phase-0b-additional-action",
        created_at=FIXED_TIME + timedelta(minutes=1),
    )
    WorkflowRunRepository(harness.database).add(run)
    return harness.executor.prepare(
        run=run,
        plan_id=plan.plan_id,
        policy_decision_id=decision.decision_id,
        now=FIXED_TIME + timedelta(minutes=2),
    )
