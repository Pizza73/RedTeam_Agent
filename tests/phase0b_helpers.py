from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from redteam_agent.executor import (
    Executor,
    MockExecutionAdapter,
    MockRawResultSinkFactory,
    create_workflow_run,
)
from redteam_agent.models.execution import WorkflowRunBinding
from redteam_agent.repositories import (
    ExecutionRepository,
    ExecutionResultRepository,
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
    )
    capabilities = environment.adapter_snapshot.adapters[0]
    adapter = MockExecutionAdapter(
        capabilities=capabilities,
        now=FIXED_TIME + timedelta(minutes=3),
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
    )


def prepare_execution(harness: ExecutionHarness):
    return harness.executor.prepare(
        run=harness.run,
        plan_id=harness.environment.plan.plan_id,
        policy_decision_id=harness.kernel.decision.decision_id,
        now=FIXED_TIME + timedelta(minutes=2),
    )
