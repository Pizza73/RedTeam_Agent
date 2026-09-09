"""Phase 0B test/local composition root (execution safety).

Extends the Phase 0A authorization kernel with the durable execution-safety layer:
execution/dispatch-claim/result-collection/result-ingestion repositories, the mock
execution adapter behind a fixed trusted dispatch port, the executor-owned secret
dispatch transaction, the reconciliation service and the result collection
coordinator. There is still no production encryption, TPM or real adapter, and no
caller-supplied secret, clock, sink, adapter, broker, channel or callback.

The execution-safety repositories share one composition-issued write guard
(distinct from the Phase 0A guard); it is bound here once and held only by the
execution services, so a caller holding a repository reference cannot forge a
write.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.composition.testing import DEFAULT_REGISTRY_REVISION, Phase0AKernel, build_test_kernel
from redteam_agent.execution.adapter import MockExecutionAdapter
from redteam_agent.execution.budget import MissionExecutionBudgetService
from redteam_agent.execution.collection import ResultCollectionCoordinator
from redteam_agent.execution.dispatch_port import FixedTrustedAdapterDispatchPort
from redteam_agent.execution.executor import Executor
from redteam_agent.execution.ingestion import ResultIngestionCoordinator
from redteam_agent.execution.models import SecureIngestionRetryPolicy
from redteam_agent.execution.reconcile import ReconciliationService
from redteam_agent.execution.recovery import ExecutionRecoveryService
from redteam_agent.execution.secret_source import StaticTrustedSecretSource
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.execution_repositories import (
    CancelAttemptRepository,
    DispatchClaimRepository,
    ExecutionRecordRepository,
    ExecutionRecoveryAuthorityRepository,
    ExecutionResultProjectionRepository,
    ExecutionResultRepository,
    MissionExecutionBudgetRepository,
    RawControlMetadataRepository,
    ResultCollectionAuthorityRepository,
    ResultCollectionStateRepository,
    ResultIngestionStateRepository,
    ResultTaskBindingRepository,
)
from redteam_agent.storage.guard import WriteGuard

# The Phase 0A test tool's fixed adapter id (see tests.support.ADAPTER_ID).
DEFAULT_ADAPTER_ID = "c2-main"
DEFAULT_QUARANTINE_RETENTION_SECONDS = 14 * 24 * 3600
DEFAULT_SYSTEM_HARD_OUTPUT_CAP = 8 * 1024 * 1024


@dataclass
class Phase0BKernel:
    phase0a: Phase0AKernel
    execution_guard: WriteGuard
    mock_adapter: MockExecutionAdapter
    _secret_source: StaticTrustedSecretSource
    # repositories
    execution_repository: ExecutionRecordRepository
    claim_repository: DispatchClaimRepository
    task_binding_repository: ResultTaskBindingRepository
    collection_authority_repository: ResultCollectionAuthorityRepository
    collection_state_repository: ResultCollectionStateRepository
    control_metadata_repository: RawControlMetadataRepository
    ingestion_repository: ResultIngestionStateRepository
    projection_repository: ExecutionResultProjectionRepository
    result_repository: ExecutionResultRepository
    recovery_authority_repository: ExecutionRecoveryAuthorityRepository
    cancel_attempt_repository: CancelAttemptRepository
    budget_repository: MissionExecutionBudgetRepository
    # services
    executor: Executor
    reconciliation: ReconciliationService
    collection_coordinator: ResultCollectionCoordinator
    ingestion_coordinator: ResultIngestionCoordinator
    recovery_service: ExecutionRecoveryService
    budget_service: MissionExecutionBudgetService
    retry_policy: SecureIngestionRetryPolicy

    def seed_secret_for_test(self, secret_version_id: str, value: bytes) -> None:
        """Seed the private test source without exporting a plaintext resolver."""
        self._secret_source.put(secret_version_id, value)


def build_phase0b_kernel(
    *,
    db_path: str = ":memory:",
    registry_revision: int = DEFAULT_REGISTRY_REVISION,
    clock: Clock | None = None,
    adapter_id: str = DEFAULT_ADAPTER_ID,
    result_delivery_mode: str = "provider_task",
    phase0a: Phase0AKernel | None = None,
    mock_adapter: MockExecutionAdapter | None = None,
) -> Phase0BKernel:
    kernel = phase0a if phase0a is not None else build_test_kernel(
        db_path=db_path, registry_revision=registry_revision, clock=clock
    )
    database = kernel.database
    ds = kernel.digest_service
    exec_guard = WriteGuard()

    execution_repo = ExecutionRecordRepository(database, ds)
    claim_repo = DispatchClaimRepository(database, ds)
    binding_repo = ResultTaskBindingRepository(database, ds)
    coll_auth_repo = ResultCollectionAuthorityRepository(database, ds)
    coll_state_repo = ResultCollectionStateRepository(database, ds)
    control_repo = RawControlMetadataRepository(database, ds)
    ingestion_repo = ResultIngestionStateRepository(database, ds)
    projection_repo = ExecutionResultProjectionRepository(database, ds)
    result_repo = ExecutionResultRepository(database, ds)
    recovery_repo = ExecutionRecoveryAuthorityRepository(database, ds)
    cancel_repo = CancelAttemptRepository(database, ds)
    budget_repo = MissionExecutionBudgetRepository(database, ds)

    for repo in (
        execution_repo, claim_repo, binding_repo, coll_auth_repo, coll_state_repo, control_repo,
        ingestion_repo, projection_repo, result_repo, recovery_repo, cancel_repo, budget_repo,
    ):
        repo.bind_owner(exec_guard)

    adapter = mock_adapter if mock_adapter is not None else MockExecutionAdapter(
        adapter_id=adapter_id,
        result_delivery_mode=result_delivery_mode,  # type: ignore[arg-type]
        clock_value=kernel.clock.now(),
    )
    adapters = {adapter_id: adapter}
    secret_source = StaticTrustedSecretSource()
    dispatch_port = FixedTrustedAdapterDispatchPort(adapters)

    collection_coordinator = ResultCollectionCoordinator(
        database=database, execution_repository=execution_repo, authority_repository=coll_auth_repo,
        state_repository=coll_state_repo, control_metadata_repository=control_repo,
        ingestion_repository=ingestion_repo, task_binding_repository=binding_repo,
        recovery_repository=recovery_repo,
        registry_repository=kernel.registry_repository, context_resolver=kernel.context_resolver,
        adapters=adapters, clock=kernel.clock, digest_service=ds, write_guard=exec_guard,
        registry_revision=registry_revision,
        quarantine_retention_seconds=DEFAULT_QUARANTINE_RETENTION_SECONDS,
        system_hard_output_cap=DEFAULT_SYSTEM_HARD_OUTPUT_CAP,
    )
    reconciliation = ReconciliationService(
        database=database, execution_repository=execution_repo, task_binding_repository=binding_repo,
        recovery_repository=recovery_repo, context_resolver=kernel.context_resolver,
        adapters=adapters,
        local_result_reconciler=lambda execution_id: collection_coordinator.collect(
            execution_id=execution_id
        ),
        clock=kernel.clock, digest_service=ds, write_guard=exec_guard,
    )
    retry_policy = SecureIngestionRetryPolicy(policy_revision="secure-ingestion-retry-v1", max_attempts_per_ingestion=3)
    ingestion_coordinator = ResultIngestionCoordinator(
        database=database, ingestion_repository=ingestion_repo, projection_repository=projection_repo,
        result_repository=result_repo, control_metadata_repository=control_repo,
        task_binding_repository=binding_repo, execution_repository=execution_repo, clock=kernel.clock,
        digest_service=ds, write_guard=exec_guard, retry_policy=retry_policy,
    )
    recovery_service = ExecutionRecoveryService(
        database=database, execution_repository=execution_repo, recovery_repository=recovery_repo,
        task_binding_repository=binding_repo, cancel_repository=cancel_repo,
        context_resolver=kernel.context_resolver, adapters=adapters, clock=kernel.clock,
        digest_service=ds, write_guard=exec_guard,
    )
    budget_service = MissionExecutionBudgetService(
        database=database, repository=budget_repo, clock=kernel.clock, digest_service=ds, write_guard=exec_guard,
    )
    executor = Executor(
        database=database, gate=kernel.authorization_gate, execution_repository=execution_repo,
        claim_repository=claim_repo, task_binding_repository=binding_repo,
        decision_repository=kernel.decision_repository, request_repository=kernel.request_repository,
        record_repository=kernel.record_repository, registry_repository=kernel.registry_repository,
        secret_metadata_reader=kernel.secret_metadata_store, secret_source=secret_source,
        dispatch_port=dispatch_port, reconciliation=reconciliation,
        collection_coordinator=collection_coordinator, budget_service=budget_service,
        clock=kernel.clock, digest_service=ds, write_guard=exec_guard,
        registry_revision=registry_revision,
    )
    return Phase0BKernel(
        phase0a=kernel,
        execution_guard=exec_guard,
        mock_adapter=adapter,
        _secret_source=secret_source,
        execution_repository=execution_repo,
        claim_repository=claim_repo,
        task_binding_repository=binding_repo,
        collection_authority_repository=coll_auth_repo,
        collection_state_repository=coll_state_repo,
        control_metadata_repository=control_repo,
        ingestion_repository=ingestion_repo,
        projection_repository=projection_repo,
        result_repository=result_repo,
        recovery_authority_repository=recovery_repo,
        cancel_attempt_repository=cancel_repo,
        budget_repository=budget_repo,
        executor=executor,
        reconciliation=reconciliation,
        collection_coordinator=collection_coordinator,
        ingestion_coordinator=ingestion_coordinator,
        recovery_service=recovery_service,
        budget_service=budget_service,
        retry_policy=retry_policy,
    )
