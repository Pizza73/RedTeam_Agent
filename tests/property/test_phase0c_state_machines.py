"""Property / state-machine evidence for Phase 0C stateful families (SystemDesign §37.1).

Covered: lease timing/fencing, authenticated generation (crash/recovery), and
ingestion/erasure/result recovery idempotency. Oracles are independent of the product
edge tables so the comparison is not tautological.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.generation_store import GenerationRecordStore, InMemoryRecordAuthenticationKey
from redteam_agent.canonical.digest_catalog import CATALOG_REVISION
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LeaseError
from redteam_agent.execution.models import ProviderTaskBinding
from redteam_agent.execution.records import finalize_provider_task_binding
from redteam_agent.leases.models import LeasePolicy
from redteam_agent.leases.service import DeploymentEpochService, LeaseService

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


class LeaseFencingMachine(RuleBasedStateMachine):
    """Fence tokens strictly increase across takeovers; a stale fence never validates."""

    def __init__(self) -> None:
        super().__init__()
        from redteam_agent.runtime.clock import ClockIntegrityGuard, ManualMonotonicClock
        from redteam_agent.storage.database import Database
        from redteam_agent.storage.guard import WriteGuard

        ds = DigestService()
        db = Database(":memory:")
        guard = WriteGuard()
        self._clock = ManualMonotonicClock(T0)
        epoch = DeploymentEpochService(db, ds, guard)
        epoch.establish(guard=guard, trust_epoch=1, deployment_epoch=7, nv_identity_digest="id",
                        provider_identity="tpm2_nv", established_at_iso="2026-01-15T12:00:00Z")
        self._leases = LeaseService(database=db, digest_service=ds, clock_guard=ClockIntegrityGuard(self._clock),
                                    epoch_service=epoch, anchor_verifier=lambda: epoch.current(),
                                    write_guard=guard, policy=LeasePolicy())
        self._binding = finalize_provider_task_binding(
            ProviderTaskBinding(task_id="t", execution_id="e", adapter_identity_digest="a",
                                provider_identity_digest="p", provider_task_id="pt", dispatch_claim_id="c",
                                binding_digest="pending"), ds)
        self._caps = (T0 + timedelta(days=30), T0 + timedelta(days=30))
        self._owner_seq = 0
        self._current = None  # type: ignore[var-annotated]
        self._stale: list[tuple[str, object]] = []
        self._max_token = 0

    def _acquire(self) -> None:
        self._owner_seq += 1
        owner = f"w{self._owner_seq}"
        lease = self._leases.takeover_collection_lease(
            collection_id="c1", execution_id="e", authority_digest="ad", task_binding=self._binding,
            sink_id="s1", new_owner_id=owner, expected_execution_state_version=1, caps=self._caps,
        )
        assert lease.fence.fencing_token > self._max_token
        self._max_token = lease.fence.fencing_token
        if self._current is not None:
            self._stale.append(self._current)
        self._current = (owner, lease)

    @rule()
    def acquire_or_takeover(self) -> None:
        if self._current is None:
            self._acquire()
            return
        owner, lease = self._current
        expired = self._clock.read().monotonic_ns >= lease.lease_deadline_monotonic_ns
        if expired:
            self._acquire()

    @rule()
    def advance(self) -> None:
        self._clock.advance(seconds=25)

    @invariant()
    def stale_never_validates(self) -> None:
        for owner, lease in self._stale:
            with pytest.raises(LeaseError):
                self._leases.validate_collection_lease(
                    collection_id="c1", owner_id=owner, lease_id=lease.lease_id, fence=lease.fence,  # type: ignore[attr-defined]
                    authority_digest="ad", expected_execution_state_version=1,
                )

    @invariant()
    def live_owner_validates_when_unexpired(self) -> None:
        if self._current is None:
            return
        owner, lease = self._current
        if self._clock.read().monotonic_ns < lease.lease_deadline_monotonic_ns:
            self._leases.validate_collection_lease(
                collection_id="c1", owner_id=owner, lease_id=lease.lease_id, fence=lease.fence,
                authority_digest="ad", expected_execution_state_version=1,
            )


class GenerationCommitMachine(RuleBasedStateMachine):
    """current() always resolves the latest fully-committed generation content."""

    def __init__(self) -> None:
        super().__init__()
        from redteam_agent.audit.nv_witness import InMemoryNvExtendWitness
        from redteam_agent.storage.database import Database

        ds = DigestService()
        self._db = Database(":memory:")
        self._witness = InMemoryNvExtendWitness(digest_service=ds)
        self._store = GenerationRecordStore(self._db, ds, InMemoryRecordAuthenticationKey(b"k" * 32))
        self._ds = ds
        self._coordinator = self._new_coordinator()
        self._committed_gen = -1
        self._op = 0
        genesis = self._coordinator.genesis("audit_head", initial_state_digest="s0", initial_content="c0")
        self._committed_gen = genesis.generation

    def _new_coordinator(self, fault: object | None = None) -> AuthenticatedGenerationCoordinator:
        return AuthenticatedGenerationCoordinator(
            database=self._db, witness=self._witness, record_store=self._store, digest_service=self._ds,
            digest_catalog_revision=CATALOG_REVISION,
            fault_injector=fault,  # type: ignore[arg-type]
        )

    @rule()
    def commit(self) -> None:
        self._op += 1
        record = self._coordinator.commit("audit_head", new_state_digest=f"s{self._op}",
                                          new_content=f"c{self._op}", operation_id=f"op-{self._op}")
        self._committed_gen = record.generation

    @rule()
    def crash_commit_then_recover(self) -> None:
        from redteam_agent.storage.unit_of_work import ArmedFaultInjector, CommitBoundaryFault

        self._op += 1
        faulted = self._new_coordinator(ArmedFaultInjector("before_extend"))
        try:
            faulted.commit("audit_head", new_state_digest=f"s{self._op}", new_content=f"c{self._op}",
                           operation_id=f"op-{self._op}")
        except CommitBoundaryFault:
            pass
        # A clean coordinator completes the interrupted commit deterministically.
        record = self._coordinator.commit("audit_head", new_state_digest=f"s{self._op}",
                                          new_content=f"c{self._op}", operation_id=f"op-{self._op}")
        self._committed_gen = record.generation

    @invariant()
    def current_matches_committed(self) -> None:
        current = self._coordinator.current("audit_head")
        assert current is not None and current.generation == self._committed_gen


class IngestionErasureRecoveryMachine(RuleBasedStateMachine):
    """Repeated ingest/erase calls converge idempotently to a materialized result."""

    def __init__(self) -> None:
        super().__init__()
        import support_phase0c as s

        self._s = s
        self._kernel = s.make_phase0c()
        d = s.seed_dispatched(self._kernel)
        self._execution_id = d.execution_id
        self._ingestion_id = s.collect(self._kernel, execution_id=d.execution_id)
        self._deletion_intent_id: str | None = None
        self._erased = False

    @rule()
    def ingest(self) -> None:
        outcome = self._kernel.ingestion_service.ingest(ingestion_id=self._ingestion_id)
        assert outcome.status in ("DELETE_PENDING", "SUCCEEDED")
        if outcome.deletion_intent_id is not None:
            self._deletion_intent_id = outcome.deletion_intent_id

    @precondition(lambda self: self._deletion_intent_id is not None)
    @rule()
    def erase(self) -> None:
        outcome = self._kernel.eraser.run(deletion_intent_id=self._deletion_intent_id)
        assert outcome.ingestion_status in ("QUARANTINE_ERASED", "SUCCEEDED")
        self._erased = True

    @invariant()
    def result_present_after_erasure(self) -> None:
        if self._erased:
            assert self._kernel.phase0b.result_repository.get(self._execution_id) is not None


LeaseFencingMachine.TestCase.settings = settings(max_examples=25, deadline=None, stateful_step_count=12)
GenerationCommitMachine.TestCase.settings = settings(max_examples=25, deadline=None, stateful_step_count=12)
IngestionErasureRecoveryMachine.TestCase.settings = settings(max_examples=10, deadline=None, stateful_step_count=8)

TestLeaseFencing = LeaseFencingMachine.TestCase
TestGenerationCommit = GenerationCommitMachine.TestCase
TestIngestionErasureRecovery = IngestionErasureRecoveryMachine.TestCase
