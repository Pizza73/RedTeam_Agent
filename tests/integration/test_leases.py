"""Typed collection/ingestion leases: fencing, monotonic expiry, takeover (SystemDesign §10.3)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import support_phase0c as s
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import ClockIntegrityError, LeaseError
from redteam_agent.execution.models import ProviderTaskBinding
from redteam_agent.execution.records import finalize_provider_task_binding
from redteam_agent.leases.models import LeasePolicy
from redteam_agent.leases.service import DeploymentEpochService, LeaseService
from redteam_agent.runtime.clock import ClockIntegrityGuard, ManualMonotonicClock
from redteam_agent.storage.database import Database
from redteam_agent.storage.guard import WriteGuard

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _binding(ds, execution_id="exec-1"):
    return finalize_provider_task_binding(
        ProviderTaskBinding(task_id=f"task-{execution_id}", execution_id=execution_id, adapter_identity_digest="ad",
                            provider_identity_digest="pd", provider_task_id="pt", dispatch_claim_id="c",
                            binding_digest="pending"),
        ds,
    )


def _caps() -> tuple[datetime, ...]:
    return (T0 + timedelta(days=1), T0 + timedelta(days=2))


def test_acquire_validate_and_reject_wrong_owner() -> None:
    clock = ManualMonotonicClock(T0)
    kernel = s.make_phase0c(monotonic_clock=clock)
    ds = kernel.phase0b.phase0a.digest_service
    binding = _binding(ds)
    lease = kernel.lease_service.acquire_collection_lease(
        collection_id="c1", execution_id="exec-1", authority_digest="ad", task_binding=binding, sink_id="sink-1",
        owner_id="w1", expected_execution_state_version=3, caps=_caps(),
    )
    kernel.lease_service.validate_collection_lease(
        collection_id="c1", owner_id="w1", lease_id=lease.lease_id, fence=lease.fence, authority_digest="ad",
        expected_execution_state_version=3,
    )
    with pytest.raises(LeaseError):
        kernel.lease_service.validate_collection_lease(
            collection_id="c1", owner_id="intruder", lease_id=lease.lease_id, fence=lease.fence,
            authority_digest="ad", expected_execution_state_version=3,
        )


def test_monotonic_expiry_and_takeover_increasing_fence() -> None:
    clock = ManualMonotonicClock(T0)
    kernel = s.make_phase0c(monotonic_clock=clock)
    ds = kernel.phase0b.phase0a.digest_service
    binding = _binding(ds)
    l1 = kernel.lease_service.acquire_collection_lease(
        collection_id="c1", execution_id="exec-1", authority_digest="ad", task_binding=binding, sink_id="sink-1",
        owner_id="w1", expected_execution_state_version=3, caps=_caps(),
    )
    clock.advance(seconds=61)  # past the 60s monotonic deadline
    with pytest.raises(LeaseError):
        kernel.lease_service.validate_collection_lease(
            collection_id="c1", owner_id="w1", lease_id=l1.lease_id, fence=l1.fence, authority_digest="ad",
            expected_execution_state_version=3,
        )
    l2 = kernel.lease_service.takeover_collection_lease(
        collection_id="c1", execution_id="exec-1", authority_digest="ad", task_binding=binding, sink_id="sink-1",
        new_owner_id="w2", expected_execution_state_version=3, caps=(T0 + timedelta(days=1), T0 + timedelta(days=2)),
    )
    assert l2.fence.fencing_token > l1.fence.fencing_token
    # The stale old-fence writer is now rejected; the new owner validates.
    with pytest.raises(LeaseError):
        kernel.lease_service.validate_collection_lease(
            collection_id="c1", owner_id="w1", lease_id=l1.lease_id, fence=l1.fence, authority_digest="ad",
            expected_execution_state_version=3,
        )
    kernel.lease_service.validate_collection_lease(
        collection_id="c1", owner_id="w2", lease_id=l2.lease_id, fence=l2.fence, authority_digest="ad",
        expected_execution_state_version=3,
    )


def test_cannot_take_over_a_live_lease() -> None:
    kernel = s.make_phase0c()
    ds = kernel.phase0b.phase0a.digest_service
    binding = _binding(ds)
    kernel.lease_service.acquire_collection_lease(
        collection_id="c1", execution_id="exec-1", authority_digest="ad", task_binding=binding, sink_id="sink-1",
        owner_id="w1", expected_execution_state_version=3, caps=_caps(),
    )
    with pytest.raises(LeaseError):
        kernel.lease_service.takeover_collection_lease(
            collection_id="c1", execution_id="exec-1", authority_digest="ad", task_binding=binding, sink_id="sink-1",
            new_owner_id="w2", expected_execution_state_version=3, caps=_caps(),
        )


def test_utc_rollback_stops_lease_validation() -> None:
    clock = ManualMonotonicClock(T0)
    kernel = s.make_phase0c(monotonic_clock=clock)
    ds = kernel.phase0b.phase0a.digest_service
    binding = _binding(ds)
    lease = kernel.lease_service.acquire_collection_lease(
        collection_id="c1", execution_id="exec-1", authority_digest="ad", task_binding=binding, sink_id="sink-1",
        owner_id="w1", expected_execution_state_version=3, caps=_caps(),
    )
    clock.advance(seconds=5)
    kernel.clock_guard.read()  # establish a high-water mark
    clock.set(utc=T0 - timedelta(hours=1))  # roll UTC back below the mark
    with pytest.raises(ClockIntegrityError):
        kernel.lease_service.validate_collection_lease(
            collection_id="c1", owner_id="w1", lease_id=lease.lease_id, fence=lease.fence, authority_digest="ad",
            expected_execution_state_version=3,
        )


def test_authority_and_state_version_mismatch_rejected() -> None:
    kernel = s.make_phase0c()
    ds = kernel.phase0b.phase0a.digest_service
    binding = _binding(ds)
    lease = kernel.lease_service.acquire_collection_lease(
        collection_id="c1", execution_id="exec-1", authority_digest="ad", task_binding=binding, sink_id="sink-1",
        owner_id="w1", expected_execution_state_version=3, caps=_caps(),
    )
    with pytest.raises(LeaseError):
        kernel.lease_service.validate_collection_lease(
            collection_id="c1", owner_id="w1", lease_id=lease.lease_id, fence=lease.fence,
            authority_digest="WRONG", expected_execution_state_version=3,
        )
    with pytest.raises(LeaseError):
        kernel.lease_service.validate_collection_lease(
            collection_id="c1", owner_id="w1", lease_id=lease.lease_id, fence=lease.fence,
            authority_digest="ad", expected_execution_state_version=99,
        )


def test_concurrent_acquire_has_exactly_one_live_owner(tmp_path: Path) -> None:
    path = str(tmp_path / "leases.sqlite")
    setup_db = Database(path)
    setup_ds = DigestService()
    setup_guard = WriteGuard()
    epoch = DeploymentEpochService(setup_db, setup_ds, setup_guard)
    epoch.establish(
        guard=setup_guard, trust_epoch=1, deployment_epoch=1,
        nv_identity_digest="nv-id", provider_identity="test",
        established_at_iso="2026-01-15T12:00:00Z",
    )
    setup_db.close()
    binding = _binding(setup_ds)
    barrier = threading.Barrier(2)
    results: list[str] = []

    def acquire(owner: str) -> None:
        db = Database(path, create_schema=False)
        ds = DigestService()
        guard = WriteGuard()
        local_epoch = DeploymentEpochService(db, ds, guard)
        leases = LeaseService(
            database=db, digest_service=ds,
            clock_guard=ClockIntegrityGuard(ManualMonotonicClock(T0)),
            epoch_service=local_epoch, anchor_verifier=lambda: local_epoch.current(),
            write_guard=guard, policy=LeasePolicy(),
        )
        barrier.wait()
        try:
            leases.acquire_collection_lease(
                collection_id="concurrent", execution_id="exec-1", authority_digest="ad",
                task_binding=binding, sink_id="sink", owner_id=owner,
                expected_execution_state_version=3, caps=_caps(),
            )
        except LeaseError:
            results.append("rejected")
        else:
            results.append(owner)
        finally:
            db.close()

    threads = [threading.Thread(target=acquire, args=(owner,)) for owner in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results).count("rejected") == 1
    assert len(results) == 2
