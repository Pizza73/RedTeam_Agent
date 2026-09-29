"""Verified erasure crash boundaries + local retention scheduler (SystemDesign §10.3 / §33.2)."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
import support_phase0c as s
from redteam_agent.erasure.service import VerifiedQuarantineEraser
from redteam_agent.errors import VerifiedErasureError
from redteam_agent.execution.models import ProviderTaskBinding
from redteam_agent.execution.records import finalize_provider_task_binding
from redteam_agent.storage.unit_of_work import (
    ApplicationUnitOfWork,
    ArmedFaultInjector,
    CommitBoundaryFault,
    compute_input_digest,
)


def _published(kernel, execution_id="exec-1"):
    d = s.seed_dispatched(kernel, execution_id=execution_id)
    ingestion_id = s.collect(kernel, execution_id=execution_id)
    return d, kernel.ingestion_service.ingest(ingestion_id=ingestion_id)


def test_reconcile_first_then_destroy_then_readback_unlink() -> None:
    kernel = s.make_phase0c()
    _d, published = _published(kernel)
    erased = kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)
    assert erased.key_destruction_state == "CONFIRMED" and erased.ciphertext_unlinked
    # A second reconcile of the same erasure_id returns CONFIRMED (no second destroy).
    ds = kernel.phase0b.phase0a.digest_service
    enc = kernel.collection_service._quarantine.encryption_metadata(f"q-{_d.execution_id}")
    inventory = ds.compute("copy_inventory_digest", {"quarantine_id": f"q-{_d.execution_id}", "class": "encrypted_blob"})
    r = kernel.eraser._keys.reconcile_resource_key_destruction(
        erasure_id=f"erasure-{published.deletion_intent_id}", metadata=enc,
        key_metadata_digest=enc.metadata_digest, resource_copy_inventory_digest=inventory,
    )
    assert r.state == "CONFIRMED"


def test_crash_after_claim_before_key_destroy_reconciles() -> None:
    kernel = s.make_phase0c()
    _d, published = _published(kernel)
    faulted = VerifiedQuarantineEraser(
        database=kernel.phase0b.phase0a.database, digest_service=kernel.phase0b.phase0a.digest_service,
        clock=kernel.monotonic_clock, exec_guard=kernel.phase0b.execution_guard,
        ingestion_repository=kernel.phase0b.ingestion_repository, execution_repository=kernel.phase0b.execution_repository,
        projection_repository=kernel.phase0b.projection_repository, result_repository=kernel.phase0b.result_repository,
        quarantine_store=kernel.collection_service._quarantine, key_provider=kernel.eraser._keys, audit_store=kernel.audit_store,
        fault_injector=ArmedFaultInjector("after_reconcile"),
    )
    with pytest.raises(CommitBoundaryFault):
        faulted.run(deletion_intent_id=published.deletion_intent_id)
    # The claim committed (DELETE_PENDING -> ERASURE_CLAIMED) but the key was not destroyed;
    # a clean eraser completes it with the same erasure_id.
    erased = kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)
    assert erased.ingestion_status == "SUCCEEDED" and erased.key_destruction_state == "CONFIRMED"


def test_unknown_reconciliation_holds_ciphertext_and_never_retries_destroy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = s.make_phase0c()
    dispatched, published = _published(kernel)
    faulted = VerifiedQuarantineEraser(
        database=kernel.phase0b.phase0a.database, digest_service=kernel.phase0b.phase0a.digest_service,
        clock=kernel.monotonic_clock, exec_guard=kernel.phase0b.execution_guard,
        ingestion_repository=kernel.phase0b.ingestion_repository,
        execution_repository=kernel.phase0b.execution_repository,
        projection_repository=kernel.phase0b.projection_repository,
        result_repository=kernel.phase0b.result_repository,
        quarantine_store=kernel.collection_service._quarantine, key_provider=kernel.eraser._keys,
        audit_store=kernel.audit_store, fault_injector=ArmedFaultInjector("after_reconcile"),
    )
    with pytest.raises(CommitBoundaryFault):
        faulted.run(deletion_intent_id=published.deletion_intent_id)
    quarantine_id = f"q-{dispatched.execution_id}"
    assert kernel.collection_service._quarantine.ciphertext_handles(quarantine_id)
    original = kernel.eraser._keys.reconcile_resource_key_destruction
    not_started = original(
        erasure_id=f"erasure-{published.deletion_intent_id}",
        metadata=kernel.collection_service._quarantine.encryption_metadata(quarantine_id),
        key_metadata_digest=kernel.collection_service._quarantine.encryption_key_metadata_digest(quarantine_id),
        resource_copy_inventory_digest=kernel.phase0b.phase0a.digest_service.compute(
            "copy_inventory_digest", {"quarantine_id": quarantine_id, "class": "encrypted_blob"}
        ),
    )
    destroy_calls = 0
    original_destroy = kernel.eraser._keys.destroy_resource_key

    def unknown(**_kwargs):
        return not_started.model_copy(update={"state": "UNKNOWN"})

    def counted_destroy(**kwargs):
        nonlocal destroy_calls
        destroy_calls += 1
        return original_destroy(**kwargs)

    monkeypatch.setattr(kernel.eraser._keys, "reconcile_resource_key_destruction", unknown)
    # Keep a separately captured callable so the assertion also proves UNKNOWN did
    # not enter the destructive path.
    monkeypatch.setattr(kernel.eraser._keys, "destroy_resource_key", counted_destroy)
    with pytest.raises(VerifiedErasureError, match="UNKNOWN"):
        kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)
    assert destroy_calls == 0
    assert kernel.collection_service._quarantine.ciphertext_handles(quarantine_id)


def test_terminal_replay_rechecks_key_destruction(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = s.make_phase0c()
    _dispatched, published = _published(kernel)
    kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)
    confirmed = kernel.eraser._keys.reconcile_resource_key_destruction(
        erasure_id=f"erasure-{published.deletion_intent_id}",
        metadata=kernel.collection_service._quarantine.encryption_metadata("q-exec-1"),
        key_metadata_digest=kernel.collection_service._quarantine.encryption_key_metadata_digest("q-exec-1"),
        resource_copy_inventory_digest=kernel.phase0b.phase0a.digest_service.compute(
            "copy_inventory_digest", {"quarantine_id": "q-exec-1", "class": "encrypted_blob"}
        ),
    )
    monkeypatch.setattr(
        kernel.eraser._keys, "reconcile_resource_key_destruction",
        lambda **_kwargs: confirmed.model_copy(update={"state": "UNKNOWN"}),
    )
    with pytest.raises(VerifiedErasureError, match="UNKNOWN"):
        kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)


def test_missing_publication_trail_blocks_post_ingestion_erasure() -> None:
    kernel = s.make_phase0c()
    _d, published = _published(kernel)
    # Corrupt the manifest digest binding on the deletion intent's stored manifest.
    db = kernel.phase0b.phase0a.database
    db.connection.execute("DELETE FROM occ_store WHERE namespace = 'secure_ingestion_manifest'")
    db.connection.commit()
    with pytest.raises(VerifiedErasureError):
        kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)


def test_evidence_retention_expiry_then_unresolved_erasure() -> None:
    clock = s.ManualMonotonicClock(support.T0)
    kernel = s.make_phase0c(monotonic_clock=clock)
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)
    state = kernel.phase0b.ingestion_repository.get(ingestion_id)
    assert state is not None and state.status == "PENDING"
    clock.advance(seconds=6 * 24 * 3600)  # past the fixed quarantine retention
    outcome = kernel.retention_scheduler.expire_evidence_retention(
        ingestion_id=ingestion_id, expected_state_version=state.state_version)
    assert outcome.kind == "retention_expiry" and outcome.ingestion_status == "DELETE_PENDING"
    erased = kernel.eraser.run(deletion_intent_id=outcome.deletion_intent_id)
    assert erased.ingestion_status == "ERASURE_COMPLETED_UNRESOLVED"
    # No ExecutionResult is materialized for an expiry erasure (no manifest).
    assert kernel.phase0b.result_repository.get(d.execution_id) is None


def test_incomplete_collection_expiry_erases_quarantine() -> None:
    clock = s.ManualMonotonicClock(support.T0)
    kernel = s.make_phase0c(monotonic_clock=clock)
    d = s.seed_dispatched(kernel)
    ds = kernel.phase0b.phase0a.digest_service
    binding = finalize_provider_task_binding(
        ProviderTaskBinding(task_id="task-exec-1", execution_id="exec-1", adapter_identity_digest="ad",
                            provider_identity_digest="pd", provider_task_id="pt", dispatch_claim_id="c",
                            binding_digest="pending"), ds)
    db = kernel.phase0b.phase0a.database
    with ApplicationUnitOfWork(db, aggregate_name="QuarantineAggregate", operation_id="q-open-1",
                               input_digest=compute_input_digest({"q": "open"})) as uow:
        kernel.collection_service._quarantine.create_quarantine(
            quarantine_id="q-open-1", mission_id=d.mission_id, mission_revision=1, execution_id="exec-1",
            task_binding=binding, deployment_epoch=kernel.deployment_epoch, fencing_token=1,
            retention_until=support.T0 + timedelta(days=4))
        uow.record_result("q-open-1")
    assert kernel.quarantine_metadata.get("q-open-1").status == "OPEN"
    clock.advance(seconds=5 * 24 * 3600)
    outcome = kernel.retention_scheduler.expire_incomplete_collection(quarantine_id="q-open-1", execution_id="exec-1")
    assert outcome.kind == "incomplete_collection_expiry" and outcome.quarantine_status == "RETENTION_EXPIRED"
    erased = kernel.eraser.run(deletion_intent_id=outcome.deletion_intent_id)
    assert erased.ciphertext_unlinked and erased.key_destruction_state == "CONFIRMED"
    assert kernel.quarantine_metadata.get("q-open-1").status == "DELETED"


def test_retention_scheduler_not_due_is_noop() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)
    state = kernel.phase0b.ingestion_repository.get(ingestion_id)
    outcome = kernel.retention_scheduler.expire_evidence_retention(
        ingestion_id=ingestion_id, expected_state_version=state.state_version)
    assert outcome.kind == "not_due"
