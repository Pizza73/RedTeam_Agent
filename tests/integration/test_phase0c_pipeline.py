"""End-to-end Phase 0C pipeline: encrypted collection -> secure ingestion -> verified erasure."""

from __future__ import annotations

import pytest

import support_phase0c as s
from redteam_agent.errors import RawResultQuarantineError, SecureIngestionError
from redteam_agent.storage.unit_of_work import ApplicationUnitOfWork


def test_full_pipeline_publishes_and_erases() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)

    quarantine = kernel.quarantine_metadata.get(f"q-{d.execution_id}")
    assert quarantine is not None and quarantine.status == "COMMITTED"

    published = kernel.ingestion_service.ingest(ingestion_id=ingestion_id)
    assert published.status == "DELETE_PENDING"
    assert published.manifest_id is not None and published.deletion_intent_id is not None
    assert len(published.redacted_artifact_ids) == 1 and len(published.detected_secret_version_ids) == 1
    # Detected secret is DETECTED only (not implicitly confirmed).
    assert kernel.secret_metadata.current_state(published.detected_secret_version_ids[0]) == "DETECTED"

    erased = kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)
    assert erased.ingestion_status == "SUCCEEDED"
    assert erased.key_destruction_state == "CONFIRMED" and erased.ciphertext_unlinked

    # ExecutionResult is rebuilt from the projection alone.
    result = kernel.phase0b.result_repository.get(d.execution_id)
    assert result is not None and result.status == "SUCCEEDED"
    # Quarantine is DELETED and its ciphertext is undecryptable.
    assert kernel.quarantine_metadata.get(f"q-{d.execution_id}").status == "DELETED"
    with pytest.raises(RawResultQuarantineError):
        kernel.collection_service._quarantine._open_reader_for_ingestion(f"q-{d.execution_id}")
    kernel.audit_store.verify_chain(d.mission_id)


def test_ingest_is_idempotent_on_replay() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)
    first = kernel.ingestion_service.ingest(ingestion_id=ingestion_id)
    again = kernel.ingestion_service.ingest(ingestion_id=ingestion_id)
    assert again.status == "DELETE_PENDING" and again.manifest_id == first.manifest_id


def test_erase_is_idempotent_on_replay() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)
    published = kernel.ingestion_service.ingest(ingestion_id=ingestion_id)
    assert published.deletion_intent_id is not None
    first = kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)
    again = kernel.eraser.run(deletion_intent_id=published.deletion_intent_id)
    assert first.erasure_id == again.erasure_id and again.ingestion_status == "SUCCEEDED"


def test_no_plaintext_in_application_db_or_blob_after_collection() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    s.collect(kernel, execution_id=d.execution_id, stdout=b'{"host": "h", "status": "open", "port": 1, "credential": "leakcanary"}')
    # The raw secret value must not appear in the normal application DB rows...
    rows = kernel.phase0b.phase0a.database.connection.execute(
        "SELECT json FROM occ_store"
    ).fetchall()
    assert all(b"leakcanary" not in str(r[0]).encode() for r in rows)
    exec_rows = kernel.phase0b.phase0a.database.connection.execute("SELECT json FROM executions").fetchall()
    assert all(b"leakcanary" not in str(r[0]).encode() for r in exec_rows)
    # ...and only ciphertext lives in the quarantine blob store.
    blobs = kernel.collection_service._quarantine._blobs
    for handle in blobs.list_prefix(f"q-{d.execution_id}"):
        assert b"leakcanary" not in blobs.get(handle)


def test_encrypted_raw_artifact_is_not_readable_without_bound_grant_authority() -> None:
    kernel = s.make_phase0c()
    body = b"raw-artifact-secret"
    ref, handle, ciphertext, encryption = kernel.ingestion_service._artifacts.build_encrypted_raw(
        artifact_id="raw-artifact-1",
        mission_id="mission-1",
        execution_id="execution-1",
        body=body,
        created_at=kernel.monotonic_clock.now(),
        retention_until=None,
    )
    assert body not in ciphertext
    with ApplicationUnitOfWork(
        kernel.phase0b.phase0a.database,
        aggregate_name="IngestionPublicationAggregate",
        operation_id="persist-raw-artifact-1",
        input_digest=ref.artifact_digest,
    ) as uow:
        kernel.ingestion_service._artifacts.persist_in_txn(
            ref,
            blob_handle=handle,
            blob_bytes=ciphertext,
            encryption=encryption,
        )
        uow.record_result(ref.artifact_digest)
    with pytest.raises(SecureIngestionError):
        kernel.ingestion_service._artifacts._read_body_with_grant(
            "raw-artifact-1", execution_id="execution-1", grant=object()  # type: ignore[arg-type]
        )
