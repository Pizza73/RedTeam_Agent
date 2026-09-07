"""Repository-bound secure ingestion: window, create-or-verify, retention (SystemDesign §33.2 / §10.4)."""

from __future__ import annotations

import pytest

import support
import support_phase0c as s
from redteam_agent.errors import SecureIngestionError


def test_only_repository_bound_ingestion_id_starts_ingestion() -> None:
    kernel = s.make_phase0c()
    with pytest.raises(SecureIngestionError):
        kernel.ingestion_service.ingest(ingestion_id="does-not-exist")


def test_ingest_requires_committed_quarantine() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)
    # Force the quarantine back to a non-committed state to model a not-yet-collected input.
    kernel.quarantine_store.set_status(f"q-{d.execution_id}", "STREAMING")
    with pytest.raises(SecureIngestionError):
        kernel.ingestion_service.ingest(ingestion_id=ingestion_id)


def test_ingest_refused_after_retention_passed() -> None:
    clock = s.ManualMonotonicClock(support.T0)
    kernel = s.make_phase0c(monotonic_clock=clock)
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)
    clock.advance(seconds=6 * 24 * 3600)  # past the fixed quarantine retention
    with pytest.raises(SecureIngestionError):
        kernel.ingestion_service.ingest(ingestion_id=ingestion_id)


def test_same_input_retry_is_create_or_verify() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)
    first = kernel.ingestion_service.ingest(ingestion_id=ingestion_id)
    again = kernel.ingestion_service.ingest(ingestion_id=ingestion_id)
    # The replay resolves the same manifest (create-or-verify); the manifest is immutable.
    assert first.manifest_id == again.manifest_id and again.status == "DELETE_PENDING"
    manifest = kernel.ingestion_service.get_manifest(first.manifest_id)
    assert manifest is not None and manifest.quarantine_id == f"q-{d.execution_id}"
    assert tuple(a.artifact_id for a in manifest.redacted_artifacts) == first.redacted_artifact_ids


def test_manifest_binds_execution_receipt_quarantine_rule() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    ingestion_id = s.collect(kernel, execution_id=d.execution_id)
    published = kernel.ingestion_service.ingest(ingestion_id=ingestion_id)
    manifest = kernel.ingestion_service.get_manifest(published.manifest_id)
    assert manifest is not None
    assert manifest.execution_id == d.execution_id
    assert manifest.output_publication_rule_id == "pub-1"
    assert manifest.quarantine_ciphertext_digest  # bound to the exact quarantine ciphertext
