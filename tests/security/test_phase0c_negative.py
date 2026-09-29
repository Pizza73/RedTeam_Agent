"""Phase 0C fail-closed / no-leak negatives (SystemDesign §33 / §34)."""

from __future__ import annotations

import os

import pytest

import support_phase0c as s
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto import aead
from redteam_agent.crypto.key_provider import InMemoryEnvelopeKeyProvider
from redteam_agent.errors import (
    EncryptionUnavailableError,
    RawResultQuarantineError,
    RepositoryIntegrityError,
)


def test_missing_cryptography_fails_closed_never_downgrades(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate the standard AEAD backend being unavailable.
    monkeypatch.setattr(aead, "_AESGCM", None)
    with pytest.raises(EncryptionUnavailableError):
        InMemoryEnvelopeKeyProvider(digest_service=DigestService())


def test_quarantine_ciphertext_tamper_detected_on_readback() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    s.collect(kernel, execution_id=d.execution_id)
    # Tamper with a stored ciphertext chunk blob.
    handles = kernel.collection_service._quarantine._blobs.list_prefix(f"q-{d.execution_id}")
    kernel.collection_service._quarantine._blobs.put(handles[0], b'{"encryption_metadata_id": "x", "key_domain": "raw_result_quarantine",'
                                            b' "algorithm_id": "aes_256_gcm_v1", "nonce": "00", "ciphertext": "00",'
                                            b' "aad_digest": "00", "ciphertext_digest": "deadbeef"}')
    with pytest.raises(RawResultQuarantineError):
        kernel.ingestion_service.ingest(ingestion_id=f"ingestion-{d.execution_id}")


def test_quarantine_plaintext_reader_is_absent_from_public_kernel() -> None:
    kernel = s.make_phase0c()
    assert not hasattr(kernel, "quarantine_store")
    assert not hasattr(kernel.quarantine_metadata, "open_reader")


def test_secret_plaintext_absent_from_audit_and_normal_db() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    payload = b'{"host": "h", "status": "open", "port": 1, "credential": "uniqueleaktoken42"}'
    ingestion_id = s.collect(kernel, execution_id=d.execution_id, stdout=payload)
    kernel.ingestion_service.ingest(ingestion_id=ingestion_id)
    conn = kernel.phase0b.phase0a.database.connection
    for table in ("occ_store", "executions", "kv_store", "result_ingestion_states"):
        rows = conn.execute(f"SELECT json FROM {table}").fetchall()
        assert all(b"uniqueleaktoken42" not in str(r[0]).encode() for r in rows), table


def test_occ_row_tamper_detected_on_read() -> None:
    kernel = s.make_phase0c()
    d = s.seed_dispatched(kernel)
    s.collect(kernel, execution_id=d.execution_id)
    conn = kernel.phase0b.phase0a.database.connection
    # Edit a quarantine metadata row's JSON without recomputing its row_digest.
    conn.execute(
        "UPDATE occ_store SET json = json || ' ' WHERE namespace = 'raw_result_quarantine_metadata'"
    )
    conn.commit()
    with pytest.raises(RepositoryIntegrityError):
        kernel.quarantine_metadata.get(f"q-{d.execution_id}")


def test_ingestion_service_has_no_key_destruction_capability() -> None:
    kernel = s.make_phase0c()
    # The ingestion service exposes no destroy/unlink; only the dedicated eraser does.
    assert not hasattr(kernel.ingestion_service, "destroy_resource_key")
    assert not hasattr(kernel.ingestion_service, "unlink_ciphertext")
    assert hasattr(kernel.eraser, "run")


def test_cross_domain_ciphertext_rejected() -> None:
    from redteam_agent.errors import CrossDomainKeyError

    provider = InMemoryEnvelopeKeyProvider(digest_service=DigestService())
    q = provider.create_resource_key(domain="raw_result_quarantine", resource_binding_type="quarantine_id",
                                     resource_binding_id="q-x")
    h = provider.open_resource_key_handle(metadata=q, operation="encrypt")
    ct = h.encrypt(encryption_metadata_id="q-x", nonce=os.urandom(12), plaintext=b"x",
                   aad_fields={"mission_id": "m", "execution_id": "e", "quarantine_id": "q-x"})
    h.close()
    # A different-domain key/handle cannot open a quarantine ciphertext (no cross-domain fallback).
    art = provider.create_resource_key(domain="artifact_store", resource_binding_type="artifact_id",
                                       resource_binding_id="a-x")
    reader = provider.open_resource_key_handle(metadata=art, operation="decrypt")
    with pytest.raises(CrossDomainKeyError):
        reader.decrypt(record=ct, aad_fields={"mission_id": "m", "execution_id": "e", "quarantine_id": "q-x"})
    reader.close()
