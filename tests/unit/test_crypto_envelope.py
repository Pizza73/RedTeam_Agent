"""Domain-separated envelope encryption (SystemDesign §34.1): AES-256-GCM only."""

from __future__ import annotations

import os

import pytest

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto import aead
from redteam_agent.crypto.key_provider import InMemoryEnvelopeKeyProvider
from redteam_agent.errors import (
    CrossDomainKeyError,
    EncryptionUnavailableError,
    KeyDomainSeparationError,
    NonceReuseError,
)


def _provider() -> InMemoryEnvelopeKeyProvider:
    return InMemoryEnvelopeKeyProvider(digest_service=DigestService())


def test_standard_aead_round_trip_aes_256_gcm() -> None:
    key, nonce = os.urandom(32), os.urandom(12)
    ct = aead.aead_encrypt(algorithm_id="aes_256_gcm_v1", key=key, nonce=nonce, plaintext=b"data", aad=b"aad")
    assert ct != b"data"
    assert aead.aead_decrypt(algorithm_id="aes_256_gcm_v1", key=key, nonce=nonce, ciphertext=ct, aad=b"aad") == b"data"


def test_unsupported_algorithm_fails_closed() -> None:
    with pytest.raises(EncryptionUnavailableError):
        aead.aead_encrypt(algorithm_id="rot13_v1", key=os.urandom(32), nonce=os.urandom(12), plaintext=b"x", aad=b"")


def test_missing_backend_fails_closed_no_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aead, "_AESGCM", None)
    with pytest.raises(EncryptionUnavailableError):
        aead.require_aead()
    with pytest.raises(EncryptionUnavailableError):
        aead.aead_encrypt(algorithm_id="aes_256_gcm_v1", key=os.urandom(32), nonce=os.urandom(12), plaintext=b"x", aad=b"")


def test_envelope_round_trip_and_aad_binding() -> None:
    provider = _provider()
    md = provider.create_resource_key(domain="artifact_store", resource_binding_type="artifact_id",
                                      resource_binding_id="a-1")
    handle = provider.open_resource_key_handle(metadata=md, operation="encrypt")
    ct = handle.encrypt(encryption_metadata_id="a-1", nonce=os.urandom(12), plaintext=b"body",
                        aad_fields={"mission_id": "m1", "execution_id": "e1", "artifact_id": "a-1"})
    handle.close()
    reader = provider.open_resource_key_handle(metadata=md, operation="decrypt")
    assert reader.decrypt(record=ct, aad_fields={"mission_id": "m1", "execution_id": "e1", "artifact_id": "a-1"}) == b"body"
    with pytest.raises(CrossDomainKeyError):
        reader.decrypt(record=ct, aad_fields={"mission_id": "WRONG", "execution_id": "e1", "artifact_id": "a-1"})
    reader.close()


def test_nonce_reuse_rejected() -> None:
    provider = _provider()
    md = provider.create_resource_key(domain="artifact_store", resource_binding_type="artifact_id",
                                      resource_binding_id="a-2")
    handle = provider.open_resource_key_handle(metadata=md, operation="encrypt")
    nonce = os.urandom(12)
    handle.encrypt(encryption_metadata_id="a-2", nonce=nonce, plaintext=b"x", aad_fields={"mission_id": "m1"})
    with pytest.raises(NonceReuseError):
        handle.encrypt(encryption_metadata_id="a-2", nonce=nonce, plaintext=b"y", aad_fields={"mission_id": "m1"})
    handle.close()


def test_domain_separation_distinct_keys_and_tags() -> None:
    provider = _provider()
    tags = {d: provider.get_active_domain_key_metadata(d).key_separation_tag  # type: ignore[arg-type]
            for d in ("secret_store", "raw_result_quarantine", "artifact_store", "audit_signing")}
    assert len(set(tags.values())) == 4
    provider.self_check()


def test_seeded_provider_generates_independent_keks_and_deks() -> None:
    provider = InMemoryEnvelopeKeyProvider(digest_service=DigestService(), rng=b"fixed-test-seed")
    # Private inspection is intentional for this test double: the public capability
    # API never exposes raw key material, while this regression must compare it.
    keks = [entry[0] for entry in provider._domains.values()]
    assert len(set(keks)) == len(keks)
    first = provider.create_resource_key(
        domain="artifact_store", resource_binding_type="artifact_id", resource_binding_id="seeded-a"
    )
    second = provider.create_resource_key(
        domain="artifact_store", resource_binding_type="artifact_id", resource_binding_id="seeded-b"
    )
    first_dek = provider._unwrap(first)
    second_dek = provider._unwrap(second)
    try:
        assert first_dek != second_dek
    finally:
        first_dek[:] = b"\x00" * len(first_dek)
        second_dek[:] = b"\x00" * len(second_dek)


def test_cross_domain_key_cannot_open_other_domain_ciphertext() -> None:
    provider = _provider()
    q = provider.create_resource_key(domain="raw_result_quarantine", resource_binding_type="quarantine_id",
                                     resource_binding_id="q-1")
    handle = provider.open_resource_key_handle(metadata=q, operation="encrypt")
    ct = handle.encrypt(encryption_metadata_id="q-1", nonce=os.urandom(12), plaintext=b"secret",
                        aad_fields={"mission_id": "m1", "execution_id": "e1", "quarantine_id": "q-1"})
    handle.close()
    # A secret_store resource key/handle cannot decrypt a quarantine ciphertext.
    s = provider.create_resource_key(domain="secret_store", resource_binding_type="secret_version_id",
                                     resource_binding_id="s-1")
    other = provider.open_resource_key_handle(metadata=s, operation="decrypt")
    with pytest.raises(CrossDomainKeyError):
        other.decrypt(record=ct, aad_fields={"mission_id": "m1", "execution_id": "e1", "quarantine_id": "q-1"})
    other.close()


def test_per_resource_cryptographic_erasure_isolated() -> None:
    provider = _provider()
    a = provider.create_resource_key(domain="artifact_store", resource_binding_type="artifact_id",
                                     resource_binding_id="a-A")
    b = provider.create_resource_key(domain="artifact_store", resource_binding_type="artifact_id",
                                     resource_binding_id="a-B")
    ha = provider.open_resource_key_handle(metadata=a, operation="encrypt")
    ha.encrypt(encryption_metadata_id="a-A", nonce=os.urandom(12), plaintext=b"A", aad_fields={"mission_id": "m1"})
    ha.close()
    hb = provider.open_resource_key_handle(metadata=b, operation="encrypt")
    ct_b = hb.encrypt(encryption_metadata_id="a-B", nonce=os.urandom(12), plaintext=b"B", aad_fields={"mission_id": "m1"})
    hb.close()
    result = provider.destroy_resource_key(erasure_id="er-A", metadata=a, key_metadata_digest=a.metadata_digest,
                                           resource_copy_inventory_digest="inv")
    assert result.state == "CONFIRMED" and result.erasure_evidence_digest is not None
    # A is undecryptable; B is intact.
    with pytest.raises(EncryptionUnavailableError):
        provider.open_resource_key_handle(metadata=a, operation="decrypt")
    hb2 = provider.open_resource_key_handle(metadata=b, operation="decrypt")
    assert hb2.decrypt(record=ct_b, aad_fields={"mission_id": "m1"}) == b"B"
    hb2.close()


def test_destroy_reconcile_idempotent_and_reason_bound() -> None:
    provider = _provider()
    a = provider.create_resource_key(domain="secret_store", resource_binding_type="secret_version_id",
                                     resource_binding_id="s-2")
    first = provider.destroy_resource_key(erasure_id="er-2", metadata=a, key_metadata_digest=a.metadata_digest,
                                          resource_copy_inventory_digest="inv")
    again = provider.destroy_resource_key(erasure_id="er-2", metadata=a, key_metadata_digest=a.metadata_digest,
                                          resource_copy_inventory_digest="inv")
    assert first.result_digest == again.result_digest  # idempotent by erasure_id
    with pytest.raises(KeyDomainSeparationError):
        provider.destroy_resource_key(erasure_id="er-2", metadata=a, key_metadata_digest=a.metadata_digest,
                                      resource_copy_inventory_digest="DIFFERENT")


def test_reconcile_before_destroy_is_not_started() -> None:
    provider = _provider()
    a = provider.create_resource_key(domain="secret_store", resource_binding_type="secret_version_id",
                                     resource_binding_id="s-3")
    r = provider.reconcile_resource_key_destruction(erasure_id="er-3", metadata=a,
                                                    key_metadata_digest=a.metadata_digest,
                                                    resource_copy_inventory_digest="inv")
    assert r.state == "NOT_STARTED" and r.erasure_evidence_digest is None
