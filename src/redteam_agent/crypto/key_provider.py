"""Domain KEK + per-resource DEK envelope encryption (SystemDesign §34.1).

An :class:`EncryptionKeyProvider` owns one Key Encryption Key (KEK) per key domain
and issues one independent Data Encryption Key (DEK) per resource. A resource DEK is
wrapped by its domain KEK and stored only inside the provider; the application
database keeps just :class:`EncryptionMetadata` and non-secret digests. Callers never
receive DEK/KEK bytes: they open an :class:`OpaqueKeyHandle` that encrypts/decrypts
internally and zeroizes on close.

Guarantees enforced here:

* domain separation: each domain has a distinct KEK, ``domain_key_id`` and
  ``key_separation_tag``; a ciphertext from one domain cannot be opened with another
  domain's key (:class:`CrossDomainKeyError`);
* per-resource erasure: destroying one resource DEK leaves every other resource in the
  same domain decryptable; the shared domain KEK is never destroyed as resource erasure;
* AAD binding: domain, mission, execution and the resource binding are authenticated;
* nonce uniqueness: a nonce may not be reused for a resource key (:class:`NonceReuseError`);
* fail closed: the standard AEAD backend must be present (:class:`EncryptionUnavailableError`).

The production provider stores wrapped DEKs and provider state through the same
interface; this in-memory provider is a deterministic test double (SystemDesign
§35.2 forbids it in production, enforced by the composition self-check).
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto import aead as _aead
from redteam_agent.crypto.aead import AES_256_GCM_V1, require_aead
from redteam_agent.crypto.models import (
    DomainKeyMetadata,
    EncryptionMetadata,
    EnvelopeCiphertext,
    KeyDestructionResult,
    KeyDestructionState,
    KeyDomain,
)
from redteam_agent.errors import (
    CrossDomainKeyError,
    EncryptionUnavailableError,
    KeyDomainSeparationError,
    NonceReuseError,
)

_NONCE_STRATEGY_REVISION = "nonce-random-96bit-v1"
_DEK_WRAP_DOMAIN = "redteam-envelope-dek-wrap/v1"

WrappedStateWitness = Callable[
    [str, tuple[str, ...], str, EnvelopeCiphertext], bool
]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _finalize(model_payload: dict[str, object], digest_name: str, digest_field: str, ds: DigestService) -> str:
    payload = {k: v for k, v in model_payload.items() if k != digest_field}
    return ds.compute(digest_name, payload)


class OpaqueKeyHandle:
    """An in-call encrypt/decrypt capability that never exposes DEK bytes.

    The handle holds the unwrapped DEK in a private mutable buffer and zeroizes it on
    :meth:`close`. It builds the AEAD AAD from the resource metadata plus the caller's
    per-operation binding fields (mission/execution/resource-specific).
    """

    def __init__(self, *, metadata: EncryptionMetadata, dek: bytearray, nonce_ledger: set[str]) -> None:
        self._metadata = metadata
        self._dek = dek
        self._nonce_ledger = nonce_ledger
        self._closed = False

    def _require_open(self) -> None:
        if self._closed:
            raise EncryptionUnavailableError("key handle is closed")

    def _aad(self, aad_fields: dict[str, object]) -> bytes:
        reserved = {"key_domain", "resource_binding_type", "resource_binding_id",
                    "resource_key_id", "resource_key_version"}
        overlap = reserved.intersection(aad_fields)
        if overlap:
            raise CrossDomainKeyError(f"aad fields may not override resource binding: {sorted(overlap)}")
        base = {
            "key_domain": self._metadata.key_domain,
            "resource_binding_type": self._metadata.resource_binding_type,
            "resource_binding_id": self._metadata.resource_binding_id,
            "resource_key_id": self._metadata.resource_key_id,
            "resource_key_version": self._metadata.resource_key_version,
            **aad_fields,
        }
        return canonical_dumps(base)

    def encrypt(self, *, encryption_metadata_id: str, nonce: bytes, plaintext: bytes,
                aad_fields: dict[str, object]) -> EnvelopeCiphertext:
        self._require_open()
        nonce_hex = nonce.hex()
        if nonce_hex in self._nonce_ledger:
            raise NonceReuseError("nonce reuse for resource key is forbidden")
        aad = self._aad(aad_fields)
        ciphertext = _aead.aead_encrypt(
            algorithm_id=self._metadata.encryption_algorithm, key=bytes(self._dek), nonce=nonce,
            plaintext=plaintext, aad=aad,
        )
        self._nonce_ledger.add(nonce_hex)
        return EnvelopeCiphertext(
            encryption_metadata_id=encryption_metadata_id, key_domain=self._metadata.key_domain,
            algorithm_id=self._metadata.encryption_algorithm, nonce=nonce_hex, ciphertext=ciphertext.hex(),
            aad_digest=_sha256_hex(aad), ciphertext_digest=_sha256_hex(ciphertext),
        )

    def decrypt(self, *, record: EnvelopeCiphertext, aad_fields: dict[str, object]) -> bytes:
        self._require_open()
        if record.key_domain != self._metadata.key_domain:
            raise CrossDomainKeyError("ciphertext key domain does not match the resource key domain")
        aad = self._aad(aad_fields)
        if _sha256_hex(aad) != record.aad_digest:
            raise CrossDomainKeyError("ciphertext aad binding does not match the resource binding")
        return _aead.aead_decrypt(
            algorithm_id=record.algorithm_id, key=bytes(self._dek), nonce=bytes.fromhex(record.nonce),
            ciphertext=bytes.fromhex(record.ciphertext), aad=aad,
        )

    def close(self) -> None:
        for i in range(len(self._dek)):
            self._dek[i] = 0
        self._closed = True

    def __enter__(self) -> OpaqueKeyHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class EncryptionKeyProvider(Protocol):
    provider_identity: str

    def get_active_domain_key_metadata(self, domain: KeyDomain) -> DomainKeyMetadata: ...

    def create_resource_key(
        self, *, domain: KeyDomain, resource_binding_type: str, resource_binding_id: str
    ) -> EncryptionMetadata: ...

    def open_resource_key_handle(
        self, *, metadata: EncryptionMetadata, operation: str
    ) -> OpaqueKeyHandle: ...

    def destroy_resource_key(
        self, *, erasure_id: str, metadata: EncryptionMetadata, key_metadata_digest: str,
        resource_copy_inventory_digest: str,
    ) -> KeyDestructionResult: ...

    def reconcile_resource_key_destruction(
        self, *, erasure_id: str, metadata: EncryptionMetadata, key_metadata_digest: str,
        resource_copy_inventory_digest: str,
    ) -> KeyDestructionResult: ...

    def self_check(self) -> None: ...


class InMemoryEnvelopeKeyProvider:
    """Deterministic in-memory envelope key provider (test double)."""

    provider_identity = "in-memory-envelope-key-provider-v1"
    is_production = False

    def __init__(self, *, digest_service: DigestService, rng: bytes | None = None) -> None:
        require_aead()
        self._ds = digest_service
        self._algorithm = AES_256_GCM_V1
        self._domains: dict[KeyDomain, tuple[bytes, DomainKeyMetadata]] = {}
        self._wrapped: dict[str, tuple[bytes, bytes]] = {}  # resource_key_id -> (wrap_nonce, wrapped_dek)
        self._metadata: dict[str, EncryptionMetadata] = {}
        self._nonce_ledgers: dict[str, set[str]] = {}
        self._destructions: dict[str, KeyDestructionResult] = {}
        self._counter = 0
        self._seed = rng
        self._random_call_counter = 0
        self._wrapped_state_witness: WrappedStateWitness | None = None
        self._last_witnessed_state_digest: str | None = None
        self._state_snapshot_cache: dict[str, EnvelopeCiphertext] = {}
        for index, domain in enumerate(("secret_store", "raw_result_quarantine", "artifact_store", "audit_signing")):
            self._provision_domain(domain, index)  # type: ignore[arg-type]

    # --- provisioning -----------------------------------------------------

    def _random(self, n: int) -> bytes:
        if self._seed is not None:
            # Stateful, domain-separated deterministic expansion for reproducible
            # tests only.  A fresh invocation must never restart the same stream:
            # domain KEKs and per-resource DEKs still have to be independent.
            call = self._random_call_counter
            self._random_call_counter += 1
            out = b""
            block = 0
            while len(out) < n:
                out += hashlib.sha256(
                    b"redteam-test-key-stream-v1\x00"
                    + self._seed
                    + call.to_bytes(8, "big")
                    + block.to_bytes(4, "big")
                ).digest()
                block += 1
            return out[:n]
        return os.urandom(n)

    def _provision_domain(self, domain: KeyDomain, index: int) -> None:
        kek = self._random(self._algorithm.key_length)
        separation_tag = _sha256_hex(f"domain-separation:{domain}:{self.provider_identity}".encode())
        payload = {
            "key_domain": domain, "domain_key_id": f"kek-{domain}", "domain_key_version": 1,
            "provider_identity": self.provider_identity, "key_separation_tag": separation_tag,
            "algorithm": self._algorithm.algorithm_id, "rotation_state": "active",
        }
        metadata = DomainKeyMetadata(
            **payload,  # type: ignore[arg-type]
            metadata_digest=self._ds.compute("domain_key_metadata_digest", payload),
        )
        self._domains[domain] = (kek, metadata)

    def get_active_domain_key_metadata(self, domain: KeyDomain) -> DomainKeyMetadata:
        entry = self._domains.get(domain)
        if entry is None:
            raise EncryptionUnavailableError(f"no domain key for {domain}")
        return entry[1]

    # --- resource keys ----------------------------------------------------

    def create_resource_key(
        self, *, domain: KeyDomain, resource_binding_type: str, resource_binding_id: str
    ) -> EncryptionMetadata:
        require_aead()
        kek, domain_meta = self._domains[domain]
        resource_key_id = f"dek-{domain}-{resource_binding_type}-{resource_binding_id}"
        if resource_key_id in self._metadata:
            existing = self._metadata[resource_key_id]
            if existing.resource_binding_id != resource_binding_id:  # pragma: no cover - defensive
                raise KeyDomainSeparationError("resource key id collision across bindings")
            self._publish_wrapped_state()
            return existing
        dek = self._random(self._algorithm.key_length)
        self._counter += 1
        wrap_nonce = self._counter.to_bytes(self._algorithm.nonce_length, "big")
        wrap_aad = canonical_dumps({
            "domain": _DEK_WRAP_DOMAIN, "key_domain": domain, "domain_key_id": domain_meta.domain_key_id,
            "resource_binding_type": resource_binding_type, "resource_binding_id": resource_binding_id,
            "resource_key_id": resource_key_id, "resource_key_version": 1,
        })
        wrapped = _aead.aead_encrypt(
            algorithm_id=self._algorithm.algorithm_id, key=kek, nonce=wrap_nonce, plaintext=dek, aad=wrap_aad,
        )
        payload = {
            "key_domain": domain, "resource_key_id": resource_key_id, "resource_key_version": 1,
            "resource_binding_type": resource_binding_type, "resource_binding_id": resource_binding_id,
            "domain_key_id": domain_meta.domain_key_id, "domain_key_version": domain_meta.domain_key_version,
            "wrapped_resource_key_digest": _sha256_hex(wrapped),
            "encryption_algorithm": self._algorithm.algorithm_id,
            "nonce_strategy_revision": _NONCE_STRATEGY_REVISION,
            "created_at": datetime(2000, 1, 1, tzinfo=UTC), "rotation_state": "active",
        }
        # created_at is fixed here only for the test double's determinism; the caller
        # never depends on it for authorization. It is still bound by metadata_digest.
        metadata = EncryptionMetadata(
            **payload,  # type: ignore[arg-type]
            metadata_digest=self._ds.compute("encryption_metadata_digest", payload),
        )
        self._wrapped[resource_key_id] = (wrap_nonce, wrapped)
        self._metadata[resource_key_id] = metadata
        self._nonce_ledgers[resource_key_id] = set()
        self._publish_wrapped_state()
        return metadata

    def connect_wrapped_state_witness(self, witness: WrappedStateWitness) -> None:
        """Require an exact wrapped-state TPM commit after every provider mutation."""
        if self._wrapped_state_witness is not None:
            raise KeyDomainSeparationError("wrapped-state witness is already connected")
        # A dedicated audit-signing resource key encrypts the opaque provider snapshot.
        self.create_resource_key(
            domain="audit_signing",
            resource_binding_type="provider_state",
            resource_binding_id="provider-state-root",
        )
        self._wrapped_state_witness = witness
        self._publish_wrapped_state()

    def _provider_state_payload(self) -> bytes:
        return canonical_dumps(
            {
                "provider_identity": self.provider_identity,
                "domain_key_metadata": [
                    metadata.model_dump(mode="json")
                    for _domain, (_key, metadata) in sorted(self._domains.items())
                ],
                "resource_key_metadata": [
                    self._metadata[key].model_dump(mode="json") for key in sorted(self._metadata)
                ],
                "wrapped_resource_keys": {
                    key: {"nonce": value[0].hex(), "ciphertext": value[1].hex()}
                    for key, value in sorted(self._wrapped.items())
                },
                "destructions": [
                    self._destructions[key].model_dump(mode="json") for key in sorted(self._destructions)
                ],
            }
        )

    def _publish_wrapped_state(self) -> None:
        if self._wrapped_state_witness is None:
            return
        plaintext = self._provider_state_payload()
        logical_digest = _sha256_hex(plaintext)
        envelope = self._state_snapshot_cache.get(logical_digest)
        if envelope is None:
            root_id = "dek-audit_signing-provider_state-provider-state-root"
            root = self._metadata[root_id]
            with OpaqueKeyHandle(
                metadata=root,
                dek=self._unwrap(root),
                nonce_ledger=self._nonce_ledgers.setdefault(root.resource_key_id, set()),
            ) as handle:
                envelope = handle.encrypt(
                    encryption_metadata_id=root.resource_key_id,
                    nonce=hashlib.sha256(b"provider-state-snapshot-v1\x00" + plaintext).digest()[:12],
                    plaintext=plaintext,
                    aad_fields={"provider_identity": self.provider_identity, "state_digest": logical_digest},
                )
            self._state_snapshot_cache[logical_digest] = envelope
        domain_digests = tuple(
            metadata.metadata_digest for _domain, (_key, metadata) in sorted(self._domains.items())
        )
        bindings_digest = self._ds.compute(
            "security_projection_digest",
            {
                "provider_state_digest": logical_digest,
                "resource_metadata_digests": tuple(
                    self._metadata[key].metadata_digest for key in sorted(self._metadata)
                ),
                "destruction_result_digests": tuple(
                    self._destructions[key].result_digest for key in sorted(self._destructions)
                ),
            },
        )
        witnessed_now = self._wrapped_state_witness(
            logical_digest, domain_digests, bindings_digest, envelope
        )
        if witnessed_now:
            self._last_witnessed_state_digest = logical_digest

    def confirm_wrapped_state(self, state_digest: str) -> None:
        """Complete a state publication deferred until the surrounding DB commit."""
        if _sha256_hex(self._provider_state_payload()) == state_digest:
            self._last_witnessed_state_digest = state_digest

    def _unwrap(self, metadata: EncryptionMetadata) -> bytearray:
        entry = self._wrapped.get(metadata.resource_key_id)
        if entry is None:
            raise EncryptionUnavailableError("resource key destroyed or unavailable")
        kek, domain_meta = self._domains[metadata.key_domain]
        wrap_nonce, wrapped = entry
        wrap_aad = canonical_dumps({
            "domain": _DEK_WRAP_DOMAIN, "key_domain": metadata.key_domain, "domain_key_id": domain_meta.domain_key_id,
            "resource_binding_type": metadata.resource_binding_type,
            "resource_binding_id": metadata.resource_binding_id,
            "resource_key_id": metadata.resource_key_id, "resource_key_version": metadata.resource_key_version,
        })
        return bytearray(_aead.aead_decrypt(
            algorithm_id=metadata.encryption_algorithm, key=kek, nonce=wrap_nonce, ciphertext=wrapped, aad=wrap_aad,
        ))

    def open_resource_key_handle(self, *, metadata: EncryptionMetadata, operation: str) -> OpaqueKeyHandle:
        require_aead()
        if self._wrapped_state_witness is not None:
            current_digest = _sha256_hex(self._provider_state_payload())
            if current_digest != self._last_witnessed_state_digest:
                raise EncryptionUnavailableError("provider state is not selected by the wrapped-state witness")
        if operation not in ("encrypt", "decrypt"):
            raise EncryptionUnavailableError(f"unsupported key operation: {operation}")
        if metadata.rotation_state == "destroyed":
            raise EncryptionUnavailableError("resource key is destroyed")
        dek = self._unwrap(metadata)
        return OpaqueKeyHandle(
            metadata=metadata, dek=dek, nonce_ledger=self._nonce_ledgers.setdefault(metadata.resource_key_id, set())
        )

    # --- destruction (cryptographic erasure) ------------------------------

    def _result(self, *, erasure_id: str, metadata: EncryptionMetadata, key_metadata_digest: str,
                copy_inventory_digest: str, state: KeyDestructionState,
                provider_operation_id: str | None, evidence: str | None) -> KeyDestructionResult:
        payload = {
            "erasure_id": erasure_id, "resource_key_id": metadata.resource_key_id,
            "key_metadata_digest": key_metadata_digest, "state": state,
            "provider_operation_id": provider_operation_id,
            "resource_copy_inventory_digest": copy_inventory_digest, "erasure_evidence_digest": evidence,
        }
        return KeyDestructionResult(
            **payload,  # type: ignore[arg-type]
            result_digest=self._ds.compute("key_destruction_result_digest", payload),
        )

    def destroy_resource_key(
        self, *, erasure_id: str, metadata: EncryptionMetadata, key_metadata_digest: str,
        resource_copy_inventory_digest: str,
    ) -> KeyDestructionResult:
        if metadata.metadata_digest != key_metadata_digest:
            raise KeyDomainSeparationError("key metadata digest mismatch")
        existing = self._destructions.get(erasure_id)
        if existing is not None:
            if existing.resource_key_id != metadata.resource_key_id \
                    or existing.resource_copy_inventory_digest != resource_copy_inventory_digest:
                raise KeyDomainSeparationError("erasure id reused for a different resource/inventory")
            return existing
        # Cryptographic erasure: irreversibly drop the only wrapped-DEK copy so the
        # resource ciphertext can never be decrypted. Other resources' DEKs (and the
        # domain KEK) are untouched.
        self._wrapped.pop(metadata.resource_key_id, None)
        self._nonce_ledgers.pop(metadata.resource_key_id, None)
        evidence = _sha256_hex(
            f"erasure:{erasure_id}:{metadata.resource_key_id}:{resource_copy_inventory_digest}".encode()
        )
        result = self._result(
            erasure_id=erasure_id, metadata=metadata, key_metadata_digest=key_metadata_digest,
            copy_inventory_digest=resource_copy_inventory_digest, state="CONFIRMED",
            provider_operation_id=f"op-{erasure_id}", evidence=evidence,
        )
        self._destructions[erasure_id] = result
        self._publish_wrapped_state()
        return result

    def reconcile_resource_key_destruction(
        self, *, erasure_id: str, metadata: EncryptionMetadata, key_metadata_digest: str,
        resource_copy_inventory_digest: str,
    ) -> KeyDestructionResult:
        if metadata.metadata_digest != key_metadata_digest:
            raise KeyDomainSeparationError("key metadata digest mismatch")
        existing = self._destructions.get(erasure_id)
        if existing is not None:
            if existing.resource_copy_inventory_digest != resource_copy_inventory_digest:
                raise KeyDomainSeparationError("erasure id reconciled with a different inventory")
            return existing
        return self._result(
            erasure_id=erasure_id, metadata=metadata, key_metadata_digest=key_metadata_digest,
            copy_inventory_digest=resource_copy_inventory_digest, state="NOT_STARTED",
            provider_operation_id=None, evidence=None,
        )

    # --- self check -------------------------------------------------------

    def self_check(self) -> None:
        require_aead()
        tags: dict[str, str] = {}
        ids: dict[str, str] = {}
        key_fingerprints: set[str] = set()
        for domain, (kek, meta) in self._domains.items():
            if meta.key_separation_tag in tags.values():
                raise KeyDomainSeparationError("duplicate key separation tag across domains")
            if meta.domain_key_id in ids.values():
                raise KeyDomainSeparationError("duplicate domain key id across domains")
            tags[domain] = meta.key_separation_tag
            ids[domain] = meta.domain_key_id
            fingerprint = _sha256_hex(kek)
            if fingerprint in key_fingerprints:
                raise KeyDomainSeparationError("duplicate KEK material across domains")
            key_fingerprints.add(fingerprint)
