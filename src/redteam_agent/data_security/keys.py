"""Domain-separated authenticated encryption for trusted storage adapters.

The in-memory provider is a development/test implementation of the provider boundary. It
never serializes key material; deployments must substitute an OS key store or vault adapter.
"""

from __future__ import annotations

import base64
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from typing import Literal, Protocol

from redteam_agent.canonical import canonicalize, sha256_digest, stable_id
from redteam_agent.errors import (
    EncryptionIntegrityError,
    EncryptionKeyUnavailableError,
    EncryptionNonceReuseError,
)

from .models import EncryptedPayload, EncryptionMetadata, KeyDomain, RotationState

ALGORITHM = "HMAC-SHA256-STREAM-v1"


class EncryptionKeyProvider(Protocol):
    def get_active_key_metadata(self, domain: KeyDomain) -> EncryptionMetadata: ...

    def seal(
        self, domain: KeyDomain, plaintext: bytes, aad: dict[str, object]
    ) -> EncryptedPayload: ...

    def open(
        self, domain: KeyDomain, payload: EncryptedPayload, aad: dict[str, object]
    ) -> bytes: ...

    def verify(
        self, domain: KeyDomain, payload: EncryptedPayload, aad: dict[str, object]
    ) -> None: ...

    def metadata_id(self, metadata: EncryptionMetadata) -> str: ...

    def keyed_digest(
        self,
        domain: KeyDomain,
        purpose: str,
        value: bytes,
        *,
        metadata: EncryptionMetadata | None = None,
    ) -> str: ...

    def seal_for_resource(
        self,
        domain: KeyDomain,
        resource_id: str,
        plaintext: bytes,
        aad: dict[str, object],
        *,
        created_at: datetime,
    ) -> EncryptedPayload: ...

    def destroy_resource_key(self, metadata: EncryptionMetadata) -> None: ...

    def resource_key_destroyed(self, metadata: EncryptionMetadata) -> bool: ...


@dataclass(frozen=True, slots=True)
class _KeyRecord:
    metadata: EncryptionMetadata
    material: bytearray | None
    resource_key: bool = False
    parent_key: tuple[str, int] | None = None


class InMemoryEncryptionKeyProvider:
    """Explicit local-only provider with opaque, non-persistent key records."""

    def __init__(self) -> None:
        self._records: dict[tuple[KeyDomain, str, int], _KeyRecord] = {}
        self._active: dict[KeyDomain, tuple[str, int]] = {}
        self._key_ids: set[str] = set()
        self._separation_tags: set[str] = set()
        self._material_fingerprints: set[bytes] = set()
        self._used_nonces: set[tuple[KeyDomain, str, int, bytes]] = set()
        self._lock = RLock()

    def register_key(
        self,
        *,
        domain: KeyDomain,
        key_id: str,
        key_version: int,
        key_separation_tag: str,
        material: bytes,
        created_at: datetime,
        rotation_state: RotationState = "active",
    ) -> EncryptionMetadata:
        return self._register_key(
            domain=domain,
            key_id=key_id,
            key_version=key_version,
            key_separation_tag=key_separation_tag,
            material=material,
            created_at=created_at,
            rotation_state=rotation_state,
            resource_key=False,
        )

    def _register_key(
        self,
        *,
        domain: KeyDomain,
        key_id: str,
        key_version: int,
        key_separation_tag: str,
        material: bytes,
        created_at: datetime,
        rotation_state: RotationState,
        resource_key: bool,
        parent_key: tuple[str, int] | None = None,
    ) -> EncryptionMetadata:
        if len(material) < 32:
            raise EncryptionKeyUnavailableError("key material does not meet provider policy")
        fingerprint = hmac.digest(b"redteam-key-equality-v1", material, "sha256")
        identity = (domain, key_id, key_version)
        with self._lock:
            if identity in self._records:
                raise EncryptionKeyUnavailableError("key identity is already registered")
            if key_id in self._key_ids or key_separation_tag in self._separation_tags:
                raise EncryptionKeyUnavailableError("key domain separation policy failed")
            if fingerprint in self._material_fingerprints:
                raise EncryptionKeyUnavailableError("key material domain separation policy failed")
            if rotation_state == "active" and domain in self._active and not resource_key:
                raise EncryptionKeyUnavailableError("key domain already has an active version")
            metadata = EncryptionMetadata(
                key_domain=domain,
                key_id=key_id,
                key_version=key_version,
                encryption_algorithm=ALGORITHM,
                key_separation_tag=key_separation_tag,
                created_at=created_at,
                rotation_state=rotation_state,
            )
            self._records[identity] = _KeyRecord(
                metadata=metadata,
                material=bytearray(material),
                resource_key=resource_key,
                parent_key=parent_key,
            )
            self._key_ids.add(key_id)
            self._separation_tags.add(key_separation_tag)
            self._material_fingerprints.add(fingerprint)
            if rotation_state == "active" and not resource_key:
                self._active[domain] = (key_id, key_version)
            return metadata

    def set_rotation_state(
        self, domain: KeyDomain, key_id: str, key_version: int, state: RotationState
    ) -> None:
        identity = (domain, key_id, key_version)
        with self._lock:
            record = self._records.get(identity)
            if record is None:
                raise EncryptionKeyUnavailableError("key identity is unavailable")
            transitions: dict[RotationState, frozenset[RotationState]] = {
                "active": frozenset({"active", "decrypt_only", "revoked", "destroyed"}),
                "decrypt_only": frozenset({"decrypt_only", "revoked", "destroyed"}),
                "revoked": frozenset({"revoked", "destroyed"}),
                "destroyed": frozenset({"destroyed"}),
            }
            if state not in transitions[record.metadata.rotation_state]:
                raise EncryptionKeyUnavailableError("key rotation transition is forbidden")
            active = self._active.get(domain)
            if (
                state == "active"
                and not record.resource_key
                and active not in {None, (key_id, key_version)}
            ):
                raise EncryptionKeyUnavailableError("key domain already has an active version")
            metadata = record.metadata.model_copy(update={"rotation_state": state})
            material = record.material
            if state == "destroyed" and material is not None:
                material[:] = b"\x00" * len(material)
                material = None
            self._records[identity] = _KeyRecord(
                metadata=metadata,
                material=material,
                resource_key=record.resource_key,
                parent_key=record.parent_key,
            )
            if state == "active" and not record.resource_key:
                self._active[domain] = (key_id, key_version)
            elif active == (key_id, key_version):
                self._active.pop(domain, None)

    def get_active_key_metadata(self, domain: KeyDomain) -> EncryptionMetadata:
        with self._lock:
            active = self._active.get(domain)
            record = self._records.get((domain, *active)) if active is not None else None
            if record is None or record.metadata.rotation_state != "active":
                raise EncryptionKeyUnavailableError("active key is unavailable")
            return record.metadata

    def seal(
        self,
        domain: KeyDomain,
        plaintext: bytes,
        aad: dict[str, object],
        *,
        nonce: bytes | None = None,
    ) -> EncryptedPayload:
        metadata = self.get_active_key_metadata(domain)
        return self._seal_with_metadata(metadata, plaintext, aad, nonce=nonce)

    def seal_for_resource(
        self,
        domain: KeyDomain,
        resource_id: str,
        plaintext: bytes,
        aad: dict[str, object],
        *,
        created_at: datetime,
    ) -> EncryptedPayload:
        parent = self.get_active_key_metadata(domain)
        key_id = stable_id(
            "resourcekey",
            {"schema_version": "resource-key-v1", "domain": domain, "resource_id": resource_id},
        )
        identity = (domain, key_id, 1)
        with self._lock:
            existing = self._records.get(identity)
        if existing is None:
            metadata = self._register_key(
                domain=domain,
                key_id=key_id,
                key_version=1,
                key_separation_tag=stable_id(
                    "keytag",
                    {
                        "schema_version": "resource-key-tag-v1",
                        "domain": domain,
                        "resource_id": resource_id,
                    },
                ),
                material=secrets.token_bytes(32),
                created_at=created_at,
                rotation_state="active",
                resource_key=True,
                parent_key=(parent.key_id, parent.key_version),
            )
        else:
            if not (
                existing.resource_key
                and existing.metadata.rotation_state == "active"
                and existing.parent_key == (parent.key_id, parent.key_version)
            ):
                raise EncryptionKeyUnavailableError("resource key is unavailable")
            metadata = existing.metadata
        return self._seal_with_metadata(metadata, plaintext, aad)

    def destroy_resource_key(self, metadata: EncryptionMetadata) -> None:
        identity = (metadata.key_domain, metadata.key_id, metadata.key_version)
        with self._lock:
            record = self._records.get(identity)
            if record is None or not record.resource_key:
                raise EncryptionKeyUnavailableError("resource key is unavailable")
        self.set_rotation_state(
            metadata.key_domain, metadata.key_id, metadata.key_version, "destroyed"
        )

    def resource_key_destroyed(self, metadata: EncryptionMetadata) -> bool:
        identity = (metadata.key_domain, metadata.key_id, metadata.key_version)
        with self._lock:
            record = self._records.get(identity)
            if record is None or not record.resource_key:
                raise EncryptionKeyUnavailableError("resource key is unavailable")
            embedded = record.metadata.model_copy(
                update={"rotation_state": metadata.rotation_state}
            )
            if embedded != metadata:
                raise EncryptionKeyUnavailableError("resource key metadata does not match")
            return record.metadata.rotation_state == "destroyed"

    def _seal_with_metadata(
        self,
        metadata: EncryptionMetadata,
        plaintext: bytes,
        aad: dict[str, object],
        *,
        nonce: bytes | None = None,
    ) -> EncryptedPayload:
        record = self._record_for(metadata, operation="encrypt")
        actual_nonce = secrets.token_bytes(24) if nonce is None else bytes(nonce)
        if len(actual_nonce) != 24:
            raise EncryptionKeyUnavailableError("encryption nonce does not meet provider policy")
        nonce_identity = (
            metadata.key_domain,
            metadata.key_id,
            metadata.key_version,
            actual_nonce,
        )
        with self._lock:
            if nonce_identity in self._used_nonces:
                raise EncryptionNonceReuseError("encryption nonce was already used")
            self._used_nonces.add(nonce_identity)
        aad_bytes = canonicalize(aad)
        ciphertext = self._xor_stream(record.material, actual_nonce, plaintext)
        tag = hmac.digest(
            self._mac_key(record.material), aad_bytes + actual_nonce + ciphertext, "sha256"
        )
        return EncryptedPayload(
            metadata=metadata,
            nonce=self._encode(actual_nonce),
            ciphertext=self._encode(ciphertext),
            authentication_tag=self._encode(tag),
            aad_digest=sha256_digest(aad),
        )

    def open(
        self, domain: KeyDomain, payload: EncryptedPayload, aad: dict[str, object]
    ) -> bytes:
        nonce, ciphertext = self._verified_ciphertext(domain, payload, aad)
        record = self._record_for(payload.metadata, operation="decrypt")
        return self._xor_stream(record.material, nonce, ciphertext)

    def verify(
        self, domain: KeyDomain, payload: EncryptedPayload, aad: dict[str, object]
    ) -> None:
        self._verified_ciphertext(domain, payload, aad)

    def _verified_ciphertext(
        self, domain: KeyDomain, payload: EncryptedPayload, aad: dict[str, object]
    ) -> tuple[bytes, bytes]:
        metadata = payload.metadata
        if metadata.key_domain != domain or metadata.encryption_algorithm != ALGORITHM:
            raise EncryptionKeyUnavailableError("ciphertext key domain or algorithm is unavailable")
        record = self._record_for(metadata, operation="decrypt")
        if metadata.key_separation_tag != record.metadata.key_separation_tag:
            raise EncryptionKeyUnavailableError("ciphertext key metadata does not match")
        if not hmac.compare_digest(payload.aad_digest, sha256_digest(aad)):
            raise EncryptionIntegrityError("authenticated data binding failed")
        try:
            nonce = self._decode(payload.nonce)
            ciphertext = self._decode(payload.ciphertext)
            tag = self._decode(payload.authentication_tag)
        except ValueError as exc:
            raise EncryptionIntegrityError("ciphertext encoding is invalid") from exc
        if len(nonce) != 24:
            raise EncryptionIntegrityError("ciphertext nonce is invalid")
        expected = hmac.digest(
            self._mac_key(record.material), canonicalize(aad) + nonce + ciphertext, "sha256"
        )
        if not hmac.compare_digest(expected, tag):
            raise EncryptionIntegrityError("ciphertext authentication failed")
        return nonce, ciphertext

    def metadata_id(self, metadata: EncryptionMetadata) -> str:
        return stable_id(
            "encryption",
            {
                "domain": metadata.key_domain,
                "key_id": metadata.key_id,
                "key_version": metadata.key_version,
                "algorithm": metadata.encryption_algorithm,
                "separation_tag": metadata.key_separation_tag,
            },
        )

    def keyed_digest(
        self,
        domain: KeyDomain,
        purpose: str,
        value: bytes,
        *,
        metadata: EncryptionMetadata | None = None,
    ) -> str:
        """Return a purpose-separated digest that does not support offline guesses."""

        if not purpose or not purpose.isascii():
            raise EncryptionKeyUnavailableError("keyed digest purpose is invalid")
        if metadata is None:
            metadata = self.get_active_key_metadata(domain)
        if metadata.key_domain != domain:
            raise EncryptionKeyUnavailableError("keyed digest domain is invalid")
        record = self._record_for(metadata, operation="decrypt")
        if record.parent_key is not None:
            with self._lock:
                parent = self._records.get((domain, *record.parent_key))
            if parent is None or parent.metadata.rotation_state not in {
                "active",
                "decrypt_only",
            }:
                raise EncryptionKeyUnavailableError("keyed digest parent is unavailable")
            record = parent
        purpose_key = hmac.digest(
            self._required_material(record),
            b"redteam-keyed-digest-v1\x00" + purpose.encode("ascii"),
            "sha256",
        )
        return "sha256:" + hmac.digest(purpose_key, value, "sha256").hex()

    def _record_for(
        self, metadata: EncryptionMetadata, *, operation: Literal["encrypt", "decrypt"]
    ) -> _KeyRecord:
        with self._lock:
            record = self._records.get(
                (metadata.key_domain, metadata.key_id, metadata.key_version)
            )
            allowed = {"active"} if operation == "encrypt" else {"active", "decrypt_only"}
            if record is None or record.metadata.rotation_state not in allowed:
                raise EncryptionKeyUnavailableError("required key version is unavailable")
            if record.parent_key is not None:
                parent = self._records.get(
                    (metadata.key_domain, record.parent_key[0], record.parent_key[1])
                )
                if parent is None or parent.metadata.rotation_state not in allowed:
                    raise EncryptionKeyUnavailableError("parent key version is unavailable")
            return record

    @staticmethod
    def _mac_key(material: bytes | bytearray | None) -> bytes:
        if material is None:
            raise EncryptionKeyUnavailableError("key material is destroyed")
        return hmac.digest(material, b"redteam-authentication-v1", "sha256")

    @staticmethod
    def _required_material(record: _KeyRecord) -> bytes | bytearray:
        if record.material is None:
            raise EncryptionKeyUnavailableError("key material is destroyed")
        return record.material

    @staticmethod
    def _xor_stream(
        material: bytes | bytearray | None, nonce: bytes, value: bytes
    ) -> bytes:
        if material is None:
            raise EncryptionKeyUnavailableError("key material is destroyed")
        output = bytearray(len(value))
        offset = 0
        counter = 0
        while offset < len(value):
            block = hmac.digest(
                material,
                b"redteam-encryption-v1" + nonce + counter.to_bytes(8, "big"),
                "sha256",
            )
            width = min(len(block), len(value) - offset)
            for index in range(width):
                output[offset + index] = value[offset + index] ^ block[index]
            offset += width
            counter += 1
        return bytes(output)

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.b64decode(value.encode("ascii"), validate=True)
