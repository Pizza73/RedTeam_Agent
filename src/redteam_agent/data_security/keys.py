"""Domain-separated authenticated encryption for trusted storage adapters.

The in-memory provider is development-only. The wrapped-file provider persists authenticated
ciphertext and requires its root wrapping key to come from an OS key store or external vault.
"""

from __future__ import annotations

import base64
import fcntl
import hmac
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Literal, Protocol

from pydantic import Field

from redteam_agent.canonical import (
    canonical_loads,
    canonicalize,
    sha256_digest,
    stable_id,
)
from redteam_agent.errors import (
    EncryptionIntegrityError,
    EncryptionKeyUnavailableError,
    EncryptionNonceReuseError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel

from .models import EncryptedPayload, EncryptionMetadata, KeyDomain, RotationState

ALGORITHM = "HMAC-SHA256-STREAM-v1"
_MAX_WRAPPED_STATE_BYTES = 16 * 1024 * 1024


class _PersistedKeyRecord(StrictImmutableBoundaryModel):
    metadata: EncryptionMetadata
    material: str | None
    resource_key: bool
    parent_key: tuple[str, int] | None


class _PersistedNonce(StrictImmutableBoundaryModel):
    domain: KeyDomain
    key_id: str
    key_version: int
    nonce: str


class _PersistedKeyState(StrictImmutableBoundaryModel):
    schema_version: Literal["wrapped-key-state-v2"]
    generation: int = Field(ge=1)
    records: tuple[_PersistedKeyRecord, ...]
    material_fingerprints: tuple[str, ...]
    used_nonces: tuple[_PersistedNonce, ...]


class _WrappedKeyState(StrictImmutableBoundaryModel):
    schema_version: Literal["wrapped-key-file-v2"]
    generation: int = Field(ge=1)
    nonce: str
    ciphertext: str
    authentication_tag: str


class KeyStateGenerationStore(Protocol):
    """OS-keystore/vault monotonic anchor for one wrapped state file."""

    def current_generation(self) -> int: ...

    def compare_and_set_generation(self, *, expected: int, new: int) -> bool: ...


class EncryptionKeyProvider(Protocol):
    def get_active_key_metadata(self, domain: KeyDomain) -> EncryptionMetadata: ...

    def get_key_metadata(
        self,
        domain: KeyDomain,
        key_id: str,
        key_version: int,
    ) -> EncryptionMetadata: ...

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

    def get_key_metadata(
        self,
        domain: KeyDomain,
        key_id: str,
        key_version: int,
    ) -> EncryptionMetadata:
        with self._lock:
            record = self._records.get((domain, key_id, key_version))
            if record is None:
                raise EncryptionKeyUnavailableError("key identity is unavailable")
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


class WrappedFileEncryptionKeyProvider(InMemoryEncryptionKeyProvider):
    """Explicit local provider whose state is wrapped by an external keystore key.

    The caller must obtain ``wrapping_key`` from an OS key store or vault. Only one
    authenticated ciphertext file is persisted; plaintext key material is never
    written to the application database, configuration, or filesystem.
    """

    def __init__(
        self,
        *,
        state_path: Path,
        wrapping_key: bytes,
        generation_store: KeyStateGenerationStore,
    ) -> None:
        super().__init__()
        if len(wrapping_key) < 32:
            raise EncryptionKeyUnavailableError(
                "key-state wrapping material does not meet provider policy"
            )
        absolute_path = Path(os.path.abspath(state_path))
        if not absolute_path.is_absolute() or absolute_path.name in {"", ".", ".."}:
            raise EncryptionKeyUnavailableError("key-state path is invalid")
        parent = absolute_path.parent
        try:
            parent_metadata = os.lstat(parent)
        except OSError as exc:
            raise EncryptionKeyUnavailableError(
                "key-state directory is unavailable"
            ) from exc
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) & 0o077
        ):
            raise EncryptionKeyUnavailableError(
                "key-state directory permissions are invalid"
            )
        self._state_path = absolute_path
        self._state_parent_identity = (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
        )
        self._wrapping_key = bytes(wrapping_key)
        self._generation_store = generation_store
        self._generation = 0
        self._state_lock_path = parent / f".{absolute_path.name}.lock"
        self._state_lock = RLock()
        self._updating = False
        with self._state_lock, self._locked_state_file():
            if absolute_path.exists() or absolute_path.is_symlink():
                self._load_persisted_state()
            elif self._external_generation() != 0:
                raise EncryptionKeyUnavailableError(
                    "key-state file is missing for external generation"
                )

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
        with self._update_state():
            return super().register_key(
                domain=domain,
                key_id=key_id,
                key_version=key_version,
                key_separation_tag=key_separation_tag,
                material=material,
                created_at=created_at,
                rotation_state=rotation_state,
            )

    def set_rotation_state(
        self,
        domain: KeyDomain,
        key_id: str,
        key_version: int,
        state: RotationState,
    ) -> None:
        with self._update_state():
            super().set_rotation_state(domain, key_id, key_version, state)

    def seal(
        self,
        domain: KeyDomain,
        plaintext: bytes,
        aad: dict[str, object],
        *,
        nonce: bytes | None = None,
    ) -> EncryptedPayload:
        with self._update_state():
            return super().seal(domain, plaintext, aad, nonce=nonce)

    def seal_for_resource(
        self,
        domain: KeyDomain,
        resource_id: str,
        plaintext: bytes,
        aad: dict[str, object],
        *,
        created_at: datetime,
    ) -> EncryptedPayload:
        with self._update_state():
            return super().seal_for_resource(
                domain,
                resource_id,
                plaintext,
                aad,
                created_at=created_at,
            )

    def destroy_resource_key(self, metadata: EncryptionMetadata) -> None:
        with self._update_state():
            identity = (metadata.key_domain, metadata.key_id, metadata.key_version)
            with self._lock:
                record = self._records.get(identity)
                if record is None or not record.resource_key:
                    raise EncryptionKeyUnavailableError("resource key is unavailable")
            InMemoryEncryptionKeyProvider.set_rotation_state(
                self,
                metadata.key_domain,
                metadata.key_id,
                metadata.key_version,
                "destroyed",
            )

    def get_active_key_metadata(self, domain: KeyDomain) -> EncryptionMetadata:
        self._refresh_if_idle()
        return super().get_active_key_metadata(domain)

    def get_key_metadata(
        self,
        domain: KeyDomain,
        key_id: str,
        key_version: int,
    ) -> EncryptionMetadata:
        self._refresh_if_idle()
        return super().get_key_metadata(domain, key_id, key_version)

    def open(
        self,
        domain: KeyDomain,
        payload: EncryptedPayload,
        aad: dict[str, object],
    ) -> bytes:
        self._refresh_if_idle()
        return super().open(domain, payload, aad)

    def verify(
        self,
        domain: KeyDomain,
        payload: EncryptedPayload,
        aad: dict[str, object],
    ) -> None:
        self._refresh_if_idle()
        super().verify(domain, payload, aad)

    def keyed_digest(
        self,
        domain: KeyDomain,
        purpose: str,
        value: bytes,
        *,
        metadata: EncryptionMetadata | None = None,
    ) -> str:
        self._refresh_if_idle()
        return super().keyed_digest(
            domain,
            purpose,
            value,
            metadata=metadata,
        )

    def resource_key_destroyed(self, metadata: EncryptionMetadata) -> bool:
        self._refresh_if_idle()
        return super().resource_key_destroyed(metadata)

    @contextmanager
    def _update_state(self) -> Iterator[None]:
        with self._state_lock, self._locked_state_file():
            if self._state_path.exists() or self._state_path.is_symlink():
                self._load_persisted_state()
            elif self._external_generation() != 0:
                raise EncryptionKeyUnavailableError(
                    "key-state file is missing for external generation"
                )
            snapshot = self._snapshot()
            generation = self._generation
            self._updating = True
            try:
                yield
                self._persist_state(expected_generation=generation)
            except Exception:
                self._restore(snapshot)
                self._generation = generation
                raise
            finally:
                self._updating = False

    def _refresh_if_idle(self) -> None:
        with self._state_lock:
            if self._updating:
                return
            with self._locked_state_file():
                if not (self._state_path.exists() or self._state_path.is_symlink()):
                    raise EncryptionKeyUnavailableError("key-state file is unavailable")
                self._load_persisted_state()

    def _snapshot(self) -> tuple[
        dict[tuple[KeyDomain, str, int], _KeyRecord],
        dict[KeyDomain, tuple[str, int]],
        set[str],
        set[str],
        set[bytes],
        set[tuple[KeyDomain, str, int, bytes]],
    ]:
        with self._lock:
            records = {
                identity: _KeyRecord(
                    metadata=record.metadata,
                    material=(
                        None
                        if record.material is None
                        else bytearray(record.material)
                    ),
                    resource_key=record.resource_key,
                    parent_key=record.parent_key,
                )
                for identity, record in self._records.items()
            }
            return (
                records,
                dict(self._active),
                set(self._key_ids),
                set(self._separation_tags),
                set(self._material_fingerprints),
                set(self._used_nonces),
            )

    def _restore(
        self,
        snapshot: tuple[
            dict[tuple[KeyDomain, str, int], _KeyRecord],
            dict[KeyDomain, tuple[str, int]],
            set[str],
            set[str],
            set[bytes],
            set[tuple[KeyDomain, str, int, bytes]],
        ],
    ) -> None:
        with self._lock:
            (
                self._records,
                self._active,
                self._key_ids,
                self._separation_tags,
                self._material_fingerprints,
                self._used_nonces,
            ) = snapshot

    def _persisted_state(self, *, generation: int) -> _PersistedKeyState:
        with self._lock:
            records = tuple(
                _PersistedKeyRecord(
                    metadata=record.metadata,
                    material=(
                        None
                        if record.material is None
                        else self._encode(bytes(record.material))
                    ),
                    resource_key=record.resource_key,
                    parent_key=record.parent_key,
                )
                for _, record in sorted(
                    self._records.items(),
                    key=lambda item: (item[0][0], item[0][1], item[0][2]),
                )
            )
            fingerprints = tuple(
                sorted(self._encode(value) for value in self._material_fingerprints)
            )
            nonces = tuple(
                _PersistedNonce(
                    domain=domain,
                    key_id=key_id,
                    key_version=key_version,
                    nonce=self._encode(nonce),
                )
                for domain, key_id, key_version, nonce in sorted(
                    self._used_nonces,
                    key=lambda item: (item[0], item[1], item[2], item[3]),
                )
            )
        return _PersistedKeyState(
            schema_version="wrapped-key-state-v2",
            generation=generation,
            records=records,
            material_fingerprints=fingerprints,
            used_nonces=nonces,
        )

    def _persist_state(self, *, expected_generation: int) -> None:
        if self._external_generation() != expected_generation:
            raise EncryptionKeyUnavailableError("external key-state generation changed")
        generation = expected_generation + 1
        plaintext = canonicalize(
            self._persisted_state(generation=generation).model_dump(mode="python")
        )
        nonce = secrets.token_bytes(24)
        encryption_key = hmac.digest(
            self._wrapping_key,
            b"redteam-key-state-encryption-v2",
            "sha256",
        )
        authentication_key = hmac.digest(
            self._wrapping_key,
            b"redteam-key-state-authentication-v2",
            "sha256",
        )
        ciphertext = self._xor_stream(encryption_key, nonce, plaintext)
        tag = hmac.digest(
            authentication_key,
            generation.to_bytes(16, "big") + nonce + ciphertext,
            "sha256",
        )
        wrapped = canonicalize(
            _WrappedKeyState(
                schema_version="wrapped-key-file-v2",
                generation=generation,
                nonce=self._encode(nonce),
                ciphertext=self._encode(ciphertext),
                authentication_tag=self._encode(tag),
            ).model_dump(mode="python")
        )
        self._write_wrapped_state_locked(wrapped)
        try:
            advanced = self._generation_store.compare_and_set_generation(
                expected=expected_generation,
                new=generation,
            )
        except Exception as exc:
            raise EncryptionKeyUnavailableError(
                "external key-state generation is unavailable"
            ) from exc
        if not advanced:
            raise EncryptionKeyUnavailableError(
                "external key-state generation update conflicted"
            )
        self._generation = generation

    def _load_persisted_state(self) -> None:
        raw = self._read_wrapped_state()
        try:
            duplicate_free = canonical_loads(raw)
            wrapped = _WrappedKeyState.model_validate_json(
                canonicalize(duplicate_free),
                strict=True,
            )
            nonce = self._decode(wrapped.nonce)
            ciphertext = self._decode(wrapped.ciphertext)
            actual_tag = self._decode(wrapped.authentication_tag)
        except (TypeError, ValueError) as exc:
            raise EncryptionKeyUnavailableError("key-state file is invalid") from exc
        if len(nonce) != 24:
            raise EncryptionKeyUnavailableError("key-state nonce is invalid")
        authentication_key = hmac.digest(
            self._wrapping_key,
            b"redteam-key-state-authentication-v2",
            "sha256",
        )
        expected_tag = hmac.digest(
            authentication_key,
            wrapped.generation.to_bytes(16, "big") + nonce + ciphertext,
            "sha256",
        )
        if not hmac.compare_digest(actual_tag, expected_tag):
            raise EncryptionKeyUnavailableError("key-state authentication failed")
        encryption_key = hmac.digest(
            self._wrapping_key,
            b"redteam-key-state-encryption-v2",
            "sha256",
        )
        plaintext = self._xor_stream(encryption_key, nonce, ciphertext)
        try:
            duplicate_free = canonical_loads(plaintext)
            state = _PersistedKeyState.model_validate_json(
                canonicalize(duplicate_free),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise EncryptionKeyUnavailableError("key-state payload is invalid") from exc
        if state.generation != wrapped.generation:
            raise EncryptionKeyUnavailableError("key-state generation binding failed")
        external_generation = self._external_generation()
        if state.generation != external_generation:
            raise EncryptionKeyUnavailableError(
                "key-state rollback or generation mismatch detected"
            )
        self._restore_loaded_state(state)
        self._generation = state.generation

    def _external_generation(self) -> int:
        try:
            generation = self._generation_store.current_generation()
        except Exception as exc:
            raise EncryptionKeyUnavailableError(
                "external key-state generation is unavailable"
            ) from exc
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
            or generation >= 2**128
        ):
            raise EncryptionKeyUnavailableError(
                "external key-state generation is invalid"
            )
        return generation

    def _restore_loaded_state(self, state: _PersistedKeyState) -> None:
        records: dict[tuple[KeyDomain, str, int], _KeyRecord] = {}
        active: dict[KeyDomain, tuple[str, int]] = {}
        key_ids: set[str] = set()
        separation_tags: set[str] = set()
        for persisted in state.records:
            metadata = persisted.metadata
            identity = (metadata.key_domain, metadata.key_id, metadata.key_version)
            try:
                material = (
                    None
                    if persisted.material is None
                    else bytearray(self._decode(persisted.material))
                )
            except ValueError as exc:
                raise EncryptionKeyUnavailableError(
                    "persisted key material is invalid"
                ) from exc
            if (
                identity in records
                or metadata.key_id in key_ids
                or metadata.key_separation_tag in separation_tags
                or (material is not None and len(material) < 32)
                or (metadata.rotation_state == "destroyed") != (material is None)
            ):
                raise EncryptionKeyUnavailableError(
                    "persisted key metadata is inconsistent"
                )
            records[identity] = _KeyRecord(
                metadata=metadata,
                material=material,
                resource_key=persisted.resource_key,
                parent_key=persisted.parent_key,
            )
            key_ids.add(metadata.key_id)
            separation_tags.add(metadata.key_separation_tag)
            if metadata.rotation_state == "active" and not persisted.resource_key:
                if metadata.key_domain in active:
                    raise EncryptionKeyUnavailableError(
                        "persisted key domain has multiple active versions"
                    )
                active[metadata.key_domain] = (
                    metadata.key_id,
                    metadata.key_version,
                )
        try:
            fingerprints = {
                self._decode(value) for value in state.material_fingerprints
            }
            used_nonces = {
                (
                    item.domain,
                    item.key_id,
                    item.key_version,
                    self._decode(item.nonce),
                )
                for item in state.used_nonces
            }
        except ValueError as exc:
            raise EncryptionKeyUnavailableError(
                "persisted key-state metadata is invalid"
            ) from exc
        live_fingerprints = {
            hmac.digest(b"redteam-key-equality-v1", record.material, "sha256")
            for record in records.values()
            if record.material is not None
        }
        if (
            len(fingerprints) != len(state.material_fingerprints)
            or len(used_nonces) != len(state.used_nonces)
            or not live_fingerprints.issubset(fingerprints)
            or any(
                len(item[3]) != 24 or item[:3] not in records for item in used_nonces
            )
        ):
            raise EncryptionKeyUnavailableError(
                "persisted key-state metadata is inconsistent"
            )
        for record in records.values():
            if record.parent_key is not None and (
                record.metadata.key_domain,
                record.parent_key[0],
                record.parent_key[1],
            ) not in records:
                raise EncryptionKeyUnavailableError(
                    "persisted resource-key parent is unavailable"
                )
        with self._lock:
            self._records = records
            self._active = active
            self._key_ids = key_ids
            self._separation_tags = separation_tags
            self._material_fingerprints = fingerprints
            self._used_nonces = used_nonces

    def _read_wrapped_state(self) -> bytes:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        try:
            directory_descriptor = os.open(self._state_path.parent, directory_flags)
        except OSError as exc:
            raise EncryptionKeyUnavailableError(
                "key-state directory is unavailable"
            ) from exc
        try:
            directory_metadata = os.fstat(directory_descriptor)
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or (directory_metadata.st_dev, directory_metadata.st_ino)
                != self._state_parent_identity
                or stat.S_IMODE(directory_metadata.st_mode) & 0o077
            ):
                raise EncryptionKeyUnavailableError(
                    "key-state directory identity changed"
                )
            descriptor_flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                descriptor_flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(
                    self._state_path.name,
                    descriptor_flags,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise EncryptionKeyUnavailableError(
                    "key-state file is unavailable"
                ) from exc
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise EncryptionKeyUnavailableError(
                        "key-state file permissions are invalid"
                    )
                chunks: list[bytes] = []
                total_size = 0
                while True:
                    chunk = os.read(descriptor, 64 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total_size += len(chunk)
                    if total_size > _MAX_WRAPPED_STATE_BYTES:
                        raise EncryptionKeyUnavailableError(
                            "key-state file exceeds provider limit"
                        )
                return b"".join(chunks)
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_descriptor)

    @contextmanager
    def _locked_state_file(self) -> Iterator[None]:
        lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        try:
            lock_descriptor = os.open(self._state_lock_path, lock_flags, 0o600)
        except OSError as exc:
            raise EncryptionKeyUnavailableError(
                "key-state lock is unavailable"
            ) from exc
        try:
            lock_metadata = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_nlink != 1
                or stat.S_IMODE(lock_metadata.st_mode) & 0o077
            ):
                raise EncryptionKeyUnavailableError("key-state lock is invalid")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise EncryptionKeyUnavailableError("key-state lock failed") from exc
        finally:
            with suppress(OSError):
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)

    def _write_wrapped_state_locked(self, content: bytes) -> None:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        try:
            directory_descriptor = os.open(self._state_path.parent, directory_flags)
        except OSError as exc:
            raise EncryptionKeyUnavailableError(
                "key-state directory is unavailable"
            ) from exc
        temporary_name: str | None = None
        try:
            directory_metadata = os.fstat(directory_descriptor)
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or (directory_metadata.st_dev, directory_metadata.st_ino)
                != self._state_parent_identity
                or stat.S_IMODE(directory_metadata.st_mode) & 0o077
            ):
                raise EncryptionKeyUnavailableError(
                    "key-state directory identity changed"
                )
            try:
                existing = os.stat(
                    self._state_path.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                existing = None
            if existing is not None and (
                not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
            ):
                raise EncryptionKeyUnavailableError("key-state target is invalid")
            file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            descriptor: int | None = None
            for _ in range(128):
                candidate = f".{self._state_path.name}.pending-{secrets.token_hex(16)}"
                try:
                    descriptor = os.open(
                        candidate,
                        file_flags,
                        0o600,
                        dir_fd=directory_descriptor,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            if descriptor is None or temporary_name is None:
                raise EncryptionKeyUnavailableError(
                    "key-state temporary file is unavailable"
                )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(
                temporary_name,
                self._state_path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_name = None
            os.fsync(directory_descriptor)
        except OSError as exc:
            raise EncryptionKeyUnavailableError("key-state write failed") from exc
        finally:
            if temporary_name is not None:
                with suppress(OSError):
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
