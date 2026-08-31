"""Encrypted mission-scoped storage boundaries for Phase 0C."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import AsyncIterator, Callable
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Literal, Protocol

from pydantic import Field

from redteam_agent.canonical import (
    CanonicalJsonObject,
    canonical_loads,
    canonicalize,
    sha256_digest,
    stable_id,
)
from redteam_agent.errors import (
    ArtifactSecurityError,
    DigestIntegrityError,
    SecretAccessError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import UtcDatetime, require_utc
from redteam_agent.models.context import ResourceBinding
from redteam_agent.models.scope import DataAccessOperation, DataResourceType

from .audit import DataStoreAuditRecorder
from .keys import EncryptionKeyProvider
from .models import (
    ArtifactReference,
    EncryptedPayload,
    KeyDomain,
    QuarantineReference,
    SecretReferenceMetadata,
)

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ARTIFACT_STREAM_CHUNK_BYTES = 4 * 1024


def _require_bytes(value: bytes) -> None:
    if not isinstance(value, bytes):
        raise ArtifactSecurityError("storage content must be bytes")


def _require_time(value: datetime) -> None:
    try:
        require_utc(value)
    except ValueError as exc:
        raise ArtifactSecurityError("storage time must be UTC") from exc


class DataAccessAuthorizer(Protocol):
    """Trusted adapter that revalidates a complete authorization envelope."""

    def require_access(
        self,
        *,
        mission_id: str,
        resource_type: DataResourceType,
        resource: ResourceBinding,
        operation: DataAccessOperation,
        now: datetime,
    ) -> None: ...

    def require_ingestion_write(
        self,
        *,
        mission_id: str,
        source_execution_id: str,
        resource_type: Literal["artifact", "secret_reference"],
        resource: ResourceBinding,
        now: datetime,
    ) -> None: ...


class _StoredEnvelope(StrictImmutableBoundaryModel):
    schema_version: Literal["encrypted-store-v1"]
    domain: KeyDomain
    mission_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    binding: CanonicalJsonObject
    plaintext_size: int = Field(ge=0)
    plaintext_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    created_at: UtcDatetime
    retention_until: UtcDatetime | None
    encryption_metadata_id: str = Field(min_length=1)
    payload: EncryptedPayload


class _SecretTombstone(StrictImmutableBoundaryModel):
    schema_version: Literal["secret-tombstone-v1"]
    metadata: SecretReferenceMetadata
    source_execution_id: str = Field(min_length=1)
    metadata_version: Literal[2]


class _ArtifactStreamChunkBinding(StrictImmutableBoundaryModel):
    record_type: Literal["artifact_stream_chunk"]
    stream_id: str = Field(min_length=1)
    source_execution_id: str = Field(min_length=1)
    sequence_number: int = Field(ge=0)
    plaintext_offset: int = Field(ge=0)
    plaintext_size: int = Field(ge=0)
    plaintext_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class _ArtifactStreamChunkReference(StrictImmutableBoundaryModel):
    resource_id: str = Field(min_length=1)
    sequence_number: int = Field(ge=0)
    plaintext_offset: int = Field(ge=0)
    plaintext_size: int = Field(ge=0)
    plaintext_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    encryption_metadata_id: str = Field(min_length=1)


class _ArtifactStreamManifest(StrictImmutableBoundaryModel):
    schema_version: Literal["artifact-stream-v1"]
    artifact_id: str = Field(min_length=1)
    stream_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    classification: Literal["normal", "sensitive", "secret"]
    variant: Literal["redacted", "encrypted_raw"]
    source_execution_id: str = Field(min_length=1)
    derived_from_artifact_id: str | None
    chunks: tuple[_ArtifactStreamChunkReference, ...]


class _EncryptedFileStore:
    def __init__(
        self,
        *,
        root: Path,
        domain: KeyDomain,
        keys: EncryptionKeyProvider,
        max_item_bytes: int,
        mission_quota_bytes: int,
    ) -> None:
        if max_item_bytes <= 0 or mission_quota_bytes <= 0:
            raise ArtifactSecurityError("storage limits must be positive")
        if root.exists() and root.is_symlink():
            raise ArtifactSecurityError("storage root may not be a symbolic link")
        root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        self._domain = domain
        self._keys = keys
        self._max_item_bytes = max_item_bytes
        self._mission_quota_bytes = mission_quota_bytes
        self._lock = RLock()

    def write(
        self,
        *,
        mission_id: str,
        resource_id: str,
        content: bytes,
        binding: dict[str, object],
        created_at: datetime,
        retention_until: datetime | None,
    ) -> tuple[str, str]:
        _require_bytes(content)
        if len(content) > self._max_item_bytes:
            raise ArtifactSecurityError("resource exceeds its size limit")
        path = self._path(mission_id, resource_id, create_parent=True)
        with self._lock:
            if path.exists():
                existing = self._load_envelope(path)
                if not (
                    existing.created_at == created_at
                    and existing.retention_until == retention_until
                ):
                    raise ArtifactSecurityError(
                        "resource identifier conflicts with stored metadata"
                    )
                plaintext = self._open_envelope(
                    existing,
                    mission_id=mission_id,
                    resource_id=resource_id,
                    binding=binding,
                    expected_encryption_metadata_id=existing.encryption_metadata_id,
                    now=None,
                )
                if plaintext != content:
                    raise ArtifactSecurityError("resource identifier conflicts with stored content")
                return existing.plaintext_sha256, existing.encryption_metadata_id
            if self._mission_usage(path.parent) + len(content) > self._mission_quota_bytes:
                raise ArtifactSecurityError("mission storage quota exceeded")
            content_digest = self._content_digest(content)
            aad = self._aad(
                mission_id,
                resource_id,
                binding,
                plaintext_size=len(content),
                plaintext_sha256=content_digest,
                created_at=created_at,
                retention_until=retention_until,
            )
            encrypted = self._keys.seal_for_resource(
                self._domain,
                resource_id,
                content,
                aad,
                created_at=created_at,
            )
            metadata_id = self._keys.metadata_id(encrypted.metadata)
            envelope = _StoredEnvelope(
                schema_version="encrypted-store-v1",
                domain=self._domain,
                mission_id=mission_id,
                resource_id=resource_id,
                binding=CanonicalJsonObject(binding),
                plaintext_size=len(content),
                plaintext_sha256=content_digest,
                created_at=created_at,
                retention_until=retention_until,
                encryption_metadata_id=metadata_id,
                payload=encrypted,
            )
            self._atomic_write(path, canonicalize(envelope.model_dump(mode="python")))
            return envelope.plaintext_sha256, metadata_id

    def read(
        self,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        now: datetime,
        expected_encryption_metadata_id: str,
    ) -> bytes:
        path = self._path(mission_id, resource_id, create_parent=False)
        envelope = self._load_envelope(path)
        return self._open_envelope(
            envelope,
            mission_id=mission_id,
            resource_id=resource_id,
            binding=binding,
            expected_encryption_metadata_id=expected_encryption_metadata_id,
            now=now,
        )

    def read_bound(
        self, *, mission_id: str, resource_id: str, now: datetime | None
    ) -> tuple[bytes, _StoredEnvelope]:
        path = self._path(mission_id, resource_id, create_parent=False)
        envelope = self._load_envelope(path)
        plaintext = self._open_envelope(
            envelope,
            mission_id=mission_id,
            resource_id=resource_id,
            binding=envelope.binding.to_dict(),
            expected_encryption_metadata_id=envelope.encryption_metadata_id,
            now=now,
        )
        return plaintext, envelope

    def verified_envelope(
        self, *, mission_id: str, resource_id: str, now: datetime | None
    ) -> _StoredEnvelope:
        path = self._path(mission_id, resource_id, create_parent=False)
        envelope = self._load_envelope(path)
        self._verify_envelope(
            envelope,
            mission_id=mission_id,
            resource_id=resource_id,
            binding=envelope.binding.to_dict(),
            expected_encryption_metadata_id=envelope.encryption_metadata_id,
            now=now,
        )
        return envelope

    def has_resource(self, *, mission_id: str, resource_id: str) -> bool:
        return self._path(mission_id, resource_id, create_parent=False).is_file()

    def envelopes_for(self, mission_id: str) -> tuple[_StoredEnvelope, ...]:
        mission_root = self._root / mission_id
        self._validate_token(mission_id)
        if not mission_root.exists():
            return ()
        if mission_root.is_symlink():
            raise ArtifactSecurityError("mission storage may not be a symbolic link")
        envelopes: list[_StoredEnvelope] = []
        for path in sorted(mission_root.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise ArtifactSecurityError("unexpected mission storage entry")
            envelope = self._load_envelope(path)
            self._verify_envelope(
                envelope,
                mission_id=mission_id,
                resource_id=envelope.resource_id,
                binding=envelope.binding.to_dict(),
                expected_encryption_metadata_id=envelope.encryption_metadata_id,
                now=None,
            )
            envelopes.append(envelope)
        return tuple(envelopes)

    def _open_envelope(
        self,
        envelope: _StoredEnvelope,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        expected_encryption_metadata_id: str,
        now: datetime | None,
    ) -> bytes:
        self._verify_envelope(
            envelope,
            mission_id=mission_id,
            resource_id=resource_id,
            binding=binding,
            expected_encryption_metadata_id=expected_encryption_metadata_id,
            now=now,
        )
        plaintext = self._keys.open(
            self._domain,
            envelope.payload,
            self._aad(
                mission_id,
                resource_id,
                binding,
                plaintext_size=envelope.plaintext_size,
                plaintext_sha256=envelope.plaintext_sha256,
                created_at=envelope.created_at,
                retention_until=envelope.retention_until,
            ),
        )
        if not (
            len(plaintext) == envelope.plaintext_size
            and self._content_digest(plaintext) == envelope.plaintext_sha256
        ):
            raise DigestIntegrityError("decrypted resource integrity failed")
        return plaintext

    def _verify_envelope(
        self,
        envelope: _StoredEnvelope,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        expected_encryption_metadata_id: str,
        now: datetime | None,
    ) -> None:
        expected_binding = CanonicalJsonObject(binding)
        if not (
            envelope.domain == self._domain
            and envelope.mission_id == mission_id
            and envelope.resource_id == resource_id
            and envelope.binding == expected_binding
            and envelope.encryption_metadata_id == expected_encryption_metadata_id
            and envelope.encryption_metadata_id == self._keys.metadata_id(envelope.payload.metadata)
        ):
            raise ArtifactSecurityError("encrypted resource binding is invalid")
        if (
            now is not None
            and envelope.retention_until is not None
            and now >= envelope.retention_until
        ):
            raise ArtifactSecurityError("encrypted resource retention has expired")
        self._keys.verify(
            self._domain,
            envelope.payload,
            self._aad(
                mission_id,
                resource_id,
                binding,
                plaintext_size=envelope.plaintext_size,
                plaintext_sha256=envelope.plaintext_sha256,
                created_at=envelope.created_at,
                retention_until=envelope.retention_until,
            ),
        )

    def delete(
        self,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        expected_encryption_metadata_id: str,
    ) -> None:
        path = self._path(mission_id, resource_id, create_parent=False)
        if not path.exists():
            return
        envelope = self._load_envelope(path)
        if not (
            envelope.binding == CanonicalJsonObject(binding)
            and envelope.encryption_metadata_id == expected_encryption_metadata_id
        ):
            raise ArtifactSecurityError("encrypted resource deletion binding is invalid")
        if not self._keys.resource_key_destroyed(envelope.payload.metadata):
            self._verify_envelope(
                envelope,
                mission_id=mission_id,
                resource_id=resource_id,
                binding=binding,
                expected_encryption_metadata_id=expected_encryption_metadata_id,
                now=None,
            )
        self.erase_resource(mission_id=mission_id, resource_id=resource_id)

    def erase_resource(self, *, mission_id: str, resource_id: str) -> None:
        """Idempotently finish cryptographic erasure after an unlink interruption."""

        path = self._path(mission_id, resource_id, create_parent=False)
        if not path.exists():
            return
        envelope = self._load_envelope(path)
        if not (
            envelope.domain == self._domain
            and envelope.mission_id == mission_id
            and envelope.resource_id == resource_id
            and envelope.encryption_metadata_id
            == self._keys.metadata_id(envelope.payload.metadata)
        ):
            raise ArtifactSecurityError("erasure target binding is invalid")
        if not self._keys.resource_key_destroyed(envelope.payload.metadata):
            self._verify_envelope(
                envelope,
                mission_id=mission_id,
                resource_id=resource_id,
                binding=envelope.binding.to_dict(),
                expected_encryption_metadata_id=envelope.encryption_metadata_id,
                now=None,
            )
            self._keys.destroy_resource_key(envelope.payload.metadata)
        try:
            path.unlink()
        except OSError as exc:
            raise ArtifactSecurityError("encrypted resource erasure failed") from exc

    def _path(self, mission_id: str, resource_id: str, *, create_parent: bool) -> Path:
        self._validate_token(mission_id)
        self._validate_token(resource_id)
        mission_root = self._root / mission_id
        if mission_root.exists() and mission_root.is_symlink():
            raise ArtifactSecurityError("mission storage may not be a symbolic link")
        if create_parent:
            mission_root.mkdir(mode=0o700, exist_ok=True)
        path = mission_root / f"{resource_id}.json"
        if path.exists() and path.is_symlink():
            raise ArtifactSecurityError("resource may not be a symbolic link")
        try:
            candidate = path.resolve(strict=False)
        except OSError as exc:
            raise ArtifactSecurityError("resource path cannot be resolved") from exc
        if not candidate.is_relative_to(self._root):
            raise ArtifactSecurityError("resource path escaped storage root")
        return path

    @staticmethod
    def _validate_token(value: str) -> None:
        if _SAFE_TOKEN.fullmatch(value) is None or value in {".", ".."}:
            raise ArtifactSecurityError("storage identifier is not an internal token")

    @staticmethod
    def _content_digest(content: bytes) -> str:
        return "sha256:" + hashlib.sha256(content).hexdigest()

    def _mission_usage(self, mission_root: Path) -> int:
        if not mission_root.exists():
            return 0
        total = 0
        for child in mission_root.iterdir():
            if child.is_symlink() or not child.is_file():
                raise ArtifactSecurityError("unexpected mission storage entry")
            envelope = self._load_envelope(child)
            if not (
                envelope.domain == self._domain
                and envelope.mission_id == mission_root.name
                and child.name == f"{envelope.resource_id}.json"
            ):
                raise ArtifactSecurityError("mission storage binding is invalid")
            self._verify_envelope(
                envelope,
                mission_id=envelope.mission_id,
                resource_id=envelope.resource_id,
                binding=envelope.binding.to_dict(),
                expected_encryption_metadata_id=envelope.encryption_metadata_id,
                now=None,
            )
            total += envelope.plaintext_size
        return total

    @staticmethod
    def _load_envelope(path: Path) -> _StoredEnvelope:
        try:
            raw = path.read_bytes()
            canonical_loads(raw)
            return _StoredEnvelope.model_validate_json(raw, strict=True)
        except (OSError, TypeError, ValueError) as exc:
            raise ArtifactSecurityError("encrypted resource metadata is unavailable") from exc

    def _aad(
        self,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        *,
        plaintext_size: int,
        plaintext_sha256: str,
        created_at: datetime,
        retention_until: datetime | None,
    ) -> dict[str, object]:
        return {
            "schema_version": "encrypted-store-aad-v1",
            "domain": self._domain,
            "mission_id": mission_id,
            "resource_id": resource_id,
            "binding": binding,
            "plaintext_size": plaintext_size,
            "plaintext_sha256": plaintext_sha256,
            "created_at": created_at,
            "retention_until": retention_until,
        }

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if path.exists() or path.is_symlink():
                raise ArtifactSecurityError("resource identifier already exists")
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()


class EncryptedRawResultQuarantine:
    def __init__(
        self,
        *,
        root: Path,
        keys: EncryptionKeyProvider,
        audit: DataStoreAuditRecorder,
        max_item_bytes: int,
        mission_quota_bytes: int,
    ) -> None:
        self._store = _EncryptedFileStore(
            root=root,
            domain="raw_result_quarantine",
            keys=keys,
            max_item_bytes=max_item_bytes,
            mission_quota_bytes=mission_quota_bytes,
        )
        self._audit = audit

    def commit(
        self,
        *,
        mission_id: str,
        mission_revision: int,
        execution_id: str,
        content: bytes,
        created_at: datetime,
        retention_until: datetime,
    ) -> QuarantineReference:
        _require_bytes(content)
        _require_time(created_at)
        _require_time(retention_until)
        if mission_revision < 1 or retention_until <= created_at:
            raise ArtifactSecurityError("quarantine binding or retention is invalid")
        binding: dict[str, object] = {
            "mission_revision": mission_revision,
            "execution_id": execution_id,
        }
        resource_id = stable_id(
            "quarantine",
            {
                "mission_id": mission_id,
                **binding,
                "content_sha256": _EncryptedFileStore._content_digest(content),
            },
        )
        digest, metadata_id = self._store.write(
            mission_id=mission_id,
            resource_id=resource_id,
            content=content,
            binding=binding,
            created_at=created_at,
            retention_until=retention_until,
        )
        reference = QuarantineReference(
            quarantine_id=resource_id,
            mission_id=mission_id,
            mission_revision=mission_revision,
            execution_id=execution_id,
            size_bytes=len(content),
            sha256=digest,
            encryption_metadata_id=metadata_id,
            created_at=created_at,
            retention_until=retention_until,
        )
        self._audit.record(
            mission_id=mission_id,
            resource_type="raw_result_quarantine",
            resource_id=resource_id,
            operation="commit",
            metadata_digest=digest,
            occurred_at=created_at,
        )
        return reference

    def resume(self, reference: QuarantineReference, *, now: datetime) -> bytes:
        content = self._store.read(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
            binding={
                "mission_revision": reference.mission_revision,
                "execution_id": reference.execution_id,
            },
            now=now,
            expected_encryption_metadata_id=reference.encryption_metadata_id,
        )
        if not (
            len(content) == reference.size_bytes
            and self._store._content_digest(content) == reference.sha256
        ):
            raise DigestIntegrityError("quarantine reference integrity failed")
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=reference.quarantine_id,
            operation="resume",
            metadata_digest=reference.sha256,
            occurred_at=now,
        )
        return content

    def delete(self, reference: QuarantineReference, *, now: datetime) -> None:
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=reference.quarantine_id,
            operation="delete",
            metadata_digest=reference.sha256,
            occurred_at=now,
        )
        self._store.delete(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
            binding={
                "mission_revision": reference.mission_revision,
                "execution_id": reference.execution_id,
            },
            expected_encryption_metadata_id=reference.encryption_metadata_id,
        )


class ArtifactStore:
    def __init__(
        self,
        *,
        root: Path,
        keys: EncryptionKeyProvider,
        authorizer: DataAccessAuthorizer,
        audit: DataStoreAuditRecorder,
        max_item_bytes: int,
        mission_quota_bytes: int,
    ) -> None:
        self._store = _EncryptedFileStore(
            root=root,
            domain="artifact_store",
            keys=keys,
            max_item_bytes=max_item_bytes,
            mission_quota_bytes=mission_quota_bytes,
        )
        self._authorizer = authorizer
        self._audit = audit
        self.max_observed_stream_chunk_bytes = 0

    def put(
        self,
        *,
        mission_id: str,
        content: bytes,
        media_type: str,
        classification: Literal["normal", "sensitive", "secret"],
        variant: Literal["redacted", "encrypted_raw"],
        source_execution_id: str,
        created_at: datetime,
        retention_until: datetime | None = None,
        derived_from_artifact_id: str | None = None,
    ) -> ArtifactReference:
        _require_bytes(content)
        self._validate_metadata(
            media_type=media_type,
            classification=classification,
            variant=variant,
            created_at=created_at,
            retention_until=retention_until,
        )
        content_digest = self._store._content_digest(content)
        artifact_id = self._artifact_id(
            mission_id=mission_id,
            content_digest=content_digest,
            classification=classification,
            variant=variant,
            derived_from_artifact_id=derived_from_artifact_id,
        )
        binding = self._binding(
            artifact_id=artifact_id,
            media_type=media_type,
            classification=classification,
            variant=variant,
            derived_from_artifact_id=derived_from_artifact_id,
            source_execution_id=source_execution_id,
        )
        self._authorizer.require_ingestion_write(
            mission_id=mission_id,
            source_execution_id=source_execution_id,
            resource_type="artifact",
            resource=ResourceBinding(
                resource_id=artifact_id,
                resource_version="1",
                resource_digest=content_digest,
            ),
            now=created_at,
        )
        if self._store.has_resource(mission_id=mission_id, resource_id=artifact_id):
            existing_content, envelope = self._store.read_bound(
                mission_id=mission_id,
                resource_id=artifact_id,
                now=None,
            )
            if not (
                existing_content == content
                and envelope.binding == CanonicalJsonObject(binding)
                and envelope.retention_until == retention_until
            ):
                raise ArtifactSecurityError(
                    "artifact identifier conflicts with stored content"
                )
        else:
            self._store.write(
                mission_id=mission_id,
                resource_id=artifact_id,
                content=content,
                binding=binding,
                created_at=created_at,
                retention_until=retention_until,
            )
            envelope = self._store.verified_envelope(
                mission_id=mission_id,
                resource_id=artifact_id,
                now=None,
            )
        reference = ArtifactReference(
            artifact_id=artifact_id,
            mission_id=mission_id,
            media_type=media_type,
            size_bytes=len(content),
            sha256=content_digest,
            classification=classification,
            variant=variant,
            encrypted=True,
            encryption_metadata_id=envelope.encryption_metadata_id,
            derived_from_artifact_id=derived_from_artifact_id,
            created_at=envelope.created_at,
            retention_until=envelope.retention_until,
        )
        self._reconcile_create_audit(reference)
        return reference

    async def put_stream(
        self,
        *,
        mission_id: str,
        chunks: AsyncIterator[bytes],
        media_type: str,
        classification: Callable[
            [], Literal["normal", "sensitive", "secret"]
        ],
        variant: Literal["redacted", "encrypted_raw"],
        source_execution_id: str,
        created_at: datetime,
        retention_until: datetime | None = None,
        derived_from_artifact_id: str | None = None,
    ) -> ArtifactReference:
        """Persist a logical artifact without materializing the complete content."""

        _require_time(created_at)
        if not media_type or variant not in {"redacted", "encrypted_raw"}:
            raise ArtifactSecurityError("artifact stream metadata is invalid")
        if retention_until is not None:
            _require_time(retention_until)
            if retention_until <= created_at:
                raise ArtifactSecurityError("artifact retention is invalid")
        stream_id = stable_id(
            "artifactstream",
            {
                "schema_version": "artifact-stream-v1",
                "mission_id": mission_id,
                "media_type": media_type,
                "variant": variant,
                "source_execution_id": source_execution_id,
                "derived_from_artifact_id": derived_from_artifact_id,
            },
        )
        stream_metadata_digest = sha256_digest(
            {
                "stream_id": stream_id,
                "mission_id": mission_id,
                "media_type": media_type,
                "variant": variant,
                "source_execution_id": source_execution_id,
                "derived_from_artifact_id": derived_from_artifact_id,
            }
        )
        self._authorizer.require_ingestion_write(
            mission_id=mission_id,
            source_execution_id=source_execution_id,
            resource_type="artifact",
            resource=ResourceBinding(
                resource_id=stream_id,
                resource_version="1",
                resource_digest=stream_metadata_digest,
            ),
            now=created_at,
        )
        digest = hashlib.sha256()
        size_bytes = 0
        sequence = 0
        pending = bytearray()
        chunk_references: list[_ArtifactStreamChunkReference] = []

        async def persist(content: bytes) -> None:
            nonlocal sequence, size_bytes
            next_size = size_bytes + len(content)
            if next_size > self._store._max_item_bytes:
                raise ArtifactSecurityError("resource exceeds its size limit")
            content_digest = self._store._content_digest(content)
            binding = _ArtifactStreamChunkBinding(
                record_type="artifact_stream_chunk",
                stream_id=stream_id,
                source_execution_id=source_execution_id,
                sequence_number=sequence,
                plaintext_offset=size_bytes,
                plaintext_size=len(content),
                plaintext_sha256=content_digest,
            )
            resource_id = stable_id(
                "artifactchunk",
                {
                    "schema_version": "artifact-stream-chunk-v1",
                    "stream_id": stream_id,
                    "sequence_number": sequence,
                },
            )
            if self._store.has_resource(
                mission_id=mission_id, resource_id=resource_id
            ):
                existing, envelope = self._store.read_bound(
                    mission_id=mission_id,
                    resource_id=resource_id,
                    now=None,
                )
                if not (
                    existing == content
                    and envelope.binding
                    == CanonicalJsonObject(binding.model_dump(mode="python"))
                    and envelope.retention_until == retention_until
                ):
                    raise ArtifactSecurityError(
                        "artifact stream chunk conflicts with durable content"
                    )
            else:
                self._store.write(
                    mission_id=mission_id,
                    resource_id=resource_id,
                    content=content,
                    binding=binding.model_dump(mode="python"),
                    created_at=created_at,
                    retention_until=retention_until,
                )
                envelope = self._store.verified_envelope(
                    mission_id=mission_id,
                    resource_id=resource_id,
                    now=None,
                )
            digest.update(content)
            self.max_observed_stream_chunk_bytes = max(
                self.max_observed_stream_chunk_bytes, len(content)
            )
            chunk_references.append(
                _ArtifactStreamChunkReference(
                    resource_id=resource_id,
                    sequence_number=sequence,
                    plaintext_offset=size_bytes,
                    plaintext_size=len(content),
                    plaintext_sha256=content_digest,
                    encryption_metadata_id=envelope.encryption_metadata_id,
                )
            )
            size_bytes = next_size
            sequence += 1

        async for chunk in chunks:
            _require_bytes(chunk)
            pending.extend(chunk)
            while len(pending) >= _ARTIFACT_STREAM_CHUNK_BYTES:
                content = bytes(pending[:_ARTIFACT_STREAM_CHUNK_BYTES])
                del pending[:_ARTIFACT_STREAM_CHUNK_BYTES]
                await persist(content)
        if pending or not chunk_references:
            await persist(bytes(pending))

        content_digest = "sha256:" + digest.hexdigest()
        resolved_classification = classification()
        self._validate_metadata(
            media_type=media_type,
            classification=resolved_classification,
            variant=variant,
            created_at=created_at,
            retention_until=retention_until,
        )
        artifact_id = self._artifact_id(
            mission_id=mission_id,
            content_digest=content_digest,
            classification=resolved_classification,
            variant=variant,
            derived_from_artifact_id=derived_from_artifact_id,
        )
        manifest = _ArtifactStreamManifest(
            schema_version="artifact-stream-v1",
            artifact_id=artifact_id,
            stream_id=stream_id,
            mission_id=mission_id,
            media_type=media_type,
            size_bytes=size_bytes,
            sha256=content_digest,
            classification=resolved_classification,
            variant=variant,
            source_execution_id=source_execution_id,
            derived_from_artifact_id=derived_from_artifact_id,
            chunks=tuple(chunk_references),
        )
        binding = self._binding(
            artifact_id=artifact_id,
            media_type=media_type,
            classification=resolved_classification,
            variant=variant,
            derived_from_artifact_id=derived_from_artifact_id,
            source_execution_id=source_execution_id,
            storage_format="artifact-stream-v1",
            logical_size=size_bytes,
            logical_sha256=content_digest,
            stream_id=stream_id,
        )
        self._authorizer.require_ingestion_write(
            mission_id=mission_id,
            source_execution_id=source_execution_id,
            resource_type="artifact",
            resource=ResourceBinding(
                resource_id=artifact_id,
                resource_version="1",
                resource_digest=content_digest,
            ),
            now=created_at,
        )
        manifest_content = canonicalize(manifest.model_dump(mode="python"))
        if self._store.has_resource(mission_id=mission_id, resource_id=artifact_id):
            existing, envelope = self._store.read_bound(
                mission_id=mission_id,
                resource_id=artifact_id,
                now=None,
            )
            if not (
                existing == manifest_content
                and envelope.binding == CanonicalJsonObject(binding)
                and envelope.retention_until == retention_until
            ):
                raise ArtifactSecurityError(
                    "artifact stream manifest conflicts with durable content"
                )
        else:
            self._store.write(
                mission_id=mission_id,
                resource_id=artifact_id,
                content=manifest_content,
                binding=binding,
                created_at=created_at,
                retention_until=retention_until,
            )
            envelope = self._store.verified_envelope(
                mission_id=mission_id,
                resource_id=artifact_id,
                now=None,
            )
        reference = ArtifactReference(
            artifact_id=artifact_id,
            mission_id=mission_id,
            media_type=media_type,
            size_bytes=size_bytes,
            sha256=content_digest,
            classification=resolved_classification,
            variant=variant,
            encrypted=True,
            encryption_metadata_id=envelope.encryption_metadata_id,
            derived_from_artifact_id=derived_from_artifact_id,
            created_at=envelope.created_at,
            retention_until=envelope.retention_until,
        )
        self._reconcile_create_audit(reference)
        return reference

    def read(
        self,
        reference: ArtifactReference,
        *,
        operation: Literal["read", "export"],
        now: datetime,
    ) -> bytes:
        authoritative = self._stored_reference(
            mission_id=reference.mission_id,
            artifact_id=reference.artifact_id,
            now=now,
        )
        if authoritative != reference:
            raise DigestIntegrityError("artifact reference integrity failed")
        self._reconcile_create_audit(authoritative)
        self._authorizer.require_access(
            mission_id=reference.mission_id,
            resource_type="artifact",
            resource=ResourceBinding(
                resource_id=reference.artifact_id,
                resource_version="1",
                resource_digest=reference.sha256,
            ),
            operation=operation,
            now=now,
        )
        envelope = self._store.verified_envelope(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
            now=now,
        )
        if envelope.binding.to_dict().get("storage_format") == "artifact-stream-v1":
            content = self._read_stream(reference, now=now)
        else:
            content = self._store.read(
                mission_id=reference.mission_id,
                resource_id=reference.artifact_id,
                binding=self._binding(
                    artifact_id=reference.artifact_id,
                    media_type=reference.media_type,
                    classification=reference.classification,
                    variant=reference.variant,
                    derived_from_artifact_id=reference.derived_from_artifact_id,
                    source_execution_id=self._source_execution_id(reference),
                ),
                now=now,
                expected_encryption_metadata_id=reference.encryption_metadata_id or "",
            )
        if not (
            len(content) == reference.size_bytes
            and self._store._content_digest(content) == reference.sha256
        ):
            raise DigestIntegrityError("artifact reference integrity failed")
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="artifact",
            resource_id=reference.artifact_id,
            operation=operation,
            metadata_digest=reference.sha256,
            occurred_at=now,
        )
        return content

    def _read_stream(self, reference: ArtifactReference, *, now: datetime) -> bytes:
        raw, envelope = self._store.read_bound(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
            now=now,
        )
        try:
            canonical_loads(raw)
            manifest = _ArtifactStreamManifest.model_validate_json(raw, strict=True)
        except (TypeError, ValueError) as exc:
            raise ArtifactSecurityError("artifact stream manifest is invalid") from exc
        if not self._manifest_matches_reference(manifest, reference, envelope):
            raise DigestIntegrityError("artifact stream manifest binding failed")
        output = bytearray()
        expected_offset = 0
        for expected_sequence, chunk in enumerate(manifest.chunks):
            content, chunk_envelope = self._store.read_bound(
                mission_id=reference.mission_id,
                resource_id=chunk.resource_id,
                now=now,
            )
            try:
                binding = _ArtifactStreamChunkBinding.model_validate(
                    chunk_envelope.binding.to_dict()
                )
            except ValueError as exc:
                raise ArtifactSecurityError("artifact stream chunk binding is invalid") from exc
            if not (
                chunk.sequence_number == expected_sequence
                and chunk.plaintext_offset == expected_offset
                and binding.stream_id == manifest.stream_id
                and binding.source_execution_id == manifest.source_execution_id
                and binding.sequence_number == chunk.sequence_number
                and binding.plaintext_offset == chunk.plaintext_offset
                and binding.plaintext_size == chunk.plaintext_size == len(content)
                and binding.plaintext_sha256
                == chunk.plaintext_sha256
                == self._store._content_digest(content)
                and chunk.encryption_metadata_id
                == chunk_envelope.encryption_metadata_id
            ):
                raise DigestIntegrityError("artifact stream chunk integrity failed")
            output.extend(content)
            expected_offset += len(content)
        result = bytes(output)
        if not (
            len(result) == reference.size_bytes == expected_offset
            and self._store._content_digest(result) == reference.sha256
        ):
            raise DigestIntegrityError("artifact stream aggregate integrity failed")
        return result

    def _stored_reference(
        self, *, mission_id: str, artifact_id: str, now: datetime | None
    ) -> ArtifactReference:
        envelope = self._store.verified_envelope(
            mission_id=mission_id,
            resource_id=artifact_id,
            now=now,
        )
        binding = envelope.binding.to_dict()
        if binding.get("storage_format") == "artifact-stream-v1":
            expected_keys = {
                "artifact_id",
                "media_type",
                "classification",
                "variant",
                "derived_from_artifact_id",
                "source_execution_id",
                "storage_format",
                "logical_size",
                "logical_sha256",
                "stream_id",
            }
            if set(binding) != expected_keys:
                raise ArtifactSecurityError("artifact stream binding is invalid")
            logical_size = binding["logical_size"]
            classification = binding["classification"]
            variant = binding["variant"]
            if not (
                binding["artifact_id"] == artifact_id
                and isinstance(logical_size, int)
                and not isinstance(logical_size, bool)
                and classification in {"normal", "sensitive", "secret"}
                and variant in {"redacted", "encrypted_raw"}
                and isinstance(binding["source_execution_id"], str)
                and isinstance(binding["stream_id"], str)
            ):
                raise ArtifactSecurityError("artifact stream binding is invalid")
            return ArtifactReference(
                artifact_id=artifact_id,
                mission_id=mission_id,
                media_type=str(binding["media_type"]),
                size_bytes=logical_size,
                sha256=str(binding["logical_sha256"]),
                classification=classification,
                variant=variant,
                encrypted=True,
                encryption_metadata_id=envelope.encryption_metadata_id,
                derived_from_artifact_id=(
                    None
                    if binding["derived_from_artifact_id"] is None
                    else str(binding["derived_from_artifact_id"])
                ),
                created_at=envelope.created_at,
                retention_until=envelope.retention_until,
            )
        expected_keys = {
            "artifact_id",
            "media_type",
            "classification",
            "variant",
            "derived_from_artifact_id",
            "source_execution_id",
        }
        if set(binding) != expected_keys:
            raise ArtifactSecurityError("artifact binding is invalid")
        return ArtifactReference(
            artifact_id=artifact_id,
            mission_id=mission_id,
            media_type=str(binding["media_type"]),
            size_bytes=envelope.plaintext_size,
            sha256=envelope.plaintext_sha256,
            classification=str(binding["classification"]),  # type: ignore[arg-type]
            variant=str(binding["variant"]),  # type: ignore[arg-type]
            encrypted=True,
            encryption_metadata_id=envelope.encryption_metadata_id,
            derived_from_artifact_id=(
                None
                if binding["derived_from_artifact_id"] is None
                else str(binding["derived_from_artifact_id"])
            ),
            created_at=envelope.created_at,
            retention_until=envelope.retention_until,
        )

    @staticmethod
    def _binding(
        *,
        artifact_id: str,
        media_type: str,
        classification: Literal["normal", "sensitive", "secret"],
        variant: Literal["redacted", "encrypted_raw"],
        derived_from_artifact_id: str | None,
        source_execution_id: str,
        **extra: object,
    ) -> dict[str, object]:
        return {
            "artifact_id": artifact_id,
            "media_type": media_type,
            "classification": classification,
            "variant": variant,
            "derived_from_artifact_id": derived_from_artifact_id,
            "source_execution_id": source_execution_id,
            **extra,
        }

    @staticmethod
    def _artifact_id(
        *,
        mission_id: str,
        content_digest: str,
        classification: str,
        variant: str,
        derived_from_artifact_id: str | None,
    ) -> str:
        return stable_id(
            "artifact",
            {
                "mission_id": mission_id,
                "content_sha256": content_digest,
                "classification": classification,
                "variant": variant,
                "derived_from": derived_from_artifact_id,
            },
        )

    @staticmethod
    def _validate_metadata(
        *,
        media_type: str,
        classification: str,
        variant: str,
        created_at: datetime,
        retention_until: datetime | None,
    ) -> None:
        _require_time(created_at)
        if not media_type:
            raise ArtifactSecurityError("artifact media type is required")
        if classification not in {"normal", "sensitive", "secret"}:
            raise ArtifactSecurityError("artifact classification is invalid")
        if variant not in {"redacted", "encrypted_raw"}:
            raise ArtifactSecurityError("artifact variant is invalid")
        if variant == "encrypted_raw" and classification != "secret":
            raise ArtifactSecurityError("encrypted raw artifact classification is invalid")
        if retention_until is not None:
            _require_time(retention_until)
            if retention_until <= created_at:
                raise ArtifactSecurityError("artifact retention is invalid")

    def _manifest_matches_reference(
        self,
        manifest: _ArtifactStreamManifest,
        reference: ArtifactReference,
        envelope: _StoredEnvelope,
    ) -> bool:
        return (
            manifest.artifact_id == reference.artifact_id == envelope.resource_id
            and manifest.mission_id == reference.mission_id == envelope.mission_id
            and manifest.media_type == reference.media_type
            and manifest.size_bytes == reference.size_bytes
            and manifest.sha256 == reference.sha256
            and manifest.classification == reference.classification
            and manifest.variant == reference.variant
            and manifest.derived_from_artifact_id
            == reference.derived_from_artifact_id
            and envelope.binding
            == CanonicalJsonObject(
                self._binding(
                    artifact_id=manifest.artifact_id,
                    media_type=manifest.media_type,
                    classification=manifest.classification,
                    variant=manifest.variant,
                    derived_from_artifact_id=manifest.derived_from_artifact_id,
                    source_execution_id=manifest.source_execution_id,
                    storage_format="artifact-stream-v1",
                    logical_size=manifest.size_bytes,
                    logical_sha256=manifest.sha256,
                    stream_id=manifest.stream_id,
                )
            )
        )

    def _reconcile_create_audit(self, reference: ArtifactReference) -> None:
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="artifact",
            resource_id=reference.artifact_id,
            operation="create",
            operation_id=stable_id(
                "auditop",
                {
                    "schema_version": "artifact-create-audit-v1",
                    "artifact_id": reference.artifact_id,
                },
            ),
            metadata_digest=reference.sha256,
            occurred_at=reference.created_at,
        )

    def _source_execution_id(self, reference: ArtifactReference) -> str:
        envelope = self._store._load_envelope(
            self._store._path(reference.mission_id, reference.artifact_id, create_parent=False)
        )
        value = envelope.binding.to_dict().get("source_execution_id")
        if not isinstance(value, str) or not value:
            raise ArtifactSecurityError("artifact source execution binding is invalid")
        return value


class SecretStore:
    def __init__(
        self,
        *,
        root: Path,
        keys: EncryptionKeyProvider,
        authorizer: DataAccessAuthorizer,
        audit: DataStoreAuditRecorder,
        max_item_bytes: int,
        mission_quota_bytes: int,
    ) -> None:
        self._store = _EncryptedFileStore(
            root=root,
            domain="secret_store",
            keys=keys,
            max_item_bytes=max_item_bytes,
            mission_quota_bytes=mission_quota_bytes,
        )
        self._authorizer = authorizer
        self._audit = audit

    def create(
        self,
        *,
        mission_id: str,
        secret_value: bytes,
        credential_type: str,
        associated_principal_ref: str | None,
        source_execution_id: str,
        created_at: datetime,
        expires_at: datetime | None = None,
    ) -> SecretReferenceMetadata:
        _require_bytes(secret_value)
        _require_time(created_at)
        if not secret_value or not credential_type or not source_execution_id:
            raise SecretAccessError("secret metadata or value is incomplete")
        if expires_at is not None:
            _require_time(expires_at)
            if expires_at <= created_at:
                raise SecretAccessError("secret expiry is invalid")
        secret_reference_id = stable_id(
            "secret",
            {
                "mission_id": mission_id,
                "source_execution_id": source_execution_id,
                "credential_type": credential_type,
                "secret_digest": self._store._content_digest(secret_value),
            },
        )
        binding: dict[str, object] = {
            "secret_reference_id": secret_reference_id,
            "credential_type": credential_type,
            "associated_principal_ref": associated_principal_ref,
            "source_execution_id": source_execution_id,
            "verification_state": "detected",
            "metadata_version": 1,
        }
        write_binding = ResourceBinding(
            resource_id=secret_reference_id,
            resource_version="1",
            resource_digest=self._store._content_digest(secret_value),
        )
        self._authorizer.require_ingestion_write(
            mission_id=mission_id,
            source_execution_id=source_execution_id,
            resource_type="secret_reference",
            resource=write_binding,
            now=created_at,
        )
        if self._store.has_resource(
            mission_id=mission_id, resource_id=secret_reference_id
        ):
            existing, envelope = self._store.read_bound(
                mission_id=mission_id,
                resource_id=secret_reference_id,
                now=None,
            )
            if not (
                existing == secret_value
                and envelope.binding == CanonicalJsonObject(binding)
                and envelope.retention_until == expires_at
            ):
                raise SecretAccessError(
                    "secret reference conflicts with durable content"
                )
        else:
            self._store.write(
                mission_id=mission_id,
                resource_id=secret_reference_id,
                content=secret_value,
                binding=binding,
                created_at=created_at,
                retention_until=expires_at,
            )
            envelope = self._store.verified_envelope(
                mission_id=mission_id,
                resource_id=secret_reference_id,
                now=None,
            )
        metadata = SecretReferenceMetadata(
            secret_reference_id=secret_reference_id,
            mission_id=mission_id,
            credential_type=credential_type,
            associated_principal_ref=associated_principal_ref,
            encryption_metadata_id=envelope.encryption_metadata_id,
            created_at=envelope.created_at,
            expires_at=expires_at,
            verification_state="detected",
        )
        self._audit.record(
            mission_id=mission_id,
            resource_type="secret_reference",
            resource_id=secret_reference_id,
            operation="create",
            operation_id=stable_id(
                "auditop",
                {
                    "schema_version": "secret-create-audit-v1",
                    "secret_reference_id": secret_reference_id,
                },
            ),
            metadata_digest=sha256_digest(metadata),
            occurred_at=envelope.created_at,
        )
        return metadata

    def resolve(
        self,
        reference: SecretReferenceMetadata,
        *,
        now: datetime,
    ) -> bytes:
        authoritative, source_execution_id, version = self._authoritative_metadata(reference)
        if authoritative.verification_state == "revoked":
            raise SecretAccessError("secret reference is revoked")
        self._authorizer.require_access(
            mission_id=authoritative.mission_id,
            resource_type="secret_reference",
            resource=ResourceBinding(
                resource_id=authoritative.secret_reference_id,
                resource_version=str(version),
                resource_digest=sha256_digest(authoritative),
            ),
            operation="resolve",
            now=now,
        )
        value = self._store.read(
            mission_id=authoritative.mission_id,
            resource_id=authoritative.secret_reference_id,
            binding={
                "secret_reference_id": authoritative.secret_reference_id,
                "credential_type": authoritative.credential_type,
                "associated_principal_ref": authoritative.associated_principal_ref,
                "source_execution_id": source_execution_id,
                "verification_state": authoritative.verification_state,
                "metadata_version": version,
            },
            now=now,
            expected_encryption_metadata_id=authoritative.encryption_metadata_id,
        )
        self._audit.record(
            mission_id=authoritative.mission_id,
            resource_type="secret_reference",
            resource_id=authoritative.secret_reference_id,
            operation="resolve",
            metadata_digest=sha256_digest(authoritative),
            occurred_at=now,
        )
        return value

    def revoke(
        self, reference: SecretReferenceMetadata, *, now: datetime
    ) -> SecretReferenceMetadata:
        authoritative, source_execution_id, version = self._authoritative_metadata(reference)
        self._authorizer.require_access(
            mission_id=authoritative.mission_id,
            resource_type="secret_reference",
            resource=ResourceBinding(
                resource_id=authoritative.secret_reference_id,
                resource_version=str(version),
                resource_digest=sha256_digest(authoritative),
            ),
            operation="write",
            now=now,
        )
        if authoritative.verification_state == "revoked":
            self._audit.record(
                mission_id=authoritative.mission_id,
                resource_type="secret_reference",
                resource_id=authoritative.secret_reference_id,
                operation="revoke",
                metadata_digest=sha256_digest(authoritative),
                occurred_at=now,
            )
            return authoritative
        revoked = authoritative.model_copy(update={"verification_state": "revoked"})
        tombstone = _SecretTombstone(
            schema_version="secret-tombstone-v1",
            metadata=revoked,
            source_execution_id=source_execution_id,
            metadata_version=2,
        )
        tombstone_id = self._tombstone_id(authoritative.secret_reference_id)
        tombstone_digest = sha256_digest(tombstone)
        self._store.write(
            mission_id=authoritative.mission_id,
            resource_id=tombstone_id,
            content=canonicalize(tombstone.model_dump(mode="python")),
            binding={
                "secret_reference_id": authoritative.secret_reference_id,
                "metadata_version": 2,
                "metadata_digest": tombstone_digest,
            },
            created_at=now,
            retention_until=None,
        )
        self._audit.record(
            mission_id=authoritative.mission_id,
            resource_type="secret_reference",
            resource_id=authoritative.secret_reference_id,
            operation="revoke",
            metadata_digest=tombstone_digest,
            occurred_at=now,
        )
        self._audit.record(
            mission_id=authoritative.mission_id,
            resource_type="secret_reference",
            resource_id=authoritative.secret_reference_id,
            operation="delete",
            metadata_digest=tombstone_digest,
            occurred_at=now,
        )
        self._store.delete(
            mission_id=authoritative.mission_id,
            resource_id=authoritative.secret_reference_id,
            binding={
                "secret_reference_id": authoritative.secret_reference_id,
                "credential_type": authoritative.credential_type,
                "associated_principal_ref": authoritative.associated_principal_ref,
                "source_execution_id": source_execution_id,
                "verification_state": "detected",
                "metadata_version": 1,
            },
            expected_encryption_metadata_id=authoritative.encryption_metadata_id,
        )
        return revoked

    def _authoritative_metadata(
        self, reference: SecretReferenceMetadata
    ) -> tuple[SecretReferenceMetadata, str, int]:
        tombstone_id = self._tombstone_id(reference.secret_reference_id)
        if self._store.has_resource(
            mission_id=reference.mission_id, resource_id=tombstone_id
        ):
            raw, envelope = self._store.read_bound(
                mission_id=reference.mission_id,
                resource_id=tombstone_id,
                now=None,
            )
            try:
                canonical_loads(raw)
                tombstone = _SecretTombstone.model_validate_json(raw, strict=True)
            except (TypeError, ValueError) as exc:
                raise SecretAccessError("secret revocation metadata is invalid") from exc
            if not (
                tombstone.metadata.mission_id == reference.mission_id
                and tombstone.metadata.secret_reference_id == reference.secret_reference_id
                and tombstone.metadata.verification_state == "revoked"
                and envelope.binding
                == CanonicalJsonObject(
                    {
                        "secret_reference_id": reference.secret_reference_id,
                        "metadata_version": 2,
                        "metadata_digest": sha256_digest(tombstone),
                    }
                )
            ):
                raise SecretAccessError("secret revocation binding is invalid")
            return tombstone.metadata, tombstone.source_execution_id, 2
        envelope = self._store.verified_envelope(
            mission_id=reference.mission_id,
            resource_id=reference.secret_reference_id,
            now=None,
        )
        binding = envelope.binding.to_dict()
        expected_keys = {
            "secret_reference_id",
            "credential_type",
            "associated_principal_ref",
            "source_execution_id",
            "verification_state",
            "metadata_version",
        }
        principal = binding.get("associated_principal_ref")
        if not (
            set(binding) == expected_keys
            and binding.get("secret_reference_id") == reference.secret_reference_id
            and isinstance(binding.get("credential_type"), str)
            and (principal is None or isinstance(principal, str))
            and isinstance(binding.get("source_execution_id"), str)
            and binding.get("verification_state") == "detected"
            and binding.get("metadata_version") == 1
        ):
            raise SecretAccessError("secret metadata binding is invalid")
        credential_type = binding["credential_type"]
        source_execution_id = binding["source_execution_id"]
        assert isinstance(credential_type, str) and isinstance(source_execution_id, str)
        authoritative = SecretReferenceMetadata(
            secret_reference_id=reference.secret_reference_id,
            mission_id=reference.mission_id,
            credential_type=credential_type,
            associated_principal_ref=principal,
            encryption_metadata_id=envelope.encryption_metadata_id,
            created_at=envelope.created_at,
            expires_at=envelope.retention_until,
            verification_state="detected",
        )
        return authoritative, source_execution_id, 1

    @staticmethod
    def _tombstone_id(secret_reference_id: str) -> str:
        return stable_id(
            "secrettombstone",
            {
                "schema_version": "secret-tombstone-v1",
                "secret_reference_id": secret_reference_id,
            },
        )
