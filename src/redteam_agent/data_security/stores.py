"""Encrypted mission-scoped storage boundaries for Phase 0C."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import re
import secrets
import stat
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, Literal, cast

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

from .audit import DataStoreAuditRecorder
from .authorization import RepositoryDataAccessAuthorizer
from .keys import EncryptionKeyProvider
from .models import (
    ArtifactReference,
    EncryptedPayload,
    EncryptionMetadata,
    KeyDomain,
    QuarantineReference,
    SecretReferenceMetadata,
)

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ARTIFACT_STREAM_CHUNK_BYTES = 4 * 1024
_RESOURCE_KEY_RECORD_QUOTA_UNIT_BYTES = 1024
_MIN_ENCRYPTED_ENVELOPE_QUOTA_BYTES = 1024
_CREATION_INTENT_PREFIX = ".resource-creation-"
_CREATION_INTENT_SUFFIX = ".intent"
_PENDING_RESOURCE_FILE = re.compile(r"^\.pending-[0-9a-f]{32}$")
_MAX_CREATION_INTENT_BYTES = 16 * 1024


def _require_bytes(value: bytes) -> None:
    if not isinstance(value, bytes):
        raise ArtifactSecurityError("storage content must be bytes")


def _require_time(value: datetime) -> None:
    try:
        require_utc(value)
    except ValueError as exc:
        raise ArtifactSecurityError("storage time must be UTC") from exc


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


class _ResourceCreationIntentBody(StrictImmutableBoundaryModel):
    schema_version: Literal["resource-creation-intent-v1"]
    domain: KeyDomain
    mission_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    key_resource_id: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
    )
    audit_required: bool


class _ResourceCreationIntent(StrictImmutableBoundaryModel):
    body: _ResourceCreationIntentBody
    verifier_metadata: EncryptionMetadata
    intent_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class _SecretTombstone(StrictImmutableBoundaryModel):
    schema_version: Literal["secret-tombstone-v1"]
    metadata: SecretReferenceMetadata
    source_execution_id: str = Field(min_length=1)
    metadata_version: Literal[2]


class _QuarantineExpiryIntent(StrictImmutableBoundaryModel):
    record_type: Literal["quarantine_expiry_intent"]
    reference: QuarantineReference


class _QuarantineDeletionIntent(StrictImmutableBoundaryModel):
    record_type: Literal["quarantine_delete_intent"]
    reference: QuarantineReference


class _SecretExpiryIntent(StrictImmutableBoundaryModel):
    record_type: Literal["secret_expiry_intent"]
    reference: SecretReferenceMetadata
    source_execution_id: str = Field(min_length=1)


class _StreamDeletionBinding(StrictImmutableBoundaryModel):
    record_type: Literal["stream_delete_intent"]
    mission_revision: int = Field(ge=1)
    stream_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    chunk_count: int = Field(ge=0)
    artifact_sequences: tuple[int, ...]
    bytes_received: int = Field(ge=0)
    aggregate_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    ingestion_id: str = Field(min_length=1)
    ingestion_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class _StreamAbortDeletionBinding(StrictImmutableBoundaryModel):
    record_type: Literal["stream_abort_delete_intent"]
    mission_revision: int = Field(ge=1)
    stream_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    chunk_count: int = Field(ge=0)
    artifact_sequences: tuple[int, ...]
    aggregate_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class _StreamExpiryDeletionBinding(StrictImmutableBoundaryModel):
    record_type: Literal["stream_expiry_delete_intent"]
    mission_revision: int = Field(ge=1)
    stream_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    terminal_state: Literal["committed", "abandoned"]
    chunk_count: int = Field(ge=0)
    artifact_sequences: tuple[int, ...]
    aggregate_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    receipt_digest: str | None = None


class _StreamIngestionAckBinding(StrictImmutableBoundaryModel):
    record_type: Literal["stream_ingestion_ack"]
    mission_revision: int = Field(ge=1)
    stream_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    chunk_count: int = Field(ge=0)
    artifact_sequences: tuple[int, ...]
    aggregate_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    receipt_id: str = Field(min_length=1)
    receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    ingestion_id: str = Field(min_length=1)
    ingestion_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_result_id: str = Field(min_length=1)
    execution_result_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class _ArtifactStreamChunkBinding(StrictImmutableBoundaryModel):
    record_type: Literal["artifact_stream_chunk"]
    stream_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
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
    attempt_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    classification: Literal["normal", "sensitive", "secret"]
    variant: Literal["redacted", "encrypted_raw"]
    source_execution_id: str = Field(min_length=1)
    derived_from_artifact_id: str | None
    chunks: tuple[_ArtifactStreamChunkReference, ...]


class _ArtifactDeletionIntent(StrictImmutableBoundaryModel):
    record_type: Literal["artifact_delete_intent"]
    reference: ArtifactReference
    resource_ids: tuple[str, ...] = Field(min_length=1)


class _ArtifactStreamCleanupIntent(StrictImmutableBoundaryModel):
    record_type: Literal["artifact_stream_cleanup_intent"]
    cleanup_id: str = Field(min_length=1)
    stream_id: str = Field(min_length=1)
    source_execution_id: str = Field(min_length=1)


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
        self._root = self._prepare_root(root)
        root_metadata = os.stat(self._root, follow_symlinks=False)
        self._root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        self._domain = domain
        self._keys = keys
        self._max_item_bytes = max_item_bytes
        self._mission_quota_bytes = mission_quota_bytes
        self._lock = RLock()
        self._transaction_lock_path = self._root / ".write-transaction.lock"
        if self._transaction_lock_path.is_symlink() or (
            self._transaction_lock_path.exists()
            and not self._transaction_lock_path.is_file()
        ):
            raise ArtifactSecurityError("store transaction lock is invalid")
        with self._lock, self._write_transaction():
            self._recover_all_resource_creations()

    @classmethod
    def _prepare_root(cls, root: Path) -> Path:
        absolute_root = Path(os.path.abspath(root))
        cls._validate_lexical_root(absolute_root)
        missing_components: list[Path] = []
        existing_ancestor = absolute_root
        while not existing_ancestor.exists():
            if existing_ancestor == existing_ancestor.parent:
                raise ArtifactSecurityError("storage root is unavailable")
            missing_components.append(existing_ancestor)
            existing_ancestor = existing_ancestor.parent
        if existing_ancestor.is_symlink() or not existing_ancestor.is_dir():
            raise ArtifactSecurityError("storage root ancestry is invalid")

        cls._sync_parent_directory(existing_ancestor.parent)
        for directory in reversed(missing_components):
            try:
                directory.mkdir(mode=0o700, exist_ok=True)
            except OSError as exc:
                raise ArtifactSecurityError("storage root is unavailable") from exc
            if directory.is_symlink() or not directory.is_dir():
                raise ArtifactSecurityError("storage root ancestry is invalid")
            cls._sync_parent_directory(directory.parent)
        try:
            cls._validate_lexical_root(absolute_root)
            resolved = absolute_root.resolve(strict=True)
        except OSError as exc:
            raise ArtifactSecurityError("storage root is unavailable") from exc
        if resolved != absolute_root:
            raise ArtifactSecurityError("storage root ancestry is invalid")
        return resolved

    @staticmethod
    def _validate_lexical_root(root: Path) -> None:
        """Reject a symlink or non-directory in every existing lexical component."""

        current = Path(root.anchor)
        for component in root.parts[1:]:
            current /= component
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                return
            except OSError as exc:
                raise ArtifactSecurityError("storage root is unavailable") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ArtifactSecurityError("storage root ancestry is invalid")

    def write(
        self,
        *,
        mission_id: str,
        resource_id: str,
        content: bytes,
        binding: dict[str, object],
        created_at: datetime,
        retention_until: datetime | None,
        require_creation_audit: bool = False,
    ) -> tuple[str, str]:
        return self._write(
            mission_id=mission_id,
            resource_id=resource_id,
            content=content,
            binding=binding,
            created_at=created_at,
            retention_until=retention_until,
            enforce_quota=True,
            require_creation_audit=require_creation_audit,
        )

    def write_artifact_deletion_intent(
        self,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        created_at: datetime,
    ) -> tuple[str, str]:
        """Persist trusted erasure metadata even when user data fills its quota."""

        try:
            intent = _ArtifactDeletionIntent.model_validate_json(
                canonicalize(binding),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactSecurityError("cleanup record binding is invalid") from exc
        expected_id = stable_id(
            "artifactdeletion",
            {
                "schema_version": "artifact-deletion-intent-v1",
                "artifact_id": intent.reference.artifact_id,
            },
        )
        if not (
            resource_id == expected_id
            and intent.reference.mission_id == mission_id
            and binding == intent.model_dump(mode="json")
        ):
            raise ArtifactSecurityError("cleanup record binding is invalid")
        return self._write(
            mission_id=mission_id,
            resource_id=resource_id,
            content=b"",
            binding=binding,
            created_at=created_at,
            retention_until=None,
            enforce_quota=False,
            require_creation_audit=False,
        )

    def write_quarantine_cleanup_intent(
        self,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        created_at: datetime,
    ) -> tuple[str, str]:
        """Persist only a strictly typed quarantine cleanup record outside quota."""

        record_type = binding.get("record_type")
        model_type: type[StrictImmutableBoundaryModel]
        if record_type == "quarantine_expiry_intent":
            model_type = _QuarantineExpiryIntent
        elif record_type == "quarantine_delete_intent":
            model_type = _QuarantineDeletionIntent
        elif record_type == "stream_delete_intent":
            model_type = _StreamDeletionBinding
        elif record_type == "stream_abort_delete_intent":
            model_type = _StreamAbortDeletionBinding
        elif record_type == "stream_expiry_delete_intent":
            model_type = _StreamExpiryDeletionBinding
        elif record_type == "stream_ingestion_ack":
            model_type = _StreamIngestionAckBinding
        else:
            raise ArtifactSecurityError("cleanup record binding is invalid")
        try:
            intent = model_type.model_validate_json(
                canonicalize(binding),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactSecurityError("cleanup record binding is invalid") from exc
        if isinstance(intent, (_QuarantineExpiryIntent, _QuarantineDeletionIntent)):
            if isinstance(intent, _QuarantineExpiryIntent):
                expected_id = stable_id(
                    "quarantineexpiry",
                    {
                        "schema_version": "quarantine-expiry-intent-v1",
                        "quarantine_id": intent.reference.quarantine_id,
                    },
                )
            else:
                expected_id = stable_id(
                    "quarantinedeletion",
                    {
                        "schema_version": "quarantine-deletion-intent-v1",
                        "quarantine_id": intent.reference.quarantine_id,
                    },
                )
            bound_mission_id = intent.reference.mission_id
        else:
            stream_intent = intent
            identity_schema = (
                "stream-ingestion-ack-v1"
                if isinstance(stream_intent, _StreamIngestionAckBinding)
                else "stream-deletion-intent-v1"
            )
            expected_id = stable_id(
                "streamack"
                if isinstance(stream_intent, _StreamIngestionAckBinding)
                else "streamdeletion",
                {
                    "schema_version": identity_schema,
                    "execution_id": stream_intent.execution_id,
                    "sink_id": stream_intent.sink_id,
                },
            )
            bound_mission_id = mission_id
        if not (
            resource_id == expected_id
            and mission_id == bound_mission_id
            and binding == intent.model_dump(mode="json")
        ):
            raise ArtifactSecurityError("cleanup record binding is invalid")
        return self._write(
            mission_id=mission_id,
            resource_id=resource_id,
            content=b"",
            binding=binding,
            created_at=created_at,
            retention_until=None,
            enforce_quota=False,
            require_creation_audit=False,
        )

    def write_secret_cleanup_intent(
        self,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        created_at: datetime,
    ) -> tuple[str, str]:
        """Persist a strictly typed secret-expiry intent outside caller quota."""

        try:
            intent = _SecretExpiryIntent.model_validate_json(
                canonicalize(binding),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactSecurityError(
                "cleanup record binding is invalid"
            ) from exc
        expected_id = stable_id(
            "secretexpiry",
            {
                "schema_version": "secret-expiry-intent-v1",
                "secret_reference_id": intent.reference.secret_reference_id,
            },
        )
        if not (
            resource_id == expected_id
            and intent.reference.mission_id == mission_id
            and intent.reference.expires_at is not None
            and intent.reference.verification_state == "detected"
            and binding == intent.model_dump(mode="json")
        ):
            raise ArtifactSecurityError("cleanup record binding is invalid")
        return self._write(
            mission_id=mission_id,
            resource_id=resource_id,
            content=b"",
            binding=binding,
            created_at=created_at,
            retention_until=None,
            enforce_quota=False,
            require_creation_audit=False,
        )

    def _write(
        self,
        *,
        mission_id: str,
        resource_id: str,
        content: bytes,
        binding: dict[str, object],
        created_at: datetime,
        retention_until: datetime | None,
        enforce_quota: bool,
        require_creation_audit: bool,
    ) -> tuple[str, str]:
        _require_bytes(content)
        if len(content) > self._max_item_bytes:
            raise ArtifactSecurityError("resource exceeds its size limit")
        with self._lock, self._write_transaction():
            path = self._path(mission_id, resource_id, create_parent=True)
            with self._anchored_mission_directory(mission_id) as (
                root_descriptor,
                mission_descriptor,
                mission_metadata,
            ):
                self._recover_resource_creations_anchored(
                    mission_id=mission_id,
                    root_descriptor=root_descriptor,
                    mission_descriptor=mission_descriptor,
                    mission_metadata=mission_metadata,
                )
                if self._resource_exists_anchored(
                    mission_descriptor=mission_descriptor,
                    resource_id=resource_id,
                ):
                    existing = self._load_envelope_from_descriptor(
                        mission_descriptor=mission_descriptor,
                        resource_id=resource_id,
                    )
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
                        expected_encryption_metadata_id=(
                            existing.encryption_metadata_id
                        ),
                        now=None,
                    )
                    if plaintext != content:
                        raise ArtifactSecurityError(
                            "resource identifier conflicts with stored content"
                        )
                    os.fsync(mission_descriptor)
                    return (
                        existing.plaintext_sha256,
                        existing.encryption_metadata_id,
                    )
                mission_usage = self._mission_usage_anchored(
                    mission_id=mission_id,
                    mission_descriptor=mission_descriptor,
                )
                if enforce_quota and (
                    mission_usage + _MIN_ENCRYPTED_ENVELOPE_QUOTA_BYTES
                    > self._mission_quota_bytes
                    or self._mission_record_count_anchored(
                        mission_id=mission_id,
                        mission_descriptor=mission_descriptor,
                    )
                    + 1
                    > max(
                        1,
                        self._mission_quota_bytes
                        // _RESOURCE_KEY_RECORD_QUOTA_UNIT_BYTES,
                    )
                ):
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
                creation_intent = self._prepare_resource_creation_intent_anchored(
                    mission_id=mission_id,
                    resource_id=resource_id,
                    root_descriptor=root_descriptor,
                    mission_descriptor=mission_descriptor,
                    mission_metadata=mission_metadata,
                    audit_required=require_creation_audit,
                )
                mission_usage = self._mission_usage_anchored(
                    mission_id=mission_id,
                    mission_descriptor=mission_descriptor,
                )
                mission_record_count = self._mission_record_count_anchored(
                    mission_id=mission_id,
                    mission_descriptor=mission_descriptor,
                )
                if enforce_quota and (
                    mission_usage + _MIN_ENCRYPTED_ENVELOPE_QUOTA_BYTES
                    > self._mission_quota_bytes
                    or mission_record_count + 1
                    > max(
                        1,
                        self._mission_quota_bytes
                        // _RESOURCE_KEY_RECORD_QUOTA_UNIT_BYTES,
                    )
                ):
                    self._recover_resource_creations_anchored(
                        mission_id=mission_id,
                        root_descriptor=root_descriptor,
                        mission_descriptor=mission_descriptor,
                        mission_metadata=mission_metadata,
                    )
                    raise ArtifactSecurityError("mission storage quota exceeded")
                try:
                    encrypted = self._keys.seal_for_resource(
                        self._domain,
                        creation_intent.body.key_resource_id,
                        content,
                        aad,
                        created_at=created_at,
                    )
                except Exception:
                    with suppress(Exception):
                        self._recover_resource_creations_anchored(
                            mission_id=mission_id,
                            root_descriptor=root_descriptor,
                            mission_descriptor=mission_descriptor,
                            mission_metadata=mission_metadata,
                        )
                    raise
                if (
                    self._content_digest(
                        content,
                        metadata=encrypted.metadata,
                    )
                    != content_digest
                ):
                    self._keys.destroy_resource_keys_for_resource(
                        self._domain,
                        creation_intent.body.key_resource_id,
                    )
                    self._finish_resource_creation_intent_anchored(
                        intent=creation_intent,
                        root_descriptor=root_descriptor,
                        mission_descriptor=mission_descriptor,
                        mission_metadata=mission_metadata,
                    )
                    raise ArtifactSecurityError(
                        "resource verifier key changed during creation"
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
                serialized_envelope = canonicalize(
                    envelope.model_dump(mode="python")
                )
                if enforce_quota and (
                    mission_usage + self._quota_charge(serialized_envelope)
                    > self._mission_quota_bytes
                ):
                    self._keys.destroy_resource_keys_for_resource(
                        self._domain,
                        creation_intent.body.key_resource_id,
                    )
                    self._finish_resource_creation_intent_anchored(
                        intent=creation_intent,
                        root_descriptor=root_descriptor,
                        mission_descriptor=mission_descriptor,
                        mission_metadata=mission_metadata,
                    )
                    raise ArtifactSecurityError("mission storage quota exceeded")
                try:
                    self._atomic_write_anchored(
                        path=path,
                        data=serialized_envelope,
                        root_descriptor=root_descriptor,
                        mission_descriptor=mission_descriptor,
                        mission_metadata=mission_metadata,
                    )
                except Exception:
                    with suppress(Exception):
                        self._recover_resource_creations_anchored(
                            mission_id=mission_id,
                            root_descriptor=root_descriptor,
                            mission_descriptor=mission_descriptor,
                            mission_metadata=mission_metadata,
                        )
                    raise
                if not require_creation_audit:
                    self._finish_resource_creation_intent_anchored(
                        intent=creation_intent,
                        root_descriptor=root_descriptor,
                        mission_descriptor=mission_descriptor,
                        mission_metadata=mission_metadata,
                    )
                return envelope.plaintext_sha256, metadata_id

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        root_descriptor: int | None = None
        lock_descriptor: int | None = None
        locked = False
        try:
            try:
                root_descriptor = os.open(self._root, directory_flags)
                root_metadata = os.fstat(root_descriptor)
                if (
                    not stat.S_ISDIR(root_metadata.st_mode)
                    or (root_metadata.st_dev, root_metadata.st_ino)
                    != self._root_identity
                ):
                    raise ArtifactSecurityError("store root identity changed")
                lock_descriptor = os.open(
                    self._transaction_lock_path.name,
                    lock_flags,
                    0o600,
                    dir_fd=root_descriptor,
                )
            except OSError as exc:
                raise ArtifactSecurityError(
                    "store transaction lock is unavailable"
                ) from exc
            metadata = os.fstat(lock_descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ArtifactSecurityError("store transaction lock is invalid")
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            except OSError as exc:
                raise ArtifactSecurityError(
                    "store transaction lock acquisition failed"
                ) from exc
            locked = True
            self._require_current_root_identity()
            yield
            self._require_current_root_identity()
        finally:
            if locked and lock_descriptor is not None:
                with suppress(OSError):
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)

    def read(
        self,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        now: datetime,
        expected_encryption_metadata_id: str,
    ) -> bytes:
        envelope = self._load_envelope_anchored(
            mission_id=mission_id,
            resource_id=resource_id,
        )
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
        envelope = self._load_envelope_anchored(
            mission_id=mission_id,
            resource_id=resource_id,
        )
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
        envelope = self._load_envelope_anchored(
            mission_id=mission_id,
            resource_id=resource_id,
        )
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
        self._validate_token(mission_id)
        self._validate_token(resource_id)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        root_descriptor: int | None = None
        mission_descriptor: int | None = None
        try:
            try:
                root_descriptor = os.open(self._root, directory_flags)
            except OSError as exc:
                raise ArtifactSecurityError("store root is unavailable") from exc
            root_metadata = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or (root_metadata.st_dev, root_metadata.st_ino)
                != self._root_identity
            ):
                raise ArtifactSecurityError("store root identity changed")
            try:
                mission_descriptor = os.open(
                    mission_id,
                    directory_flags,
                    dir_fd=root_descriptor,
                )
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource directory is unavailable"
                ) from exc
            mission_metadata = os.fstat(mission_descriptor)
            if not stat.S_ISDIR(mission_metadata.st_mode):
                raise ArtifactSecurityError("resource directory is invalid")
            self._require_current_mission_identity(
                mission_id=mission_id,
                root_descriptor=root_descriptor,
                mission_metadata=mission_metadata,
                operation="existence check",
            )
            exists = self._resource_exists_anchored(
                mission_descriptor=mission_descriptor,
                resource_id=resource_id,
            )
            self._require_current_mission_identity(
                mission_id=mission_id,
                root_descriptor=root_descriptor,
                mission_metadata=mission_metadata,
                operation="existence check",
            )
            return exists
        finally:
            if mission_descriptor is not None:
                with suppress(OSError):
                    os.close(mission_descriptor)
            if root_descriptor is not None:
                with suppress(OSError):
                    os.close(root_descriptor)

    def envelopes_for(self, mission_id: str) -> tuple[_StoredEnvelope, ...]:
        envelopes: list[_StoredEnvelope] = []
        for resource_id in self._mission_resource_ids(mission_id):
            envelope = self._load_envelope_anchored(
                mission_id=mission_id,
                resource_id=resource_id,
            )
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

    def mission_ids(self) -> tuple[str, ...]:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        try:
            root_descriptor = os.open(self._root, directory_flags)
        except OSError as exc:
            raise ArtifactSecurityError("store root is unavailable") from exc
        mission_ids: list[str] = []
        try:
            root_metadata = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or (root_metadata.st_dev, root_metadata.st_ino)
                != self._root_identity
            ):
                raise ArtifactSecurityError("store root identity changed")
            try:
                entries = sorted(os.listdir(root_descriptor))
            except OSError as exc:
                raise ArtifactSecurityError("store root is unavailable") from exc
            for entry in entries:
                if entry.startswith("."):
                    continue
                self._validate_token(entry)
                try:
                    metadata = os.stat(
                        entry,
                        dir_fd=root_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise ArtifactSecurityError(
                        "unexpected Store-root entry"
                    ) from exc
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ArtifactSecurityError("unexpected Store-root entry")
                mission_ids.append(entry)
            self._require_current_root_identity()
            return tuple(mission_ids)
        finally:
            os.close(root_descriptor)

    def resource_ids_with_prefix(
        self,
        *,
        mission_id: str,
        prefix: str,
    ) -> tuple[str, ...]:
        return tuple(
            resource_id
            for resource_id in self._mission_resource_ids(mission_id)
            if resource_id.startswith(prefix)
        )

    def _mission_resource_ids(self, mission_id: str) -> tuple[str, ...]:
        self._validate_token(mission_id)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        root_descriptor: int | None = None
        mission_descriptor: int | None = None
        try:
            try:
                root_descriptor = os.open(self._root, directory_flags)
            except OSError as exc:
                raise ArtifactSecurityError("store root is unavailable") from exc
            root_metadata = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or (root_metadata.st_dev, root_metadata.st_ino)
                != self._root_identity
            ):
                raise ArtifactSecurityError("store root identity changed")
            try:
                mission_descriptor = os.open(
                    mission_id,
                    directory_flags,
                    dir_fd=root_descriptor,
                )
            except FileNotFoundError:
                return ()
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource directory is unavailable"
                ) from exc
            mission_metadata = os.fstat(mission_descriptor)
            if not stat.S_ISDIR(mission_metadata.st_mode):
                raise ArtifactSecurityError("resource directory is invalid")
            self._require_current_mission_identity(
                mission_id=mission_id,
                root_descriptor=root_descriptor,
                mission_metadata=mission_metadata,
                operation="enumeration",
            )
            try:
                with os.scandir(mission_descriptor) as iterator:
                    entries = sorted(entry.name for entry in iterator)
            except OSError as exc:
                raise ArtifactSecurityError("mission storage is unavailable") from exc
            resource_ids: list[str] = []
            for entry in entries:
                intent_resource_id = self._creation_intent_resource_id(entry)
                if intent_resource_id is not None:
                    self._load_resource_creation_intent_anchored(
                        mission_id=mission_id,
                        resource_id=intent_resource_id,
                        mission_descriptor=mission_descriptor,
                    )
                    continue
                if not entry.endswith(".json"):
                    raise ArtifactSecurityError(
                        "unexpected mission storage entry"
                    )
                resource_id = entry.removesuffix(".json")
                self._validate_token(resource_id)
                try:
                    metadata = os.stat(
                        entry,
                        dir_fd=mission_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise ArtifactSecurityError(
                        "unexpected mission storage entry"
                    ) from exc
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ArtifactSecurityError(
                        "unexpected mission storage entry"
                    )
                resource_ids.append(resource_id)
            self._require_current_mission_identity(
                mission_id=mission_id,
                root_descriptor=root_descriptor,
                mission_metadata=mission_metadata,
                operation="enumeration",
            )
            return tuple(resource_ids)
        finally:
            if mission_descriptor is not None:
                with suppress(OSError):
                    os.close(mission_descriptor)
            if root_descriptor is not None:
                with suppress(OSError):
                    os.close(root_descriptor)

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
            and self._content_digest(
                plaintext,
                metadata=envelope.payload.metadata,
            )
            == envelope.plaintext_sha256
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
        with self._lock, self._write_transaction():
            self._erase_resource_anchored(
                mission_id=mission_id,
                resource_id=resource_id,
                expected_binding=CanonicalJsonObject(binding),
                expected_encryption_metadata_id=expected_encryption_metadata_id,
            )

    def erase_resource(self, *, mission_id: str, resource_id: str) -> None:
        """Idempotently finish cryptographic erasure after an unlink interruption."""

        with self._lock, self._write_transaction():
            self._erase_resource_anchored(
                mission_id=mission_id,
                resource_id=resource_id,
                expected_binding=None,
                expected_encryption_metadata_id=None,
            )

    def _erase_resource_anchored(
        self,
        *,
        mission_id: str,
        resource_id: str,
        expected_binding: CanonicalJsonObject | None,
        expected_encryption_metadata_id: str | None,
    ) -> None:
        self._validate_token(mission_id)
        self._validate_token(resource_id)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        root_descriptor: int | None = None
        mission_descriptor: int | None = None
        try:
            try:
                root_descriptor = os.open(self._root, directory_flags)
            except OSError as exc:
                raise ArtifactSecurityError("store root is unavailable") from exc
            root_metadata = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or (root_metadata.st_dev, root_metadata.st_ino)
                != self._root_identity
            ):
                raise ArtifactSecurityError("store root identity changed")
            try:
                mission_descriptor = os.open(
                    mission_id,
                    directory_flags,
                    dir_fd=root_descriptor,
                )
            except FileNotFoundError:
                return
            except OSError as exc:
                raise ArtifactSecurityError("resource directory is unavailable") from exc
            mission_metadata = os.fstat(mission_descriptor)
            if not stat.S_ISDIR(mission_metadata.st_mode):
                raise ArtifactSecurityError("resource directory is invalid")
            file_flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            try:
                resource_descriptor = os.open(
                    f"{resource_id}.json",
                    file_flags,
                    dir_fd=mission_descriptor,
                )
            except FileNotFoundError:
                return
            except OSError as exc:
                raise ArtifactSecurityError("erasure target is unavailable") from exc
            try:
                resource_metadata = os.fstat(resource_descriptor)
                if not stat.S_ISREG(resource_metadata.st_mode):
                    raise ArtifactSecurityError("erasure target is invalid")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(resource_descriptor, 64 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                envelope = self._parse_envelope(b"".join(chunks))
            finally:
                os.close(resource_descriptor)
            if not (
                envelope.domain == self._domain
                and envelope.mission_id == mission_id
                and envelope.resource_id == resource_id
                and envelope.encryption_metadata_id
                == self._keys.metadata_id(envelope.payload.metadata)
                and (
                    expected_binding is None
                    or envelope.binding == expected_binding
                )
                and (
                    expected_encryption_metadata_id is None
                    or envelope.encryption_metadata_id
                    == expected_encryption_metadata_id
                )
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
            try:
                current_metadata = os.stat(
                    mission_id,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource directory identity is unavailable"
                ) from exc
            if (
                not stat.S_ISDIR(current_metadata.st_mode)
                or current_metadata.st_dev != mission_metadata.st_dev
                or current_metadata.st_ino != mission_metadata.st_ino
            ):
                raise ArtifactSecurityError("resource directory changed during erasure")
            if not self._keys.resource_key_destroyed(envelope.payload.metadata):
                self._keys.destroy_resource_key(envelope.payload.metadata)
            try:
                os.unlink(f"{resource_id}.json", dir_fd=mission_descriptor)
                os.fsync(mission_descriptor)
            except FileNotFoundError:
                return
            except OSError as exc:
                raise ArtifactSecurityError("encrypted resource erasure failed") from exc
        finally:
            if mission_descriptor is not None:
                with suppress(OSError):
                    os.close(mission_descriptor)
            if root_descriptor is not None:
                with suppress(OSError):
                    os.close(root_descriptor)

    def _path(self, mission_id: str, resource_id: str, *, create_parent: bool) -> Path:
        self._validate_token(mission_id)
        self._validate_token(resource_id)
        mission_root = self._root / mission_id
        if mission_root.exists() and mission_root.is_symlink():
            raise ArtifactSecurityError("mission storage may not be a symbolic link")
        if create_parent:
            try:
                mission_root.mkdir(mode=0o700, exist_ok=True)
            except OSError as exc:
                raise ArtifactSecurityError(
                    "mission storage is unavailable"
                ) from exc
            if mission_root.is_symlink() or not mission_root.is_dir():
                raise ArtifactSecurityError("mission storage is invalid")
            self._sync_parent_directory(self._root)
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

    def _content_digest(
        self,
        content: bytes,
        *,
        metadata: EncryptionMetadata | None = None,
    ) -> str:
        if self._domain in {"secret_store", "raw_result_quarantine"}:
            return self._keys.keyed_digest(
                self._domain,
                "stored-plaintext-integrity",
                content,
                metadata=metadata,
            )
        return "sha256:" + hashlib.sha256(content).hexdigest()

    @contextmanager
    def _anchored_mission_directory(
        self,
        mission_id: str,
    ) -> Iterator[tuple[int, int, os.stat_result]]:
        """Retain verified root and mission descriptors for one store operation."""

        self._validate_token(mission_id)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        root_descriptor: int | None = None
        mission_descriptor: int | None = None
        try:
            try:
                root_descriptor = os.open(self._root, directory_flags)
            except OSError as exc:
                raise ArtifactSecurityError("store root is unavailable") from exc
            root_metadata = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or (root_metadata.st_dev, root_metadata.st_ino)
                != self._root_identity
            ):
                raise ArtifactSecurityError("store root identity changed")
            try:
                mission_descriptor = os.open(
                    mission_id,
                    directory_flags,
                    dir_fd=root_descriptor,
                )
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource directory is unavailable"
                ) from exc
            mission_metadata = os.fstat(mission_descriptor)
            if not stat.S_ISDIR(mission_metadata.st_mode):
                raise ArtifactSecurityError("resource directory is invalid")
            self._require_current_mission_identity(
                mission_id=mission_id,
                root_descriptor=root_descriptor,
                mission_metadata=mission_metadata,
                operation="access",
            )
            yield root_descriptor, mission_descriptor, mission_metadata
        finally:
            if mission_descriptor is not None:
                with suppress(OSError):
                    os.close(mission_descriptor)
            if root_descriptor is not None:
                with suppress(OSError):
                    os.close(root_descriptor)

    def _mission_usage_anchored(
        self,
        *,
        mission_id: str,
        mission_descriptor: int,
    ) -> int:
        total = 0
        try:
            entries = sorted(os.listdir(mission_descriptor))
        except OSError as exc:
            raise ArtifactSecurityError("mission storage is unavailable") from exc
        for entry in entries:
            intent_resource_id = self._creation_intent_resource_id(entry)
            if intent_resource_id is not None:
                intent = self._load_resource_creation_intent_anchored(
                    mission_id=mission_id,
                    resource_id=intent_resource_id,
                    mission_descriptor=mission_descriptor,
                )
                try:
                    intent_metadata = os.stat(
                        entry,
                        dir_fd=mission_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise ArtifactSecurityError(
                        "resource creation intent is unavailable"
                    ) from exc
                serialized_intent = canonicalize(intent.model_dump(mode="python"))
                if not (
                    stat.S_ISREG(intent_metadata.st_mode)
                    and intent_metadata.st_nlink == 1
                    and intent_metadata.st_size == len(serialized_intent)
                ):
                    raise ArtifactSecurityError(
                        "resource creation intent is invalid"
                    )
                total += intent_metadata.st_size
                continue
            if not entry.endswith(".json"):
                raise ArtifactSecurityError("unexpected mission storage entry")
            resource_id = entry.removesuffix(".json")
            self._validate_token(resource_id)
            try:
                resource_metadata = os.stat(
                    entry,
                    dir_fd=mission_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise ArtifactSecurityError(
                    "encrypted resource metadata is unavailable"
                ) from exc
            if not (
                stat.S_ISREG(resource_metadata.st_mode)
                and resource_metadata.st_nlink == 1
            ):
                raise ArtifactSecurityError(
                    "encrypted resource metadata is unavailable"
                )
            envelope = self._load_envelope_from_descriptor(
                mission_descriptor=mission_descriptor,
                resource_id=resource_id,
            )
            if not (
                envelope.domain == self._domain
                and envelope.mission_id == mission_id
                and entry == f"{envelope.resource_id}.json"
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
            serialized_envelope = canonicalize(envelope.model_dump(mode="python"))
            if resource_metadata.st_size != len(serialized_envelope):
                raise ArtifactSecurityError(
                    "encrypted resource metadata is unavailable"
                )
            total += resource_metadata.st_size
        return total

    def _mission_record_count_anchored(
        self,
        *,
        mission_id: str,
        mission_descriptor: int,
    ) -> int:
        try:
            entries = os.listdir(mission_descriptor)
        except OSError as exc:
            raise ArtifactSecurityError("mission storage is unavailable") from exc
        record_count = 0
        for entry in entries:
            intent_resource_id = self._creation_intent_resource_id(entry)
            if intent_resource_id is not None:
                self._load_resource_creation_intent_anchored(
                    mission_id=mission_id,
                    resource_id=intent_resource_id,
                    mission_descriptor=mission_descriptor,
                )
                record_count += 1
                continue
            if not entry.endswith(".json"):
                raise ArtifactSecurityError("unexpected mission storage entry")
            record_count += 1
        return record_count

    @staticmethod
    def _quota_charge(serialized_envelope: bytes) -> int:
        """Charge the canonical encrypted envelope's durable byte footprint."""

        return len(serialized_envelope)

    def _load_envelope_anchored(
        self,
        *,
        mission_id: str,
        resource_id: str,
    ) -> _StoredEnvelope:
        """Read relative to verified descriptors so directory swaps cannot redirect it."""

        with self._anchored_mission_directory(mission_id) as (
            root_descriptor,
            mission_descriptor,
            mission_metadata,
        ):
            envelope = self._load_envelope_from_descriptor(
                mission_descriptor=mission_descriptor,
                resource_id=resource_id,
            )
            self._require_current_mission_identity(
                mission_id=mission_id,
                root_descriptor=root_descriptor,
                mission_metadata=mission_metadata,
                operation="read",
            )
            return envelope

    def _resource_exists_anchored(
        self,
        *,
        mission_descriptor: int,
        resource_id: str,
    ) -> bool:
        self._validate_token(resource_id)
        try:
            metadata = os.stat(
                f"{resource_id}.json",
                dir_fd=mission_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ArtifactSecurityError(
                "encrypted resource metadata is unavailable"
            ) from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ArtifactSecurityError(
                "encrypted resource metadata is unavailable"
            )
        return True

    def _load_envelope_from_descriptor(
        self,
        *,
        mission_descriptor: int,
        resource_id: str,
    ) -> _StoredEnvelope:
        self._validate_token(resource_id)
        resource_descriptor: int | None = None
        try:
            file_flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            try:
                resource_descriptor = os.open(
                    f"{resource_id}.json",
                    file_flags,
                    dir_fd=mission_descriptor,
                )
            except OSError as exc:
                raise ArtifactSecurityError(
                    "encrypted resource metadata is unavailable"
                ) from exc
            resource_metadata = os.fstat(resource_descriptor)
            maximum_envelope_bytes = self._max_item_bytes * 4 + 256 * 1024
            if (
                not stat.S_ISREG(resource_metadata.st_mode)
                or resource_metadata.st_nlink != 1
                or resource_metadata.st_size > maximum_envelope_bytes
            ):
                raise ArtifactSecurityError(
                    "encrypted resource metadata is unavailable"
                )
            raw = bytearray()
            while len(raw) <= maximum_envelope_bytes:
                chunk = os.read(
                    resource_descriptor,
                    min(64 * 1024, maximum_envelope_bytes + 1 - len(raw)),
                )
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > maximum_envelope_bytes:
                raise ArtifactSecurityError(
                    "encrypted resource metadata is unavailable"
                )
            return self._parse_envelope(bytes(raw))
        finally:
            if resource_descriptor is not None:
                with suppress(OSError):
                    os.close(resource_descriptor)

    @staticmethod
    def _require_current_mission_identity(
        *,
        mission_id: str,
        root_descriptor: int,
        mission_metadata: os.stat_result,
        operation: str,
    ) -> None:
        try:
            current_metadata = os.stat(
                mission_id,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ArtifactSecurityError(
                "resource directory identity is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(current_metadata.st_mode)
            or current_metadata.st_dev != mission_metadata.st_dev
            or current_metadata.st_ino != mission_metadata.st_ino
        ):
            raise ArtifactSecurityError(
                f"resource directory changed during {operation}"
            )

    def _require_current_root_identity(self) -> None:
        try:
            metadata = os.stat(self._root, follow_symlinks=False)
        except OSError as exc:
            raise ArtifactSecurityError("store root is unavailable") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != self._root_identity
        ):
            raise ArtifactSecurityError("store root identity changed")

    @staticmethod
    def _parse_envelope(raw: bytes) -> _StoredEnvelope:
        try:
            canonical_loads(raw)
            return _StoredEnvelope.model_validate_json(raw, strict=True)
        except (TypeError, ValueError) as exc:
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
    def _creation_intent_name(resource_id: str) -> str:
        return f"{_CREATION_INTENT_PREFIX}{resource_id}{_CREATION_INTENT_SUFFIX}"

    def _creation_intent_resource_id(self, entry: str) -> str | None:
        if not (
            entry.startswith(_CREATION_INTENT_PREFIX)
            and entry.endswith(_CREATION_INTENT_SUFFIX)
        ):
            return None
        resource_id = entry[
            len(_CREATION_INTENT_PREFIX) : -len(_CREATION_INTENT_SUFFIX)
        ]
        self._validate_token(resource_id)
        if entry != self._creation_intent_name(resource_id):
            raise ArtifactSecurityError("resource creation intent is invalid")
        return resource_id

    def _recover_all_resource_creations(self) -> None:
        for mission_id in self.mission_ids():
            with self._anchored_mission_directory(mission_id) as (
                root_descriptor,
                mission_descriptor,
                mission_metadata,
            ):
                self._recover_resource_creations_anchored(
                    mission_id=mission_id,
                    root_descriptor=root_descriptor,
                    mission_descriptor=mission_descriptor,
                    mission_metadata=mission_metadata,
                )

    def pending_creation_audits(self) -> tuple[tuple[str, str], ...]:
        """Return fully verified committed resources awaiting their required audit."""

        pending: list[tuple[str, str]] = []
        with self._lock, self._write_transaction():
            self._recover_all_resource_creations()
            for mission_id in self.mission_ids():
                with self._anchored_mission_directory(mission_id) as (
                    _,
                    mission_descriptor,
                    _,
                ):
                    try:
                        entries = sorted(os.listdir(mission_descriptor))
                    except OSError as exc:
                        raise ArtifactSecurityError(
                            "mission storage is unavailable"
                        ) from exc
                    for entry in entries:
                        if not (
                            entry.startswith(_CREATION_INTENT_PREFIX)
                            and entry.endswith(_CREATION_INTENT_SUFFIX)
                        ):
                            continue
                        resource_id = entry[
                            len(_CREATION_INTENT_PREFIX) : -len(
                                _CREATION_INTENT_SUFFIX
                            )
                        ]
                        self._validate_token(resource_id)
                        intent = self._load_resource_creation_intent_anchored(
                            mission_id=mission_id,
                            resource_id=resource_id,
                            mission_descriptor=mission_descriptor,
                        )
                        if not (
                            intent.body.audit_required
                            and self._resource_exists_anchored(
                                mission_descriptor=mission_descriptor,
                                resource_id=resource_id,
                            )
                        ):
                            raise ArtifactSecurityError(
                                "creation-audit recovery state is invalid"
                            )
                        pending.append((mission_id, resource_id))
        return tuple(pending)

    def acknowledge_creation_audit(
        self,
        *,
        mission_id: str,
        resource_id: str,
    ) -> None:
        """Erase an audit-pending intent only after its deterministic append."""

        with self._lock, self._write_transaction():
            self._validate_token(mission_id)
            self._validate_token(resource_id)
            try:
                with self._anchored_mission_directory(mission_id) as (
                    root_descriptor,
                    mission_descriptor,
                    mission_metadata,
                ):
                    try:
                        os.stat(
                            self._creation_intent_name(resource_id),
                            dir_fd=mission_descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        return
                    except OSError as exc:
                        raise ArtifactSecurityError(
                            "resource creation intent is unavailable"
                        ) from exc
                    intent = self._load_resource_creation_intent_anchored(
                        mission_id=mission_id,
                        resource_id=resource_id,
                        mission_descriptor=mission_descriptor,
                    )
                    if not (
                        intent.body.audit_required
                        and self._resource_exists_anchored(
                            mission_descriptor=mission_descriptor,
                            resource_id=resource_id,
                        )
                    ):
                        raise ArtifactSecurityError(
                            "creation-audit acknowledgment is invalid"
                        )
                    self._finish_resource_creation_intent_anchored(
                        intent=intent,
                        root_descriptor=root_descriptor,
                        mission_descriptor=mission_descriptor,
                        mission_metadata=mission_metadata,
                    )
            except FileNotFoundError:
                return

    def _recover_resource_creations_anchored(
        self,
        *,
        mission_id: str,
        root_descriptor: int,
        mission_descriptor: int,
        mission_metadata: os.stat_result,
    ) -> None:
        """Finish or roll back every durable key-and-envelope preparation."""

        try:
            entries = sorted(os.listdir(mission_descriptor))
        except OSError as exc:
            raise ArtifactSecurityError("mission storage is unavailable") from exc
        removed_pending = False
        for entry in entries:
            if _PENDING_RESOURCE_FILE.fullmatch(entry) is None:
                continue
            try:
                metadata = os.stat(
                    entry,
                    dir_fd=mission_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise ArtifactSecurityError(
                    "pending resource creation is unavailable"
                ) from exc
            if not (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink in {1, 2}
            ):
                raise ArtifactSecurityError("pending resource creation is invalid")
            try:
                os.unlink(entry, dir_fd=mission_descriptor)
            except OSError as exc:
                raise ArtifactSecurityError(
                    "pending resource cleanup failed"
                ) from exc
            removed_pending = True
        if removed_pending:
            try:
                os.fsync(mission_descriptor)
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource directory sync failed"
                ) from exc

        for entry in entries:
            if not (
                entry.startswith(_CREATION_INTENT_PREFIX)
                and entry.endswith(_CREATION_INTENT_SUFFIX)
            ):
                continue
            resource_id = entry[
                len(_CREATION_INTENT_PREFIX) : -len(_CREATION_INTENT_SUFFIX)
            ]
            self._validate_token(resource_id)
            if entry != self._creation_intent_name(resource_id):
                raise ArtifactSecurityError("resource creation intent is invalid")
            intent = self._load_resource_creation_intent_anchored(
                mission_id=mission_id,
                resource_id=resource_id,
                mission_descriptor=mission_descriptor,
            )
            if self._resource_exists_anchored(
                mission_descriptor=mission_descriptor,
                resource_id=resource_id,
            ):
                envelope = self._load_envelope_from_descriptor(
                    mission_descriptor=mission_descriptor,
                    resource_id=resource_id,
                )
                if not (
                    envelope.domain == self._domain
                    and envelope.mission_id == mission_id
                    and envelope.resource_id == resource_id
                    and envelope.encryption_metadata_id
                    == self._keys.metadata_id(envelope.payload.metadata)
                ):
                    raise ArtifactSecurityError(
                        "committed resource creation binding is invalid"
                    )
                self._verify_envelope(
                    envelope,
                    mission_id=mission_id,
                    resource_id=resource_id,
                    binding=envelope.binding.to_dict(),
                    expected_encryption_metadata_id=(
                        envelope.encryption_metadata_id
                    ),
                    now=None,
                )
            else:
                self._keys.destroy_resource_keys_for_resource(
                    self._domain,
                    intent.body.key_resource_id,
                )
            if not (
                intent.body.audit_required
                and self._resource_exists_anchored(
                    mission_descriptor=mission_descriptor,
                    resource_id=resource_id,
                )
            ):
                self._finish_resource_creation_intent_anchored(
                    intent=intent,
                    root_descriptor=root_descriptor,
                    mission_descriptor=mission_descriptor,
                    mission_metadata=mission_metadata,
                )

    def _prepare_resource_creation_intent_anchored(
        self,
        *,
        mission_id: str,
        resource_id: str,
        root_descriptor: int,
        mission_descriptor: int,
        mission_metadata: os.stat_result,
        audit_required: bool,
    ) -> _ResourceCreationIntent:
        body = _ResourceCreationIntentBody(
            schema_version="resource-creation-intent-v1",
            domain=self._domain,
            mission_id=mission_id,
            resource_id=resource_id,
            key_resource_id=stable_id(
                "resourcecreationkey",
                {
                    "schema_version": "resource-creation-key-v1",
                    "domain": self._domain,
                    "mission_id": mission_id,
                    "resource_id": resource_id,
                    "nonce": secrets.token_hex(32),
                },
            ),
            audit_required=audit_required,
        )
        verifier_metadata = self._keys.get_active_key_metadata(self._domain)
        intent = _ResourceCreationIntent(
            body=body,
            verifier_metadata=verifier_metadata,
            intent_digest=self._keys.keyed_digest(
                self._domain,
                "resource-creation-intent",
                canonicalize(
                    {
                        "body": body.model_dump(mode="python"),
                        "verifier_metadata": verifier_metadata.model_dump(
                            mode="python"
                        ),
                    }
                ),
                metadata=verifier_metadata,
            ),
        )
        serialized = canonicalize(intent.model_dump(mode="python"))
        if len(serialized) > _MAX_CREATION_INTENT_BYTES:
            raise ArtifactSecurityError("resource creation intent is invalid")
        name = self._creation_intent_name(resource_id)
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        temporary_name: str | None = None
        try:
            descriptor: int | None = None
            for _ in range(128):
                candidate = f".pending-{os.urandom(16).hex()}"
                try:
                    descriptor = os.open(
                        candidate,
                        file_flags,
                        0o600,
                        dir_fd=mission_descriptor,
                    )
                except FileExistsError:
                    continue
                except OSError as exc:
                    raise ArtifactSecurityError(
                        "resource creation intent is unavailable"
                    ) from exc
                temporary_name = candidate
                break
            if descriptor is None or temporary_name is None:
                raise ArtifactSecurityError(
                    "resource creation intent is unavailable"
                )
            try:
                offset = 0
                while offset < len(serialized):
                    written = os.write(descriptor, serialized[offset:])
                    if written <= 0:
                        raise ArtifactSecurityError(
                            "resource creation intent write failed"
                        )
                    offset += written
                os.fsync(descriptor)
            finally:
                with suppress(OSError):
                    os.close(descriptor)
            try:
                os.link(
                    temporary_name,
                    name,
                    src_dir_fd=mission_descriptor,
                    dst_dir_fd=mission_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                raise ArtifactSecurityError(
                    "resource creation intent already exists"
                ) from None
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource creation intent is unavailable"
                ) from exc
            try:
                os.unlink(temporary_name, dir_fd=mission_descriptor)
                temporary_name = None
                os.fsync(mission_descriptor)
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource directory sync failed"
                ) from exc
            self._require_current_mission_identity(
                mission_id=mission_id,
                root_descriptor=root_descriptor,
                mission_metadata=mission_metadata,
                operation="resource creation preparation",
            )
        except Exception:
            if temporary_name is not None:
                with suppress(OSError):
                    os.unlink(temporary_name, dir_fd=mission_descriptor)
            raise
        return intent

    def _load_resource_creation_intent_anchored(
        self,
        *,
        mission_id: str,
        resource_id: str,
        mission_descriptor: int,
    ) -> _ResourceCreationIntent:
        name = self._creation_intent_name(resource_id)
        file_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    name,
                    file_flags,
                    dir_fd=mission_descriptor,
                )
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource creation intent is unavailable"
                ) from exc
            metadata = os.fstat(descriptor)
            if not (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and metadata.st_size <= _MAX_CREATION_INTENT_BYTES
            ):
                raise ArtifactSecurityError("resource creation intent is invalid")
            raw = bytearray()
            while len(raw) <= _MAX_CREATION_INTENT_BYTES:
                chunk = os.read(
                    descriptor,
                    min(
                        4096,
                        _MAX_CREATION_INTENT_BYTES + 1 - len(raw),
                    ),
                )
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > _MAX_CREATION_INTENT_BYTES:
                raise ArtifactSecurityError("resource creation intent is invalid")
            try:
                canonical_loads(bytes(raw))
                intent = _ResourceCreationIntent.model_validate_json(
                    bytes(raw),
                    strict=True,
                )
            except (TypeError, ValueError) as exc:
                raise ArtifactSecurityError(
                    "resource creation intent is invalid"
                ) from exc
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
        if not (
            intent.body.domain == self._domain
            and intent.body.mission_id == mission_id
            and intent.body.resource_id == resource_id
            and secrets.compare_digest(
                intent.intent_digest,
                self._keys.keyed_digest(
                    self._domain,
                    "resource-creation-intent",
                    canonicalize(
                        {
                            "body": intent.body.model_dump(mode="python"),
                            "verifier_metadata": (
                                intent.verifier_metadata.model_dump(
                                    mode="python"
                                )
                            ),
                        }
                    ),
                    metadata=intent.verifier_metadata,
                ),
            )
        ):
            raise ArtifactSecurityError("resource creation intent binding is invalid")
        return intent

    def _finish_resource_creation_intent_anchored(
        self,
        *,
        intent: _ResourceCreationIntent,
        root_descriptor: int,
        mission_descriptor: int,
        mission_metadata: os.stat_result,
    ) -> None:
        self._require_current_mission_identity(
            mission_id=intent.body.mission_id,
            root_descriptor=root_descriptor,
            mission_metadata=mission_metadata,
            operation="resource creation commit",
        )
        current = self._load_resource_creation_intent_anchored(
            mission_id=intent.body.mission_id,
            resource_id=intent.body.resource_id,
            mission_descriptor=mission_descriptor,
        )
        if current != intent:
            raise ArtifactSecurityError("resource creation intent binding is invalid")
        try:
            os.unlink(
                self._creation_intent_name(intent.body.resource_id),
                dir_fd=mission_descriptor,
            )
            os.fsync(mission_descriptor)
        except OSError as exc:
            raise ArtifactSecurityError(
                "resource creation commit failed"
            ) from exc
        self._require_current_mission_identity(
            mission_id=intent.body.mission_id,
            root_descriptor=root_descriptor,
            mission_metadata=mission_metadata,
            operation="resource creation commit",
        )

    def _atomic_write(self, path: Path, data: bytes) -> None:
        mission_id = path.parent.name
        if path.parent != self._root / mission_id:
            raise ArtifactSecurityError("resource path escaped storage root")
        with self._anchored_mission_directory(mission_id) as (
            root_descriptor,
            mission_descriptor,
            mission_metadata,
        ):
            self._atomic_write_anchored(
                path=path,
                data=data,
                root_descriptor=root_descriptor,
                mission_descriptor=mission_descriptor,
                mission_metadata=mission_metadata,
            )

    def _atomic_write_anchored(
        self,
        *,
        path: Path,
        data: bytes,
        root_descriptor: int,
        mission_descriptor: int,
        mission_metadata: os.stat_result,
    ) -> None:
        mission_id = path.parent.name
        resource_id = path.stem
        self._validate_token(mission_id)
        self._validate_token(resource_id)
        if (
            path.parent != self._root / mission_id
            or path.name != f"{resource_id}.json"
        ):
            raise ArtifactSecurityError("resource path escaped storage root")
        root_metadata = os.fstat(root_descriptor)
        directory_metadata = os.fstat(mission_descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or (root_metadata.st_dev, root_metadata.st_ino)
            != self._root_identity
            or not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_dev != mission_metadata.st_dev
            or directory_metadata.st_ino != mission_metadata.st_ino
        ):
            raise ArtifactSecurityError("resource directory is invalid")
        self._require_current_mission_identity(
            mission_id=mission_id,
            root_descriptor=root_descriptor,
            mission_metadata=mission_metadata,
            operation="creation",
        )
        temporary_name: str | None = None
        try:
            file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            descriptor: int | None = None
            for _ in range(128):
                candidate = f".pending-{os.urandom(16).hex()}"
                try:
                    descriptor = os.open(
                        candidate,
                        file_flags,
                        0o600,
                        dir_fd=mission_descriptor,
                    )
                except FileExistsError:
                    continue
                except OSError as exc:
                    raise ArtifactSecurityError("resource creation failed") from exc
                temporary_name = candidate
                break
            if descriptor is None or temporary_name is None:
                raise ArtifactSecurityError("resource creation failed")
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(
                    temporary_name,
                    path.name,
                    src_dir_fd=mission_descriptor,
                    dst_dir_fd=mission_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                raise ArtifactSecurityError(
                    "resource identifier already exists"
                ) from None
            except OSError as exc:
                raise ArtifactSecurityError("resource creation failed") from exc
            try:
                os.unlink(temporary_name, dir_fd=mission_descriptor)
            except OSError as exc:
                raise ArtifactSecurityError("resource creation failed") from exc
            temporary_name = None
            try:
                os.fsync(mission_descriptor)
            except OSError as exc:
                raise ArtifactSecurityError("resource directory sync failed") from exc
            try:
                self._require_current_mission_identity(
                    mission_id=mission_id,
                    root_descriptor=root_descriptor,
                    mission_metadata=mission_metadata,
                    operation="creation",
                )
            except ArtifactSecurityError:
                with suppress(OSError):
                    os.unlink(path.name, dir_fd=mission_descriptor)
                    os.fsync(mission_descriptor)
                raise
        finally:
            if temporary_name is not None:
                with suppress(OSError):
                    os.unlink(temporary_name, dir_fd=mission_descriptor)

    @staticmethod
    def _sync_parent_directory(directory: Path) -> None:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            descriptor = os.open(directory, flags)
        except OSError as exc:
            raise ArtifactSecurityError(
                "resource directory is unavailable"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ArtifactSecurityError("resource directory is invalid")
            try:
                os.fsync(descriptor)
            except OSError as exc:
                raise ArtifactSecurityError(
                    "resource directory sync failed"
                ) from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)


class EncryptedRawResultQuarantine:
    def __init__(
        self,
        *,
        root: Path,
        keys: EncryptionKeyProvider,
        audit: DataStoreAuditRecorder,
        max_item_bytes: int,
        mission_quota_bytes: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = _EncryptedFileStore(
            root=root,
            domain="raw_result_quarantine",
            keys=keys,
            max_item_bytes=max_item_bytes,
            mission_quota_bytes=mission_quota_bytes,
        )
        self._audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))
        self._reconcile_pending_creation_audits()
        self._sweep_expired()

    def _trusted_time(self) -> datetime:
        try:
            now = self._clock()
            _require_time(now)
            return now
        except Exception as exc:
            raise ArtifactSecurityError(
                "trusted quarantine clock is unavailable"
            ) from exc

    def _reconcile_pending_creation_audits(self) -> None:
        for mission_id, resource_id in self._store.pending_creation_audits():
            if not resource_id.startswith("quarantine_"):
                raise ArtifactSecurityError(
                    "quarantine creation-audit recovery is invalid"
                )
            envelope = self._store.verified_envelope(
                mission_id=mission_id,
                resource_id=resource_id,
                now=None,
            )
            self._reconcile_commit_audit(
                self._reference_from_envelope(envelope)
            )

    def _sweep_expired(
        self,
        *,
        now: datetime | None = None,
        mission_id: str | None = None,
    ) -> None:
        now = self._clock() if now is None else now
        _require_time(now)
        mission_ids = (
            self._store.mission_ids() if mission_id is None else (mission_id,)
        )
        for mission_id in mission_ids:
            for intent_id in self._store.resource_ids_with_prefix(
                mission_id=mission_id,
                prefix="quarantinedeletion_",
            ):
                deletion_intent = self._load_deletion_intent(
                    mission_id=mission_id,
                    intent_id=intent_id,
                )
                self._resume_deletion_intent(
                    deletion_intent,
                    intent_id=intent_id,
                )
            for intent_id in self._store.resource_ids_with_prefix(
                mission_id=mission_id,
                prefix="quarantineexpiry_",
            ):
                expiry_intent = self._load_expiry_intent(
                    mission_id=mission_id,
                    intent_id=intent_id,
                )
                self._resume_expiry_intent(
                    expiry_intent,
                    intent_id=intent_id,
                )
            for resource_id in self._store.resource_ids_with_prefix(
                mission_id=mission_id,
                prefix="quarantine_",
            ):
                envelope = self._store.verified_envelope(
                    mission_id=mission_id,
                    resource_id=resource_id,
                    now=None,
                )
                reference = self._reference_from_envelope(envelope)
                if now >= reference.retention_until:
                    self._expire_reference(reference, now=now)

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
        operation_time = self._trusted_time()
        self._sweep_expired(now=operation_time, mission_id=mission_id)
        if retention_until <= operation_time:
            raise ArtifactSecurityError("quarantine retention has expired")
        binding: dict[str, object] = {
            "mission_revision": mission_revision,
            "execution_id": execution_id,
        }
        resource_id = stable_id(
            "quarantine",
            {
                "schema_version": "quarantine-reference-v2",
                "mission_id": mission_id,
                **binding,
            },
        )
        digest, metadata_id = self._store.write(
            mission_id=mission_id,
            resource_id=resource_id,
            content=content,
            binding=binding,
            created_at=created_at,
            retention_until=retention_until,
            require_creation_audit=True,
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
        self._reconcile_commit_audit(reference)
        return reference

    def _reconcile_commit_audit(self, reference: QuarantineReference) -> None:
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=reference.quarantine_id,
            operation="commit",
            operation_id=stable_id(
                "auditop",
                {
                    "schema_version": "quarantine-commit-audit-v1",
                    "quarantine_id": reference.quarantine_id,
                    "encryption_metadata_id": (
                        reference.encryption_metadata_id
                    ),
                    "created_at": reference.created_at,
                },
            ),
            metadata_digest=reference.sha256,
            occurred_at=reference.created_at,
        )
        self._store.acknowledge_creation_audit(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
        )

    def resume(self, reference: QuarantineReference, *, now: datetime) -> bytes:
        del reference, now
        raise ArtifactSecurityError(
            "quarantine plaintext requires trusted ingestion"
        )

    def _resume_for_ingestion(self, publication: object) -> bytes:
        from .ingestion import _FullObjectIngestionPublication

        if type(publication) is not _FullObjectIngestionPublication:
            raise ArtifactSecurityError(
                "quarantine ingestion publication is not trusted"
            )
        trusted_publication = cast(Any, publication)
        reference, _, _ = trusted_publication._binding()
        operation_time = self._trusted_time()
        try:
            return self._release_for_ingestion(
                reference,
                operation_time=operation_time,
            )
        except Exception as failure:
            failure.__traceback__ = None
        raise ArtifactSecurityError("quarantine ingestion release failed closed")

    def _release_for_ingestion(
        self,
        reference: QuarantineReference,
        *,
        operation_time: datetime,
    ) -> bytes:
        """Decrypt and audit raw output outside the sanitized caller frame."""

        self._sweep_expired(
            now=operation_time,
            mission_id=reference.mission_id,
        )
        if operation_time >= reference.retention_until:
            self._expire_reference(reference, now=operation_time)
            raise ArtifactSecurityError("encrypted resource retention has expired")
        content, envelope = self._store.read_bound(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
            now=operation_time,
        )
        expected_binding = CanonicalJsonObject(
            {
                "mission_revision": reference.mission_revision,
                "execution_id": reference.execution_id,
            }
        )
        if not (
            envelope.binding == expected_binding
            and envelope.encryption_metadata_id == reference.encryption_metadata_id
            and len(content) == reference.size_bytes
            and self._store._content_digest(
                content,
                metadata=envelope.payload.metadata,
            )
            == reference.sha256
        ):
            raise DigestIntegrityError("quarantine reference integrity failed")
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=reference.quarantine_id,
            operation="resume",
            metadata_digest=reference.sha256,
            occurred_at=operation_time,
        )
        return content

    def _expire_reference(
        self,
        reference: QuarantineReference,
        *,
        now: datetime,
    ) -> None:
        if now < reference.retention_until:
            raise ArtifactSecurityError("quarantine retention has not expired")
        intent_id = self._expiry_intent_id(reference.quarantine_id)
        if not self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=intent_id,
        ):
            target_exists = self._store.has_resource(
                mission_id=reference.mission_id,
                resource_id=reference.quarantine_id,
            )
            if not target_exists:
                return
            authoritative = self._reference_from_envelope(
                self._store.verified_envelope(
                    mission_id=reference.mission_id,
                    resource_id=reference.quarantine_id,
                    now=None,
                )
            )
            if authoritative != reference:
                raise DigestIntegrityError(
                    "quarantine reference integrity failed"
                )
            intent = _QuarantineExpiryIntent(
                record_type="quarantine_expiry_intent",
                reference=reference,
            )
            self._store.write_quarantine_cleanup_intent(
                mission_id=reference.mission_id,
                resource_id=intent_id,
                binding=intent.model_dump(mode="json"),
                created_at=now,
            )
        intent = self._load_expiry_intent(
            mission_id=reference.mission_id,
            intent_id=intent_id,
        )
        if intent.reference != reference:
            raise DigestIntegrityError("quarantine expiry intent binding failed")
        self._resume_expiry_intent(intent, intent_id=intent_id)

    def _resume_expiry_intent(
        self,
        intent: _QuarantineExpiryIntent,
        *,
        intent_id: str,
    ) -> None:
        reference = intent.reference
        if intent_id != self._expiry_intent_id(reference.quarantine_id):
            raise ArtifactSecurityError("quarantine expiry intent binding is invalid")
        if self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
        ):
            authoritative = self._reference_from_envelope(
                self._store.verified_envelope(
                    mission_id=reference.mission_id,
                    resource_id=reference.quarantine_id,
                    now=None,
                )
            )
            if authoritative != reference:
                raise DigestIntegrityError("quarantine expiry target binding failed")
        _, intent_envelope = self._store.read_bound(
            mission_id=reference.mission_id,
            resource_id=intent_id,
            now=None,
        )
        if intent_envelope.created_at < reference.retention_until:
            raise ArtifactSecurityError(
                "quarantine expiry intent predates retention"
            )
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=reference.quarantine_id,
            operation="delete",
            operation_id=stable_id(
                "auditop",
                {
                    "schema_version": "quarantine-expiry-audit-v1",
                    "quarantine_id": reference.quarantine_id,
                },
            ),
            metadata_digest=reference.sha256,
            occurred_at=intent_envelope.created_at,
        )
        self._store.erase_resource(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
        )
        self._store.erase_resource(
            mission_id=reference.mission_id,
            resource_id=intent_id,
        )

    def _load_expiry_intent(
        self,
        *,
        mission_id: str,
        intent_id: str,
    ) -> _QuarantineExpiryIntent:
        raw, envelope = self._store.read_bound(
            mission_id=mission_id,
            resource_id=intent_id,
            now=None,
        )
        if raw:
            raise ArtifactSecurityError("quarantine expiry intent content is invalid")
        try:
            intent = _QuarantineExpiryIntent.model_validate_json(
                canonicalize(envelope.binding.to_dict()),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactSecurityError(
                "quarantine expiry intent is invalid"
            ) from exc
        if not (
            intent.reference.mission_id == mission_id
            and intent_id == self._expiry_intent_id(
                intent.reference.quarantine_id
            )
        ):
            raise ArtifactSecurityError("quarantine expiry intent binding is invalid")
        return intent

    @staticmethod
    def _reference_from_envelope(envelope: _StoredEnvelope) -> QuarantineReference:
        binding = envelope.binding.to_dict()
        mission_revision = binding.get("mission_revision")
        execution_id = binding.get("execution_id")
        if not (
            set(binding) == {"mission_revision", "execution_id"}
            and isinstance(mission_revision, int)
            and not isinstance(mission_revision, bool)
            and mission_revision >= 1
            and isinstance(execution_id, str)
            and execution_id
            and envelope.retention_until is not None
        ):
            raise ArtifactSecurityError("quarantine envelope binding is invalid")
        return QuarantineReference(
            quarantine_id=envelope.resource_id,
            mission_id=envelope.mission_id,
            mission_revision=mission_revision,
            execution_id=execution_id,
            size_bytes=envelope.plaintext_size,
            sha256=envelope.plaintext_sha256,
            encryption_metadata_id=envelope.encryption_metadata_id,
            created_at=envelope.created_at,
            retention_until=envelope.retention_until,
        )

    @staticmethod
    def _expiry_intent_id(quarantine_id: str) -> str:
        return stable_id(
            "quarantineexpiry",
            {
                "schema_version": "quarantine-expiry-intent-v1",
                "quarantine_id": quarantine_id,
            },
        )

    def delete(self, reference: QuarantineReference, *, now: datetime) -> None:
        del now
        operation_time = self._trusted_time()
        intent_id = self._deletion_intent_id(reference.quarantine_id)
        if not self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=intent_id,
        ):
            authoritative = self._reference_from_envelope(
                self._store.verified_envelope(
                    mission_id=reference.mission_id,
                    resource_id=reference.quarantine_id,
                    now=None,
                )
            )
            if authoritative != reference:
                raise DigestIntegrityError(
                    "quarantine deletion target binding failed"
                )
            intent = _QuarantineDeletionIntent(
                record_type="quarantine_delete_intent",
                reference=reference,
            )
            self._store.write_quarantine_cleanup_intent(
                mission_id=reference.mission_id,
                resource_id=intent_id,
                binding=intent.model_dump(mode="json"),
                created_at=operation_time,
            )
        intent = self._load_deletion_intent(
            mission_id=reference.mission_id,
            intent_id=intent_id,
        )
        if intent.reference != reference:
            raise DigestIntegrityError(
                "quarantine deletion intent binding failed"
            )
        self._resume_deletion_intent(intent, intent_id=intent_id)

    def _resume_deletion_intent(
        self,
        intent: _QuarantineDeletionIntent,
        *,
        intent_id: str,
    ) -> None:
        reference = intent.reference
        if intent_id != self._deletion_intent_id(reference.quarantine_id):
            raise ArtifactSecurityError(
                "quarantine deletion intent binding is invalid"
            )
        if self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
        ):
            authoritative = self._reference_from_envelope(
                self._store.verified_envelope(
                    mission_id=reference.mission_id,
                    resource_id=reference.quarantine_id,
                    now=None,
                )
            )
            if authoritative != reference:
                raise DigestIntegrityError(
                    "quarantine deletion target binding failed"
                )
        _, intent_envelope = self._store.read_bound(
            mission_id=reference.mission_id,
            resource_id=intent_id,
            now=None,
        )
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=reference.quarantine_id,
            operation="delete",
            operation_id=stable_id(
                "auditop",
                {
                    "schema_version": "quarantine-delete-audit-v1",
                    "quarantine_id": reference.quarantine_id,
                    "encryption_metadata_id": reference.encryption_metadata_id,
                    "created_at": reference.created_at,
                },
            ),
            metadata_digest=reference.sha256,
            occurred_at=intent_envelope.created_at,
        )
        if self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
        ):
            self._store.erase_resource(
                mission_id=reference.mission_id,
                resource_id=reference.quarantine_id,
            )
        self._store.erase_resource(
            mission_id=reference.mission_id,
            resource_id=intent_id,
        )

    def _load_deletion_intent(
        self,
        *,
        mission_id: str,
        intent_id: str,
    ) -> _QuarantineDeletionIntent:
        raw, envelope = self._store.read_bound(
            mission_id=mission_id,
            resource_id=intent_id,
            now=None,
        )
        if raw:
            raise ArtifactSecurityError(
                "quarantine deletion intent content is invalid"
            )
        try:
            intent = _QuarantineDeletionIntent.model_validate_json(
                canonicalize(envelope.binding.to_dict()),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactSecurityError(
                "quarantine deletion intent is invalid"
            ) from exc
        if not (
            intent.reference.mission_id == mission_id
            and intent_id == self._deletion_intent_id(
                intent.reference.quarantine_id
            )
        ):
            raise ArtifactSecurityError(
                "quarantine deletion intent binding is invalid"
            )
        return intent

    @staticmethod
    def _deletion_intent_id(quarantine_id: str) -> str:
        return stable_id(
            "quarantinedeletion",
            {
                "schema_version": "quarantine-deletion-intent-v1",
                "quarantine_id": quarantine_id,
            },
        )


class ArtifactStore:
    def __init__(
        self,
        *,
        root: Path,
        keys: EncryptionKeyProvider,
        authorizer: RepositoryDataAccessAuthorizer,
        audit: DataStoreAuditRecorder,
        max_item_bytes: int,
        mission_quota_bytes: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(authorizer) is not RepositoryDataAccessAuthorizer:
            raise SecretAccessError(
                "artifact store requires a trusted data access authorizer"
            )
        self._store = _EncryptedFileStore(
            root=root,
            domain="artifact_store",
            keys=keys,
            max_item_bytes=max_item_bytes,
            mission_quota_bytes=mission_quota_bytes,
        )
        self._authorizer = authorizer
        self._audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))
        self.max_observed_stream_chunk_bytes = 0
        self._reconcile_pending_creation_audits()
        self._resume_pending_stream_cleanups()
        self._sweep_expired_artifacts()

    def _trusted_time(self) -> datetime:
        try:
            now = self._clock()
            _require_time(now)
            return now
        except Exception as exc:
            raise ArtifactSecurityError(
                "trusted artifact clock is unavailable"
            ) from exc

    def _reconcile_pending_creation_audits(self) -> None:
        for mission_id, resource_id in self._store.pending_creation_audits():
            if not resource_id.startswith("artifact_"):
                raise ArtifactSecurityError(
                    "artifact creation-audit recovery is invalid"
                )
            self._reconcile_create_audit(
                self._stored_reference(
                    mission_id=mission_id,
                    artifact_id=resource_id,
                    now=None,
                )
            )

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
        return self._put(
            mission_id=mission_id,
            content=content,
            media_type=media_type,
            classification=classification,
            variant=variant,
            source_execution_id=source_execution_id,
            created_at=created_at,
            publication=None,
            retention_until=retention_until,
            derived_from_artifact_id=derived_from_artifact_id,
        )

    def _publish_ingested_object(
        self,
        publication: object,
    ) -> ArtifactReference:
        return self._put(
            mission_id="publication-pending",
            content=b"",
            media_type="application/octet-stream",
            classification="normal",
            variant="redacted",
            source_execution_id="publication-pending",
            created_at=datetime.min.replace(tzinfo=UTC),
            publication=publication,
            retention_until=None,
            derived_from_artifact_id=None,
        )

    def _put(
        self,
        *,
        mission_id: str,
        content: bytes,
        media_type: str,
        classification: Literal["normal", "sensitive", "secret"],
        variant: Literal["redacted", "encrypted_raw"],
        source_execution_id: str,
        created_at: datetime,
        publication: object | None,
        retention_until: datetime | None,
        derived_from_artifact_id: str | None,
    ) -> ArtifactReference:
        ingestion_evidence = None
        if publication is not None:
            from .ingestion import _IngestedObjectArtifactPublication

            if type(publication) is not _IngestedObjectArtifactPublication:
                raise ArtifactSecurityError(
                    "object-artifact publication is not trusted"
                )
            trusted_publication = cast(Any, publication)
            (
                receipt,
                mission_id,
                content,
                classification,
                variant,
                derived_from_artifact_id,
                created_at,
            ) = trusted_publication._consume()
            media_type = "application/octet-stream"
            source_execution_id = receipt.execution_id
            retention_until = None
            ingestion_evidence = self._authorizer._begin_ingestion_write(
                receipt=receipt,
                now=created_at,
            )
        _require_bytes(content)
        operation_time = self._trusted_time()
        self._sweep_expired_artifacts(
            now=operation_time,
            mission_id=mission_id,
        )
        self._validate_metadata(
            media_type=media_type,
            classification=classification,
            variant=variant,
            created_at=created_at,
            retention_until=retention_until,
        )
        if retention_until is not None and retention_until <= operation_time:
            raise ArtifactSecurityError("artifact retention has expired")
        content_digest = self._store._content_digest(content)
        artifact_id = self._artifact_id(
            mission_id=mission_id,
            content_digest=content_digest,
            media_type=media_type,
            classification=classification,
            variant=variant,
            source_execution_id=source_execution_id,
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
            evidence=ingestion_evidence,
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
                require_creation_audit=True,
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
        return await self._put_stream(
            mission_id=mission_id,
            chunks=chunks,
            media_type=media_type,
            classification=classification,
            variant=variant,
            source_execution_id=source_execution_id,
            created_at=created_at,
            publication=None,
            retention_until=retention_until,
            derived_from_artifact_id=derived_from_artifact_id,
        )

    async def _publish_redacted_stream(
        self,
        publication: object,
    ) -> ArtifactReference:
        from .ingestion import _RedactedArtifactPublication

        if type(publication) is not _RedactedArtifactPublication:
            raise ArtifactSecurityError(
                "artifact publication transaction is not trusted"
            )
        trusted_publication = cast(Any, publication)
        _, mission_id, source_execution_id, created_at = (
            trusted_publication._binding()
        )
        return await self._put_stream(
            mission_id=mission_id,
            chunks=None,
            media_type="application/octet-stream",
            classification=trusted_publication._classification,
            variant="redacted",
            source_execution_id=source_execution_id,
            created_at=created_at,
            publication=publication,
            retention_until=None,
            derived_from_artifact_id=None,
        )

    async def _put_stream(
        self,
        *,
        mission_id: str,
        chunks: AsyncIterator[bytes] | None,
        media_type: str,
        classification: Callable[
            [], Literal["normal", "sensitive", "secret"]
        ],
        variant: Literal["redacted", "encrypted_raw"],
        source_execution_id: str,
        created_at: datetime,
        publication: object | None,
        retention_until: datetime | None,
        derived_from_artifact_id: str | None,
    ) -> ArtifactReference:
        """Persist a stream with a restartable intent for orphan-chunk cleanup."""

        operation_time = self._trusted_time()
        self._sweep_expired_artifacts(
            now=operation_time,
            mission_id=mission_id,
        )
        if retention_until is not None and retention_until <= operation_time:
            raise ArtifactSecurityError("artifact retention has expired")
        stream_id = self._artifact_stream_id(
            mission_id=mission_id,
            media_type=media_type,
            variant=variant,
            source_execution_id=source_execution_id,
            derived_from_artifact_id=derived_from_artifact_id,
        )
        async with self._serialized_artifact_stream(stream_id):
            cleanup_id = self._begin_stream_cleanup(
                mission_id=mission_id,
                stream_id=stream_id,
                source_execution_id=source_execution_id,
                created_at=created_at,
            )
            try:
                reference = await self._put_stream_unreconciled(
                    mission_id=mission_id,
                    chunks=chunks,
                    media_type=media_type,
                    classification=classification,
                    variant=variant,
                    source_execution_id=source_execution_id,
                    created_at=created_at,
                    publication=publication,
                    retention_until=retention_until,
                    derived_from_artifact_id=derived_from_artifact_id,
                    attempt_id=cleanup_id,
                )
            except Exception:
                with suppress(Exception):
                    self._resume_stream_cleanup(
                        mission_id=mission_id,
                        cleanup_id=cleanup_id,
                        stream_id=stream_id,
                        source_execution_id=source_execution_id,
                    )
                raise
            self._finish_stream_cleanup(
                mission_id=mission_id,
                cleanup_id=cleanup_id,
                stream_id=stream_id,
                source_execution_id=source_execution_id,
            )
            return reference

    async def _put_stream_unreconciled(
        self,
        *,
        mission_id: str,
        chunks: AsyncIterator[bytes] | None,
        media_type: str,
        classification: Callable[
            [], Literal["normal", "sensitive", "secret"]
        ],
        variant: Literal["redacted", "encrypted_raw"],
        source_execution_id: str,
        created_at: datetime,
        publication: object | None,
        retention_until: datetime | None = None,
        derived_from_artifact_id: str | None = None,
        attempt_id: str,
    ) -> ArtifactReference:
        """Persist a logical artifact without materializing the complete content."""

        _require_time(created_at)
        ingestion_evidence = None
        if publication is not None:
            from .ingestion import _RedactedArtifactPublication

            if type(publication) is not _RedactedArtifactPublication:
                raise ArtifactSecurityError(
                    "artifact publication transaction is not trusted"
                )
            trusted_publication = cast(Any, publication)
            receipt, bound_mission_id, bound_execution_id, bound_now = (
                trusted_publication._binding()
            )
            if not (
                mission_id == bound_mission_id
                and source_execution_id == bound_execution_id
                and created_at == bound_now
                and media_type == "application/octet-stream"
                and variant == "redacted"
                and retention_until is None
                and derived_from_artifact_id is None
            ):
                raise ArtifactSecurityError(
                    "artifact publication binding is invalid"
                )
            chunks = trusted_publication._chunks()
            classification = trusted_publication._classification
            ingestion_evidence = self._authorizer._begin_ingestion_write(
                receipt=receipt,
                now=created_at,
            )
        if chunks is None:
            raise ArtifactSecurityError("artifact stream content is unavailable")
        if not media_type or variant not in {"redacted", "encrypted_raw"}:
            raise ArtifactSecurityError("artifact stream metadata is invalid")
        if retention_until is not None:
            _require_time(retention_until)
            if retention_until <= created_at:
                raise ArtifactSecurityError("artifact retention is invalid")
        stream_id = self._artifact_stream_id(
            mission_id=mission_id,
            media_type=media_type,
            variant=variant,
            source_execution_id=source_execution_id,
            derived_from_artifact_id=derived_from_artifact_id,
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
            evidence=ingestion_evidence,
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
                attempt_id=attempt_id,
                source_execution_id=source_execution_id,
                sequence_number=sequence,
                plaintext_offset=size_bytes,
                plaintext_size=len(content),
                plaintext_sha256=content_digest,
            )
            resource_id = self._artifact_stream_chunk_id(
                stream_id,
                attempt_id,
                sequence,
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
            media_type=media_type,
            classification=resolved_classification,
            variant=variant,
            source_execution_id=source_execution_id,
            derived_from_artifact_id=derived_from_artifact_id,
        )
        manifest = _ArtifactStreamManifest(
            schema_version="artifact-stream-v1",
            artifact_id=artifact_id,
            stream_id=stream_id,
            attempt_id=attempt_id,
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
            attempt_id=attempt_id,
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
            evidence=ingestion_evidence,
            now=created_at,
        )
        manifest_content = canonicalize(manifest.model_dump(mode="python"))
        if self._store.has_resource(mission_id=mission_id, resource_id=artifact_id):
            existing, envelope = self._store.read_bound(
                mission_id=mission_id,
                resource_id=artifact_id,
                now=None,
            )
            try:
                canonical_loads(existing)
                existing_manifest = _ArtifactStreamManifest.model_validate_json(
                    existing,
                    strict=True,
                )
            except (TypeError, ValueError) as exc:
                raise ArtifactSecurityError(
                    "artifact stream manifest is invalid"
                ) from exc
            equivalent_manifest = existing_manifest.model_copy(
                update={
                    "attempt_id": attempt_id,
                    "chunks": tuple(chunk_references),
                }
            )
            expected_existing_binding = {
                **binding,
                "attempt_id": existing_manifest.attempt_id,
            }
            if not (
                equivalent_manifest == manifest
                and existing
                == canonicalize(existing_manifest.model_dump(mode="python"))
                and envelope.binding
                == CanonicalJsonObject(expected_existing_binding)
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
                require_creation_audit=True,
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

    def _resume_pending_stream_cleanups(self) -> None:
        for mission_id in self._store.mission_ids():
            for cleanup_id in self._store.resource_ids_with_prefix(
                mission_id=mission_id,
                prefix="artifactcleanup_",
            ):
                intent = self._load_stream_cleanup_intent(
                    mission_id=mission_id,
                    cleanup_id=cleanup_id,
                )
                with self._try_serialized_artifact_stream(
                    intent.stream_id
                ) as acquired:
                    if not acquired or not self._store.has_resource(
                        mission_id=mission_id,
                        resource_id=cleanup_id,
                    ):
                        continue
                    self._resume_stream_cleanup(
                        mission_id=mission_id,
                        cleanup_id=cleanup_id,
                        stream_id=intent.stream_id,
                        source_execution_id=intent.source_execution_id,
                    )

    def _sweep_expired_artifacts(
        self,
        *,
        now: datetime | None = None,
        mission_id: str | None = None,
    ) -> None:
        now = self._clock() if now is None else now
        _require_time(now)
        mission_ids = (
            self._store.mission_ids() if mission_id is None else (mission_id,)
        )
        for mission_id in mission_ids:
            for intent_id in self._store.resource_ids_with_prefix(
                mission_id=mission_id,
                prefix="artifactdeletion_",
            ):
                intent, intent_envelope = self._load_deletion_intent_by_id(
                    mission_id=mission_id,
                    intent_id=intent_id,
                )
                self._resume_artifact_expiry(intent, intent_envelope)
            for artifact_id in self._store.resource_ids_with_prefix(
                mission_id=mission_id,
                prefix="artifact_",
            ):
                reference = self._stored_reference(
                    mission_id=mission_id,
                    artifact_id=artifact_id,
                    now=None,
                )
                if (
                    reference.retention_until is not None
                    and now >= reference.retention_until
                ):
                    self._expire_authoritative(reference, now=now)

    @asynccontextmanager
    async def _serialized_artifact_stream(
        self,
        stream_id: str,
    ) -> AsyncIterator[None]:
        descriptor = self._open_stream_lock(stream_id)
        locked = False
        try:
            while not locked:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                except OSError as exc:
                    raise ArtifactSecurityError(
                        "artifact stream lock acquisition failed"
                    ) from exc
            yield
        finally:
            if locked:
                with suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextmanager
    def _try_serialized_artifact_stream(
        self,
        stream_id: str,
    ) -> Iterator[bool]:
        descriptor = self._open_stream_lock(stream_id)
        locked = False
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except BlockingIOError:
                pass
            except OSError as exc:
                raise ArtifactSecurityError(
                    "artifact stream lock acquisition failed"
                ) from exc
            yield locked
        finally:
            if locked:
                with suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _open_stream_lock(self, stream_id: str) -> int:
        self._store._validate_token(stream_id)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        try:
            directory_descriptor = os.open(self._store._root, directory_flags)
        except OSError as exc:
            raise ArtifactSecurityError(
                "artifact stream lock directory is unavailable"
            ) from exc
        lock_name = f".{stream_id}.lock"
        lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        try:
            directory_metadata = os.fstat(directory_descriptor)
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or (directory_metadata.st_dev, directory_metadata.st_ino)
                != self._store._root_identity
            ):
                raise ArtifactSecurityError(
                    "artifact stream lock directory identity changed"
                )
            try:
                descriptor = os.open(
                    lock_name,
                    lock_flags,
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise ArtifactSecurityError(
                    "artifact stream lock is unavailable"
                ) from exc
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                os.close(descriptor)
                raise ArtifactSecurityError("artifact stream lock is invalid")
            return descriptor
        finally:
            os.close(directory_descriptor)

    def _begin_stream_cleanup(
        self,
        *,
        mission_id: str,
        stream_id: str,
        source_execution_id: str,
        created_at: datetime,
    ) -> str:
        for pending_id in self._store.resource_ids_with_prefix(
            mission_id=mission_id,
            prefix="artifactcleanup_",
        ):
            pending = self._load_stream_cleanup_intent(
                mission_id=mission_id,
                cleanup_id=pending_id,
            )
            if (
                pending.stream_id == stream_id
                and pending.source_execution_id == source_execution_id
            ):
                self._resume_stream_cleanup(
                    mission_id=mission_id,
                    cleanup_id=pending_id,
                    stream_id=stream_id,
                    source_execution_id=source_execution_id,
                )
        cleanup_id = stable_id(
            "artifactcleanup",
            {
                "schema_version": "artifact-stream-cleanup-v1",
                "stream_id": stream_id,
                "nonce": secrets.token_hex(16),
            },
        )
        intent = _ArtifactStreamCleanupIntent(
            record_type="artifact_stream_cleanup_intent",
            cleanup_id=cleanup_id,
            stream_id=stream_id,
            source_execution_id=source_execution_id,
        )
        self._store.write(
            mission_id=mission_id,
            resource_id=cleanup_id,
            content=b"",
            binding=intent.model_dump(mode="python"),
            created_at=created_at,
            retention_until=None,
        )
        return cleanup_id

    def _finish_stream_cleanup(
        self,
        *,
        mission_id: str,
        cleanup_id: str,
        stream_id: str,
        source_execution_id: str,
    ) -> None:
        self._resume_stream_cleanup(
            mission_id=mission_id,
            cleanup_id=cleanup_id,
            stream_id=stream_id,
            source_execution_id=source_execution_id,
        )

    def _resume_stream_cleanup(
        self,
        *,
        mission_id: str,
        cleanup_id: str,
        stream_id: str,
        source_execution_id: str,
    ) -> None:
        intent = self._load_stream_cleanup_intent(
            mission_id=mission_id,
            cleanup_id=cleanup_id,
        )
        if not (
            intent.cleanup_id == cleanup_id
            and intent.stream_id == stream_id
            and intent.source_execution_id == source_execution_id
        ):
            raise ArtifactSecurityError(
                "artifact stream cleanup binding is invalid"
            )
        completed_reference: ArtifactReference | None = None
        for artifact_id in self._store.resource_ids_with_prefix(
            mission_id=mission_id,
            prefix="artifact_",
        ):
            envelope = self._store.verified_envelope(
                mission_id=mission_id,
                resource_id=artifact_id,
                now=None,
            )
            binding = envelope.binding.to_dict()
            if (
                binding.get("storage_format") == "artifact-stream-v1"
                and binding.get("stream_id") == stream_id
                and binding.get("attempt_id") == cleanup_id
                and binding.get("source_execution_id") == source_execution_id
            ):
                completed_reference = self._stored_reference(
                    mission_id=mission_id,
                    artifact_id=artifact_id,
                    now=None,
                )
                break
        if completed_reference is None:
            maximum_chunks = max(
                1,
                (self._store._max_item_bytes + _ARTIFACT_STREAM_CHUNK_BYTES - 1)
                // _ARTIFACT_STREAM_CHUNK_BYTES,
            )
            for sequence in range(maximum_chunks):
                resource_id = self._artifact_stream_chunk_id(
                    stream_id,
                    cleanup_id,
                    sequence,
                )
                if self._store.has_resource(
                    mission_id=mission_id,
                    resource_id=resource_id,
                ):
                    self._store.erase_resource(
                        mission_id=mission_id,
                        resource_id=resource_id,
                    )
        else:
            self._reconcile_create_audit(completed_reference)
        self._store.erase_resource(
            mission_id=mission_id,
            resource_id=cleanup_id,
        )

    def _load_stream_cleanup_intent(
        self,
        *,
        mission_id: str,
        cleanup_id: str,
    ) -> _ArtifactStreamCleanupIntent:
        raw, envelope = self._store.read_bound(
            mission_id=mission_id,
            resource_id=cleanup_id,
            now=None,
        )
        if raw:
            raise ArtifactSecurityError("artifact stream cleanup content is invalid")
        try:
            intent = _ArtifactStreamCleanupIntent.model_validate_json(
                canonicalize(envelope.binding.to_dict()),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise ArtifactSecurityError(
                "artifact stream cleanup intent is invalid"
            ) from exc
        if intent.cleanup_id != cleanup_id:
            raise ArtifactSecurityError("artifact stream cleanup binding is invalid")
        return intent

    def read(
        self,
        reference: ArtifactReference,
        *,
        execution_id: str,
        operation: Literal["read", "export"],
        now: datetime,
    ) -> bytes:
        del now
        operation_time = self._trusted_time()
        self._sweep_expired_artifacts(
            now=operation_time,
            mission_id=reference.mission_id,
        )
        authoritative = self._stored_reference(
            mission_id=reference.mission_id,
            artifact_id=reference.artifact_id,
            now=operation_time,
        )
        if authoritative != reference:
            raise DigestIntegrityError("artifact reference integrity failed")
        if authoritative.variant == "encrypted_raw" and operation == "read":
            raise SecretAccessError(
                "encrypted raw artifacts are unavailable to context reads"
            )
        self._reconcile_create_audit(authoritative)
        self._authorizer.require_access(
            mission_id=reference.mission_id,
            execution_id=execution_id,
            resource_type="artifact",
            resource=ResourceBinding(
                resource_id=reference.artifact_id,
                resource_version="1",
                resource_digest=reference.sha256,
            ),
            operation=operation,
            now=operation_time,
        )
        envelope = self._store.verified_envelope(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
            now=operation_time,
        )
        try:
            return self._release_authorized_content(
                reference,
                envelope=envelope,
                operation=operation,
                now=operation_time,
            )
        except Exception as failure:
            failure.__traceback__ = None
        raise ArtifactSecurityError("artifact release failed closed")

    def _release_authorized_content(
        self,
        reference: ArtifactReference,
        *,
        envelope: _StoredEnvelope,
        operation: Literal["read", "export"],
        now: datetime,
    ) -> bytes:
        """Decrypt and audit content outside the sanitized public error frame."""

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

    def expire(
        self,
        reference: ArtifactReference,
        *,
        execution_id: str,
        now: datetime,
    ) -> None:
        """Cryptographically erase an expired Artifact through a durable intent."""

        del now
        now = self._trusted_time()
        intent_id = self._deletion_intent_id(reference.artifact_id)
        intent_exists = self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=intent_id,
        )
        if intent_exists:
            intent, intent_envelope = self._load_deletion_intent(
                mission_id=reference.mission_id,
                artifact_id=reference.artifact_id,
            )
            authoritative = intent.reference
            deletion_completed = False
        elif self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
        ):
            authoritative = self._stored_reference(
                mission_id=reference.mission_id,
                artifact_id=reference.artifact_id,
                now=None,
            )
            intent = None
            intent_envelope = None
            deletion_completed = False
        else:
            authoritative = reference
            intent = None
            intent_envelope = None
            deletion_completed = True
        if authoritative != reference:
            raise DigestIntegrityError("artifact reference integrity failed")
        if reference.retention_until is None or now < reference.retention_until:
            raise ArtifactSecurityError("artifact retention has not expired")
        self._authorizer.require_access(
            mission_id=reference.mission_id,
            execution_id=execution_id,
            resource_type="artifact",
            resource=ResourceBinding(
                resource_id=reference.artifact_id,
                resource_version="1",
                resource_digest=reference.sha256,
            ),
            operation="write",
            now=now,
        )
        if deletion_completed:
            if not self._audit.operation_recorded(
                mission_id=reference.mission_id,
                resource_type="artifact",
                resource_id=reference.artifact_id,
                operation="delete",
                operation_id=self._expiry_audit_operation_id(reference),
                metadata_digest=reference.sha256,
            ):
                raise ArtifactSecurityError(
                    "artifact deletion state is unavailable"
                )
            return
        self._expire_authoritative(
            authoritative,
            now=now,
            intent=intent,
            intent_envelope=intent_envelope,
        )

    def _expire_authoritative(
        self,
        reference: ArtifactReference,
        *,
        now: datetime,
        intent: _ArtifactDeletionIntent | None = None,
        intent_envelope: _StoredEnvelope | None = None,
    ) -> None:
        if reference.retention_until is None or now < reference.retention_until:
            raise ArtifactSecurityError("artifact retention has not expired")
        self._reconcile_create_audit(reference)
        intent_id = self._deletion_intent_id(reference.artifact_id)
        if intent is None:
            intent = _ArtifactDeletionIntent(
                record_type="artifact_delete_intent",
                reference=reference,
                resource_ids=self._deletion_targets(reference),
            )
            self._store.write_artifact_deletion_intent(
                mission_id=reference.mission_id,
                resource_id=intent_id,
                binding=intent.model_dump(mode="json"),
                created_at=now,
            )
            intent, intent_envelope = self._load_deletion_intent(
                mission_id=reference.mission_id,
                artifact_id=reference.artifact_id,
            )
        if intent_envelope is None:
            raise ArtifactSecurityError("artifact deletion intent is unavailable")
        self._resume_artifact_expiry(intent, intent_envelope)

    def _resume_artifact_expiry(
        self,
        intent: _ArtifactDeletionIntent,
        intent_envelope: _StoredEnvelope,
    ) -> None:
        reference = intent.reference
        if (
            reference.retention_until is None
            or intent_envelope.created_at < reference.retention_until
        ):
            raise ArtifactSecurityError(
                "artifact deletion intent predates retention"
            )
        self._reconcile_create_audit(reference)
        self._audit.record(
            mission_id=intent.reference.mission_id,
            resource_type="artifact",
            resource_id=intent.reference.artifact_id,
            operation="delete",
            operation_id=self._expiry_audit_operation_id(intent.reference),
            metadata_digest=intent.reference.sha256,
            occurred_at=intent_envelope.created_at,
        )
        for resource_id in intent.resource_ids:
            self._store.erase_resource(
                mission_id=intent.reference.mission_id,
                resource_id=resource_id,
            )
        self._store.erase_resource(
            mission_id=intent.reference.mission_id,
            resource_id=self._deletion_intent_id(reference.artifact_id),
        )

    def _load_deletion_intent(
        self,
        *,
        mission_id: str,
        artifact_id: str,
    ) -> tuple[_ArtifactDeletionIntent, _StoredEnvelope]:
        intent, envelope = self._load_deletion_intent_by_id(
            mission_id=mission_id,
            intent_id=self._deletion_intent_id(artifact_id),
        )
        if intent.reference.artifact_id != artifact_id:
            raise ArtifactSecurityError("artifact deletion intent binding is invalid")
        return intent, envelope

    def _load_deletion_intent_by_id(
        self,
        *,
        mission_id: str,
        intent_id: str,
    ) -> tuple[_ArtifactDeletionIntent, _StoredEnvelope]:
        raw, envelope = self._store.read_bound(
            mission_id=mission_id,
            resource_id=intent_id,
            now=None,
        )
        if raw:
            raise ArtifactSecurityError("artifact deletion intent content is invalid")
        try:
            intent = _ArtifactDeletionIntent.model_validate_json(
                canonicalize(envelope.binding.to_dict()),
                strict=True,
            )
        except ValueError as exc:
            raise ArtifactSecurityError("artifact deletion intent is invalid") from exc
        if not (
            intent.reference.mission_id == mission_id
            and self._deletion_intent_id(intent.reference.artifact_id) == intent_id
            and len(set(intent.resource_ids)) == len(intent.resource_ids)
            and intent.resource_ids[-1] == intent.reference.artifact_id
            and all(
                resource_id == intent.reference.artifact_id
                or resource_id.startswith("artifactchunk_")
                for resource_id in intent.resource_ids
            )
        ):
            raise ArtifactSecurityError("artifact deletion intent binding is invalid")
        return intent, envelope

    def _deletion_targets(self, reference: ArtifactReference) -> tuple[str, ...]:
        envelope = self._store.verified_envelope(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
            now=None,
        )
        if envelope.binding.to_dict().get("storage_format") != "artifact-stream-v1":
            return (reference.artifact_id,)
        raw, envelope = self._store.read_bound(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
            now=None,
        )
        try:
            canonical_loads(raw)
            manifest = _ArtifactStreamManifest.model_validate_json(raw, strict=True)
        except (TypeError, ValueError) as exc:
            raise ArtifactSecurityError("artifact stream manifest is invalid") from exc
        if not self._manifest_matches_reference(manifest, reference, envelope):
            raise DigestIntegrityError("artifact stream manifest binding failed")
        expected_offset = 0
        resource_ids: list[str] = []
        for expected_sequence, chunk in enumerate(manifest.chunks):
            chunk_envelope = self._store.verified_envelope(
                mission_id=reference.mission_id,
                resource_id=chunk.resource_id,
                now=None,
            )
            try:
                binding = _ArtifactStreamChunkBinding.model_validate(
                    chunk_envelope.binding.to_dict()
                )
            except ValueError as exc:
                raise ArtifactSecurityError(
                    "artifact stream chunk binding is invalid"
                ) from exc
            if not (
                chunk.sequence_number == expected_sequence
                and chunk.plaintext_offset == expected_offset
                and binding.stream_id == manifest.stream_id
                and binding.attempt_id == manifest.attempt_id
                and binding.source_execution_id == manifest.source_execution_id
                and binding.sequence_number == chunk.sequence_number
                and binding.plaintext_offset == chunk.plaintext_offset
                and binding.plaintext_size
                == chunk.plaintext_size
                == chunk_envelope.plaintext_size
                and binding.plaintext_sha256
                == chunk.plaintext_sha256
                == chunk_envelope.plaintext_sha256
                and chunk.encryption_metadata_id
                == chunk_envelope.encryption_metadata_id
            ):
                raise DigestIntegrityError("artifact stream chunk integrity failed")
            resource_ids.append(chunk.resource_id)
            expected_offset += chunk.plaintext_size
        if expected_offset != reference.size_bytes:
            raise DigestIntegrityError("artifact stream aggregate integrity failed")
        return (*resource_ids, reference.artifact_id)

    @staticmethod
    def _deletion_intent_id(artifact_id: str) -> str:
        return stable_id(
            "artifactdeletion",
            {
                "schema_version": "artifact-deletion-intent-v1",
                "artifact_id": artifact_id,
            },
        )

    @staticmethod
    def _expiry_audit_operation_id(
        reference: ArtifactReference,
    ) -> str:
        return stable_id(
            "auditop",
            {
                "schema_version": "artifact-expiry-audit-v2",
                "artifact_id": reference.artifact_id,
                "encryption_metadata_id": reference.encryption_metadata_id,
                "created_at": reference.created_at,
            },
        )

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
                and binding.attempt_id == manifest.attempt_id
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
            raw, envelope = self._store.read_bound(
                mission_id=mission_id,
                resource_id=artifact_id,
                now=now,
            )
            try:
                canonical_loads(raw)
                manifest = _ArtifactStreamManifest.model_validate_json(
                    raw,
                    strict=True,
                )
            except (TypeError, ValueError) as exc:
                raise ArtifactSecurityError(
                    "artifact stream manifest is invalid"
                ) from exc
            reference = ArtifactReference(
                artifact_id=manifest.artifact_id,
                mission_id=manifest.mission_id,
                media_type=manifest.media_type,
                size_bytes=manifest.size_bytes,
                sha256=manifest.sha256,
                classification=manifest.classification,
                variant=manifest.variant,
                encrypted=True,
                encryption_metadata_id=envelope.encryption_metadata_id,
                derived_from_artifact_id=manifest.derived_from_artifact_id,
                created_at=envelope.created_at,
                retention_until=envelope.retention_until,
            )
            if not self._manifest_matches_reference(
                manifest,
                reference,
                envelope,
            ):
                raise DigestIntegrityError(
                    "artifact stream manifest binding failed"
                )
            return reference
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
        media_type: str,
        classification: str,
        variant: str,
        source_execution_id: str,
        derived_from_artifact_id: str | None,
    ) -> str:
        return stable_id(
            "artifact",
            {
                "schema_version": "artifact-v2",
                "mission_id": mission_id,
                "content_sha256": content_digest,
                "media_type": media_type,
                "classification": classification,
                "variant": variant,
                "source_execution_id": source_execution_id,
                "derived_from": derived_from_artifact_id,
            },
        )

    @staticmethod
    def _artifact_stream_id(
        *,
        mission_id: str,
        media_type: str,
        variant: str,
        source_execution_id: str,
        derived_from_artifact_id: str | None,
    ) -> str:
        return stable_id(
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

    @staticmethod
    def _artifact_stream_chunk_id(
        stream_id: str,
        attempt_id: str,
        sequence_number: int,
    ) -> str:
        return stable_id(
            "artifactchunk",
            {
                "schema_version": "artifact-stream-chunk-v1",
                "stream_id": stream_id,
                "attempt_id": attempt_id,
                "sequence_number": sequence_number,
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
                    attempt_id=manifest.attempt_id,
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
                    "schema_version": "artifact-create-audit-v2",
                    "artifact_id": reference.artifact_id,
                    "encryption_metadata_id": reference.encryption_metadata_id,
                    "created_at": reference.created_at,
                },
            ),
            metadata_digest=reference.sha256,
            occurred_at=reference.created_at,
        )
        self._store.acknowledge_creation_audit(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
        )

    def _source_execution_id(self, reference: ArtifactReference) -> str:
        envelope = self._store._load_envelope_anchored(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
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
        authorizer: RepositoryDataAccessAuthorizer,
        audit: DataStoreAuditRecorder,
        max_item_bytes: int,
        mission_quota_bytes: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(authorizer) is not RepositoryDataAccessAuthorizer:
            raise SecretAccessError(
                "secret store requires a trusted data access authorizer"
            )
        self._store = _EncryptedFileStore(
            root=root,
            domain="secret_store",
            keys=keys,
            max_item_bytes=max_item_bytes,
            mission_quota_bytes=mission_quota_bytes,
        )
        self._authorizer = authorizer
        self._audit = audit
        self._keys = keys
        self._clock = clock or (lambda: datetime.now(UTC))
        self._reconcile_pending_creation_audits()
        self._sweep_expired_secrets()

    def _trusted_time(self) -> datetime:
        try:
            now = self._clock()
            _require_time(now)
            return now
        except Exception as exc:
            raise SecretAccessError(
                "trusted secret clock is unavailable"
            ) from exc

    def _reconcile_pending_creation_audits(self) -> None:
        for mission_id, resource_id in self._store.pending_creation_audits():
            if not resource_id.startswith("secret_"):
                raise SecretAccessError(
                    "secret creation-audit recovery is invalid"
                )
            envelope = self._store.verified_envelope(
                mission_id=mission_id,
                resource_id=resource_id,
                now=None,
            )
            metadata, _ = self._metadata_from_detected_envelope(envelope)
            self._reconcile_create_audit(metadata)

    def _sweep_expired_secrets(
        self,
        *,
        now: datetime | None = None,
        mission_id: str | None = None,
    ) -> None:
        now = self._clock() if now is None else now
        _require_time(now)
        mission_ids = (
            self._store.mission_ids() if mission_id is None else (mission_id,)
        )
        for mission_id in mission_ids:
            for intent_id in self._store.resource_ids_with_prefix(
                mission_id=mission_id,
                prefix="secretexpiry_",
            ):
                intent, envelope = self._load_expiry_intent(
                    mission_id=mission_id,
                    intent_id=intent_id,
                )
                self._resume_secret_expiry(intent, envelope)
            for secret_reference_id in self._store.resource_ids_with_prefix(
                mission_id=mission_id,
                prefix="secret_",
            ):
                envelope = self._store.verified_envelope(
                    mission_id=mission_id,
                    resource_id=secret_reference_id,
                    now=None,
                )
                metadata, source_execution_id = (
                    self._metadata_from_detected_envelope(envelope)
                )
                if metadata.expires_at is not None and now >= metadata.expires_at:
                    self._expire_detected_secret(
                        metadata,
                        source_execution_id=source_execution_id,
                        now=now,
                    )

    def _expire_detected_secret(
        self,
        reference: SecretReferenceMetadata,
        *,
        source_execution_id: str,
        now: datetime,
    ) -> None:
        if reference.expires_at is None or now < reference.expires_at:
            raise SecretAccessError("secret expiry has not elapsed")
        self._reconcile_create_audit(reference)
        intent_id = self._expiry_intent_id(reference.secret_reference_id)
        if not self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=intent_id,
        ):
            intent = _SecretExpiryIntent(
                record_type="secret_expiry_intent",
                reference=reference,
                source_execution_id=source_execution_id,
            )
            self._store.write_secret_cleanup_intent(
                mission_id=reference.mission_id,
                resource_id=intent_id,
                binding=intent.model_dump(mode="json"),
                created_at=now,
            )
        intent, envelope = self._load_expiry_intent(
            mission_id=reference.mission_id,
            intent_id=intent_id,
        )
        if not (
            intent.reference == reference
            and intent.source_execution_id == source_execution_id
        ):
            raise SecretAccessError("secret expiry binding is invalid")
        self._resume_secret_expiry(intent, envelope)

    def _resume_secret_expiry(
        self,
        intent: _SecretExpiryIntent,
        intent_envelope: _StoredEnvelope,
    ) -> None:
        reference = intent.reference
        if (
            reference.expires_at is None
            or intent_envelope.created_at < reference.expires_at
        ):
            raise SecretAccessError("secret expiry intent predates expiry")
        if self._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=reference.secret_reference_id,
        ):
            envelope = self._store.verified_envelope(
                mission_id=reference.mission_id,
                resource_id=reference.secret_reference_id,
                now=None,
            )
            authoritative, source_execution_id = (
                self._metadata_from_detected_envelope(envelope)
            )
            if not (
                authoritative == reference
                and source_execution_id == intent.source_execution_id
            ):
                raise SecretAccessError("secret expiry target binding is invalid")
        metadata_digest = sha256_digest(reference)
        self._audit.record(
            mission_id=reference.mission_id,
            resource_type="secret_reference",
            resource_id=reference.secret_reference_id,
            operation="delete",
            operation_id=self._expiry_audit_operation_id(reference),
            metadata_digest=metadata_digest,
            occurred_at=intent_envelope.created_at,
        )
        self._store.erase_resource(
            mission_id=reference.mission_id,
            resource_id=reference.secret_reference_id,
        )
        self._store.erase_resource(
            mission_id=reference.mission_id,
            resource_id=self._expiry_intent_id(reference.secret_reference_id),
        )

    def _load_expiry_intent(
        self,
        *,
        mission_id: str,
        intent_id: str,
    ) -> tuple[_SecretExpiryIntent, _StoredEnvelope]:
        raw, envelope = self._store.read_bound(
            mission_id=mission_id,
            resource_id=intent_id,
            now=None,
        )
        if raw:
            raise SecretAccessError("secret expiry intent content is invalid")
        try:
            intent = _SecretExpiryIntent.model_validate_json(
                canonicalize(envelope.binding.to_dict()),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise SecretAccessError("secret expiry intent is invalid") from exc
        if not (
            intent.reference.mission_id == mission_id
            and intent_id
            == self._expiry_intent_id(intent.reference.secret_reference_id)
        ):
            raise SecretAccessError("secret expiry intent binding is invalid")
        return intent, envelope

    @staticmethod
    def _expiry_intent_id(secret_reference_id: str) -> str:
        return stable_id(
            "secretexpiry",
            {
                "schema_version": "secret-expiry-intent-v1",
                "secret_reference_id": secret_reference_id,
            },
        )

    @staticmethod
    def _expiry_audit_operation_id(
        reference: SecretReferenceMetadata,
    ) -> str:
        return stable_id(
            "auditop",
            {
                "schema_version": "secret-expiry-audit-v1",
                "secret_reference_id": reference.secret_reference_id,
                "encryption_metadata_id": reference.encryption_metadata_id,
                "expires_at": reference.expires_at,
            },
        )

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
        return self._create(
            mission_id=mission_id,
            secret_value=secret_value,
            credential_type=credential_type,
            associated_principal_ref=associated_principal_ref,
            source_execution_id=source_execution_id,
            created_at=created_at,
            detected_publication=None,
            expires_at=expires_at,
        )

    def _create_detected(
        self,
        publication: object,
    ) -> SecretReferenceMetadata:
        return self._create(
            mission_id="publication-pending",
            secret_value=b"",
            credential_type="publication-pending",
            associated_principal_ref=None,
            source_execution_id="publication-pending",
            created_at=datetime.min.replace(tzinfo=UTC),
            detected_publication=publication,
            expires_at=None,
        )

    def _create(
        self,
        *,
        mission_id: str,
        secret_value: bytes,
        credential_type: str,
        associated_principal_ref: str | None,
        source_execution_id: str,
        created_at: datetime,
        detected_publication: object | None,
        expires_at: datetime | None,
    ) -> SecretReferenceMetadata:
        ingestion_evidence = None
        if detected_publication is not None:
            from .ingestion import _DetectedSecretPublication

            if type(detected_publication) is not _DetectedSecretPublication:
                raise SecretAccessError(
                    "detected-secret publication is not trusted"
                )
            trusted_publication = cast(Any, detected_publication)
            (
                receipt,
                mission_id,
                secret_value,
                credential_type,
                associated_principal_ref,
                created_at,
            ) = trusted_publication._consume()
            source_execution_id = receipt.execution_id
            expires_at = None
            ingestion_evidence = self._authorizer._begin_ingestion_write(
                receipt=receipt,
                now=created_at,
            )
        _require_bytes(secret_value)
        _require_time(created_at)
        operation_time = self._trusted_time()
        self._sweep_expired_secrets(
            now=operation_time,
            mission_id=mission_id,
        )
        if not secret_value or not credential_type or not source_execution_id:
            raise SecretAccessError("secret metadata or value is incomplete")
        if expires_at is not None:
            _require_time(expires_at)
            if expires_at <= created_at:
                raise SecretAccessError("secret expiry is invalid")
            if expires_at <= operation_time:
                raise SecretAccessError("secret retention has expired")
        secret_reference_id = stable_id(
            "secret",
            {
                "schema_version": "secret-reference-v2",
                "mission_id": mission_id,
                "source_execution_id": source_execution_id,
                "credential_type": credential_type,
                "secret_token": self._keys.keyed_digest(
                    "secret_store",
                    "secret-reference",
                    secret_value,
                ),
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
            resource_digest=sha256_digest(
                {
                    "schema_version": "secret-ingestion-binding-v2",
                    "mission_id": mission_id,
                    "secret_reference_id": secret_reference_id,
                    "credential_type": credential_type,
                    "associated_principal_ref": associated_principal_ref,
                    "source_execution_id": source_execution_id,
                }
            ),
        )
        self._authorizer.require_ingestion_write(
            mission_id=mission_id,
            source_execution_id=source_execution_id,
            resource_type="secret_reference",
            resource=write_binding,
            evidence=ingestion_evidence,
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
                require_creation_audit=True,
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
        self._reconcile_create_audit(metadata)
        return metadata

    def _reconcile_create_audit(
        self,
        metadata: SecretReferenceMetadata,
    ) -> None:
        self._audit.record(
            mission_id=metadata.mission_id,
            resource_type="secret_reference",
            resource_id=metadata.secret_reference_id,
            operation="create",
            operation_id=stable_id(
                "auditop",
                {
                    "schema_version": "secret-create-audit-v1",
                    "secret_reference_id": metadata.secret_reference_id,
                },
            ),
            metadata_digest=sha256_digest(metadata),
            occurred_at=metadata.created_at,
        )
        self._store.acknowledge_creation_audit(
            mission_id=metadata.mission_id,
            resource_id=metadata.secret_reference_id,
        )

    def resolve(
        self,
        reference: SecretReferenceMetadata,
        *,
        execution_id: str,
        now: datetime,
    ) -> bytes:
        del now
        operation_time = self._trusted_time()
        self._sweep_expired_secrets(
            now=operation_time,
            mission_id=reference.mission_id,
        )
        if reference.expires_at is not None and operation_time >= reference.expires_at:
            raise SecretAccessError("secret reference has expired")
        authoritative, source_execution_id, version = self._authoritative_metadata(reference)
        if authoritative.verification_state == "revoked":
            raise SecretAccessError("secret reference is revoked")
        if (
            authoritative.expires_at is not None
            and operation_time >= authoritative.expires_at
        ):
            self._expire_detected_secret(
                authoritative,
                source_execution_id=source_execution_id,
                now=operation_time,
            )
            raise SecretAccessError("secret reference has expired")
        self._authorizer.require_access(
            mission_id=authoritative.mission_id,
            execution_id=execution_id,
            resource_type="secret_reference",
            resource=ResourceBinding(
                resource_id=authoritative.secret_reference_id,
                resource_version=str(version),
                resource_digest=sha256_digest(authoritative),
            ),
            operation="resolve",
            now=operation_time,
        )
        try:
            return self._release_authorized_secret(
                authoritative,
                source_execution_id=source_execution_id,
                version=version,
                now=operation_time,
            )
        except Exception as failure:
            failure.__traceback__ = None
        raise SecretAccessError("secret resolution failed closed")

    def _release_authorized_secret(
        self,
        authoritative: SecretReferenceMetadata,
        *,
        source_execution_id: str,
        version: int,
        now: datetime,
    ) -> bytes:
        """Decrypt and audit a Secret outside the sanitized public error frame."""

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
        self,
        reference: SecretReferenceMetadata,
        *,
        execution_id: str,
        now: datetime,
    ) -> SecretReferenceMetadata:
        del now
        operation_time = self._trusted_time()
        self._sweep_expired_secrets(
            now=operation_time,
            mission_id=reference.mission_id,
        )
        authoritative, source_execution_id, version = self._authoritative_metadata(reference)
        self._authorizer.require_access(
            mission_id=authoritative.mission_id,
            execution_id=execution_id,
            resource_type="secret_reference",
            resource=ResourceBinding(
                resource_id=authoritative.secret_reference_id,
                resource_version=str(version),
                resource_digest=sha256_digest(authoritative),
            ),
            operation="write",
            now=operation_time,
        )
        if authoritative.verification_state == "revoked":
            self._audit.record(
                mission_id=authoritative.mission_id,
                resource_type="secret_reference",
                resource_id=authoritative.secret_reference_id,
                operation="revoke",
                metadata_digest=sha256_digest(authoritative),
                occurred_at=operation_time,
            )
            self._reconcile_revoked_secret_erasure(
                authoritative,
                source_execution_id=source_execution_id,
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
            created_at=operation_time,
            retention_until=None,
        )
        self._audit.record(
            mission_id=authoritative.mission_id,
            resource_type="secret_reference",
            resource_id=authoritative.secret_reference_id,
            operation="revoke",
            metadata_digest=tombstone_digest,
            occurred_at=operation_time,
        )
        self._audit.record(
            mission_id=authoritative.mission_id,
            resource_type="secret_reference",
            resource_id=authoritative.secret_reference_id,
            operation="delete",
            metadata_digest=tombstone_digest,
            occurred_at=operation_time,
        )
        self._reconcile_revoked_secret_erasure(
            revoked,
            source_execution_id=source_execution_id,
        )
        return revoked

    def _reconcile_revoked_secret_erasure(
        self,
        revoked: SecretReferenceMetadata,
        *,
        source_execution_id: str,
    ) -> None:
        """Finish a deletion durably requested by the revocation tombstone."""

        self._store.delete(
            mission_id=revoked.mission_id,
            resource_id=revoked.secret_reference_id,
            binding={
                "secret_reference_id": revoked.secret_reference_id,
                "credential_type": revoked.credential_type,
                "associated_principal_ref": revoked.associated_principal_ref,
                "source_execution_id": source_execution_id,
                "verification_state": "detected",
                "metadata_version": 1,
            },
            expected_encryption_metadata_id=revoked.encryption_metadata_id,
        )

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
        authoritative, source_execution_id = (
            self._metadata_from_detected_envelope(envelope)
        )
        if authoritative.secret_reference_id != reference.secret_reference_id:
            raise SecretAccessError("secret metadata binding is invalid")
        return authoritative, source_execution_id, 1

    @staticmethod
    def _metadata_from_detected_envelope(
        envelope: _StoredEnvelope,
    ) -> tuple[SecretReferenceMetadata, str]:
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
            and binding.get("secret_reference_id") == envelope.resource_id
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
            secret_reference_id=envelope.resource_id,
            mission_id=envelope.mission_id,
            credential_type=credential_type,
            associated_principal_ref=principal,
            encryption_metadata_id=envelope.encryption_metadata_id,
            created_at=envelope.created_at,
            expires_at=envelope.retention_until,
            verification_state="detected",
        )
        return authoritative, source_execution_id

    @staticmethod
    def _tombstone_id(secret_reference_id: str) -> str:
        return stable_id(
            "secrettombstone",
            {
                "schema_version": "secret-tombstone-v1",
                "secret_reference_id": secret_reference_id,
            },
        )
