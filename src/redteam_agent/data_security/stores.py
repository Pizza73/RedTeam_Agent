"""Encrypted mission-scoped storage boundaries for Phase 0C."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Literal, Protocol

from pydantic import Field

from redteam_agent.canonical import CanonicalJsonObject, canonical_loads, canonicalize, stable_id
from redteam_agent.errors import (
    ArtifactSecurityError,
    DigestIntegrityError,
    SecretAccessError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import UtcDatetime, require_utc
from redteam_agent.models.context import ResourceBinding
from redteam_agent.models.scope import DataAccessOperation, DataResourceType

from .keys import InMemoryEncryptionKeyProvider
from .models import (
    ArtifactReference,
    EncryptedPayload,
    KeyDomain,
    QuarantineReference,
    SecretReferenceMetadata,
)

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


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


class _StoredEnvelope(StrictImmutableBoundaryModel):
    schema_version: Literal["encrypted-store-v1"]
    domain: KeyDomain
    mission_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    binding: CanonicalJsonObject
    plaintext_size: int = Field(ge=0)
    plaintext_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    retention_until: UtcDatetime | None
    encryption_metadata_id: str = Field(min_length=1)
    payload: EncryptedPayload


class _EncryptedFileStore:
    def __init__(
        self,
        *,
        root: Path,
        domain: KeyDomain,
        keys: InMemoryEncryptionKeyProvider,
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
        retention_until: datetime | None,
    ) -> tuple[str, str]:
        _require_bytes(content)
        if len(content) > self._max_item_bytes:
            raise ArtifactSecurityError("resource exceeds its size limit")
        path = self._path(mission_id, resource_id, create_parent=True)
        with self._lock:
            if path.exists():
                existing = self._load_envelope(path)
                if existing.retention_until != retention_until:
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
                retention_until=retention_until,
            )
            encrypted = self._keys.seal(self._domain, content, aad)
            metadata_id = self._keys.metadata_id(encrypted.metadata)
            envelope = _StoredEnvelope(
                schema_version="encrypted-store-v1",
                domain=self._domain,
                mission_id=mission_id,
                resource_id=resource_id,
                binding=CanonicalJsonObject(binding),
                plaintext_size=len(content),
                plaintext_sha256=content_digest,
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
        plaintext = self._keys.open(
            self._domain,
            envelope.payload,
            self._aad(
                mission_id,
                resource_id,
                binding,
                plaintext_size=envelope.plaintext_size,
                plaintext_sha256=envelope.plaintext_sha256,
                retention_until=envelope.retention_until,
            ),
        )
        if not (
            len(plaintext) == envelope.plaintext_size
            and self._content_digest(plaintext) == envelope.plaintext_sha256
        ):
            raise DigestIntegrityError("decrypted resource integrity failed")
        return plaintext

    def delete(
        self,
        *,
        mission_id: str,
        resource_id: str,
        binding: dict[str, object],
        expected_encryption_metadata_id: str,
    ) -> None:
        path = self._path(mission_id, resource_id, create_parent=False)
        envelope = self._load_envelope(path)
        self._open_envelope(
            envelope,
            mission_id=mission_id,
            resource_id=resource_id,
            binding=binding,
            expected_encryption_metadata_id=expected_encryption_metadata_id,
            now=None,
        )
        try:
            path.unlink()
        except OSError as exc:
            raise ArtifactSecurityError("encrypted resource deletion failed") from exc

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
            self._open_envelope(
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
        keys: InMemoryEncryptionKeyProvider,
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
            retention_until=retention_until,
        )
        return QuarantineReference(
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
        return content

    def delete(self, reference: QuarantineReference) -> None:
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
        keys: InMemoryEncryptionKeyProvider,
        authorizer: DataAccessAuthorizer,
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

    def put(
        self,
        *,
        mission_id: str,
        content: bytes,
        media_type: str,
        classification: Literal["normal", "sensitive", "secret"],
        variant: Literal["redacted", "encrypted_raw"],
        created_at: datetime,
        retention_until: datetime | None = None,
        derived_from_artifact_id: str | None = None,
    ) -> ArtifactReference:
        _require_bytes(content)
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
        content_digest = self._store._content_digest(content)
        artifact_id = stable_id(
            "artifact",
            {
                "mission_id": mission_id,
                "content_sha256": content_digest,
                "classification": classification,
                "variant": variant,
                "derived_from": derived_from_artifact_id,
            },
        )
        binding: dict[str, object] = {
            "artifact_id": artifact_id,
            "media_type": media_type,
            "classification": classification,
            "variant": variant,
            "derived_from_artifact_id": derived_from_artifact_id,
        }
        _, metadata_id = self._store.write(
            mission_id=mission_id,
            resource_id=artifact_id,
            content=content,
            binding=binding,
            retention_until=retention_until,
        )
        return ArtifactReference(
            artifact_id=artifact_id,
            mission_id=mission_id,
            media_type=media_type,
            size_bytes=len(content),
            sha256=content_digest,
            classification=classification,
            variant=variant,
            encrypted=True,
            encryption_metadata_id=metadata_id,
            derived_from_artifact_id=derived_from_artifact_id,
            created_at=created_at,
            retention_until=retention_until,
        )

    def read(
        self,
        reference: ArtifactReference,
        *,
        operation: Literal["read", "export"],
        now: datetime,
    ) -> bytes:
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
        content = self._store.read(
            mission_id=reference.mission_id,
            resource_id=reference.artifact_id,
            binding={
                "artifact_id": reference.artifact_id,
                "media_type": reference.media_type,
                "classification": reference.classification,
                "variant": reference.variant,
                "derived_from_artifact_id": reference.derived_from_artifact_id,
            },
            now=now,
            expected_encryption_metadata_id=reference.encryption_metadata_id or "",
        )
        if not (
            len(content) == reference.size_bytes
            and self._store._content_digest(content) == reference.sha256
        ):
            raise DigestIntegrityError("artifact reference integrity failed")
        return content


class SecretStore:
    def __init__(
        self,
        *,
        root: Path,
        keys: InMemoryEncryptionKeyProvider,
        authorizer: DataAccessAuthorizer,
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
        }
        _, metadata_id = self._store.write(
            mission_id=mission_id,
            resource_id=secret_reference_id,
            content=secret_value,
            binding=binding,
            retention_until=expires_at,
        )
        return SecretReferenceMetadata(
            secret_reference_id=secret_reference_id,
            mission_id=mission_id,
            credential_type=credential_type,
            associated_principal_ref=associated_principal_ref,
            encryption_metadata_id=metadata_id,
            created_at=created_at,
            expires_at=expires_at,
            verification_state="detected",
        )

    def resolve(
        self,
        reference: SecretReferenceMetadata,
        *,
        source_execution_id: str,
        now: datetime,
    ) -> bytes:
        if reference.verification_state == "revoked":
            raise SecretAccessError("secret reference is revoked")
        self._authorizer.require_access(
            mission_id=reference.mission_id,
            resource_type="secret_reference",
            resource=ResourceBinding(
                resource_id=reference.secret_reference_id,
                resource_version="1",
                resource_digest=reference.encryption_metadata_id,
            ),
            operation="resolve",
            now=now,
        )
        return self._store.read(
            mission_id=reference.mission_id,
            resource_id=reference.secret_reference_id,
            binding={
                "secret_reference_id": reference.secret_reference_id,
                "credential_type": reference.credential_type,
                "associated_principal_ref": reference.associated_principal_ref,
                "source_execution_id": source_execution_id,
            },
            now=now,
            expected_encryption_metadata_id=reference.encryption_metadata_id,
        )
