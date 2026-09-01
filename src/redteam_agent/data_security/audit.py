"""Atomic mission-scoped append-only audit chains."""

from __future__ import annotations

import fcntl
import hmac
import os
import secrets
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Literal, Protocol

from pydantic import Field, model_validator

from redteam_agent.canonical import (
    CanonicalJsonObject,
    canonical_loads,
    canonicalize,
    sha256_digest,
    stable_id,
)
from redteam_agent.errors import AuditIntegrityError, AuditSequenceConflictError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.repositories.audit import AuditLogRepository
from redteam_agent.storage import Database

from .keys import EncryptionKeyProvider
from .models import AuditEvent, EncryptionMetadata

AuditResourceType = Literal[
    "artifact",
    "secret_reference",
    "raw_result_quarantine",
]
AuditOperation = Literal[
    "create",
    "write_chunk",
    "commit_artifact",
    "commit",
    "abort",
    "resume",
    "read",
    "export",
    "resolve",
    "revoke",
    "delete",
]


class AuditChainAuthenticator(Protocol):
    def active_signer(self) -> EncryptionMetadata: ...

    def digest(
        self,
        payload: dict[str, object],
        *,
        signing_key_id: str,
        signing_key_version: int,
    ) -> str: ...

    def head_digest(
        self,
        payload: dict[str, object],
        *,
        signing_key_id: str,
        signing_key_version: int,
    ) -> str: ...


class KeyedAuditChainAuthenticator:
    """Authenticates audit events outside the mutable application database."""

    def __init__(self, keys: EncryptionKeyProvider) -> None:
        self._keys = keys

    def active_signer(self) -> EncryptionMetadata:
        return self._keys.get_active_key_metadata("audit_signing")

    def digest(
        self,
        payload: dict[str, object],
        *,
        signing_key_id: str,
        signing_key_version: int,
    ) -> str:
        metadata = self._keys.get_key_metadata(
            "audit_signing",
            signing_key_id,
            signing_key_version,
        )
        return self._keys.keyed_digest(
            "audit_signing",
            "mission-audit-event-v1",
            canonicalize(payload),
            metadata=metadata,
        )

    def head_digest(
        self,
        payload: dict[str, object],
        *,
        signing_key_id: str,
        signing_key_version: int,
    ) -> str:
        metadata = self._keys.get_key_metadata(
            "audit_signing",
            signing_key_id,
            signing_key_version,
        )
        return self._keys.keyed_digest(
            "audit_signing",
            "mission-audit-head-state-v1",
            canonicalize(payload),
            metadata=metadata,
        )


class AuditHeadGenerationStore(Protocol):
    """External monotonic anchor for one authenticated audit-head state."""

    def current_generation(self) -> int: ...

    def compare_and_set_generation(self, *, expected: int, new: int) -> bool: ...


class AuditHeadStore(Protocol):
    def head(self, mission_id: str) -> tuple[int, str] | None: ...

    def prepared_append(self, mission_id: str) -> AuditEvent | None: ...

    def prepare_append(
        self,
        mission_id: str,
        *,
        expected: tuple[int, str] | None,
        event: AuditEvent,
    ) -> bool: ...

    def commit_append(
        self,
        mission_id: str,
        *,
        event: AuditEvent,
    ) -> bool: ...


class _AuditHeadRecord(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    sequence_number: int = Field(ge=1)
    event_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class _AuditPreparedAppend(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    previous_sequence_number: int | None = Field(default=None, ge=1)
    previous_event_hash: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    event: AuditEvent

    @model_validator(mode="after")
    def event_follows_previous_head(self) -> _AuditPreparedAppend:
        previous_absent = (
            self.previous_sequence_number is None
            and self.previous_event_hash is None
        )
        previous_present = (
            self.previous_sequence_number is not None
            and self.previous_event_hash is not None
        )
        expected_sequence = (
            1
            if self.previous_sequence_number is None
            else self.previous_sequence_number + 1
        )
        if not (
            (previous_absent or previous_present)
            and self.event.mission_id == self.mission_id
            and self.event.sequence_number == expected_sequence
            and self.event.previous_event_hash == self.previous_event_hash
        ):
            raise ValueError("prepared audit append is not adjacent to its head")
        return self


class _AuditHeadState(StrictImmutableBoundaryModel):
    schema_version: Literal["audit-head-state-v2"]
    generation: int = Field(ge=1)
    heads: tuple[_AuditHeadRecord, ...]
    prepared: tuple[_AuditPreparedAppend, ...]
    signing_key_id: str = Field(min_length=1)
    signing_key_version: int = Field(ge=1)
    state_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def heads_are_canonical(self) -> _AuditHeadState:
        head_missions = tuple(item.mission_id for item in self.heads)
        prepared_missions = tuple(item.mission_id for item in self.prepared)
        if (
            head_missions != tuple(sorted(head_missions))
            or len(set(head_missions)) != len(head_missions)
            or prepared_missions != tuple(sorted(prepared_missions))
            or len(set(prepared_missions)) != len(prepared_missions)
        ):
            raise ValueError("audit heads are not canonical")
        return self


class KeyedFileAuditHeadStore:
    """Authenticated audit heads anchored by an external monotonic generation."""

    _MAX_STATE_BYTES = 16 * 1024 * 1024

    def __init__(
        self,
        *,
        state_path: Path,
        authenticator: AuditChainAuthenticator,
        generation_store: AuditHeadGenerationStore,
    ) -> None:
        absolute_path = Path(os.path.abspath(state_path))
        if not absolute_path.is_absolute() or absolute_path.name in {"", ".", ".."}:
            raise AuditIntegrityError("audit-head state path is invalid")
        try:
            parent_metadata = os.lstat(absolute_path.parent)
        except OSError as exc:
            raise AuditIntegrityError(
                "audit-head state directory is unavailable"
            ) from exc
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) & 0o077
        ):
            raise AuditIntegrityError(
                "audit-head state directory permissions are invalid"
            )
        self._state_path = absolute_path
        self._state_paths = (
            absolute_path,
            absolute_path.parent / f".{absolute_path.name}.alternate",
        )
        self._parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
        self._lock_path = absolute_path.parent / f".{absolute_path.name}.lock"
        self._authenticator = authenticator
        self._generation_store = generation_store
        self._lock = RLock()

    def head(self, mission_id: str) -> tuple[int, str] | None:
        if not mission_id:
            raise AuditIntegrityError("audit-head mission binding is invalid")
        with self._lock, self._locked_state_file() as directory_descriptor:
            heads, _ = self._load_state(directory_descriptor=directory_descriptor)
            item = heads.get(mission_id)
            return None if item is None else (item.sequence_number, item.event_hash)

    def prepared_append(self, mission_id: str) -> AuditEvent | None:
        if not mission_id:
            raise AuditIntegrityError("audit-head mission binding is invalid")
        with self._lock, self._locked_state_file() as directory_descriptor:
            _, prepared = self._load_state(
                directory_descriptor=directory_descriptor
            )
            item = prepared.get(mission_id)
            return None if item is None else item.event

    def prepare_append(
        self,
        mission_id: str,
        *,
        expected: tuple[int, str] | None,
        event: AuditEvent,
    ) -> bool:
        if (
            not mission_id
            or (expected is not None and not self._valid_head(expected))
            or not self._event_follows_head(
                mission_id,
                event=event,
                expected=expected,
            )
        ):
            raise AuditIntegrityError("prepared audit append is invalid")
        self._verify_event_digest(event)
        with self._lock, self._locked_state_file() as directory_descriptor:
            generation = self._external_generation()
            heads, prepared = self._load_state(
                directory_descriptor=directory_descriptor,
                expected_generation=generation,
            )
            current_record = heads.get(mission_id)
            current = (
                None
                if current_record is None
                else (current_record.sequence_number, current_record.event_hash)
            )
            if current != expected:
                return False
            existing = prepared.get(mission_id)
            candidate = _AuditPreparedAppend(
                mission_id=mission_id,
                previous_sequence_number=(None if expected is None else expected[0]),
                previous_event_hash=(None if expected is None else expected[1]),
                event=event,
            )
            if existing is not None:
                return existing == candidate
            prepared[mission_id] = candidate
            self._persist_state(
                heads=heads,
                prepared=prepared,
                generation=generation,
                directory_descriptor=directory_descriptor,
            )
            return True

    def commit_append(
        self,
        mission_id: str,
        *,
        event: AuditEvent,
    ) -> bool:
        if not mission_id or event.mission_id != mission_id:
            raise AuditIntegrityError("committed audit append is invalid")
        self._verify_event_digest(event)
        with self._lock, self._locked_state_file() as directory_descriptor:
            generation = self._external_generation()
            heads, prepared = self._load_state(
                directory_descriptor=directory_descriptor,
                expected_generation=generation,
            )
            current_record = heads.get(mission_id)
            current = (
                None
                if current_record is None
                else (current_record.sequence_number, current_record.event_hash)
            )
            new = (event.sequence_number, event.event_hash)
            pending = prepared.get(mission_id)
            if pending is None:
                return current == new
            expected = (
                None
                if pending.previous_sequence_number is None
                else (
                    pending.previous_sequence_number,
                    pending.previous_event_hash,
                )
            )
            if not (
                pending.event == event
                and current == expected
                and self._event_follows_head(
                    mission_id,
                    event=event,
                    expected=expected,
                )
            ):
                return False
            heads[mission_id] = _AuditHeadRecord(
                mission_id=mission_id,
                sequence_number=event.sequence_number,
                event_hash=event.event_hash,
            )
            del prepared[mission_id]
            self._persist_state(
                heads=heads,
                prepared=prepared,
                generation=generation,
                directory_descriptor=directory_descriptor,
            )
            return True

    def _load_state(
        self,
        *,
        directory_descriptor: int,
        expected_generation: int | None = None,
    ) -> tuple[
        dict[str, _AuditHeadRecord],
        dict[str, _AuditPreparedAppend],
    ]:
        generation = (
            self._external_generation()
            if expected_generation is None
            else expected_generation
        )
        if generation == 0:
            return {}, {}
        raw = self._read_state(
            self._state_path_for_generation(generation),
            directory_descriptor=directory_descriptor,
        )
        try:
            duplicate_free = canonical_loads(raw)
            state = _AuditHeadState.model_validate_json(
                canonicalize(duplicate_free),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise AuditIntegrityError("audit-head state is invalid") from exc
        digest_payload = self._state_digest_payload(
            generation=state.generation,
            heads=state.heads,
            prepared=state.prepared,
            signing_key_id=state.signing_key_id,
            signing_key_version=state.signing_key_version,
        )
        expected_digest = self._authenticator.head_digest(
            digest_payload,
            signing_key_id=state.signing_key_id,
            signing_key_version=state.signing_key_version,
        )
        if state.generation != generation or not hmac.compare_digest(
            expected_digest,
            state.state_digest,
        ):
            raise AuditIntegrityError(
                "audit-head rollback, generation, or authentication failed"
            )
        return (
            {item.mission_id: item for item in state.heads},
            {item.mission_id: item for item in state.prepared},
        )

    def _persist_state(
        self,
        *,
        heads: dict[str, _AuditHeadRecord],
        prepared: dict[str, _AuditPreparedAppend],
        generation: int,
        directory_descriptor: int,
    ) -> None:
        next_generation = generation + 1
        signer = self._authenticator.active_signer()
        if signer.key_domain != "audit_signing" or signer.rotation_state != "active":
            raise AuditIntegrityError("audit signing key is unavailable")
        canonical_heads = tuple(heads[key] for key in sorted(heads))
        canonical_prepared = tuple(prepared[key] for key in sorted(prepared))
        digest_payload = self._state_digest_payload(
            generation=next_generation,
            heads=canonical_heads,
            prepared=canonical_prepared,
            signing_key_id=signer.key_id,
            signing_key_version=signer.key_version,
        )
        persisted = _AuditHeadState(
            schema_version="audit-head-state-v2",
            generation=next_generation,
            heads=canonical_heads,
            prepared=canonical_prepared,
            signing_key_id=signer.key_id,
            signing_key_version=signer.key_version,
            state_digest=self._authenticator.head_digest(
                digest_payload,
                signing_key_id=signer.key_id,
                signing_key_version=signer.key_version,
            ),
        )
        self._write_state(
            self._state_path_for_generation(next_generation),
            canonicalize(persisted.model_dump(mode="python")),
            directory_descriptor=directory_descriptor,
        )
        try:
            advanced = self._generation_store.compare_and_set_generation(
                expected=generation,
                new=next_generation,
            )
        except Exception as exc:
            raise AuditIntegrityError(
                "external audit-head generation is unavailable"
            ) from exc
        if not advanced:
            raise AuditIntegrityError(
                "external audit-head generation update conflicted"
            )

    @staticmethod
    def _state_digest_payload(
        *,
        generation: int,
        heads: tuple[_AuditHeadRecord, ...],
        prepared: tuple[_AuditPreparedAppend, ...],
        signing_key_id: str,
        signing_key_version: int,
    ) -> dict[str, object]:
        return {
            "schema_version": "audit-head-state-v2",
            "generation": generation,
            "heads": tuple(item.model_dump(mode="python") for item in heads),
            "prepared": tuple(
                item.model_dump(mode="python") for item in prepared
            ),
            "signing_key_id": signing_key_id,
            "signing_key_version": signing_key_version,
        }

    def _external_generation(self) -> int:
        try:
            generation = self._generation_store.current_generation()
        except Exception as exc:
            raise AuditIntegrityError(
                "external audit-head generation is unavailable"
            ) from exc
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
            or generation >= 2**128
        ):
            raise AuditIntegrityError("external audit-head generation is invalid")
        return generation

    def _state_path_for_generation(self, generation: int) -> Path:
        if generation <= 0:
            raise AuditIntegrityError("audit-head generation is invalid")
        return self._state_paths[0 if generation % 2 else 1]

    @contextmanager
    def _locked_state_file(self) -> Iterator[int]:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        directory_descriptor: int | None = None
        lock_descriptor: int | None = None
        locked = False
        try:
            try:
                directory_descriptor = os.open(
                    self._state_path.parent,
                    directory_flags,
                )
                directory_metadata = os.fstat(directory_descriptor)
                if (
                    not stat.S_ISDIR(directory_metadata.st_mode)
                    or (directory_metadata.st_dev, directory_metadata.st_ino)
                    != self._parent_identity
                ):
                    raise AuditIntegrityError(
                        "audit-head state directory identity changed"
                    )
                lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    lock_flags |= os.O_NOFOLLOW
                lock_descriptor = os.open(
                    self._lock_path.name,
                    lock_flags,
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise AuditIntegrityError("audit-head lock is unavailable") from exc
            try:
                metadata = os.fstat(lock_descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise AuditIntegrityError("audit-head lock is invalid")
                os.fchmod(lock_descriptor, 0o600)
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
                locked = True
                self._verify_parent_identity()
                yield directory_descriptor
            except OSError as exc:
                raise AuditIntegrityError("audit-head lock is unavailable") from exc
        finally:
            if locked and lock_descriptor is not None:
                with suppress(OSError):
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            if directory_descriptor is not None:
                os.close(directory_descriptor)

    def _read_state(self, path: Path, *, directory_descriptor: int) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                path.name,
                flags,
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            raise AuditIntegrityError("audit-head state is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > self._MAX_STATE_BYTES
            ):
                raise AuditIntegrityError("audit-head state is invalid")
            chunks: list[bytes] = []
            size = 0
            while size <= self._MAX_STATE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, self._MAX_STATE_BYTES + 1 - size),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            if size > self._MAX_STATE_BYTES:
                raise AuditIntegrityError("audit-head state is invalid")
            self._verify_parent_identity()
            return b"".join(chunks)
        except OSError as exc:
            raise AuditIntegrityError("audit-head state is unavailable") from exc
        finally:
            os.close(descriptor)

    def _write_state(
        self,
        path: Path,
        data: bytes,
        *,
        directory_descriptor: int,
    ) -> None:
        if len(data) > self._MAX_STATE_BYTES:
            raise AuditIntegrityError("audit-head state exceeds its size limit")
        temporary_name = f".pending-{secrets.token_hex(16)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
            self._verify_parent_identity()
        except OSError as exc:
            raise AuditIntegrityError("audit-head state persistence failed") from exc
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)

    def _verify_event_digest(self, event: AuditEvent) -> None:
        if event.signing_key_id is None or event.signing_key_version is None:
            raise AuditIntegrityError("prepared audit event has no signer")
        payload = {
            "event_id": event.event_id,
            "mission_id": event.mission_id,
            "mission_revision": event.mission_revision,
            "authorization_epoch": event.authorization_epoch,
            "chain_scope": event.chain_scope,
            "sequence_number": event.sequence_number,
            "previous_event_hash": event.previous_event_hash,
            "signing_key_id": event.signing_key_id,
            "signing_key_version": event.signing_key_version,
            "event_type": event.event_type,
            "canonical_payload": event.canonical_payload,
            "occurred_at": event.occurred_at,
        }
        expected = self._authenticator.digest(
            payload,
            signing_key_id=event.signing_key_id,
            signing_key_version=event.signing_key_version,
        )
        if not hmac.compare_digest(expected, event.event_hash):
            raise AuditIntegrityError("prepared audit event hash failed")

    @classmethod
    def _event_follows_head(
        cls,
        mission_id: str,
        *,
        event: AuditEvent,
        expected: tuple[int, str] | None,
    ) -> bool:
        return (
            event.mission_id == mission_id
            and event.sequence_number == (1 if expected is None else expected[0] + 1)
            and event.previous_event_hash == (None if expected is None else expected[1])
            and cls._valid_hash(event.event_hash)
        )

    def _verify_parent_identity(self) -> None:
        try:
            metadata = os.stat(self._state_path.parent, follow_symlinks=False)
        except OSError as exc:
            raise AuditIntegrityError(
                "audit-head state directory is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != self._parent_identity
        ):
            raise AuditIntegrityError("audit-head state directory identity changed")

    @staticmethod
    def _valid_hash(value: str) -> bool:
        return (
            len(value) == 71
            and value.startswith("sha256:")
            and all(character in "0123456789abcdef" for character in value[7:])
        )

    @classmethod
    def _valid_head(cls, value: tuple[int, str]) -> bool:
        return (
            len(value) == 2
            and isinstance(value[1], str)
            and isinstance(value[0], int)
            and not isinstance(value[0], bool)
            and value[0] >= 1
            and cls._valid_hash(value[1])
        )


class AuditReferencePayload(StrictImmutableBoundaryModel):
    """Reference-only audit payload; arbitrary values and raw content are impossible."""

    resource_type: AuditResourceType
    resource_id: str = Field(min_length=1)
    operation: AuditOperation
    operation_id: str = Field(
        default_factory=lambda: "auditop_" + secrets.token_hex(16),
        pattern=r"^auditop_[0-9a-f]{32}$",
    )
    metadata_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def reference_id_matches_type(self) -> AuditReferencePayload:
        prefixes = {
            "artifact": "artifact_",
            "secret_reference": "secret_",
            "raw_result_quarantine": "quarantine_",
        }
        if not self.resource_id.startswith(prefixes[self.resource_type]):
            raise ValueError("audit resource must be an internal reference ID")
        suffix = self.resource_id.removeprefix(prefixes[self.resource_type])
        if len(suffix) != 32 or any(character not in "0123456789abcdef" for character in suffix):
            raise ValueError("audit resource reference ID is malformed")
        return self


class AuditContext(StrictImmutableBoundaryModel):
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)


class AuditContextResolver(Protocol):
    def current_context(self, mission_id: str, *, now: datetime) -> AuditContext: ...


class DataStoreAuditRecorder(Protocol):
    def record(
        self,
        *,
        mission_id: str,
        resource_type: AuditResourceType,
        resource_id: str,
        operation: AuditOperation,
        metadata_digest: str,
        occurred_at: datetime,
        operation_id: str | None = None,
    ) -> AuditEvent: ...

    def operation_recorded(
        self,
        *,
        mission_id: str,
        resource_type: AuditResourceType,
        resource_id: str,
        operation: AuditOperation,
        operation_id: str,
        metadata_digest: str,
    ) -> bool: ...


class MissionAuditRecorder:
    """Resolves current mission authority before appending a typed store event."""

    def __init__(self, *, audit_log: MissionAuditLog, contexts: AuditContextResolver) -> None:
        self._audit_log = audit_log
        self._contexts = contexts

    def record(
        self,
        *,
        mission_id: str,
        resource_type: AuditResourceType,
        resource_id: str,
        operation: AuditOperation,
        metadata_digest: str,
        occurred_at: datetime,
        operation_id: str | None = None,
    ) -> AuditEvent:
        context = self._contexts.current_context(mission_id, now=occurred_at)
        payload = AuditReferencePayload(
            resource_type=resource_type,
            resource_id=resource_id,
            operation=operation,
            operation_id=(
                "auditop_" + secrets.token_hex(16)
                if operation_id is None
                else operation_id
            ),
            metadata_digest=metadata_digest,
        )
        return self._audit_log.append(
            mission_id=mission_id,
            mission_revision=context.mission_revision,
            authorization_epoch=context.authorization_epoch,
            payload=payload,
            occurred_at=occurred_at,
        )

    def operation_recorded(
        self,
        *,
        mission_id: str,
        resource_type: AuditResourceType,
        resource_id: str,
        operation: AuditOperation,
        operation_id: str,
        metadata_digest: str,
    ) -> bool:
        """Verify an exact idempotent operation against the trusted audit chain."""

        expected = AuditReferencePayload(
            resource_type=resource_type,
            resource_id=resource_id,
            operation=operation,
            operation_id=operation_id,
            metadata_digest=metadata_digest,
        )
        expected_payload = CanonicalJsonObject(expected.model_dump(mode="json"))
        matches = tuple(
            event
            for event in self._audit_log.verify(mission_id)
            if event.canonical_payload.to_dict().get("operation_id") == operation_id
        )
        if not matches:
            return False
        if len(matches) != 1 or not (
            matches[0].event_type == f"{resource_type}.{operation}"
            and matches[0].canonical_payload == expected_payload
        ):
            raise AuditIntegrityError("audit operation binding failed")
        return True


class MissionAuditLog:
    """Append-only log with keyed events and an independently anchored head."""

    def __init__(
        self,
        database: Database | None = None,
        *,
        authenticator: AuditChainAuthenticator | None = None,
        head_store: AuditHeadStore | None = None,
    ) -> None:
        if database is not None and (authenticator is None or head_store is None):
            raise AuditIntegrityError(
                "durable audit log requires an external authenticator and head store"
            )
        if database is None and head_store is not None:
            raise AuditIntegrityError(
                "in-memory audit log cannot use a durable head store"
            )
        self._database = database
        self._repository = None if database is None else AuditLogRepository(database)
        self._authenticator = authenticator
        self._head_store = head_store
        self._events: dict[str, list[AuditEvent]] = {}
        self._event_ids: dict[str, AuditEvent] = {}
        self._heads: dict[str, tuple[int, str]] = {}
        self._lock = RLock()

    def append(
        self,
        *,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        payload: AuditReferencePayload,
        occurred_at: datetime,
        expected_sequence_number: int | None = None,
    ) -> AuditEvent:
        canonical_payload = CanonicalJsonObject(payload.model_dump(mode="python"))
        if self._database is not None:
            return self._append_persistent(
                mission_id=mission_id,
                mission_revision=mission_revision,
                authorization_epoch=authorization_epoch,
                payload=payload,
                canonical_payload=canonical_payload,
                occurred_at=occurred_at,
                expected_sequence_number=expected_sequence_number,
            )
        with self._lock:
            event_type = f"{payload.resource_type}.{payload.operation}"
            event_id = stable_id(
                "auditevent",
                {
                    "mission_id": mission_id,
                    "mission_revision": mission_revision,
                    "authorization_epoch": authorization_epoch,
                    "event_type": event_type,
                    "canonical_payload": canonical_payload,
                    "occurred_at": occurred_at,
                },
            )
            existing = self._event_ids.get(event_id)
            if existing is not None:
                if not self._matches_request(
                    existing,
                    mission_id=mission_id,
                    mission_revision=mission_revision,
                    authorization_epoch=authorization_epoch,
                    event_type=event_type,
                    canonical_payload=canonical_payload,
                    occurred_at=occurred_at,
                ):
                    raise AuditSequenceConflictError(
                        "derived audit event identifier conflicted"
                    )
                return existing
            mission_events = self._events.setdefault(mission_id, [])
            sequence = len(mission_events) + 1
            if expected_sequence_number is not None and expected_sequence_number != sequence:
                raise AuditSequenceConflictError("audit sequence allocation conflict")
            previous_hash = mission_events[-1].event_hash if mission_events else None
            signing_key_id, signing_key_version = self._active_signer_binding()
            base = self._event_payload(
                event_id=event_id,
                mission_id=mission_id,
                mission_revision=mission_revision,
                authorization_epoch=authorization_epoch,
                sequence_number=sequence,
                previous_event_hash=previous_hash,
                signing_key_id=signing_key_id,
                signing_key_version=signing_key_version,
                event_type=event_type,
                canonical_payload=canonical_payload,
                occurred_at=occurred_at,
            )
            event = AuditEvent(
                event_id=event_id,
                mission_id=mission_id,
                mission_revision=mission_revision,
                authorization_epoch=authorization_epoch,
                chain_scope="mission",
                sequence_number=sequence,
                previous_event_hash=previous_hash,
                signing_key_id=signing_key_id,
                signing_key_version=signing_key_version,
                event_hash=self._event_digest(
                    base,
                    signing_key_id=signing_key_id,
                    signing_key_version=signing_key_version,
                ),
                event_type=event_type,
                canonical_payload=canonical_payload,
                occurred_at=occurred_at,
            )
            mission_events.append(event)
            self._event_ids[event_id] = event
            self._heads[mission_id] = (sequence, event.event_hash)
            return event

    def events_for(self, mission_id: str) -> tuple[AuditEvent, ...]:
        if self._database is not None:
            if self._repository is None:
                raise AuditIntegrityError("durable audit repository is unavailable")
            rows = self._repository.events_for(mission_id)
            events: list[AuditEvent] = []
            for row in rows:
                event = self._parse_event(str(row["payload_json"]))
                if not (
                    event.event_id == row["event_id"]
                    and event.mission_id == row["mission_id"]
                    and event.sequence_number == row["sequence_number"]
                    and event.event_hash == row["event_hash"]
                ):
                    raise AuditIntegrityError("persisted audit row binding failed")
                events.append(event)
            return tuple(events)
        with self._lock:
            return tuple(self._events.get(mission_id, ()))

    def verify(
        self, mission_id: str, *, events: tuple[AuditEvent, ...] | None = None
    ) -> tuple[AuditEvent, ...]:
        if self._database is not None:
            self._recover_prepared_append(mission_id)
        persisted = self.events_for(mission_id)
        if self._database is not None and events is not None and events != persisted:
            raise AuditIntegrityError("supplied audit chain differs from persistence")
        candidates = persisted if events is None else events
        previous_hash = self._verify_event_chain(mission_id, candidates)
        if self._database is None:
            trusted_head = self._trusted_head(mission_id)
            if trusted_head is None:
                if candidates:
                    raise AuditIntegrityError("mission audit chain has no trusted head")
            elif trusted_head != (len(candidates), previous_hash):
                raise AuditIntegrityError("mission audit chain head failed")
        else:
            self._reconcile_persistent_head(mission_id, candidates)
        return candidates

    def _append_persistent(
        self,
        *,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        payload: AuditReferencePayload,
        canonical_payload: CanonicalJsonObject,
        occurred_at: datetime,
        expected_sequence_number: int | None,
    ) -> AuditEvent:
        if self._database is None or self._repository is None:
            raise AuditIntegrityError("durable audit database is unavailable")
        if self._head_store is None:
            raise AuditIntegrityError("durable audit head store is unavailable")
        event_type = f"{payload.resource_type}.{payload.operation}"
        event_id = stable_id(
            "auditevent",
            {
                "mission_id": mission_id,
                "mission_revision": mission_revision,
                "authorization_epoch": authorization_epoch,
                "event_type": event_type,
                "canonical_payload": canonical_payload,
                "occurred_at": occurred_at,
            },
        )
        try:
            self.verify(mission_id)
            with self._repository.transaction():
                existing_row = self._repository.event_by_id(event_id)
                if existing_row is not None:
                    existing = self._parse_event(str(existing_row["payload_json"]))
                    if not (
                        existing.event_id == existing_row["event_id"]
                        and existing.mission_id == existing_row["mission_id"]
                        and existing.sequence_number == existing_row["sequence_number"]
                        and existing.event_hash == existing_row["event_hash"]
                        and self._matches_request(
                            existing,
                            mission_id=mission_id,
                            mission_revision=mission_revision,
                            authorization_epoch=authorization_epoch,
                            event_type=event_type,
                            canonical_payload=canonical_payload,
                            occurred_at=occurred_at,
                        )
                    ):
                        raise AuditSequenceConflictError(
                            "derived audit event identifier conflicted"
                        )
                    return existing
                head = self._repository.head(mission_id)
                sequence = 1 if head is None else int(head["sequence_number"]) + 1
                previous_hash = None if head is None else str(head["event_hash"])
                if (
                    expected_sequence_number is not None
                    and expected_sequence_number != sequence
                ):
                    raise AuditSequenceConflictError("audit sequence allocation conflict")
                if head is None and self._repository.has_event(mission_id):
                    raise AuditIntegrityError("audit chain has no trusted head")
                signing_key_id, signing_key_version = self._active_signer_binding()
                base = self._event_payload(
                    event_id=event_id,
                    mission_id=mission_id,
                    mission_revision=mission_revision,
                    authorization_epoch=authorization_epoch,
                    sequence_number=sequence,
                    previous_event_hash=previous_hash,
                    signing_key_id=signing_key_id,
                    signing_key_version=signing_key_version,
                    event_type=event_type,
                    canonical_payload=canonical_payload,
                    occurred_at=occurred_at,
                )
                event = AuditEvent(
                    event_id=event_id,
                    mission_id=mission_id,
                    mission_revision=mission_revision,
                    authorization_epoch=authorization_epoch,
                    chain_scope="mission",
                    sequence_number=sequence,
                    previous_event_hash=previous_hash,
                    signing_key_id=signing_key_id,
                    signing_key_version=signing_key_version,
                    event_hash=self._event_digest(
                        base,
                        signing_key_id=signing_key_id,
                        signing_key_version=signing_key_version,
                    ),
                    event_type=event_type,
                    canonical_payload=canonical_payload,
                    occurred_at=occurred_at,
                )
                event_json = canonicalize(event.model_dump(mode="python")).decode(
                    "utf-8"
                )
                expected_head = (
                    None
                    if head is None
                    else (int(head["sequence_number"]), str(head["event_hash"]))
                )
                if not self._head_store.prepare_append(
                    mission_id,
                    expected=expected_head,
                    event=event,
                ):
                    raise AuditSequenceConflictError(
                        "external audit append preparation conflicted"
                    )
                self._repository.insert_event(
                    event_id=event.event_id,
                    mission_id=event.mission_id,
                    sequence_number=event.sequence_number,
                    event_hash=event.event_hash,
                    payload_json=event_json,
                )
                if head is None:
                    self._repository.insert_head(
                        mission_id=mission_id,
                        sequence_number=event.sequence_number,
                        event_hash=event.event_hash,
                    )
                else:
                    if not self._repository.update_head(
                        mission_id=mission_id,
                        previous_sequence_number=int(head["sequence_number"]),
                        previous_event_hash=str(head["event_hash"]),
                        sequence_number=event.sequence_number,
                        event_hash=event.event_hash,
                    ):
                        raise AuditSequenceConflictError("audit head update conflicted")
            if not self._head_store.commit_append(
                mission_id,
                event=event,
            ) and self._head_store.head(mission_id) != (
                event.sequence_number,
                event.event_hash,
            ):
                raise AuditSequenceConflictError(
                    "external audit append commit conflicted"
                )
            self.verify(mission_id)
            return event
        except (AuditIntegrityError, AuditSequenceConflictError):
            raise
        except sqlite3.IntegrityError as exc:
            raise AuditSequenceConflictError("audit sequence allocation conflict") from exc

    def _trusted_head(self, mission_id: str) -> tuple[int, str] | None:
        if self._database is None:
            return self._heads.get(mission_id)
        if self._head_store is None:
            raise AuditIntegrityError("durable audit head store is unavailable")
        return self._head_store.head(mission_id)

    def _reconcile_persistent_head(
        self,
        mission_id: str,
        candidates: tuple[AuditEvent, ...],
    ) -> None:
        if self._repository is None or self._head_store is None:
            raise AuditIntegrityError("durable audit dependencies are unavailable")
        if self._head_store.prepared_append(mission_id) is not None:
            raise AuditIntegrityError("prepared audit append was not recovered")
        row = self._repository.head(mission_id)
        database_head = (
            None
            if row is None
            else (int(row["sequence_number"]), str(row["event_hash"]))
        )
        candidate_head = (
            None
            if not candidates
            else (candidates[-1].sequence_number, candidates[-1].event_hash)
        )
        if database_head != candidate_head:
            raise AuditIntegrityError("database audit head differs from event chain")
        external_head = self._head_store.head(mission_id)
        if external_head is not None and not KeyedFileAuditHeadStore._valid_head(
            external_head
        ):
            raise AuditIntegrityError("external audit head is invalid")
        if external_head != candidate_head:
            raise AuditIntegrityError("mission audit chain head failed")

    def _recover_prepared_append(self, mission_id: str) -> None:
        if (
            self._database is None
            or self._repository is None
            or self._head_store is None
        ):
            raise AuditIntegrityError("durable audit dependencies are unavailable")
        prepared = self._head_store.prepared_append(mission_id)
        if prepared is None:
            return
        if self._database.connection.in_transaction:
            raise AuditIntegrityError(
                "prepared audit append recovery requires its own transaction"
            )
        external_head = self._head_store.head(mission_id)
        expected_head = (
            None
            if prepared.sequence_number == 1
            else (prepared.sequence_number - 1, prepared.previous_event_hash)
        )
        if external_head != expected_head:
            raise AuditIntegrityError("prepared audit append head binding failed")
        new_head = (prepared.sequence_number, prepared.event_hash)
        with self._repository.transaction():
            candidates = self.events_for(mission_id)
            self._verify_event_chain(mission_id, candidates)
            row = self._repository.head(mission_id)
            database_head = (
                None
                if row is None
                else (int(row["sequence_number"]), str(row["event_hash"]))
            )
            candidate_head = (
                None
                if not candidates
                else (candidates[-1].sequence_number, candidates[-1].event_hash)
            )
            if database_head != candidate_head:
                raise AuditIntegrityError(
                    "database audit head differs from event chain"
                )
            if candidate_head == new_head:
                if candidates[-1] != prepared:
                    raise AuditIntegrityError(
                        "prepared audit append differs from database suffix"
                    )
            elif candidate_head == expected_head:
                event_json = canonicalize(
                    prepared.model_dump(mode="python")
                ).decode("utf-8")
                self._repository.insert_event(
                    event_id=prepared.event_id,
                    mission_id=prepared.mission_id,
                    sequence_number=prepared.sequence_number,
                    event_hash=prepared.event_hash,
                    payload_json=event_json,
                )
                if expected_head is None:
                    self._repository.insert_head(
                        mission_id=mission_id,
                        sequence_number=prepared.sequence_number,
                        event_hash=prepared.event_hash,
                    )
                elif not self._repository.update_head(
                    mission_id=mission_id,
                    previous_sequence_number=expected_head[0],
                    previous_event_hash=expected_head[1],
                    sequence_number=prepared.sequence_number,
                    event_hash=prepared.event_hash,
                ):
                    raise AuditSequenceConflictError(
                        "prepared audit head recovery conflicted"
                    )
            else:
                raise AuditIntegrityError(
                    "database chain conflicts with prepared audit append"
                )
        if not self._head_store.commit_append(
            mission_id,
            event=prepared,
        ) and self._head_store.head(mission_id) != new_head:
            raise AuditSequenceConflictError(
                "prepared audit append commit conflicted"
            )

    def _verify_event_chain(
        self,
        mission_id: str,
        candidates: tuple[AuditEvent, ...],
    ) -> str | None:
        previous_hash: str | None = None
        seen_ids: set[str] = set()
        for expected_sequence, event in enumerate(candidates, start=1):
            if not (
                event.mission_id == mission_id
                and event.chain_scope == "mission"
                and event.sequence_number == expected_sequence
                and event.previous_event_hash == previous_hash
                and event.event_id not in seen_ids
            ):
                raise AuditIntegrityError("mission audit chain binding failed")
            expected_hash = self._event_digest(
                self._event_payload(
                    event_id=event.event_id,
                    mission_id=event.mission_id,
                    mission_revision=event.mission_revision,
                    authorization_epoch=event.authorization_epoch,
                    sequence_number=event.sequence_number,
                    previous_event_hash=event.previous_event_hash,
                    signing_key_id=event.signing_key_id,
                    signing_key_version=event.signing_key_version,
                    event_type=event.event_type,
                    canonical_payload=event.canonical_payload,
                    occurred_at=event.occurred_at,
                ),
                signing_key_id=event.signing_key_id,
                signing_key_version=event.signing_key_version,
            )
            if not hmac.compare_digest(expected_hash, event.event_hash):
                raise AuditIntegrityError("mission audit event hash failed")
            seen_ids.add(event.event_id)
            previous_hash = event.event_hash
        return previous_hash

    def _active_signer_binding(self) -> tuple[str | None, int | None]:
        if self._authenticator is None:
            return None, None
        signer = self._authenticator.active_signer()
        if signer.key_domain != "audit_signing" or signer.rotation_state != "active":
            raise AuditIntegrityError("audit signing key is unavailable")
        return signer.key_id, signer.key_version

    def _event_digest(
        self,
        payload: dict[str, object],
        *,
        signing_key_id: str | None,
        signing_key_version: int | None,
    ) -> str:
        if self._authenticator is None:
            if signing_key_id is not None or signing_key_version is not None:
                raise AuditIntegrityError("unexpected audit signing-key binding")
            return sha256_digest(payload)
        if signing_key_id is None or signing_key_version is None:
            raise AuditIntegrityError("audit signing-key binding is unavailable")
        return self._authenticator.digest(
            payload,
            signing_key_id=signing_key_id,
            signing_key_version=signing_key_version,
        )

    @staticmethod
    def _parse_event(payload: str | bytes) -> AuditEvent:
        try:
            duplicate_free = canonical_loads(payload)
            return AuditEvent.model_validate_json(canonicalize(duplicate_free), strict=True)
        except (TypeError, ValueError) as exc:
            raise AuditIntegrityError("persisted audit event is invalid") from exc

    @staticmethod
    def _event_payload(
        *,
        event_id: str,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        sequence_number: int,
        previous_event_hash: str | None,
        signing_key_id: str | None,
        signing_key_version: int | None,
        event_type: str,
        canonical_payload: CanonicalJsonObject,
        occurred_at: datetime,
    ) -> dict[str, object]:
        return {
            "event_id": event_id,
            "mission_id": mission_id,
            "mission_revision": mission_revision,
            "authorization_epoch": authorization_epoch,
            "chain_scope": "mission",
            "sequence_number": sequence_number,
            "previous_event_hash": previous_event_hash,
            "signing_key_id": signing_key_id,
            "signing_key_version": signing_key_version,
            "event_type": event_type,
            "canonical_payload": canonical_payload,
            "occurred_at": occurred_at,
        }

    @staticmethod
    def _matches_request(
        event: AuditEvent,
        *,
        mission_id: str,
        mission_revision: int,
        authorization_epoch: int,
        event_type: str,
        canonical_payload: CanonicalJsonObject,
        occurred_at: datetime,
    ) -> bool:
        return (
            event.mission_id == mission_id
            and event.mission_revision == mission_revision
            and event.authorization_epoch == authorization_epoch
            and event.event_type == event_type
            and event.canonical_payload == canonical_payload
            and event.occurred_at == occurred_at
        )
