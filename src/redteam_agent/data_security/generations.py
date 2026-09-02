"""Content-bound authenticated generation commits for trusted state providers."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path
from threading import RLock
from typing import Protocol, final

from pydantic import Field, model_validator

from redteam_agent.canonical import sha256_digest, stable_id
from redteam_agent.errors import AuthenticatedGenerationError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.storage.generation_records import (
    GenerationStorageError,
    SqliteAuthenticatedGenerationRecords,
)


class AuthenticatedGenerationAnchor(StrictImmutableBoundaryModel):
    schema_version: str = Field(min_length=1)
    namespace: str = Field(min_length=1)
    generation: int = Field(ge=1)
    immutable_blob_id: str = Field(min_length=1)
    state_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    previous_anchor_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    anchor_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_anchor_digest(self) -> AuthenticatedGenerationAnchor:
        expected = sha256_digest(self.model_dump(mode="python", exclude={"anchor_digest"}))
        if not hmac.compare_digest(expected, self.anchor_digest):
            raise ValueError("generation anchor digest mismatch")
        return self


class AuthenticatedGenerationAnchorStore(Protocol):
    def current(self, namespace: str) -> AuthenticatedGenerationAnchor | None: ...

    def compare_and_set(
        self,
        *,
        namespace: str,
        expected_anchor_digest: str | None,
        new_anchor: AuthenticatedGenerationAnchor,
    ) -> bool: ...


class ImmutableGenerationBlobStore(Protocol):
    def create_or_verify(self, blob_id: str, payload: bytes) -> None: ...

    def get(self, blob_id: str) -> bytes | None: ...


@final
class InMemoryGenerationAnchorStore:
    """Deterministic trusted-store test double with atomic compare-and-set."""

    def __init__(self) -> None:
        self._anchors: dict[str, AuthenticatedGenerationAnchor] = {}
        self._lock = RLock()

    def current(self, namespace: str) -> AuthenticatedGenerationAnchor | None:
        with self._lock:
            return self._anchors.get(namespace)

    def compare_and_set(
        self,
        *,
        namespace: str,
        expected_anchor_digest: str | None,
        new_anchor: AuthenticatedGenerationAnchor,
    ) -> bool:
        with self._lock:
            current = self._anchors.get(namespace)
            current_digest = None if current is None else current.anchor_digest
            if current_digest != expected_anchor_digest:
                return False
            self._anchors[namespace] = new_anchor
            return True


@final
class InMemoryImmutableGenerationBlobStore:
    """Content-addressed immutable blob-store test double."""

    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}
        self._lock = RLock()

    def create_or_verify(self, blob_id: str, payload: bytes) -> None:
        if not blob_id or not isinstance(payload, bytes):
            raise AuthenticatedGenerationError("generation blob is invalid")
        with self._lock:
            existing = self._blobs.get(blob_id)
            if existing is not None and not hmac.compare_digest(existing, payload):
                raise AuthenticatedGenerationError("immutable generation blob conflicted")
            self._blobs[blob_id] = bytes(payload)

    def get(self, blob_id: str) -> bytes | None:
        with self._lock:
            value = self._blobs.get(blob_id)
            return None if value is None else bytes(value)


@final
class DurableAuthenticatedGenerationBackend:
    """Durable authenticated CAS anchors and immutable blobs for production use."""

    _ANCHOR_PURPOSE = b"redteam-generation-anchor-v1\x00"
    _BLOB_PURPOSE = b"redteam-generation-blob-v1\x00"

    def __init__(self, *, database_path: Path, authentication_key: bytes) -> None:
        if len(authentication_key) < 32:
            raise AuthenticatedGenerationError(
                "generation authentication material does not meet provider policy"
            )
        path = Path(os.path.abspath(database_path))
        if not path.is_absolute() or path.name in {"", ".", ".."}:
            raise AuthenticatedGenerationError("generation backend path is invalid")
        try:
            parent_metadata = os.lstat(path.parent)
            existing_metadata = os.lstat(path) if os.path.lexists(path) else None
        except OSError as exc:
            raise AuthenticatedGenerationError("generation backend path is unavailable") from exc
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) & 0o077
            or (
                existing_metadata is not None
                and (
                    stat.S_ISLNK(existing_metadata.st_mode)
                    or not stat.S_ISREG(existing_metadata.st_mode)
                    or stat.S_IMODE(existing_metadata.st_mode) & 0o077
                )
            )
        ):
            raise AuthenticatedGenerationError("generation backend permissions are invalid")
        self._path = path
        self._parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
        self._authentication_key = bytes(authentication_key)
        self._lock = RLock()
        try:
            if existing_metadata is None:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(descriptor)
            self._records = SqliteAuthenticatedGenerationRecords(path)
            os.chmod(path, 0o600)
            path_metadata = os.lstat(path)
            if not stat.S_ISREG(path_metadata.st_mode):
                raise AuthenticatedGenerationError(
                    "generation backend path is invalid"
                )
            self._path_identity = (path_metadata.st_dev, path_metadata.st_ino)
        except (OSError, GenerationStorageError) as exc:
            raise AuthenticatedGenerationError("generation backend is unavailable") from exc

    def create_or_verify(self, blob_id: str, payload: bytes) -> None:
        if not blob_id or not isinstance(payload, bytes):
            raise AuthenticatedGenerationError("generation blob is invalid")
        with self._lock:
            self._verify_path_identity()
            try:
                self._records.begin()
                row = self._records.get_blob(blob_id)
                if row is None:
                    nonce = secrets.token_bytes(24)
                    ciphertext = self._crypt_blob(blob_id, nonce, payload)
                    self._records.insert_blob(
                        blob_id=blob_id,
                        nonce=nonce,
                        ciphertext=ciphertext,
                        authentication_tag=self._blob_tag(blob_id, nonce, ciphertext),
                    )
                else:
                    existing = self._open_blob(
                        blob_id,
                        bytes(row[0]),
                        bytes(row[1]),
                        bytes(row[2]),
                    )
                    if not hmac.compare_digest(existing, payload):
                        raise AuthenticatedGenerationError("immutable generation blob conflicted")
                self._records.commit()
            except AuthenticatedGenerationError:
                self._rollback()
                raise
            except GenerationStorageError as exc:
                self._rollback()
                raise AuthenticatedGenerationError("generation blob persistence failed") from exc

    def get(self, blob_id: str) -> bytes | None:
        if not blob_id:
            raise AuthenticatedGenerationError("generation blob identity is invalid")
        with self._lock:
            self._verify_path_identity()
            try:
                row = self._records.get_blob(blob_id)
            except GenerationStorageError as exc:
                raise AuthenticatedGenerationError("generation blob lookup failed") from exc
            if row is None:
                return None
            return self._open_blob(
                blob_id,
                bytes(row[0]),
                bytes(row[1]),
                bytes(row[2]),
            )

    def current(self, namespace: str) -> AuthenticatedGenerationAnchor | None:
        if not namespace:
            raise AuthenticatedGenerationError("generation anchor namespace is invalid")
        with self._lock:
            self._verify_path_identity()
            try:
                row = self._records.get_anchor(namespace)
            except GenerationStorageError as exc:
                raise AuthenticatedGenerationError("generation anchor lookup failed") from exc
            if row is None:
                return None
            return self._decode_anchor(namespace, bytes(row[0]), bytes(row[1]))

    def compare_and_set(
        self,
        *,
        namespace: str,
        expected_anchor_digest: str | None,
        new_anchor: AuthenticatedGenerationAnchor,
    ) -> bool:
        if not namespace or new_anchor.namespace != namespace:
            raise AuthenticatedGenerationError("generation anchor namespace mismatch")
        encoded = new_anchor.model_dump_json().encode("utf-8")
        with self._lock:
            self._verify_path_identity()
            try:
                self._records.begin()
                row = self._records.get_anchor(namespace)
                current = (
                    None
                    if row is None
                    else self._decode_anchor(namespace, bytes(row[0]), bytes(row[1]))
                )
                current_digest = None if current is None else current.anchor_digest
                if current_digest != expected_anchor_digest:
                    self._records.rollback()
                    return False
                expected_generation = 1 if current is None else current.generation + 1
                if not (
                    new_anchor.generation == expected_generation
                    and new_anchor.previous_anchor_digest == current_digest
                    and self._verified_blob_for_anchor(new_anchor)
                ):
                    raise AuthenticatedGenerationError("generation anchor transition is invalid")
                tag = self._anchor_tag(namespace, encoded)
                if current is None:
                    self._records.insert_anchor(
                        namespace=namespace,
                        anchor_json=encoded,
                        authentication_tag=tag,
                    )
                else:
                    if row is None:
                        raise AuthenticatedGenerationError(
                            "generation anchor record is unavailable"
                        )
                    if not self._records.update_anchor(
                        namespace=namespace,
                        anchor_json=encoded,
                        authentication_tag=tag,
                        expected_anchor_json=bytes(row[0]),
                    ):
                        self._records.rollback()
                        return False
                self._records.commit()
                return True
            except AuthenticatedGenerationError:
                self._rollback()
                raise
            except GenerationStorageError as exc:
                self._rollback()
                raise AuthenticatedGenerationError("generation anchor persistence failed") from exc

    def _verified_blob_for_anchor(
        self,
        anchor: AuthenticatedGenerationAnchor,
    ) -> bool:
        row = self._records.get_blob(anchor.immutable_blob_id)
        if row is None:
            return False
        payload = self._open_blob(
            anchor.immutable_blob_id,
            bytes(row[0]),
            bytes(row[1]),
            bytes(row[2]),
        )
        return hmac.compare_digest(
            anchor.state_digest,
            "sha256:" + hashlib.sha256(payload).hexdigest(),
        )

    def _decode_anchor(
        self,
        namespace: str,
        encoded: bytes,
        tag: bytes,
    ) -> AuthenticatedGenerationAnchor:
        if not hmac.compare_digest(tag, self._anchor_tag(namespace, encoded)):
            raise AuthenticatedGenerationError("generation anchor authentication failed")
        try:
            anchor = AuthenticatedGenerationAnchor.model_validate_json(
                encoded,
                strict=True,
            )
        except ValueError as exc:
            raise AuthenticatedGenerationError("generation anchor is invalid") from exc
        if anchor.namespace != namespace:
            raise AuthenticatedGenerationError("generation anchor namespace mismatch")
        return anchor

    def _verify_path_identity(self) -> None:
        try:
            parent_metadata = os.lstat(self._path.parent)
            path_metadata = os.lstat(self._path)
        except OSError as exc:
            raise AuthenticatedGenerationError("generation backend path is unavailable") from exc
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or (parent_metadata.st_dev, parent_metadata.st_ino) != self._parent_identity
            or stat.S_IMODE(parent_metadata.st_mode) & 0o077
            or stat.S_ISLNK(path_metadata.st_mode)
            or not stat.S_ISREG(path_metadata.st_mode)
            or (path_metadata.st_dev, path_metadata.st_ino) != self._path_identity
            or stat.S_IMODE(path_metadata.st_mode) & 0o077
        ):
            raise AuthenticatedGenerationError("generation backend identity changed")

    def _anchor_tag(self, namespace: str, encoded: bytes) -> bytes:
        return hmac.digest(
            self._authentication_key,
            self._ANCHOR_PURPOSE + namespace.encode("utf-8") + b"\x00" + encoded,
            "sha256",
        )

    def _blob_tag(self, blob_id: str, nonce: bytes, ciphertext: bytes) -> bytes:
        return hmac.digest(
            self._authentication_key,
            self._BLOB_PURPOSE + blob_id.encode("utf-8") + b"\x00" + nonce + ciphertext,
            "sha256",
        )

    def _open_blob(
        self,
        blob_id: str,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> bytes:
        if not hmac.compare_digest(
            tag,
            self._blob_tag(blob_id, nonce, ciphertext),
        ):
            raise AuthenticatedGenerationError("generation blob authentication failed")
        return self._crypt_blob(blob_id, nonce, ciphertext)

    def _crypt_blob(self, blob_id: str, nonce: bytes, value: bytes) -> bytes:
        encryption_key = hmac.digest(
            self._authentication_key,
            b"redteam-generation-blob-encryption-v1\x00" + blob_id.encode("utf-8"),
            "sha256",
        )
        output = bytearray(len(value))
        offset = 0
        counter = 0
        while offset < len(value):
            block = hmac.digest(
                encryption_key,
                nonce + counter.to_bytes(8, "big"),
                "sha256",
            )
            width = min(len(block), len(value) - offset)
            for index in range(width):
                output[offset + index] = value[offset + index] ^ block[index]
            offset += width
            counter += 1
        return bytes(output)

    def _rollback(self) -> None:
        with suppress(GenerationStorageError):
            self._records.rollback()


@final
class AuthenticatedGenerationCoordinator:
    """Commit and recover exact state through a digest/blob-bound external anchor."""

    def __init__(
        self,
        *,
        namespace: str,
        anchors: AuthenticatedGenerationAnchorStore,
        blobs: ImmutableGenerationBlobStore,
    ) -> None:
        if not namespace or anchors is None or blobs is None:
            raise AuthenticatedGenerationError(
                "authenticated generation dependencies are incomplete"
            )
        self._namespace = namespace
        self._anchors = anchors
        self._blobs = blobs
        self._production_ready = (
            type(anchors) is DurableAuthenticatedGenerationBackend and anchors is blobs
        )

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def production_ready(self) -> bool:
        return self._production_ready

    def current_anchor(self) -> AuthenticatedGenerationAnchor | None:
        anchor = self._anchors.current(self._namespace)
        if anchor is not None and anchor.namespace != self._namespace:
            raise AuthenticatedGenerationError("generation anchor namespace mismatch")
        return anchor

    def commit(
        self,
        payload: bytes,
        *,
        expected_anchor_digest: str | None,
    ) -> AuthenticatedGenerationAnchor:
        if not isinstance(payload, bytes):
            raise AuthenticatedGenerationError("generation payload must be bytes")
        current = self._anchors.current(self._namespace)
        current_digest = None if current is None else current.anchor_digest
        if current_digest != expected_anchor_digest:
            raise AuthenticatedGenerationError("generation anchor changed")
        generation = 1 if current is None else current.generation + 1
        state_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        blob_id = stable_id(
            "generationblob",
            {
                "schema_version": "authenticated-generation-blob-v1",
                "namespace": self._namespace,
                "state_digest": state_digest,
            },
        )
        self._blobs.create_or_verify(blob_id, payload)
        self._verify_blob(blob_id, state_digest)
        anchor_payload = {
            "schema_version": "authenticated-generation-anchor-v1",
            "namespace": self._namespace,
            "generation": generation,
            "immutable_blob_id": blob_id,
            "state_digest": state_digest,
            "previous_anchor_digest": current_digest,
        }
        anchor = AuthenticatedGenerationAnchor(
            schema_version="authenticated-generation-anchor-v1",
            namespace=self._namespace,
            generation=generation,
            immutable_blob_id=blob_id,
            state_digest=state_digest,
            previous_anchor_digest=current_digest,
            anchor_digest=sha256_digest(anchor_payload),
        )
        if not self._anchors.compare_and_set(
            namespace=self._namespace,
            expected_anchor_digest=current_digest,
            new_anchor=anchor,
        ):
            raise AuthenticatedGenerationError("generation anchor CAS conflicted")
        committed = self._anchors.current(self._namespace)
        if committed != anchor:
            raise AuthenticatedGenerationError("committed generation anchor is unavailable")
        self._verify_blob(anchor.immutable_blob_id, anchor.state_digest)
        return anchor

    def recover(self) -> tuple[AuthenticatedGenerationAnchor, bytes]:
        anchor = self._anchors.current(self._namespace)
        if anchor is None or anchor.namespace != self._namespace:
            raise AuthenticatedGenerationError("committed generation anchor is unavailable")
        payload = self._verify_blob(anchor.immutable_blob_id, anchor.state_digest)
        return anchor, payload

    def _verify_blob(self, blob_id: str, state_digest: str) -> bytes:
        payload = self._blobs.get(blob_id)
        if payload is None:
            raise AuthenticatedGenerationError("anchored generation blob is missing")
        actual = "sha256:" + hashlib.sha256(payload).hexdigest()
        if not hmac.compare_digest(actual, state_digest):
            raise AuthenticatedGenerationError("anchored generation blob is corrupt")
        expected_blob_id = stable_id(
            "generationblob",
            {
                "schema_version": "authenticated-generation-blob-v1",
                "namespace": self._namespace,
                "state_digest": state_digest,
            },
        )
        if blob_id != expected_blob_id:
            raise AuthenticatedGenerationError("generation blob identity mismatch")
        return payload
