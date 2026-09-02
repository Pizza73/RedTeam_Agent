"""Content-bound authenticated generation commits for trusted state providers."""

from __future__ import annotations

import hashlib
import hmac
from threading import RLock
from typing import Protocol, final

from pydantic import Field, model_validator

from redteam_agent.canonical import sha256_digest, stable_id
from redteam_agent.errors import AuthenticatedGenerationError
from redteam_agent.models.base import StrictImmutableBoundaryModel


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
        expected = sha256_digest(
            self.model_dump(mode="python", exclude={"anchor_digest"})
        )
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

    @property
    def namespace(self) -> str:
        return self._namespace

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
