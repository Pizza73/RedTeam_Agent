"""Artifact store: redacted / encrypted-raw artifacts with integrity + classification (SystemDesign §33).

The store assigns internal paths (never trusting an adapter/LLM path), enforces
Mission-scoped access, size, integrity (SHA-256), classification and encryption for
sensitive/secret artifacts. Redacted artifacts carry no secrets and are stored in the
clear; ``encrypted_raw`` bodies use a per-artifact DEK (domain ``artifact_store``).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto.key_provider import EncryptionKeyProvider
from redteam_agent.crypto.models import EncryptionMetadata, EnvelopeCiphertext
from redteam_agent.errors import SecureIngestionError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.policy.models import DataAccessGrant
from redteam_agent.quarantine.blob_store import QuarantineBlobStore
from redteam_agent.storage.database import Database

_ARTIFACT_NS = "artifact"
_ARTIFACT_ENC_NS = "artifact_encryption"


class ArtifactReference(StrictImmutableBoundaryModel):
    artifact_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(min_length=1)
    classification: Literal["normal", "sensitive", "secret"]
    variant: Literal["redacted", "encrypted_raw"]
    encrypted: bool
    encryption_metadata_id: str | None
    derived_from_artifact_id: str | None
    created_at: datetime
    retention_until: datetime | None
    artifact_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _encryption_consistency(self) -> ArtifactReference:
        if self.encrypted and self.encryption_metadata_id is None:
            raise ValueError("encrypted artifact requires an encryption_metadata_id")
        if not self.encrypted and self.encryption_metadata_id is not None:
            raise ValueError("unencrypted artifact must not carry an encryption_metadata_id")
        if self.variant == "encrypted_raw" and not (self.encrypted and self.classification == "secret"):
            raise ValueError("encrypted_raw artifacts are encrypted and classified secret")
        return self


class ArtifactStore:
    def __init__(
        self, *, database: Database, blob_store: QuarantineBlobStore, key_provider: EncryptionKeyProvider,
        digest_service: DigestService,
        read_authority: object,
    ) -> None:
        self._db = database
        self._blobs = blob_store
        self._keys = key_provider
        self._ds = digest_service
        self._read_authority = read_authority

    def _artifact_digest(self, fields: dict[str, object]) -> str:
        return self._ds.compute("artifact_digest", {k: v for k, v in fields.items() if k != "artifact_digest"})

    def get(self, artifact_id: str) -> ArtifactReference | None:
        row = self._db.occ_get(_ARTIFACT_NS, artifact_id)
        if row is None:
            return None
        ref = ArtifactReference.model_validate_json(row[1])
        self._ds.verify("artifact_digest",
                        {k: v for k, v in ref.model_dump(mode="python").items() if k != "artifact_digest"},
                        ref.artifact_digest)
        return ref

    def _blob_handle(self, mission_id: str, artifact_id: str) -> str:
        return f"artifacts/{mission_id}/{artifact_id}"

    def build_redacted(
        self, *, artifact_id: str, mission_id: str, body: bytes, created_at: datetime,
        retention_until: datetime | None,
    ) -> tuple[ArtifactReference, str, bytes]:
        """Return (reference, blob_handle, blob_bytes) for a normal redacted artifact.

        The caller persists them inside the publication unit of work (create-or-verify).
        """
        fields = {
            "artifact_id": artifact_id, "mission_id": mission_id, "media_type": "application/json",
            "size_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "classification": "normal",
            "variant": "redacted", "encrypted": False, "encryption_metadata_id": None,
            "derived_from_artifact_id": None, "created_at": created_at, "retention_until": retention_until,
        }
        ref = ArtifactReference(**fields, artifact_digest=self._artifact_digest(fields))  # type: ignore[arg-type]
        return ref, self._blob_handle(mission_id, artifact_id), body

    def build_encrypted_raw(
        self, *, artifact_id: str, mission_id: str, execution_id: str, body: bytes, created_at: datetime,
        retention_until: datetime | None,
    ) -> tuple[ArtifactReference, str, bytes, EncryptionMetadata]:
        enc = self._keys.create_resource_key(
            domain="artifact_store", resource_binding_type="artifact_id", resource_binding_id=artifact_id
        )
        handle = self._keys.open_resource_key_handle(metadata=enc, operation="encrypt")
        try:
            import os
            envelope = handle.encrypt(
                encryption_metadata_id=enc.resource_key_id, nonce=os.urandom(12), plaintext=body,
                aad_fields={"mission_id": mission_id, "execution_id": execution_id, "artifact_id": artifact_id},
            )
        finally:
            handle.close()
        blob = json.dumps(envelope.model_dump(mode="json"), sort_keys=True).encode("utf-8")
        fields = {
            "artifact_id": artifact_id, "mission_id": mission_id, "media_type": "application/octet-stream",
            "size_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "classification": "secret",
            "variant": "encrypted_raw", "encrypted": True, "encryption_metadata_id": enc.resource_key_id,
            "derived_from_artifact_id": None, "created_at": created_at, "retention_until": retention_until,
        }
        ref = ArtifactReference(**fields, artifact_digest=self._artifact_digest(fields))  # type: ignore[arg-type]
        return ref, self._blob_handle(mission_id, artifact_id), blob, enc

    def persist_in_txn(self, ref: ArtifactReference, *, blob_handle: str, blob_bytes: bytes,
                       encryption: EncryptionMetadata | None = None) -> None:
        """Persist artifact metadata + body inside the caller's unit of work (create-or-verify)."""
        if encryption is not None:
            self._db.occ_insert_idempotent(_ARTIFACT_ENC_NS, ref.artifact_id, 1,
                                           json.dumps(encryption.model_dump(mode="json"), sort_keys=True))
        self._db.occ_insert_idempotent(_ARTIFACT_NS, ref.artifact_id, 1,
                                       json.dumps(ref.model_dump(mode="json"), sort_keys=True))
        self._blobs.put(blob_handle, blob_bytes)

    def read_body(
        self, artifact_id: str, *, execution_id: str, grant: DataAccessGrant, authority: object,
    ) -> bytes:
        if authority is not self._read_authority:
            raise SecureIngestionError("artifact body requires an authorized reader")
        ref = self.get(artifact_id)
        if ref is None:
            raise SecureIngestionError("artifact not found")
        if (
            grant.resource_type != "artifact"
            or "read" not in grant.operations
            or grant.resource.resource_id != artifact_id
            or grant.resource.resource_version != ref.sha256
            or grant.resource.resource_digest != ref.artifact_digest
            or grant.authorization_state_digest != ref.artifact_digest
        ):
            raise SecureIngestionError("artifact DataAccessGrant does not bind the current artifact")
        blob = self._blobs.get(self._blob_handle(ref.mission_id, artifact_id))
        if not ref.encrypted:
            return blob
        enc_row = self._db.occ_get(_ARTIFACT_ENC_NS, artifact_id)
        if enc_row is None:
            raise SecureIngestionError("encrypted artifact key metadata missing")
        enc = EncryptionMetadata.model_validate_json(enc_row[1])
        envelope = EnvelopeCiphertext.model_validate_json(blob.decode("utf-8"))
        handle = self._keys.open_resource_key_handle(metadata=enc, operation="decrypt")
        try:
            return handle.decrypt(record=envelope, aad_fields={
                "mission_id": ref.mission_id, "execution_id": execution_id, "artifact_id": artifact_id})
        finally:
            handle.close()
