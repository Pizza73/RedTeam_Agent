"""Signed remote-model artifact manifests for split-host vLLM deployments.

The GPU host hashes the exact immutable snapshot and signs this bounded manifest with
an Ed25519 deployment key.  The Red Agent host trusts only the public key and therefore
does not need to mount or re-read the 59+ GiB model for every attestation.
"""

from __future__ import annotations

import base64
import re
import stat
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import DigestIntegrityError, LLMAttestationError
from redteam_agent.models.base import StrictImmutableBoundaryModel

MANIFEST_REVISION: Literal["vllm-artifact-manifest-v1"] = "vllm-artifact-manifest-v1"
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class RemoteModelArtifactManifest(StrictImmutableBoundaryModel):
    """Immutable operator assertion binding a running vLLM to exact artifacts."""

    manifest_revision: Literal["vllm-artifact-manifest-v1"] = MANIFEST_REVISION
    key_id: str = Field(min_length=1)
    served_model_id: str = Field(min_length=1)
    model_root: str = Field(min_length=1)
    snapshot_revision: str = Field(min_length=1)
    model_hash: str = Field(min_length=1)
    tokenizer_revision: str = Field(min_length=1)
    chat_template_digest: str | None
    runtime_version: str = Field(min_length=1)
    max_model_len: int = Field(gt=0)
    container_image_digest: str = Field(min_length=1)
    manifest_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _bounded(self) -> RemoteModelArtifactManifest:
        if not Path(self.model_root).is_absolute():
            raise ValueError("manifest model_root must be absolute")
        if not _HEX_40.fullmatch(self.snapshot_revision):
            raise ValueError("snapshot_revision must be a lowercase 40-hex revision")
        for value in (self.model_hash, self.tokenizer_revision, self.manifest_digest):
            if not _HEX_64.fullmatch(value):
                raise ValueError("manifest digest fields must be lowercase SHA-256")
        if self.chat_template_digest is not None and not _HEX_64.fullmatch(
            self.chat_template_digest
        ):
            raise ValueError("chat_template_digest must be lowercase SHA-256")
        if not self.container_image_digest.startswith("sha256:") or not _HEX_64.fullmatch(
            self.container_image_digest.removeprefix("sha256:")
        ):
            raise ValueError("container_image_digest must be sha256:<lowercase-hex>")
        return self


class SignedRemoteModelArtifactManifest(StrictImmutableBoundaryModel):
    manifest: RemoteModelArtifactManifest
    signature_base64: str = Field(min_length=1)


def _manifest_payload(manifest: RemoteModelArtifactManifest) -> dict[str, object]:
    payload = manifest.model_dump(mode="python")
    payload.pop("manifest_digest")
    return payload


def build_remote_model_artifact_manifest(
    *,
    key_id: str,
    served_model_id: str,
    model_root: str,
    snapshot_revision: str,
    model_hash: str,
    tokenizer_revision: str,
    chat_template_digest: str | None,
    runtime_version: str,
    max_model_len: int,
    container_image_digest: str,
    digest_service: DigestService,
) -> RemoteModelArtifactManifest:
    draft = RemoteModelArtifactManifest(
        key_id=key_id,
        served_model_id=served_model_id,
        model_root=model_root,
        snapshot_revision=snapshot_revision,
        model_hash=model_hash,
        tokenizer_revision=tokenizer_revision,
        chat_template_digest=chat_template_digest,
        runtime_version=runtime_version,
        max_model_len=max_model_len,
        container_image_digest=container_image_digest,
        manifest_digest="0" * 64,
    )
    return draft.model_copy(
        update={
            "manifest_digest": digest_service.compute(
                "llm_remote_artifact_manifest_digest", _manifest_payload(draft)
            )
        }
    )


def sign_remote_model_artifact_manifest(
    manifest: RemoteModelArtifactManifest,
    private_key: Ed25519PrivateKey,
    digest_service: DigestService,
) -> SignedRemoteModelArtifactManifest:
    try:
        digest_service.verify(
            "llm_remote_artifact_manifest_digest",
            _manifest_payload(manifest),
            manifest.manifest_digest,
        )
    except DigestIntegrityError:
        raise LLMAttestationError("signed artifact manifest digest is invalid") from None
    signature = private_key.sign(canonical_dumps(manifest.model_dump(mode="python")))
    return SignedRemoteModelArtifactManifest(
        manifest=manifest,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )


def _safe_public_key(path: Path) -> Ed25519PublicKey:
    if not path.is_absolute():
        raise LLMAttestationError("attestation public-key path must be absolute")
    try:
        metadata = path.lstat()
        body = path.read_bytes()
    except OSError:
        raise LLMAttestationError("attestation public key is unavailable") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LLMAttestationError("attestation public key must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise LLMAttestationError("attestation public key is writable by group or other")
    try:
        loaded = serialization.load_pem_public_key(body)
    except (TypeError, ValueError):
        raise LLMAttestationError("attestation public key is malformed") from None
    if not isinstance(loaded, Ed25519PublicKey):
        raise LLMAttestationError("attestation public key must be Ed25519")
    return loaded


def load_and_verify_remote_model_artifact_manifest(
    *,
    manifest_path: str | Path,
    public_key_path: str | Path,
    expected_key_id: str,
    digest_service: DigestService,
) -> RemoteModelArtifactManifest:
    path = Path(manifest_path)
    if not path.is_absolute():
        raise LLMAttestationError("signed artifact-manifest path must be absolute")
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError:
        raise LLMAttestationError("signed artifact manifest is unavailable") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LLMAttestationError("signed artifact manifest must be a regular non-symlink file")
    try:
        envelope = SignedRemoteModelArtifactManifest.from_untrusted_json(raw)
    except Exception:
        raise LLMAttestationError("signed artifact manifest is malformed") from None
    manifest = envelope.manifest
    if manifest.key_id != expected_key_id:
        raise LLMAttestationError("signed artifact manifest uses an unexpected key id")
    try:
        digest_service.verify(
            "llm_remote_artifact_manifest_digest",
            _manifest_payload(manifest),
            manifest.manifest_digest,
        )
    except DigestIntegrityError:
        raise LLMAttestationError("signed artifact manifest digest is invalid") from None
    try:
        signature = base64.b64decode(envelope.signature_base64, validate=True)
        _safe_public_key(Path(public_key_path)).verify(
            signature,
            canonical_dumps(manifest.model_dump(mode="python")),
        )
    except (InvalidSignature, TypeError, ValueError):
        raise LLMAttestationError("signed artifact manifest signature is invalid") from None
    return manifest


__all__ = [
    "MANIFEST_REVISION",
    "RemoteModelArtifactManifest",
    "SignedRemoteModelArtifactManifest",
    "build_remote_model_artifact_manifest",
    "load_and_verify_remote_model_artifact_manifest",
    "sign_remote_model_artifact_manifest",
]
