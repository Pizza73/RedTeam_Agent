from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMAttestationError
from redteam_agent.llm.artifact_manifest import (
    build_remote_model_artifact_manifest,
    load_and_verify_remote_model_artifact_manifest,
    sign_remote_model_artifact_manifest,
)


def _signed_files(tmp_path):  # type: ignore[no-untyped-def]
    tmp_path.mkdir(parents=True, exist_ok=True)
    ds = DigestService()
    private = Ed25519PrivateKey.generate()
    public_path = tmp_path / "attestation-public.pem"
    public_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_path.chmod(0o644)
    manifest = build_remote_model_artifact_manifest(
        key_id="gpu-host-1",
        served_model_id="gemma-4-31B-it",
        model_root="/model-repository/snapshots/" + "a" * 40,
        snapshot_revision="a" * 40,
        model_hash="b" * 64,
        tokenizer_revision="c" * 64,
        chat_template_digest="d" * 64,
        runtime_version="0.25.1",
        max_model_len=131072,
        container_image_digest="sha256:" + "e" * 64,
        digest_service=ds,
    )
    signed = sign_remote_model_artifact_manifest(manifest, private, ds)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(signed.model_dump_json())
    return ds, public_path, manifest_path, manifest


def test_signed_remote_manifest_round_trip(tmp_path) -> None:
    ds, public_path, manifest_path, expected = _signed_files(tmp_path)
    loaded = load_and_verify_remote_model_artifact_manifest(
        manifest_path=manifest_path,
        public_key_path=public_path,
        expected_key_id="gpu-host-1",
        digest_service=ds,
    )
    assert loaded == expected


def test_signed_remote_manifest_rejects_tampering_and_wrong_key_id(tmp_path) -> None:
    ds, public_path, manifest_path, _ = _signed_files(tmp_path)
    body = json.loads(manifest_path.read_text())
    body["manifest"]["runtime_version"] = "other"
    manifest_path.write_text(json.dumps(body))
    with pytest.raises(LLMAttestationError):
        load_and_verify_remote_model_artifact_manifest(
            manifest_path=manifest_path,
            public_key_path=public_path,
            expected_key_id="gpu-host-1",
            digest_service=ds,
        )
    ds, public_path, manifest_path, _ = _signed_files(tmp_path / "second")
    with pytest.raises(LLMAttestationError):
        load_and_verify_remote_model_artifact_manifest(
            manifest_path=manifest_path,
            public_key_path=public_path,
            expected_key_id="other-host",
            digest_service=ds,
        )
