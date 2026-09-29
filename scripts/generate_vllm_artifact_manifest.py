#!/usr/bin/env python3
"""Generate and Ed25519-sign a split-host vLLM artifact manifest.

This GPU-host utility has no project-package dependency.  It deliberately delegates
private-key operations to OpenSSL so the signing key never leaves the vLLM manager
host.  The emitted JSON is verified by ``SignedManifestArtifactSource`` on Red Agent.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

DOMAIN = b"digest-catalog-v1:llm_remote_artifact_manifest_digest:v1\x00"
WEIGHT_SUFFIXES = (".safetensors", ".bin", ".pt", ".gguf")
MODEL_CONFIG_FILES = ("config.json", "generation_config.json", "model.safetensors.index.json")
TOKENIZER_FILES = (
    "tokenizer.json",
    "tokenizer_config.json",
    "tokenizer.model",
    "special_tokens_map.json",
    "vocab.json",
    "merges.txt",
    "added_tokens.json",
)


def canonical(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False).encode()
    if isinstance(value, int):
        return str(value).encode()
    if isinstance(value, list | tuple):
        return b"[" + b",".join(canonical(item) for item in value) + b"]"
    if isinstance(value, dict):
        return b"{" + b",".join(
            json.dumps(key, ensure_ascii=False).encode() + b":" + canonical(value[key])
            for key in sorted(value)
        ) + b"}"
    raise TypeError("manifest contains a non-canonical value")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_digest(directory: Path, files: list[Path]) -> str:
    rows = [
        {
            "path": path.relative_to(directory).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(files)
    ]
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def artifact_identity(directory: Path) -> tuple[str, str, str | None]:
    weights = [
        path for path in directory.iterdir()
        if path.is_file() and path.suffix in WEIGHT_SUFFIXES
    ]
    configs = [directory / name for name in MODEL_CONFIG_FILES if (directory / name).is_file()]
    tokenizers = [directory / name for name in TOKENIZER_FILES if (directory / name).is_file()]
    if not weights or not tokenizers:
        raise ValueError("model snapshot must contain weights and tokenizer artifacts")
    template = directory / "chat_template.jinja"
    template_digest = sha256_file(template) if template.is_file() else None
    if template_digest is None:
        config = directory / "tokenizer_config.json"
        body = json.loads(config.read_text(encoding="utf-8"))
        inline = body.get("chat_template") if isinstance(body, dict) else None
        if isinstance(inline, str):
            template_digest = hashlib.sha256(inline.encode()).hexdigest()
    return (
        manifest_digest(directory, weights + configs),
        manifest_digest(directory, tokenizers),
        template_digest,
    )


def require_private_key(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("private key must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("private key permissions must be owner-only")


def sign(body: bytes, private_key: Path) -> bytes:
    require_private_key(private_key)
    with tempfile.TemporaryDirectory(prefix="vllm-manifest-sign-") as temporary:
        input_path = Path(temporary) / "manifest.canonical"
        signature_path = Path(temporary) / "manifest.sig"
        input_path.write_bytes(body)
        subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
                "-in", str(input_path), "-out", str(signature_path),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return signature_path.read_bytes()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-directory", type=Path, required=True)
    parser.add_argument("--model-root", required=True)
    parser.add_argument("--served-model-id", required=True)
    parser.add_argument("--runtime-version", required=True)
    parser.add_argument("--max-model-len", type=int, required=True)
    parser.add_argument("--container-image-digest", required=True)
    parser.add_argument("--snapshot-revision", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    directory = args.model_directory.resolve(strict=True)
    if directory.name != args.snapshot_revision:
        raise ValueError("snapshot directory name must equal snapshot revision")
    if args.max_model_len <= 0:
        raise ValueError("max_model_len must be positive")
    model_hash, tokenizer_revision, chat_template_digest = artifact_identity(directory)
    payload = {
        "manifest_revision": "vllm-artifact-manifest-v1",
        "key_id": args.key_id,
        "served_model_id": args.served_model_id,
        "model_root": args.model_root,
        "snapshot_revision": args.snapshot_revision,
        "model_hash": model_hash,
        "tokenizer_revision": tokenizer_revision,
        "chat_template_digest": chat_template_digest,
        "runtime_version": args.runtime_version,
        "max_model_len": args.max_model_len,
        "container_image_digest": args.container_image_digest,
    }
    payload["manifest_digest"] = hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()
    signature = sign(canonical(payload), args.private_key)
    envelope = {
        "manifest": payload,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=args.output.name + ".", dir=args.output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(envelope, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, args.output)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


if __name__ == "__main__":
    main()
