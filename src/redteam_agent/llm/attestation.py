"""Live local vLLM server / model attestation (SystemDesign §6.2 / §7 / §36.E1).

A direct ``httpx.HTTPTransport`` proves only that *some* HTTP server answered; it says
nothing about which model, tokenizer, chat template or runtime produced the evidence.
Before a capability or 300-run result may be labelled ``real_local_llm`` the
configured server is attested against the immutable :class:`LocalLLMProfile`:

* ``GET /health`` must be 200 and ``GET /version`` must report exactly
``profile.runtime_version`` (vLLM serves both at the server root). A configured
API credential is read from its Secret-file for each request and is never persisted.
* ``GET /v1/models`` must list exactly one model whose ``id`` equals the configured
  endpoint model / profile ``model_name`` (zero or duplicate entries are ambiguous).
  vLLM's model card also carries ``root`` (the ``--model`` path / id) and
  ``max_model_len``; the latter must cover ``profile.max_context_tokens``.
* The served model name is mutable configuration (``--served-model-name``), so it is
  never sufficient on its own. The immutable identity (model hash, tokenizer revision,
  chat-template digest) is resolved from the model artifacts the server reports as its
  ``root`` through a :class:`ModelArtifactSource`; a server whose artifacts cannot be
  resolved is rejected as name-only evidence.
* The profile's structured-output mode is exercised with one minimal, context-free
  probe request (no mission data, no secrets, no headers); the response must honour the
  mode and, when it echoes ``model``, name the attested model.

The evidence is canonicalized into an immutable :class:`ServerAttestation` sealed by
``attestation_digest`` and bound to the profile digest and endpoint. Its ``provenance``
is derived from the concrete provider / artifact-source types: only the production
:class:`HttpServerMetadataProvider` over its own retry-disabled network transport
together with :class:`LocalModelArtifactSource` or a verified
:class:`SignedManifestArtifactSource` yields ``direct_network``; any injected provider,
transport or artifact source is ``test_double`` and can never make evidence real.

vLLM API limitation: the OpenAI-compatible API exposes no model hash, tokenizer
revision, chat-template digest or structured-output capability flag, and does not
reveal a ``--tokenizer`` / ``--chat-template`` override. Those are therefore attested
from the local artifacts at the reported ``root`` plus the behavioural probe, and a
server whose ``root`` is not locally readable requires the signed-manifest source.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

import httpx
from pydantic import Field, model_validator

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import LLMAttestationError
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.llm.profile import LocalLLMProfile, verify_profile_digest
from redteam_agent.llm.secrets import APIKeySource, authorization_headers
from redteam_agent.models.base import StrictImmutableBoundaryModel

AttestationProvenance = Literal["direct_network", "test_double"]

PROBE_TOOL_NAME = "attest_probe"
_PROBE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}
_PROBE_USER = 'Reply with the JSON object {"ok": true} and nothing else.'

# Artifact files whose content fixes the immutable model / tokenizer identity.
_WEIGHT_SUFFIXES = (".safetensors", ".bin", ".pt", ".gguf")
_MODEL_CONFIG_FILES = ("config.json", "generation_config.json", "model.safetensors.index.json")
_TOKENIZER_FILES = (
    "tokenizer.json", "tokenizer_config.json", "tokenizer.model", "special_tokens_map.json",
    "vocab.json", "merges.txt", "added_tokens.json",
)
_CHAT_TEMPLATE_FILE = "chat_template.jinja"


@dataclass(frozen=True)
class RawServerEvidence:
    """Raw, untrusted responses gathered from the configured server."""

    health_status: int | None
    version: object
    models: object
    structured_output_probe: object


class ServerMetadataProvider(Protocol):
    """Collects raw metadata / probe responses from a server (injectable test seam)."""

    def collect(
        self, *, base_url: str, model: str, structured_output_mode: str, timeout_seconds: float
    ) -> RawServerEvidence:
        ...


def structured_output_probe_payload(model: str, structured_output_mode: str) -> dict[str, Any]:
    """The fixed, context-free structured-output probe request body (no secrets)."""
    payload: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": _PROBE_USER}],
        "max_tokens": 16,
        "temperature": 0.0,
        "stream": False,
    }
    if structured_output_mode == "native_json_schema":
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": PROBE_TOOL_NAME, "schema": _PROBE_SCHEMA, "strict": True},
        }
    elif structured_output_mode == "tool_output_json":
        payload["tools"] = [
            {"type": "function", "function": {"name": PROBE_TOOL_NAME, "parameters": _PROBE_SCHEMA}}
        ]
        payload["tool_choice"] = {"type": "function", "function": {"name": PROBE_TOOL_NAME}}
    else:
        raise LLMAttestationError("structured_output_mode is not attestable")
    return payload


def server_root(base_url: str) -> str:
    """vLLM serves ``/health`` and ``/version`` at the origin, not under ``/v1``."""
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise LLMAttestationError("base_url must be an absolute http(s) URL")
    return f"{parts.scheme}://{parts.netloc}"


class HttpServerMetadataProvider:
    """Production provider: authenticated GET/POST over a retry-disabled transport."""

    def __init__(
        self,
        *,
        api_key_source: APIKeySource | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._transport = transport if transport is not None else httpx.HTTPTransport(retries=0)
        self._api_key_source = api_key_source

    @property
    def uses_direct_network_transport(self) -> bool:
        return type(self._transport) is httpx.HTTPTransport

    def collect(
        self, *, base_url: str, model: str, structured_output_mode: str, timeout_seconds: float
    ) -> RawServerEvidence:
        if timeout_seconds <= 0:
            raise LLMAttestationError("attestation timeout must be positive")
        base = base_url.rstrip("/")
        root = server_root(base)
        try:
            with httpx.Client(
                transport=self._transport,
                timeout=httpx.Timeout(timeout_seconds),
                headers=authorization_headers(self._api_key_source),
            ) as client:
                health = client.get(f"{root}/health")
                version = client.get(f"{root}/version")
                models = client.get(f"{base}/models")
                probe = client.post(
                    f"{base}/chat/completions",
                    json=structured_output_probe_payload(model, structured_output_mode),
                )
        except httpx.HTTPError:
            raise LLMAttestationError("server metadata request failed") from None
        return RawServerEvidence(
            health_status=health.status_code,
            version=_json_or_none(version),
            models=_json_or_none(models),
            structured_output_probe=_json_or_none(probe),
        )


def _json_or_none(response: httpx.Response) -> object:
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


@dataclass(frozen=True)
class ModelArtifactIdentity:
    """Immutable identity resolved from the model artifacts the server serves."""

    model_hash: str
    tokenizer_revision: str
    chat_template_digest: str | None
    served_model_id: str | None = None
    runtime_version: str | None = None
    max_model_len: int | None = None
    snapshot_revision: str | None = None
    container_image_digest: str | None = None
    manifest_digest: str | None = None


class ModelArtifactSource(Protocol):
    """Resolves the immutable artifact identity for a served model ``root``."""

    def resolve(self, model_root: str) -> ModelArtifactIdentity | None:
        ...


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_digest(directory: Path, files: list[Path]) -> str:
    manifest = [
        {"path": path.relative_to(directory).as_posix(), "size": path.stat().st_size,
         "sha256": _sha256_file(path)}
        for path in sorted(files)
    ]
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode("utf-8")).hexdigest()


class LocalModelArtifactSource:
    """Hashes the local model directory reported as the served ``root``.

    ``model_hash`` covers the weight shards and model configs; ``tokenizer_revision`` the
    tokenizer files; ``chat_template_digest`` the external ``chat_template.jinja`` or the
    ``chat_template`` entry of ``tokenizer_config.json`` (``None`` only when neither
    exists, i.e. the template is built into the served artifacts).
    """

    def resolve(self, model_root: str) -> ModelArtifactIdentity | None:
        directory = Path(model_root)
        if not directory.is_absolute() or not directory.is_dir():
            return None  # a Hub id / relative name is mutable, name-only identity
        weights = [p for p in directory.iterdir() if p.is_file() and p.suffix in _WEIGHT_SUFFIXES]
        configs = [directory / name for name in _MODEL_CONFIG_FILES if (directory / name).is_file()]
        tokenizer = [directory / name for name in _TOKENIZER_FILES if (directory / name).is_file()]
        if not weights or not tokenizer:
            return None
        template_digest = self._chat_template_digest(directory)
        return ModelArtifactIdentity(
            model_hash=_manifest_digest(directory, weights + configs),
            tokenizer_revision=_manifest_digest(directory, tokenizer),
            chat_template_digest=template_digest,
        )

    @staticmethod
    def _chat_template_digest(directory: Path) -> str | None:
        external = directory / _CHAT_TEMPLATE_FILE
        if external.is_file():
            return _sha256_file(external)
        config = directory / "tokenizer_config.json"
        if config.is_file():
            try:
                body = json.loads(config.read_text(encoding="utf-8"))
            except ValueError:
                return None
            template = body.get("chat_template") if isinstance(body, dict) else None
            if isinstance(template, str):
                return hashlib.sha256(template.encode("utf-8")).hexdigest()
        return None


class SignedManifestArtifactSource:
    """Resolve remote artifacts from an operator-signed, locally verified manifest."""

    def __init__(
        self,
        *,
        manifest_path: str | Path,
        public_key_path: str | Path,
        expected_key_id: str,
        digest_service: DigestService,
    ) -> None:
        self._manifest_path = Path(manifest_path)
        self._public_key_path = Path(public_key_path)
        self._expected_key_id = expected_key_id
        self._digest_service = digest_service

    def resolve(self, model_root: str) -> ModelArtifactIdentity | None:
        from redteam_agent.llm.artifact_manifest import (
            load_and_verify_remote_model_artifact_manifest,
        )

        manifest = load_and_verify_remote_model_artifact_manifest(
            manifest_path=self._manifest_path,
            public_key_path=self._public_key_path,
            expected_key_id=self._expected_key_id,
            digest_service=self._digest_service,
        )
        if manifest.model_root != model_root:
            return None
        return ModelArtifactIdentity(
            model_hash=manifest.model_hash,
            tokenizer_revision=manifest.tokenizer_revision,
            chat_template_digest=manifest.chat_template_digest,
            served_model_id=manifest.served_model_id,
            runtime_version=manifest.runtime_version,
            max_model_len=manifest.max_model_len,
            snapshot_revision=manifest.snapshot_revision,
            container_image_digest=manifest.container_image_digest,
            manifest_digest=manifest.manifest_digest,
        )


class ServerAttestation(StrictImmutableBoundaryModel):
    """Canonical, digest-sealed evidence that the configured server serves the profile."""

    profile_digest: str = Field(min_length=1)
    base_url: str = Field(min_length=1)
    endpoint_model: str = Field(min_length=1)
    wire_api: Literal["chat_completions"]
    served_model_id: str = Field(min_length=1)
    model_root: str = Field(min_length=1)
    model_hash: str = Field(min_length=1)
    tokenizer_revision: str = Field(min_length=1)
    chat_template_digest: str | None
    runtime_version: str = Field(min_length=1)
    max_model_len: int | None
    artifact_manifest_digest: str | None = None
    snapshot_revision: str | None = None
    container_image_digest: str | None = None
    structured_output_mode: str = Field(min_length=1)
    structured_output_verified: bool
    evidence_sources: tuple[str, ...] = Field(min_length=1)
    provenance: AttestationProvenance
    attestation_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _bounded(self) -> ServerAttestation:
        if not self.structured_output_verified:
            raise ValueError("an attestation requires a verified structured-output probe")
        if self.served_model_id != self.endpoint_model:
            raise ValueError("attested served model must equal the endpoint model")
        return self


def derive_attestation_provenance(
    provider: object, artifact_source: object
) -> AttestationProvenance:
    """Provenance from concrete types only; never from a caller flag."""
    if (
        type(provider) is HttpServerMetadataProvider
        and provider.uses_direct_network_transport
        and type(artifact_source) in (LocalModelArtifactSource, SignedManifestArtifactSource)
    ):
        return "direct_network"
    return "test_double"


def _require_served_model(models: object, model: str) -> dict[str, Any]:
    if not isinstance(models, dict) or not isinstance(models.get("data"), list):
        raise LLMAttestationError("server model list is missing or malformed")
    matches = [
        entry for entry in models["data"]
        if isinstance(entry, dict) and entry.get("id") == model
    ]
    if not matches:
        raise LLMAttestationError("server does not list the profile model")
    if len(matches) != 1:
        raise LLMAttestationError("server lists the profile model ambiguously")
    entry = matches[0]
    if entry.get("object", "model") != "model":
        raise LLMAttestationError("served model entry is not a model card")
    root = entry.get("root")
    if not isinstance(root, str) or not root:
        raise LLMAttestationError("served model card carries no artifact root")
    return entry


def _require_version(version: object, runtime_version: str) -> str:
    if not isinstance(version, dict) or not isinstance(version.get("version"), str):
        raise LLMAttestationError("server version is missing or malformed")
    if version["version"] != runtime_version:
        raise LLMAttestationError("server runtime version does not match the profile")
    return str(version["version"])


def _verify_probe(body: object, *, model: str, mode: str) -> None:
    if not isinstance(body, dict):
        raise LLMAttestationError("structured-output probe response is missing or malformed")
    if "model" in body and body["model"] != model:
        raise LLMAttestationError("structured-output probe was answered by another model")
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise LLMAttestationError("structured-output probe response has no choices")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise LLMAttestationError("structured-output probe response has no message")
    raw: object = None
    if mode == "native_json_schema":
        raw = message.get("content")
    else:
        calls = message.get("tool_calls")
        if isinstance(calls, list) and calls and isinstance(calls[0], dict):
            function = calls[0].get("function")
            if isinstance(function, dict) and function.get("name") == PROBE_TOOL_NAME:
                raw = function.get("arguments")
    if not isinstance(raw, str):
        raise LLMAttestationError("structured-output probe did not honour the output mode")
    try:
        parsed = parse_json_no_duplicate_keys(raw)
    except Exception:
        raise LLMAttestationError("structured-output probe body is not strict JSON") from None
    if not isinstance(parsed, dict) or set(parsed) != {"ok"} or not isinstance(parsed["ok"], bool):
        raise LLMAttestationError("structured-output probe body does not match the schema")


def attest_local_llm_server(
    *,
    profile: LocalLLMProfile,
    endpoint: LocalLLMEndpointConfig,
    provider: ServerMetadataProvider,
    artifact_source: ModelArtifactSource,
    digest_service: DigestService,
    timeout_seconds: float = 10.0,
) -> ServerAttestation:
    """Fail-closed attestation of the configured server against the immutable profile."""
    verify_profile_digest(profile, digest_service)
    if endpoint.base_url is None:
        raise LLMAttestationError("no local vLLM endpoint is configured")
    if endpoint.model != profile.model_name or endpoint.wire_api != profile.wire_api:
        raise LLMAttestationError("endpoint does not bind the profile model / wire API")
    base_url = endpoint.base_url.rstrip("/")
    evidence = provider.collect(
        base_url=base_url, model=endpoint.model,
        structured_output_mode=profile.structured_output_mode, timeout_seconds=timeout_seconds,
    )
    if evidence.health_status != 200:
        raise LLMAttestationError("server health check did not succeed")
    runtime_version = _require_version(evidence.version, profile.runtime_version)
    card = _require_served_model(evidence.models, endpoint.model)
    max_model_len = card.get("max_model_len")
    if max_model_len is not None:
        if not isinstance(max_model_len, int) or isinstance(max_model_len, bool):
            raise LLMAttestationError("served model max_model_len is malformed")
        if max_model_len < profile.max_context_tokens:
            raise LLMAttestationError("served model context is smaller than the profile")
    identity = artifact_source.resolve(str(card["root"]))
    if identity is None:
        raise LLMAttestationError(
            "served model identity is name-only; immutable artifacts could not be resolved"
        )
    if identity.model_hash != profile.model_hash:
        raise LLMAttestationError("served model hash does not match the profile")
    if identity.tokenizer_revision != profile.tokenizer_revision:
        raise LLMAttestationError("served tokenizer revision does not match the profile")
    if identity.chat_template_digest != profile.chat_template_digest:
        raise LLMAttestationError("served chat template does not match the profile")
    if identity.served_model_id is not None and identity.served_model_id != card["id"]:
        raise LLMAttestationError("signed manifest served model does not match the server")
    if identity.runtime_version is not None and identity.runtime_version != runtime_version:
        raise LLMAttestationError("signed manifest runtime does not match the server")
    if identity.max_model_len is not None and identity.max_model_len != max_model_len:
        raise LLMAttestationError("signed manifest context length does not match the server")
    _verify_probe(
        evidence.structured_output_probe, model=endpoint.model,
        mode=profile.structured_output_mode,
    )
    fields: dict[str, object] = {
        "profile_digest": profile.profile_digest,
        "base_url": base_url,
        "endpoint_model": endpoint.model,
        "wire_api": endpoint.wire_api,
        "served_model_id": str(card["id"]),
        "model_root": str(card["root"]),
        "model_hash": identity.model_hash,
        "tokenizer_revision": identity.tokenizer_revision,
        "chat_template_digest": identity.chat_template_digest,
        "runtime_version": runtime_version,
        "max_model_len": max_model_len,
        "artifact_manifest_digest": identity.manifest_digest,
        "snapshot_revision": identity.snapshot_revision,
        "container_image_digest": identity.container_image_digest,
        "structured_output_mode": profile.structured_output_mode,
        "structured_output_verified": True,
        "evidence_sources": ("/health", "/version", "/v1/models", "/v1/chat/completions#probe"),
        "provenance": derive_attestation_provenance(provider, artifact_source),
    }
    attestation_digest = digest_service.compute("llm_server_attestation_digest", fields)
    return ServerAttestation(**fields, attestation_digest=attestation_digest)  # type: ignore[arg-type]


def verify_server_attestation(attestation: ServerAttestation, digest_service: DigestService) -> None:
    digest_service.verify(
        "llm_server_attestation_digest",
        {k: v for k, v in attestation.model_dump(mode="python").items() if k != "attestation_digest"},
        attestation.attestation_digest,
    )


def require_attestation_binding(
    attestation: ServerAttestation,
    *,
    profile: LocalLLMProfile,
    base_url: str,
    digest_service: DigestService,
) -> None:
    """Fail closed unless the attestation is intact and bound to this profile / endpoint."""
    verify_server_attestation(attestation, digest_service)
    if attestation.profile_digest != profile.profile_digest:
        raise LLMAttestationError("server attestation is not bound to this profile")
    if attestation.base_url != base_url.rstrip("/"):
        raise LLMAttestationError("server attestation is not bound to this endpoint")
    if (
        attestation.model_hash != profile.model_hash
        or attestation.tokenizer_revision != profile.tokenizer_revision
        or attestation.chat_template_digest != profile.chat_template_digest
        or attestation.runtime_version != profile.runtime_version
        or attestation.structured_output_mode != profile.structured_output_mode
        or attestation.served_model_id != profile.model_name
    ):
        raise LLMAttestationError("server attestation identity does not match the profile")


def attestation_is_real(attestation: ServerAttestation | None) -> bool:
    return attestation is not None and attestation.provenance == "direct_network"


__all__ = [
    "PROBE_TOOL_NAME",
    "AttestationProvenance",
    "HttpServerMetadataProvider",
    "LocalModelArtifactSource",
    "ModelArtifactIdentity",
    "ModelArtifactSource",
    "RawServerEvidence",
    "ServerAttestation",
    "ServerMetadataProvider",
    "SignedManifestArtifactSource",
    "attest_local_llm_server",
    "attestation_is_real",
    "derive_attestation_provenance",
    "require_attestation_binding",
    "server_root",
    "structured_output_probe_payload",
    "verify_server_attestation",
]
