"""Live server / model attestation: exact match, every mismatch, missing metadata,
spoofed model name over direct HTTP, and PASS blocked without a valid attestation."""

from __future__ import annotations

import json

import httpx
import pytest

import support_phase2 as fake
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition.phase2 import build_phase2_kernel
from redteam_agent.errors import LLMAttestationError, LLMEvaluationError
from redteam_agent.llm.attestation import (
    HttpServerMetadataProvider,
    LocalModelArtifactSource,
    attest_local_llm_server,
    derive_attestation_provenance,
    verify_server_attestation,
)
from redteam_agent.llm.attestation_store import ServerAttestationRepository
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.storage.database import Database

BASE = "http://127.0.0.1:8000/v1"


def _ds() -> DigestService:
    return build_phase2_kernel().phase1.phase0c.phase0b.phase0a.digest_service


def _attest(ds, profile, evidence=None, identity="default", endpoint=None):
    return attest_local_llm_server(
        profile=profile,
        endpoint=endpoint or fake.endpoint_config(profile),
        provider=fake.StaticMetadataProvider(evidence or fake.server_evidence(profile)),
        artifact_source=fake.StaticArtifactSource(
            fake.artifact_identity(profile) if identity == "default" else identity
        ),
        digest_service=ds,
    )


def test_exact_match_produces_bound_test_double_attestation() -> None:
    ds = _ds()
    profile = fake.local_profile(ds)
    attestation = _attest(ds, profile)
    verify_server_attestation(attestation, ds)
    assert attestation.provenance == "test_double"  # static doubles are never real
    assert attestation.profile_digest == profile.profile_digest
    assert attestation.served_model_id == profile.model_name
    assert attestation.model_hash == profile.model_hash
    assert attestation.base_url == BASE
    with pytest.raises(LLMAttestationError):
        ServerAttestationRepository(Database(":memory:"), ds).save(attestation)


@pytest.mark.parametrize("kwargs", [
    {"served_model_id": "other-model"},
    {"runtime_version": "vllm-other"},
    {"health_status": 503},
    {"health_status": None},
    {"max_model_len": 1024},
    {"duplicate_model": True},
    {"probe_model": "other-model"},
    {"probe_content": '{"ok": "yes"}'},
    {"probe_content": '{"ok": true, "extra": 1}'},
    {"probe_content": "sure, here it is"},
    {"version": None},
    {"version": {"version": 1}},
    {"models": None},
    {"models": {"object": "list", "data": []}},
    {"probe": None},
])
def test_each_server_mismatch_or_missing_metadata_is_rejected(kwargs) -> None:
    ds = _ds()
    profile = fake.local_profile(ds)
    with pytest.raises(LLMAttestationError):
        _attest(ds, profile, evidence=fake.server_evidence(profile, **kwargs))


@pytest.mark.parametrize("overrides", [
    {"model_hash": "other-hash"},
    {"tokenizer_revision": "tok-other"},
    {"chat_template_digest": "external-template-digest"},
])
def test_each_artifact_identity_mismatch_is_rejected(overrides) -> None:
    ds = _ds()
    profile = fake.local_profile(ds)
    with pytest.raises(LLMAttestationError):
        _attest(ds, profile, identity=fake.artifact_identity(profile, **overrides))


def test_name_only_identity_is_rejected() -> None:
    ds = _ds()
    profile = fake.local_profile(ds)
    with pytest.raises(LLMAttestationError):
        _attest(ds, profile, identity=None)


def test_endpoint_profile_binding_mismatch_is_rejected() -> None:
    ds = _ds()
    profile = fake.local_profile(ds)
    with pytest.raises(LLMAttestationError):
        _attest(ds, profile, endpoint=LocalLLMEndpointConfig(model="other", base_url=BASE))
    with pytest.raises(LLMAttestationError):
        _attest(ds, profile, endpoint=LocalLLMEndpointConfig(model=profile.model_name))


def test_spoofed_model_name_over_direct_http_is_rejected_and_never_real() -> None:
    ds = _ds()
    profile = fake.local_profile(ds)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if path == "/health":
            return httpx.Response(200)
        if path == "/version":
            return httpx.Response(200, json={"version": profile.runtime_version})
        if path == "/v1/models":
            return httpx.Response(200, json={"object": "list", "data": [
                {"id": "qwen-test", "object": "model", "root": "/nonexistent/model-dir"}]})
        return httpx.Response(200, json={"model": "qwen-test", "choices": [
            {"index": 0, "message": {"role": "assistant", "content": '{"ok": true}'},
             "finish_reason": "stop"}]})

    provider = HttpServerMetadataProvider(transport=httpx.MockTransport(handler))
    # Same served name as the profile, but the artifacts cannot be resolved: name-only.
    with pytest.raises(LLMAttestationError):
        attest_local_llm_server(
            profile=profile, endpoint=fake.endpoint_config(profile), provider=provider,
            artifact_source=LocalModelArtifactSource(), digest_service=ds,
        )
    assert all("authorization" not in {k.lower() for k in r.headers} for r in seen)
    assert [r.url.path for r in seen] == ["/health", "/version", "/v1/models", "/v1/chat/completions"]
    probe = json.loads(seen[-1].content)
    assert probe["response_format"]["type"] == "json_schema"
    # Even a fully matching answer through an injected transport is a test double.
    assert derive_attestation_provenance(provider, LocalModelArtifactSource()) == "test_double"
    assert derive_attestation_provenance(
        HttpServerMetadataProvider(), fake.StaticArtifactSource(None)
    ) == "test_double"


def test_local_artifact_source_hashes_model_directory(tmp_path) -> None:
    (tmp_path / "model.safetensors").write_bytes(b"weights")
    (tmp_path / "config.json").write_text("{}")
    (tmp_path / "tokenizer.json").write_text("{}")
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({"chat_template": "{{ x }}"}))
    identity = LocalModelArtifactSource().resolve(str(tmp_path))
    assert identity is not None and identity.chat_template_digest is not None
    (tmp_path / "model.safetensors").write_bytes(b"other")
    changed = LocalModelArtifactSource().resolve(str(tmp_path))
    assert changed is not None and changed.model_hash != identity.model_hash
    assert changed.tokenizer_revision == identity.tokenizer_revision
    assert LocalModelArtifactSource().resolve("org/hub-model-id") is None


def test_direct_transport_without_attestation_is_test_double() -> None:
    ds = _ds()
    profile = fake.local_profile(ds)
    client = VLLMChatClient(base_url=BASE)  # direct HTTPTransport, never contacted
    probe = fake.live_probe(ds, profile, client=client)
    assert client.uses_direct_network_transport
    assert probe.evidence_kind == "test_double"
    assert probe.attestation_digest is None
    # A test-double attestation over a direct transport is still not real evidence.
    from redteam_agent.llm.evaluation import LiveCapabilityProbe

    attestation = fake.test_double_attestation(ds, profile)
    kwargs = {
        "profile": profile,
        "policy": fake.build_request_budget_policy(profile=profile, digest_service=ds),
        "endpoint": fake.endpoint_config(profile), "client": client,
        "token_counter": fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        "gateway": fake.EvaluationGateway(
            database=Database(":memory:"), digest_service=ds, clock=_clock(), run_id="a"
        ),
        "run_budget": _budget(), "clock": _clock(), "digest_service": ds,
    }
    bound = LiveCapabilityProbe(**kwargs, attestation=attestation)
    assert bound.evidence_kind == "test_double"
    assert bound.attestation_digest == attestation.attestation_digest
    other = fake.local_profile(ds, profile_revision="other")
    with pytest.raises(LLMAttestationError):
        LiveCapabilityProbe(**kwargs, attestation=fake.test_double_attestation(ds, other))


def _clock():
    from datetime import UTC, datetime

    return fake.ManualClock(datetime(2026, 9, 7, 12, 0, tzinfo=UTC))


def _budget():
    from datetime import timedelta

    clock = _clock()
    return fake.EvaluationRunBudget(
        max_calls=10, max_total_tokens=100_000, deadline=clock.now() + timedelta(seconds=60), clock=clock
    )


def test_kernel_blocks_capability_and_quality_pass_without_valid_attestation() -> None:
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url=BASE)
    kernel = build_phase2_kernel(
        endpoint=endpoint, qualification_commit_id="a" * 40, dependency_lock_digest="b" * 64
    )
    ds = kernel.phase1.phase0c.phase0b.phase0a.digest_service
    profile = fake.local_profile(ds)
    # Kernel attestation over doubles is returned but never persisted as real.
    attestation = kernel.attest_server(
        profile=profile, provider=fake.StaticMetadataProvider(fake.server_evidence(profile)),
        artifact_source=fake.StaticArtifactSource(fake.artifact_identity(profile)),
    )
    assert attestation.provenance == "test_double"
    assert kernel.server_attestation_repository().get(attestation.attestation_digest) is None
    # Forged "real" capability rows reference no persisted attestation -> binding refused.
    results = fake.passing_real_capability_results(ds, profile, kernel.schema_corpus)
    for result in results:
        kernel.capability_repository.save(result)
    with pytest.raises(LLMEvaluationError):
        kernel.build_evaluation_binding(
            profile=profile, capability_results=results, attestation=attestation
        )
    binding = kernel.build_evaluation_binding(profile=profile, capability_results=results)
    driver = kernel.build_quality_driver(
        profile=profile, policy=kernel.request_budget_policy(profile),
        client=VLLMChatClient(base_url=BASE),
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding, run_id="no-attestation",
    )
    assert driver.evidence_kind == "test_double"  # direct transport alone is insufficient
    with pytest.raises(LLMEvaluationError):
        kernel.qualify_real_local_llm(
            profile=profile, driver=driver, evaluation_binding=binding, capability_results=results,
        )
    # A mission can never be qualified by a capability result lacking an attestation.
    from redteam_agent.errors import LLMCapabilityError

    fields = results[0].model_dump(mode="python")
    fields["server_attestation_digest"] = None
    fields.pop("result_digest")
    unattested = results[0].model_copy(update={
        "server_attestation_digest": None,
        "result_digest": ds.compute("llm_schema_capability_result_digest", fields),
    })
    with pytest.raises(LLMCapabilityError):
        kernel.capability_repository.save(unattested)
