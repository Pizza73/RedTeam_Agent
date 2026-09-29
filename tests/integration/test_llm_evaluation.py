"""Tests for the Local Evaluation Entry Point and live capability probe (§6.2/§6.3)."""

from __future__ import annotations

import pytest

import support_phase2 as fake
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMProfileMismatchError
from redteam_agent.llm.capability_corpus import build_schema_capability_corpus
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.llm.evaluation import (
    LocalEvaluationHarness,
    SyntheticCapabilityProbe,
    assert_endpoint_matches_profile,
)


def _valid_body_for(schema_name: str) -> str:
    corpus = build_schema_capability_corpus()
    for case in corpus.cases_for(schema_name):
        if case.expectation == "accept" and case.reference_output is not None:
            return case.reference_output
    raise AssertionError("no valid body")


def _accept_case(corpus, schema_name: str):
    return next(c for c in corpus.cases_for(schema_name) if c.expectation == "accept")


def test_synthetic_probe_is_always_test_double() -> None:
    assert SyntheticCapabilityProbe().evidence_kind == "test_double"


def test_live_probe_accept_and_reject_paths() -> None:
    ds = DigestService()
    profile = fake.local_profile(ds)
    corpus = build_schema_capability_corpus()

    accept_case = _accept_case(corpus, "analysis_result")
    reject_case = next(c for c in corpus.cases_for("analysis_result") if c.expectation == "reject")

    valid = _valid_body_for("analysis_result")
    accept_client = VLLMChatClient(base_url="http://127.0.0.1:8000/v1",
                                   transport=fake.transport_returning(fake.native_response(valid)))
    probe = fake.live_probe(ds, profile, client=accept_client)
    assert probe.evidence_kind == "test_double"
    assert probe.probe(accept_case).kind == "output"
    # A boundary-reject case replays the fixed malformed body with no network I/O.
    assert probe.probe(reject_case).raw is not None


def test_live_probe_requires_endpoint_profile_match() -> None:
    # Endpoint/profile binding is mandatory: constructing a live probe against an endpoint
    # serving a different model fails closed.
    ds = DigestService()
    profile = fake.local_profile(ds)  # model_name == "qwen-test"
    client = VLLMChatClient(base_url="http://127.0.0.1:8000/v1",
                            transport=fake.transport_returning(fake.native_response("{}")))
    wrong_endpoint = LocalLLMEndpointConfig(model="other-model", base_url="http://127.0.0.1:8000/v1")
    with pytest.raises(LLMProfileMismatchError):
        fake.live_probe(ds, profile, client=client, endpoint=wrong_endpoint)


def test_live_probe_timeout_only_on_real_timeout() -> None:
    ds = DigestService()
    profile = fake.local_profile(ds)
    corpus = build_schema_capability_corpus()
    timeout_case = next(c for c in corpus.cases_for("analysis_result") if c.expectation == "timeout")

    timeout_client = VLLMChatClient(base_url="http://127.0.0.1:8000/v1", transport=fake.transport_timeout())
    probe = fake.live_probe(ds, profile, client=timeout_client)
    assert probe.probe(timeout_case).kind == "timeout"


def test_live_probe_cancel_requires_genuine_in_flight_cancellation() -> None:
    ds = DigestService()
    profile = fake.local_profile(ds)
    corpus = build_schema_capability_corpus()
    cancel_case = next(c for c in corpus.cases_for("analysis_result") if c.expectation == "cancel")
    valid = _valid_body_for("analysis_result")

    # Without a controllable in-flight cancellation, the case is unsupported (fail closed).
    plain_client = VLLMChatClient(base_url="http://127.0.0.1:8000/v1",
                                  transport=fake.transport_returning(fake.native_response(valid)))
    unsupported = fake.live_probe(ds, profile, client=plain_client)
    assert unsupported.probe(cancel_case).kind == "cancel_unsupported"

    # With a genuine in-flight cancellation, the late response is discarded -> cancelled.
    cancellation = fake.FakeInFlightCancellation()
    cancelling_client = VLLMChatClient(
        base_url="http://127.0.0.1:8000/v1",
        transport=cancellation.transport(fake.native_response(valid)),
    )
    genuine = fake.live_probe(ds, profile, client=cancelling_client, cancellation=cancellation)
    assert genuine.probe(cancel_case).kind == "cancelled"


def test_harness_live_probe_generation_and_boundary_are_honest() -> None:
    ds = DigestService()
    profile = fake.local_profile(ds)
    corpus = build_schema_capability_corpus()
    harness = LocalEvaluationHarness(digest_service=ds, corpus=corpus)

    def handler(request):  # type: ignore[no-untyped-def]
        body = request.content.decode("utf-8")
        for schema in ("planner_output", "execution_plan_proposal", "analysis_result"):
            if schema in body:
                return fake.native_response(_valid_body_for(schema))
        return fake.native_response(_valid_body_for("analysis_result"))

    client = VLLMChatClient(base_url="http://127.0.0.1:8000/v1", transport=fake.CountingTransport(handler))
    probe = fake.live_probe(ds, profile, client=client)
    # Evidence is real_local_llm (the trusted live path), but a synchronous fake server
    # without cancellation cannot exercise in-flight cancellation, so the result is
    # honestly NOT a pass (fail closed) rather than a fabricated one.
    results = harness.run_capability(profile=profile, probe=probe)
    for result in results:
        assert result.evidence_kind == "test_double"
        assert result.unsafe_boundary_acceptances == 0
        assert result.cancellation_failures == result.cancel_case_count
        assert result.passed is False


def test_case_aware_server_remains_test_double_evidence() -> None:
    ds = DigestService()
    profile = fake.local_profile(ds)
    corpus = build_schema_capability_corpus()
    results = fake.passing_real_capability_results(ds, profile, corpus)
    assert len(results) == 3
    for result in results:
        assert result.evidence_kind == "real_local_llm"  # explicitly forged hostile row helper
        assert result.passed is True
        assert result.valid_within_retry_budget == result.sample_count


def test_endpoint_model_must_match_profile() -> None:
    ds = DigestService()
    profile = fake.local_profile(ds)  # model_name == "qwen-test"
    ok = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    assert_endpoint_matches_profile(ok, profile)
    wrong = LocalLLMEndpointConfig(model="other-model", base_url="http://127.0.0.1:8000/v1")
    with pytest.raises(LLMProfileMismatchError):
        assert_endpoint_matches_profile(wrong, profile)


def test_live_probe_reference_is_untouched_when_synthetic() -> None:
    # Sanity: the synthetic probe still replays the fixed corpus reference bodies.
    corpus = build_schema_capability_corpus()
    accept_case = _accept_case(corpus, "planner_output")
    assert SyntheticCapabilityProbe().probe(accept_case).raw == accept_case.reference_output
