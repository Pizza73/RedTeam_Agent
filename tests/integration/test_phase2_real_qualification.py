"""The reachable formal real-local-LLM 300-run qualification path (SystemDesign §36.E1).

These tests prove that the formal path rejects injected transports, forged provenance,
wrong bindings and altered seeds before network access. A real PASS requires the
external vLLM prerequisites and is not fabricated in the test suite.
"""

from __future__ import annotations

import json

import pytest

import support_phase2 as fake
from redteam_agent.composition.phase2 import build_phase2_kernel
from redteam_agent.errors import LLMCapabilityError, LLMEvaluationError
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.llm.evaluation import SyntheticCapabilityProbe
from redteam_agent.quality.drivers import CompliantTestDoubleDriver
from redteam_agent.quality.models import EvaluationBinding


def _kernel_with_endpoint():
    endpoint = LocalLLMEndpointConfig(model="qwen-test", base_url="http://127.0.0.1:8000/v1")
    kernel = build_phase2_kernel(
        endpoint=endpoint,
        qualification_commit_id="a" * 40,
        dependency_lock_digest="b" * 64,
    )
    ds = kernel.phase1.phase0c.phase0b.phase0a.digest_service
    profile = fake.local_profile(ds)
    return kernel, ds, profile


def _real_bundle(kernel, ds, profile):
    results = fake.passing_real_capability_results(ds, profile, kernel.schema_corpus)
    for result in results:
        kernel.capability_repository.save(result)
    binding = kernel.build_evaluation_binding(
        profile=profile, capability_results=results
    )
    return results, binding


def test_formal_path_rejects_real_label_on_test_harness() -> None:
    kernel, ds, profile = _kernel_with_endpoint()
    results, binding = _real_bundle(kernel, ds, profile)
    with pytest.raises(LLMEvaluationError):
        kernel.qualify_real_local_llm(
            profile=profile, driver=fake.RealEvidenceHarnessDriver(),
            evaluation_binding=binding, capability_results=results,
        )


def test_formal_path_rejects_test_double_driver() -> None:
    kernel, ds, profile = _kernel_with_endpoint()
    results, binding = _real_bundle(kernel, ds, profile)
    # A test-double driver can never be a real qualification (fail closed).
    with pytest.raises(LLMEvaluationError):
        kernel.qualify_real_local_llm(
            profile=profile, driver=CompliantTestDoubleDriver(),
            evaluation_binding=binding, capability_results=results,
        )


def test_formal_path_rejects_test_double_capability_results() -> None:
    # Production APIs cannot relabel a test double as real: real-evidence driver + binding
    # but test-double capability evidence is rejected.
    kernel, ds, profile = _kernel_with_endpoint()
    test_double_results = kernel.run_capability_evaluation(
        profile=profile, probe=SyntheticCapabilityProbe()
    )
    real_results, binding = _real_bundle(kernel, ds, profile)
    with pytest.raises(LLMEvaluationError):
        kernel.qualify_real_local_llm(
            profile=profile, driver=fake.RealEvidenceHarnessDriver(),
            evaluation_binding=binding, capability_results=test_double_results,
        )


def test_formal_path_rejects_relabeled_test_double_observations() -> None:
    # A driver that *claims* real but yields test-double observations is caught by the
    # runner's per-observation evidence check.
    kernel, ds, profile = _kernel_with_endpoint()
    results, binding = _real_bundle(kernel, ds, profile)

    class _MislabeledDriver:
        evidence_kind = "real_local_llm"

        def drive(self, fixture, attempt_index):  # type: ignore[no-untyped-def]
            return CompliantTestDoubleDriver().drive(fixture, attempt_index)  # observation says test_double

    with pytest.raises(LLMEvaluationError):
        kernel.qualify_real_local_llm(
            profile=profile, driver=_MislabeledDriver(),  # type: ignore[arg-type]
            evaluation_binding=binding, capability_results=results,
        )


def test_no_endpoint_host_reports_not_run() -> None:
    # On a host with no configured vLLM endpoint, the formal path honestly returns
    # NOT_RUN — never a fabricated PASS.
    kernel, ds, profile = _kernel_with_endpoint()
    results, binding = _real_bundle(kernel, ds, profile)
    no_endpoint = build_phase2_kernel()  # endpoint is None here
    report = no_endpoint.qualify_real_local_llm(
        profile=profile, driver=fake.RealEvidenceHarnessDriver(),
        evaluation_binding=binding, capability_results=results,
    )
    assert report.gate_status == "NOT_RUN"
    assert report.external_prerequisites


def test_kernel_live_probe_persists_real_capability() -> None:
    # The kernel's production wiring builds a live probe over the evaluation gateway and
    # persists only real_local_llm capability results.
    kernel, ds, profile = _kernel_with_endpoint()
    kernel.phase1.phase0c.phase0b.phase0a.profile_repository.save(profile)
    server = fake.CaseAwareCapabilityServer(kernel.schema_corpus)
    from redteam_agent.llm.client import VLLMChatClient

    client = VLLMChatClient(base_url="http://127.0.0.1:8000/v1", transport=server.transport())
    policy = kernel.request_budget_policy(profile)
    probe = kernel.build_live_capability_probe(
        profile=profile, policy=policy, client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        run_id="kernel-eval", cancellation=server,
    )
    results = kernel.run_capability_evaluation(profile=profile, probe=probe)
    assert all(r.evidence_kind == "test_double" and r.passed for r in results)
    # An injected fake transport is never persisted and cannot qualify a mission.
    with pytest.raises(LLMCapabilityError):
        kernel.capability_verifier.verify_mission_capability(
            profile, _revision_stub(profile)
        )


def _revision_stub(profile):
    class _Revision:
        llm_profile_digest = profile.profile_digest

    return _Revision()


def test_binding_builder_rejects_capability_results_for_other_profile() -> None:
    kernel, ds, profile = _kernel_with_endpoint()
    _real_bundle(kernel, ds, profile)
    other_profile = fake.local_profile(ds, profile_revision="other-rev")
    other_results = fake.passing_real_capability_results(ds, other_profile, kernel.schema_corpus)
    for result in other_results:
        kernel.capability_repository.save(result)
    with pytest.raises(LLMEvaluationError):
        kernel.build_evaluation_binding(
            profile=profile, capability_results=other_results
        )


def test_binding_builder_rejects_stale_capability_prompt_revision() -> None:
    kernel, ds, profile = _kernel_with_endpoint()
    results, _ = _real_bundle(kernel, ds, profile)
    original = results[0]
    fields = original.model_dump(mode="python")
    fields["prompt_set_digest"] = "f" * 64
    fields.pop("result_digest")
    stale = original.model_copy(
        update={
            "prompt_set_digest": fields["prompt_set_digest"],
            "result_digest": ds.compute("llm_schema_capability_result_digest", fields),
        }
    )
    with pytest.raises(LLMEvaluationError, match="stale"):
        kernel.build_evaluation_binding(
            profile=profile,
            capability_results=(stale, *results[1:]),
        )


def test_formal_path_blocks_tampered_seed_before_network() -> None:
    kernel, ds, profile = _kernel_with_endpoint()
    results, binding = _real_bundle(kernel, ds, profile)
    fields = binding.model_dump(mode="python")
    seeds = list(binding.run_seeds)
    first = seeds[0]
    seeds[0] = (first[0], first[1], first[2] + ":changed")
    fields["run_seeds"] = tuple(seeds)
    fields.pop("binding_digest")
    digest = ds.compute("agent_quality_evaluation_binding_digest", fields)
    changed = EvaluationBinding(**fields, binding_digest=digest)  # type: ignore[arg-type]
    driver = kernel.build_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=VLLMChatClient(base_url="http://127.0.0.1:8000/v1"),
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=changed,
        run_id="must-not-connect",
    )
    report = kernel.qualify_real_local_llm(
        profile=profile,
        driver=driver,
        evaluation_binding=changed,
        capability_results=results,
    )
    assert report.gate_status == "BLOCKED"
    assert report.total_runs == 0
    assert any("run_seeds" in reason for reason in report.blocking_reasons)


def test_quality_driver_with_injected_transport_is_test_double() -> None:
    kernel, ds, profile = _kernel_with_endpoint()
    results, binding = _real_bundle(kernel, ds, profile)
    client = VLLMChatClient(
        base_url="http://127.0.0.1:8000/v1",
        transport=fake.transport_returning(fake.native_response("{}")),
    )
    driver = kernel.build_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        run_id="mock-quality",
    )
    assert driver.evidence_kind == "test_double"
    with pytest.raises(LLMEvaluationError):
        kernel.qualify_real_local_llm(
            profile=profile,
            driver=driver,
            evaluation_binding=binding,
            capability_results=results,
        )


def test_quality_driver_routes_planner_and_analyzer_through_gateway() -> None:
    kernel, ds, profile = _kernel_with_endpoint()
    _, binding = _real_bundle(kernel, ds, profile)
    fixture = kernel.quality_corpus.all_fixtures()[0]
    analyzer_outputs = []
    for fact in fixture.extraction_target_facts:
        body = json.loads(fake.VALID_ANALYSIS_OUTPUT)
        body["object_ref"] = fact
        analyzer_outputs.append(fake.native_response(json.dumps(body)))
    client = VLLMChatClient(
        base_url="http://127.0.0.1:8000/v1",
        transport=fake.transport_sequence(
            [
                fake.native_response(fake.VALID_PLANNER_ACTION),
                fake.native_response(fake.VALID_PLANNER_ACTION.replace("f1-act-a", "f1-act-b")),
                *analyzer_outputs,
            ]
        ),
    )
    driver = kernel.build_quality_driver(
        profile=profile,
        policy=kernel.request_budget_policy(profile),
        client=client,
        token_counter=fake.ApproxChatTokenCounter(profile.tokenizer_revision),
        evaluation_binding=binding,
        run_id="quality-path",
    )
    observation = driver.drive(fixture, 0)
    assert observation.evidence_kind == "test_double"
    assert observation.extracted_facts == fixture.extraction_target_facts
