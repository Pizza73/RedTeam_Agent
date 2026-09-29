"""Integration tests for the agent-quality-policy-v2 gate (SystemDesign §36.E1 / D11)."""

from __future__ import annotations

import pytest

import support_phase2 as fake
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AuthorizationKernelError, LLMEvaluationError
from redteam_agent.llm.budget import build_request_budget_policy
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.quality.corpus import build_agent_quality_corpus
from redteam_agent.quality.drivers import CompliantTestDoubleDriver, FaultyTestDoubleDriver
from redteam_agent.quality.evidence import QualityEvidenceRepository
from redteam_agent.quality.gate import not_run_report, run_agent_quality_gate
from redteam_agent.quality.models import (
    FAMILY_COUNT,
    TOTAL_RUNS,
    AgentQualityCorpus,
    QualityAttemptFailure,
    QualityRunObservation,
    RunDiagnostics,
    RunVerdict,
)
from redteam_agent.quality.oracle import QualityOracle
from redteam_agent.quality.runner import QualityRunner, real_llm_usage_blocking_reasons
from redteam_agent.storage.database import Database


def _corpus() -> tuple[AgentQualityCorpus, DigestService]:
    ds = DigestService()
    return build_agent_quality_corpus(ds), ds


def _runner(corpus: AgentQualityCorpus, ds: DigestService, driver) -> QualityRunner:
    return QualityRunner(corpus=corpus, oracle=QualityOracle(), driver=driver, digest_service=ds)


def test_corpus_is_ten_by_ten_and_deterministic() -> None:
    corpus, ds = _corpus()
    assert len(corpus.families) == FAMILY_COUNT
    assert all(len(f.fixtures) == 10 for f in corpus.families)
    assert len(corpus.all_fixtures()) == 100
    assert corpus.corpus_digest(ds) == build_agent_quality_corpus(ds).corpus_digest(ds)


def test_fixtures_within_family_are_semantically_distinct() -> None:
    corpus, _ = _corpus()
    for family in corpus.families:
        stimuli = [f.scenario_stimulus for f in family.fixtures]
        assert len(set(stimuli)) == len(stimuli)
        assert all(f.acceptance_criteria_ids for f in family.fixtures)


def test_compliant_test_double_reports_not_run_with_green_metrics() -> None:
    corpus, ds = _corpus()
    report = run_agent_quality_gate(corpus=corpus, digest_service=ds, driver=CompliantTestDoubleDriver())
    assert report.gate_status == "NOT_RUN"
    assert report.total_runs == TOTAL_RUNS
    assert report.evidence_kind == "test_double"
    assert report.expected_reach_rate == 1.0
    assert report.per_family_min_reach_rate == 1.0
    assert report.extraction_recall == 1.0
    assert report.scope_false_allow_count == 0
    assert report.pass_cubed_rate == 1.0
    assert report.acceptance_criteria_ids
    assert report.evaluation_binding_digest is None


def test_threshold_math_passes_on_compliant_verdicts() -> None:
    # Exercise the PASS threshold arithmetic using test_double evidence only; this never
    # sets the reported gate status to PASS for a test double.
    corpus, ds = _corpus()
    driver = CompliantTestDoubleDriver()
    oracle = QualityOracle()
    verdicts = [
        oracle.score(fixture, driver.drive(fixture, attempt))
        for fixture in corpus.all_fixtures()
        for attempt in range(3)
    ]
    status, reasons = _runner(corpus, ds, driver).evaluate_thresholds(verdicts)
    assert status == "PASS"
    assert reasons == ()


def test_threshold_math_fails_on_injected_defect() -> None:
    corpus, ds = _corpus()
    driver = FaultyTestDoubleDriver(inject="secret_leak")
    oracle = QualityOracle()
    verdicts = [
        oracle.score(fixture, driver.drive(fixture, attempt))
        for fixture in corpus.all_fixtures()
        for attempt in range(3)
    ]
    status, reasons = _runner(corpus, ds, driver).evaluate_thresholds(verdicts)
    assert status == "FAIL"
    assert reasons


def test_real_labeled_driver_without_binding_is_blocked() -> None:
    # A real-evidence label alone can never yield PASS: without an immutable evaluation
    # binding manifest the gate is BLOCKED (fail closed), never a fabricated pass.
    corpus, ds = _corpus()

    class _RealLabeled:
        @property
        def evidence_kind(self) -> str:
            return "real_local_llm"

        def drive(self, fixture, attempt_index):  # type: ignore[no-untyped-def]
            base = CompliantTestDoubleDriver().drive(fixture, attempt_index)
            return base.model_copy(update={"evidence_kind": "real_local_llm"})

    with pytest.raises(LLMEvaluationError):
        run_agent_quality_gate(corpus=corpus, digest_service=ds, driver=_RealLabeled())  # type: ignore[arg-type]


def test_incomplete_corpus_is_blocked() -> None:
    corpus, ds = _corpus()
    one_family = AgentQualityCorpus(corpus_version=corpus.corpus_version, families=(corpus.families[0],))
    report = run_agent_quality_gate(corpus=one_family, digest_service=ds, driver=CompliantTestDoubleDriver())
    assert report.gate_status == "BLOCKED"
    assert any("ten families" in r for r in report.blocking_reasons)


def test_rewritten_fixture_is_blocked() -> None:
    corpus, ds = _corpus()
    family = corpus.families[0]
    tampered_fixture = family.fixtures[0].model_copy(update={"title": "rewritten title"})
    tampered_family = family.model_copy(update={"fixtures": (tampered_fixture, *family.fixtures[1:])})
    tampered = corpus.model_copy(update={"families": (tampered_family, *corpus.families[1:])})
    report = run_agent_quality_gate(corpus=tampered, digest_service=ds, driver=CompliantTestDoubleDriver())
    assert report.gate_status == "BLOCKED"
    assert any("digest mismatch" in r for r in report.blocking_reasons)


def test_not_run_report_records_prerequisites() -> None:
    corpus, ds = _corpus()
    report = not_run_report(corpus=corpus, digest_service=ds, reason="no vLLM endpoint configured")
    assert report.gate_status == "NOT_RUN"
    assert report.total_runs == 0
    assert report.recall_denominator == 0
    assert len(report.external_prerequisites) >= 1
    assert report.acceptance_criteria_ids


def test_driver_exception_becomes_failed_run_not_dropped() -> None:
    corpus, ds = _corpus()

    class _Flaky:
        @property
        def evidence_kind(self) -> str:
            return "test_double"

        def drive(self, fixture, attempt_index):  # type: ignore[no-untyped-def]
            if fixture.family_id == 1 and attempt_index == 0:
                raise AuthorizationKernelError("model failure")
            return CompliantTestDoubleDriver().drive(fixture, attempt_index)

    report = run_agent_quality_gate(corpus=corpus, digest_service=ds, driver=_Flaky())  # type: ignore[arg-type]
    # Exactly 300 runs reported; the failed runs simply lower the reach rate.
    assert report.total_runs == TOTAL_RUNS
    assert report.expected_reach_rate < 1.0


def test_oracle_flags_each_injected_defect() -> None:
    corpus, ds = _corpus()
    oracle = QualityOracle()
    achieving = next(f for f in corpus.all_fixtures() if f.goal_expected_achieved)
    not_achieving = next(f for f in corpus.all_fixtures() if not f.goal_expected_achieved)
    for fixture, injection, attr in (
        (achieving, "scope_false_allow", "scope_false_allow"),
        (achieving, "secret_leak", "secret_leakage"),
        (not_achieving, "false_goal", "false_goal"),
        (achieving, "duplicate", "duplicate_side_effect"),
        (achieving, "prohibited", "scope_false_allow"),
        (achieving, "false_confirmed", "false_confirmed_fact"),
    ):
        obs = FaultyTestDoubleDriver(inject=injection).drive(fixture, 0)
        verdict = oracle.score(fixture, obs)
        assert getattr(verdict, attr) is True, injection


def test_oracle_flags_unexpected_human_wait_on_normal_fixture() -> None:
    corpus, ds = _corpus()
    oracle = QualityOracle()
    fixture = next(f for f in corpus.all_fixtures() if f.is_normal_run and not f.expected_human_gate)
    obs = FaultyTestDoubleDriver(inject="human_wait").drive(fixture, 0)
    assert oracle.score(fixture, obs).unexpected_human_wait is True


def test_oracle_rejects_wrong_fixture_observation() -> None:
    corpus, ds = _corpus()
    fixtures = corpus.all_fixtures()
    obs = CompliantTestDoubleDriver().drive(fixtures[1], 0)
    try:
        QualityOracle().score(fixtures[0], obs)
    except LLMEvaluationError:
        return
    raise AssertionError("oracle accepted an observation bound to another fixture")


def test_runner_rejects_driver_wrong_attempt() -> None:
    corpus, ds = _corpus()

    class _WrongAttempt:
        @property
        def evidence_kind(self) -> str:
            return "test_double"

        def drive(self, fixture, attempt_index):  # type: ignore[no-untyped-def]
            return CompliantTestDoubleDriver().drive(fixture, 0)  # always attempt 0

    runner = QualityRunner(corpus=corpus, oracle=QualityOracle(), driver=_WrongAttempt(),  # type: ignore[arg-type]
                           digest_service=ds)
    try:
        runner.run()
    except LLMEvaluationError:
        return
    raise AssertionError("runner accepted a mismatched attempt index")


def test_local_llm_scenario_double_via_fake_server_is_test_double() -> None:
    corpus, ds = _corpus()
    profile = fake.local_profile(ds)
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response(fake.VALID_PLANNER_OUTPUT)))
    driver = fake.LocalLLMScenarioTestDouble(profile=profile, policy=policy, client=client)
    obs = driver.drive(corpus.all_fixtures()[0], 0)
    assert isinstance(obs, QualityRunObservation)
    assert obs.evidence_kind == "test_double"
    report = run_agent_quality_gate(corpus=corpus, digest_service=ds, driver=driver)
    assert report.gate_status == "NOT_RUN"


def test_scenario_double_flags_out_of_scope_selection() -> None:
    corpus, ds = _corpus()
    profile = fake.local_profile(ds)
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    rogue_action = fake.VALID_PLANNER_ACTION.replace("f1-act-a", "rogue-tool")
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response(rogue_action)))
    driver = fake.LocalLLMScenarioTestDouble(profile=profile, policy=policy, client=client)
    fixture = next(f for f in corpus.all_fixtures() if f.family_id == 2)  # allowed ids are f2-act-*
    verdict = QualityOracle().score(fixture, driver.drive(fixture, 0))
    assert verdict.scope_false_allow is True


def _binding(
    ds: DigestService,
    corpus: AgentQualityCorpus,
    *,
    corpus_digest: str,
    server_attestation_digest: str | None = None,
) -> object:
    from redteam_agent.quality.models import EvaluationBinding, build_run_seeds

    fields = {
        "commit_id": "deadbeef",
        "profile_digest": "pd", "model_hash": "mh", "tokenizer_revision": "tok-1",
        "chat_template_digest": None, "runtime_version": "vllm-test-0.1", "output_mode": "native_json_schema",
        "schema_capability_corpus_version": "schema-capability-corpus-v2",
        "schema_capability_corpus_digest": "scd",
        "agent_quality_corpus_version": corpus.corpus_version,
        "agent_quality_corpus_digest": corpus_digest,
        "schema_digests": (("planner_output", "sd"),),
        "prompt_set_digests": (("planner_output", "psd"),),
        "contract_digest": "cd", "catalog_digest": "catd",
        "gateway_budget_policy_digest": "gbpd", "dependency_lock_digest": "dld",
        "capability_result_digests": ("crd-1",),
        "server_attestation_digest": server_attestation_digest,
        "run_seeds": build_run_seeds(corpus),
    }
    digest = ds.compute("agent_quality_evaluation_binding_digest", fields)
    return EvaluationBinding(**fields, binding_digest=digest)  # type: ignore[arg-type]


def _verdict(*, diagnostics: RunDiagnostics) -> RunVerdict:
    return RunVerdict(
        fixture_id="f", attempt_index=0, family_id=1, reached_expected=True,
        scope_false_allow=False, approval_bypass=False, secret_leakage=False,
        duplicate_side_effect=False, false_confirmed_fact=False, false_goal=False,
        unexpected_human_wait=False, hard_limit_ok=True, is_normal_run=True,
        recall_numerator=1, recall_denominator=1, diagnostics=diagnostics,
    )


def test_real_llm_usage_blocking_reasons_is_clean_with_recorded_usage() -> None:
    verdict = _verdict(diagnostics=RunDiagnostics(llm_calls=4, prompt_tokens=400, completion_tokens=80))
    assert real_llm_usage_blocking_reasons([verdict]) == ()


def test_real_llm_usage_blocking_reasons_flags_missing_usage() -> None:
    verdict = _verdict(
        diagnostics=RunDiagnostics(llm_calls=4, prompt_tokens=300, completion_tokens=60, usage_missing_count=1)
    )
    reasons = real_llm_usage_blocking_reasons([verdict])
    assert reasons
    assert any("missing" in reason for reason in reasons)


def test_real_llm_usage_blocking_reasons_flags_calls_with_zero_tokens() -> None:
    # Reproduces the exact defect this closes: real LLM calls happened but the
    # aggregate token usage is all-zero (the original phase 2 report's shape).
    verdict = _verdict(diagnostics=RunDiagnostics(llm_calls=1284))
    reasons = real_llm_usage_blocking_reasons([verdict])
    assert reasons
    assert any("zero prompt/completion tokens" in reason for reason in reasons)


def test_real_llm_usage_blocking_reasons_allows_zero_calls() -> None:
    assert real_llm_usage_blocking_reasons([_verdict(diagnostics=RunDiagnostics())]) == ()


def test_real_labeled_driver_with_wrong_binding_corpus_is_blocked() -> None:
    corpus, ds = _corpus()

    class _RealLabeled:
        @property
        def evidence_kind(self) -> str:
            return "real_local_llm"

        def drive(self, fixture, attempt_index):  # type: ignore[no-untyped-def]
            base = CompliantTestDoubleDriver().drive(fixture, attempt_index)
            return base.model_copy(update={"evidence_kind": "real_local_llm"})

    binding = _binding(ds, corpus, corpus_digest="wrong-digest")
    with pytest.raises(LLMEvaluationError):
        run_agent_quality_gate(
            corpus=corpus, digest_service=ds, driver=_RealLabeled(),  # type: ignore[arg-type]
            evaluation_binding=binding,  # type: ignore[arg-type]
        )


def test_fixed_300_run_gate_cannot_pass_when_a_failed_runs_usage_is_missing() -> None:
    """End-to-end proof that the fix closing the evidence-integrity gap in commit
    cdab8ec holds at the gate: a real-local-LLM qualification with 299 compliant runs
    and one run that fails *after* consuming a real LLM network attempt with missing
    server usage can never report ``PASS``.

    Before the fix, ``QualityRunner`` replaced that failed run's diagnostics with a
    fabricated all-zero default, so its missing usage was invisible to
    :func:`real_llm_usage_blocking_reasons` and the qualification could pass with a
    silently unaccounted real attempt.
    """
    corpus, ds = _corpus()
    sink = QualityEvidenceRepository(database=Database(":memory:"), digest_service=ds)
    binding = _binding(
        ds, corpus, corpus_digest=corpus.corpus_digest(ds), server_attestation_digest="sad-1"
    )
    # The binding fields this test cares about (attestation / capability digests) are
    # bound to the driver below so `_binding_blocking_reasons` accepts it.
    failing = corpus.all_fixtures()[0]
    failed_diagnostics = RunDiagnostics(
        llm_calls=1, prompt_tokens=12, completion_tokens=4, usage_missing_count=1
    )

    class _RealAttemptDriver:
        """Stands in for :class:`WorkflowBackedQualityDriver`: every run drives a real
        Phase 1 workflow attempt; one of them fails after the model call, exactly as a
        real vLLM output-validation exhaustion would.
        """

        @property
        def evidence_kind(self) -> str:
            # Never self-declares real evidence: this test forces the runner's
            # evidence kind directly below, the same way `derive_driver_evidence_kind`
            # would for a real, composition-owned workflow driver.
            return "test_double"

        @property
        def evaluation_binding_digest(self) -> str:
            return binding.binding_digest  # type: ignore[attr-defined]

        @property
        def server_attestation_digest(self) -> str:
            return binding.server_attestation_digest  # type: ignore[attr-defined]

        def drive(self, fixture, attempt_index):  # type: ignore[no-untyped-def]
            if fixture.fixture_id == failing.fixture_id and attempt_index == 0:
                raise QualityAttemptFailure(
                    original_exception_type="RuntimeError", diagnostics=failed_diagnostics
                )
            base = CompliantTestDoubleDriver().drive(fixture, attempt_index)
            return base.model_copy(update={"evidence_kind": "real_local_llm"})

    runner = QualityRunner(
        corpus=corpus, oracle=QualityOracle(), driver=_RealAttemptDriver(),  # type: ignore[arg-type]
        digest_service=ds, evaluation_binding=binding,  # type: ignore[arg-type]
        expected_capability_result_digests=binding.capability_result_digests,  # type: ignore[attr-defined]
        evidence_sink=sink, evaluation_id="eval-real-attempt-failure",
    )
    assert runner._evidence_kind == "test_double"
    runner._evidence_kind = "real_local_llm"

    report = runner.run()

    assert report.total_runs == TOTAL_RUNS
    assert report.gate_status != "PASS"
    assert report.gate_status == "BLOCKED"
    assert any("missing" in reason for reason in report.blocking_reasons)
    # The durable evidence for the failed run carries its exact real-attempt
    # diagnostics -- never a fabricated zero.
    stored = sink.runs("eval-real-attempt-failure")
    failed_record = next(
        r for r in stored if r.fixture_id == failing.fixture_id and r.attempt_index == 0
    )
    assert failed_record.failure == "RuntimeError"
    assert failed_record.observation.diagnostics.llm_calls == 1
    assert failed_record.observation.diagnostics.usage_missing_count == 1
    assert failed_record.verdict.diagnostics.usage_missing_count == 1
