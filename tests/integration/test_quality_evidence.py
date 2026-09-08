"""D11 durable evidence and diagnostics (SystemDesign §36.E1 / §37.1 D11 row 2)."""

from __future__ import annotations

import json

import pytest

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    AuthorizationKernelError,
    DigestIntegrityError,
    LLMEvaluationError,
    RepositoryIntegrityError,
)
from redteam_agent.quality.corpus import build_agent_quality_corpus
from redteam_agent.quality.drivers import CompliantTestDoubleDriver
from redteam_agent.quality.evidence import QualityEvidenceRepository, run_row_key
from redteam_agent.quality.gate import not_run_report, run_agent_quality_gate
from redteam_agent.quality.models import (
    TOTAL_RUNS,
    QualityDiagnosticsSummary,
    QualityFixture,
    QualityRunObservation,
    RunDiagnostics,
)
from redteam_agent.quality.oracle import QualityOracle
from redteam_agent.quality.runner import QualityRunner
from redteam_agent.storage.database import Database


def _setup():  # type: ignore[no-untyped-def]
    ds = DigestService()
    corpus = build_agent_quality_corpus(ds)
    db = Database(":memory:")
    return ds, corpus, db, QualityEvidenceRepository(database=db, digest_service=ds)


class _Flaky:
    """Fails one run with an exception and returns diagnostics on the others."""

    @property
    def evidence_kind(self) -> str:
        return "test_double"

    def drive(self, fixture: QualityFixture, attempt_index: int) -> QualityRunObservation:
        if fixture.family_id == 2 and attempt_index == 1:
            raise AuthorizationKernelError("model failure")
        base = CompliantTestDoubleDriver().drive(fixture, attempt_index)
        diagnostics = RunDiagnostics(
            tool_dispatches=2, tool_failures=1, action_attempts=3, invalid_actions=1,
            llm_calls=4, validation_errors=1, retries=1, prompt_tokens=100,
            completion_tokens=20, outcome_unknown_count=1 if attempt_index == 0 else 0,
            checkpoint_recovery_attempts=1, checkpoint_recovery_successes=1,
            human_gate_reason="APPROVAL_REQUIRED" if base.reached_human_gate else None,
            planner_latencies_ms=(10, 30), analyzer_latencies_ms=(5,),
        )
        return base.model_copy(update={"diagnostics": diagnostics})


def test_every_attempted_run_is_persisted_including_exceptions() -> None:
    ds, corpus, db, sink = _setup()
    report = run_agent_quality_gate(
        corpus=corpus, digest_service=ds, driver=_Flaky(),  # type: ignore[arg-type]
        evidence_sink=sink, evaluation_id="eval-1",
    )
    assert report.total_runs == TOTAL_RUNS
    assert report.persisted_run_count == TOTAL_RUNS
    assert report.evaluation_id == "eval-1"
    records = sink.verify_complete("eval-1")
    # Exact 300-run identity, nothing dropped or duplicated.
    assert [(r.fixture_id, r.attempt_index) for r in records] == [
        (f.fixture_id, a) for f in corpus.all_fixtures() for a in range(3)
    ]
    failed = [r for r in records if r.failure is not None]
    assert len(failed) == 10
    assert all(r.failure == "AuthorizationKernelError" for r in failed)
    assert all(r.verdict.run_failed and not r.verdict.reached_expected for r in failed)
    assert all(r.observation.terminal_state == "no_candidate_stop" for r in failed)
    ok = [r for r in records if r.failure is None]
    assert all(r.verdict.reached_expected and not r.verdict.run_failed for r in ok)
    # Every record binds its inputs, digests and oracle verdict.
    first = records[0]
    assert first.fixture_digest == corpus.all_fixtures()[0].fixture_digest
    assert first.corpus_digest == corpus.corpus_digest(ds)
    assert first.evidence_kind == "test_double"
    assert first.seed is None and first.evaluation_binding_digest is None
    ds.verify("agent_quality_run_input_digest", {
        "fixture_id": first.fixture_id, "fixture_digest": first.fixture_digest,
        "attempt_index": 0, "seed": None,
    }, first.input_digest)
    # The aggregate report is persisted and re-verifies.
    stored = sink.report("eval-1")
    assert stored is not None and stored.report_digest == report.report_digest
    assert report.diagnostics.failed_run_count == 10


def test_report_diagnostics_are_aggregated_and_split_by_input_kind() -> None:
    ds, corpus, db, sink = _setup()
    report = run_agent_quality_gate(
        corpus=corpus, digest_service=ds, driver=_Flaky(),  # type: ignore[arg-type]
        evidence_sink=sink, evaluation_id="eval-2",
    )
    d = report.diagnostics
    good = TOTAL_RUNS - 10
    assert d.success_count == good and d.success_rate == pytest.approx(good / TOTAL_RUNS)
    assert d.mean_iterations > 0 and d.p95_iterations >= 1
    assert d.tool_dispatch_count == 2 * good and d.tool_failure_rate == pytest.approx(0.5)
    assert d.invalid_action_rate == pytest.approx(1 / 3)
    assert d.validation_error_rate == pytest.approx(0.25) and d.llm_call_count == 4 * good
    assert d.extraction_precision == 1.0 and d.precision_denominator > 0
    assert d.extraction_recall == report.extraction_recall
    assert d.outcome_unknown_count > 0 and 0.0 < d.outcome_unknown_rate < 1.0
    assert d.checkpoint_recovery_rate == 1.0
    assert d.human_gate_count == sum(
        3 for f in corpus.all_fixtures() if f.expected_human_gate
    )
    assert dict(d.human_gate_reasons).get("APPROVAL_REQUIRED") == d.human_gate_count
    assert d.planner_p50_latency_ms == 10 and d.planner_p95_latency_ms == 30
    assert d.analyzer_p50_latency_ms == 5 and d.analyzer_p95_latency_ms == 5
    assert d.total_tokens == 120 * good and d.retry_count == good
    # Normal vs untrusted are reported separately and jointly cover all runs.
    untrusted = sum(3 for f in corpus.all_fixtures() if f.untrusted_input)
    assert d.untrusted_run_count == untrusted and untrusted > 0
    assert d.normal_run_count == TOTAL_RUNS - untrusted
    assert d.normal_safety_rate == 1.0 and d.untrusted_safety_rate == 1.0
    assert 0.0 < d.normal_achievement_rate <= 1.0
    # Family 2 carries the failed runs; its rate is reported separately from the other kind.
    failed_kind = corpus.families[1].fixtures[0].untrusted_input
    failed_rate = d.untrusted_achievement_rate if failed_kind else d.normal_achievement_rate
    other_rate = d.normal_achievement_rate if failed_kind else d.untrusted_achievement_rate
    assert failed_rate < 1.0 and other_rate == 1.0
    # Normative thresholds / pass^3 / pass@3 are untouched by diagnostics.
    assert report.gate_status == "NOT_RUN"
    assert report.pass_cubed_rate == pytest.approx(0.9)
    assert report.pass_at_three_rate == 1.0


def test_not_run_report_has_zero_diagnostics() -> None:
    ds, corpus, _, _ = _setup()
    report = not_run_report(corpus=corpus, digest_service=ds, reason="no endpoint")
    assert report.diagnostics == QualityDiagnosticsSummary()
    assert report.evaluation_id is None and report.persisted_run_count == 0
    ds.verify(
        "agent_quality_report_digest",
        {k: v for k, v in report.model_dump(mode="python").items() if k != "report_digest"},
        report.report_digest,
    )


def test_persistence_is_optional_for_test_doubles() -> None:
    ds, corpus, _, _ = _setup()
    report = run_agent_quality_gate(corpus=corpus, digest_service=ds, driver=CompliantTestDoubleDriver())
    assert report.persisted_run_count == 0 and report.evaluation_id is None
    assert report.gate_status == "NOT_RUN"


def test_sink_requires_evaluation_id() -> None:
    ds, corpus, _, sink = _setup()
    with pytest.raises(LLMEvaluationError):
        QualityRunner(
            corpus=corpus, oracle=QualityOracle(), driver=CompliantTestDoubleDriver(),
            digest_service=ds, evidence_sink=sink,
        )


def test_stored_run_cannot_be_overwritten_and_tampering_is_detected() -> None:
    ds, corpus, db, sink = _setup()
    run_agent_quality_gate(
        corpus=corpus, digest_service=ds, driver=CompliantTestDoubleDriver(),
        evidence_sink=sink, evaluation_id="eval-3",
    )
    # A second qualification under the same id with different results is rejected.
    with pytest.raises(RepositoryIntegrityError):
        run_agent_quality_gate(
            corpus=corpus, digest_service=ds, driver=_Flaky(),  # type: ignore[arg-type]
            evidence_sink=sink, evaluation_id="eval-3",
        )
    # Re-appending identical evidence is a no-op, and the stored set still verifies.
    assert len(sink.verify_complete("eval-3")) == TOTAL_RUNS
    # Payload tampering (with a re-sealed row) fails the catalog digest on read.
    key = run_row_key("eval-3", 7)
    raw = db.get("agent_quality_run", key)
    assert raw is not None
    payload = json.loads(raw)
    payload["verdict"]["reached_expected"] = not payload["verdict"]["reached_expected"]
    db.overwrite("agent_quality_run", key, json.dumps(payload))
    with pytest.raises(DigestIntegrityError):
        sink.runs("eval-3")


def test_missing_stored_run_blocks_completeness() -> None:
    ds, corpus, db, sink = _setup()
    run_agent_quality_gate(
        corpus=corpus, digest_service=ds, driver=CompliantTestDoubleDriver(),
        evidence_sink=sink, evaluation_id="eval-4",
    )
    db.connection.execute(
        "DELETE FROM kv_store WHERE namespace = ? AND key = ?",
        ("agent_quality_run", run_row_key("eval-4", 299)),
    )
    with pytest.raises(RepositoryIntegrityError):
        sink.verify_complete("eval-4")


def test_real_pass_is_blocked_without_durable_storage() -> None:
    """Threshold-passing real evidence is BLOCKED when no evidence sink is bound."""
    ds, corpus, _, sink = _setup()
    verdicts = [
        QualityOracle().score(f, CompliantTestDoubleDriver().drive(f, a))
        for f in corpus.all_fixtures() for a in range(3)
    ]

    class _NoSink(QualityRunner):
        def _gate(self, verdicts):  # type: ignore[no-untyped-def, override]
            return "PASS", ()

    runner = _NoSink(
        corpus=corpus, oracle=QualityOracle(), driver=CompliantTestDoubleDriver(), digest_service=ds
    )
    report = runner._finish(verdicts=tuple(verdicts), gate_status="PASS", blocking_reasons=())
    assert report.gate_status == "BLOCKED"
    assert any("durable evidence sink" in r for r in report.blocking_reasons)
    # With a sink but an incomplete durable set it is still BLOCKED.
    with_sink = _NoSink(
        corpus=corpus, oracle=QualityOracle(), driver=CompliantTestDoubleDriver(),
        digest_service=ds, evidence_sink=sink, evaluation_id="eval-5",
    )
    report = with_sink._finish(verdicts=tuple(verdicts), gate_status="PASS", blocking_reasons=())
    assert report.gate_status == "BLOCKED"
    assert report.persisted_run_count == 0
    assert any("fixed 300 runs" in r for r in report.blocking_reasons)
    assert sink.report("eval-5") is not None


def test_persistence_failure_propagates_instead_of_dropping_evidence() -> None:
    ds, corpus, db, sink = _setup()

    class _Broken(QualityEvidenceRepository):
        def append_run(self, record):  # type: ignore[no-untyped-def, override]
            raise RepositoryIntegrityError("disk full")

    with pytest.raises(RepositoryIntegrityError):
        run_agent_quality_gate(
            corpus=corpus, digest_service=ds, driver=CompliantTestDoubleDriver(),
            evidence_sink=_Broken(database=db, digest_service=ds), evaluation_id="eval-6",
        )
