"""Quality gate orchestration (SystemDesign §36.E1 / §37.1 D11).

``run_agent_quality_gate`` runs the fixed 300-run gate with a driver. When no real
local vLLM endpoint / real-LLM driver is configured, ``not_run_report`` records the
exact external prerequisites and returns a ``NOT_RUN`` report rather than a fabricated
pass. A real ``PASS`` is only possible with real-local-LLM evidence.
"""

from __future__ import annotations

from collections.abc import Mapping

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.quality.evidence import QualityEvidenceRepository
from redteam_agent.quality.models import (
    AgentQualityCorpus,
    EvaluationBinding,
    QualityReport,
    report_fields_zero_diagnostics,
)
from redteam_agent.quality.oracle import QualityOracle
from redteam_agent.quality.runner import QualityRunner, RunDriver

REAL_LLM_PREREQUISITES: tuple[str, ...] = (
    "a configured local vLLM chat_completions endpoint (base_url) reachable from the host",
    "a capability-checked LocalLLMProfile whose model_hash / tokenizer_revision match the served model",
    "the model's real tokenizer wired under the profile tokenizer_revision for the budget equation",
    "a pinned runtime_version matching the running vLLM",
    "a persisted direct_network ServerAttestation of the served model hash / tokenizer / "
    "chat template / runtime / structured-output mode bound to the profile and endpoint",
)


def run_agent_quality_gate(
    *,
    corpus: AgentQualityCorpus,
    digest_service: DigestService,
    driver: RunDriver,
    external_prerequisites: tuple[str, ...] = (),
    evaluation_binding: EvaluationBinding | None = None,
    expected_capability_result_digests: tuple[str, ...] = (),
    expected_binding_fields: Mapping[str, object] | None = None,
    evidence_sink: QualityEvidenceRepository | None = None,
    evaluation_id: str | None = None,
) -> QualityReport:
    runner = QualityRunner(
        corpus=corpus, oracle=QualityOracle(), driver=driver, digest_service=digest_service,
        external_prerequisites=external_prerequisites, evaluation_binding=evaluation_binding,
        expected_capability_result_digests=expected_capability_result_digests,
        expected_binding_fields=expected_binding_fields,
        evidence_sink=evidence_sink, evaluation_id=evaluation_id,
    )
    return runner.run()


def not_run_report(
    *,
    corpus: AgentQualityCorpus,
    digest_service: DigestService,
    reason: str,
    prerequisites: tuple[str, ...] = REAL_LLM_PREREQUISITES,
) -> QualityReport:
    """Build a ``NOT_RUN`` report (zero runs) when no real endpoint is configured."""
    return _zero_run_report(
        corpus=corpus, digest_service=digest_service, gate_status="NOT_RUN", reasons=(reason,),
        prerequisites=prerequisites, evaluation_binding_digest=None,
    )


def blocked_report(
    *,
    corpus: AgentQualityCorpus,
    digest_service: DigestService,
    reasons: tuple[str, ...],
    evaluation_binding_digest: str | None,
) -> QualityReport:
    """A zero-run ``BLOCKED`` report for a qualification rejected before any driver call."""
    return _zero_run_report(
        corpus=corpus, digest_service=digest_service, gate_status="BLOCKED", reasons=reasons,
        prerequisites=REAL_LLM_PREREQUISITES, evaluation_binding_digest=evaluation_binding_digest,
    )


def _zero_run_report(
    *,
    corpus: AgentQualityCorpus,
    digest_service: DigestService,
    gate_status: str,
    reasons: tuple[str, ...],
    prerequisites: tuple[str, ...],
    evaluation_binding_digest: str | None,
) -> QualityReport:
    fields = {
        "corpus_version": corpus.corpus_version,
        "corpus_digest": corpus.corpus_digest(digest_service),
        "evidence_kind": "test_double",
        "gate_status": gate_status,
        "total_runs": 0,
        "expected_reach_rate": 0.0,
        "per_family_min_reach_rate": 0.0,
        "per_family_reach": (),
        "scope_false_allow_count": 0,
        "approval_bypass_count": 0,
        "secret_leakage_count": 0,
        "duplicate_side_effect_count": 0,
        "false_confirmed_count": 0,
        "false_goal_count": 0,
        "extraction_recall": 0.0,
        "recall_numerator": 0,
        "recall_denominator": 0,
        "unexpected_human_wait_rate": 0.0,
        "normal_run_count": 0,
        "hard_limit_violations": 0,
        "pass_cubed_rate": 0.0,
        "pass_at_three_rate": 0.0,
        "acceptance_criteria_ids": tuple(sorted({
            ac for fixture in corpus.all_fixtures() for ac in fixture.acceptance_criteria_ids
        })),
        "evaluation_binding_digest": evaluation_binding_digest,
        "blocking_reasons": reasons,
        "external_prerequisites": prerequisites,
        **report_fields_zero_diagnostics(),
    }
    report_digest = digest_service.compute("agent_quality_report_digest", fields)
    return QualityReport(**fields, report_digest=report_digest)  # type: ignore[arg-type]


__all__ = ["REAL_LLM_PREREQUISITES", "blocked_report", "not_run_report", "run_agent_quality_gate"]
