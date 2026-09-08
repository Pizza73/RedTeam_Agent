"""Unit tests for schema capability evaluation and binding (SystemDesign §6.2)."""

from __future__ import annotations

import pytest

import support_phase2 as fake
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMCapabilityError
from redteam_agent.llm.capability import (
    CapabilityEvaluator,
    CapabilityRepository,
    MissionCapabilityVerifier,
    ProbeOutcome,
    SchemaProbeCase,
)
from redteam_agent.llm.capability_corpus import build_schema_capability_corpus
from redteam_agent.llm.evaluation import SyntheticCapabilityProbe
from redteam_agent.llm.profile import build_local_llm_profile
from redteam_agent.llm.schemas import compute_schema_digest
from redteam_agent.storage.database import Database


def _profile(ds: DigestService, **overrides: object):
    kwargs: dict[str, object] = {
        "profile_revision": "p", "max_context_tokens": 8192, "max_output_tokens": 1024,
        "model_name": "q", "model_hash": "h1", "chat_template_digest": None,
        "tokenizer_revision": "t1", "runtime_version": "r1",
    }
    kwargs.update(overrides)
    return build_local_llm_profile(digest_service=ds, **kwargs)  # type: ignore[arg-type]


_VALID_ANALYSIS_BODY = (
    '{"observation_id": "o", "condition_id": "c1", "source_execution_id": "e1", '
    '"observation_type": "asset", "subject_ref": "host:h", "predicate": "p", "object_ref": null, '
    '"attributes": {}, "source_artifact_ids": [], "llm_confidence": 0.5, '
    '"subject_entity_type": null, "subject_strong_key_type": null, "subject_strong_key_value": null}'
)


class _UnsafeProbe:
    """Returns a valid body for every case (so reject cases are wrongly accepted) and
    ignores cancellation, so the evaluator must record unsafe acceptances and a
    cancellation failure and refuse to pass. It is a test double (never real evidence)."""

    def probe(self, case: SchemaProbeCase) -> ProbeOutcome:
        if case.expectation == "cancel":
            return ProbeOutcome(kind="cancel_ignored")
        return ProbeOutcome(kind="output", raw=_VALID_ANALYSIS_BODY)


def test_synthetic_probe_passes_all_schemas() -> None:
    ds = DigestService()
    profile = _profile(ds)
    corpus = build_schema_capability_corpus()
    evaluator = CapabilityEvaluator(digest_service=ds)
    for schema_name in ("planner_output", "execution_plan_proposal", "analysis_result"):
        result = evaluator.evaluate(
            profile=profile, schema_name=schema_name,
            schema_digest=compute_schema_digest(schema_name, ds), corpus=corpus,
            probe=SyntheticCapabilityProbe(),
        )
        assert result.passed
        # Provenance is derived from the concrete probe: a synthetic probe is test-double.
        assert result.evidence_kind == "test_double"
        assert result.unsafe_boundary_acceptances == 0
        assert result.cancellation_failures == 0


def test_unsafe_boundary_acceptance_fails_closed() -> None:
    ds = DigestService()
    profile = _profile(ds)
    corpus = build_schema_capability_corpus()
    evaluator = CapabilityEvaluator(digest_service=ds)
    result = evaluator.evaluate(
        profile=profile, schema_name="analysis_result",
        schema_digest=compute_schema_digest("analysis_result", ds), corpus=corpus,
        probe=_UnsafeProbe(),
    )
    assert result.unsafe_boundary_acceptances > 0
    assert result.cancellation_failures > 0
    assert result.passed is False


def test_repository_binding_invalidates_on_change() -> None:
    ds = DigestService()
    profile = _profile(ds)
    corpus = build_schema_capability_corpus()
    repo = CapabilityRepository(database=Database(":memory:"), digest_service=ds)
    # Real evidence comes only through the trusted live path (never a synthetic probe).
    result = fake.real_capability_result(ds, profile=profile, schema_name="planner_output", corpus=corpus)
    assert result.evidence_kind == "real_local_llm"
    repo.save(result)
    # Found under the exact binding.
    assert repo.get(
        profile_digest=profile.profile_digest, model_hash=profile.model_hash,
        runtime_version=profile.runtime_version, tokenizer_revision=profile.tokenizer_revision,
        chat_template_digest=profile.chat_template_digest, schema_name="planner_output",
        schema_digest=result.schema_digest, corpus_version=corpus.corpus_version,
        corpus_digest=result.corpus_digest, prompt_set_digest=result.prompt_set_digest,
        structured_output_mode=profile.structured_output_mode,
    ) is not None
    # Any changed binding component makes it unfindable.
    assert repo.get(
        profile_digest=profile.profile_digest, model_hash="changed", runtime_version=profile.runtime_version,
        tokenizer_revision=profile.tokenizer_revision, chat_template_digest=profile.chat_template_digest,
        schema_name="planner_output", schema_digest=result.schema_digest,
        corpus_version=corpus.corpus_version, corpus_digest=result.corpus_digest,
        prompt_set_digest=result.prompt_set_digest,
        structured_output_mode=profile.structured_output_mode,
    ) is None


def test_mission_verifier_requires_all_schemas() -> None:
    ds = DigestService()
    profile = _profile(ds)
    corpus = build_schema_capability_corpus()
    repo = CapabilityRepository(database=Database(":memory:"), digest_service=ds)
    verifier = MissionCapabilityVerifier(repository=repo, digest_service=ds, corpus=corpus)

    class _Revision:
        llm_profile_digest = profile.profile_digest

    with pytest.raises(LLMCapabilityError):
        verifier.verify_mission_capability(profile, _Revision())  # type: ignore[arg-type]
    # Persist only two of three schemas -> still fails closed.
    for schema_name in ("planner_output", "execution_plan_proposal"):
        repo.save(fake.real_capability_result(ds, profile=profile, schema_name=schema_name, corpus=corpus))
    with pytest.raises(LLMCapabilityError):
        verifier.verify_mission_capability(profile, _Revision())  # type: ignore[arg-type]
    repo.save(fake.real_capability_result(ds, profile=profile, schema_name="analysis_result", corpus=corpus))
    verifier.verify_mission_capability(profile, _Revision())  # type: ignore[arg-type]


def test_verifier_rejects_test_double_evidence_even_if_passed() -> None:
    ds = DigestService()
    profile = _profile(ds)
    corpus = build_schema_capability_corpus()
    evaluator = CapabilityEvaluator(digest_service=ds)

    # A fully-passing result but derived from a synthetic (test-double) probe must never
    # qualify a real mission.
    passing_test_double = {
        name: evaluator.evaluate(
            profile=profile, schema_name=name,
            schema_digest=compute_schema_digest(name, ds), corpus=corpus,
            probe=SyntheticCapabilityProbe(),
        )
        for name in ("planner_output", "execution_plan_proposal", "analysis_result")
    }
    assert all(r.passed for r in passing_test_double.values())
    assert all(r.evidence_kind == "test_double" for r in passing_test_double.values())

    class _StubRepo:
        def get(self, *, schema_name: str, **_kw: object):
            return passing_test_double[schema_name]

    verifier = MissionCapabilityVerifier(repository=_StubRepo(), digest_service=ds, corpus=corpus)  # type: ignore[arg-type]

    class _Revision:
        llm_profile_digest = profile.profile_digest

    with pytest.raises(LLMCapabilityError):
        verifier.verify_mission_capability(profile, _Revision())  # type: ignore[arg-type]
