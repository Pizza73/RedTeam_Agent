"""Unit tests for the LLM request budget equation (SystemDesign §6.3, D8)."""

from __future__ import annotations

import pytest

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMRequestBudgetError
from redteam_agent.llm.budget import build_request_budget_policy, evaluate_token_budget
from redteam_agent.llm.profile import build_local_llm_profile


def _profile(ds: DigestService, *, max_context: int = 4096, max_output: int = 1024):
    return build_local_llm_profile(
        digest_service=ds, profile_revision="p", max_context_tokens=max_context,
        max_output_tokens=max_output, model_name="q", model_hash="h", chat_template_digest=None,
        tokenizer_revision="t", runtime_version="r",
    )


def test_reserved_output_equals_profile_max_output() -> None:
    ds = DigestService()
    profile = _profile(ds)
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    assert policy.reserved_output_tokens == profile.max_output_tokens
    assert policy.safety_margin_tokens >= 256


def test_within_budget_returns_total() -> None:
    ds = DigestService()
    profile = _profile(ds)
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    total = evaluate_token_budget(profile=profile, policy=policy, rendered_input_tokens=100)
    assert total == 100 + policy.reserved_output_tokens + policy.safety_margin_tokens


def test_over_budget_rejected() -> None:
    ds = DigestService()
    profile = _profile(ds, max_context=1200, max_output=800)
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    with pytest.raises(LLMRequestBudgetError):
        evaluate_token_budget(profile=profile, policy=policy, rendered_input_tokens=500)


def test_unmeasurable_rejected() -> None:
    ds = DigestService()
    profile = _profile(ds)
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    with pytest.raises(LLMRequestBudgetError):
        evaluate_token_budget(profile=profile, policy=policy, rendered_input_tokens=-1)


def test_reserved_output_mismatch_rejected() -> None:
    ds = DigestService()
    profile = _profile(ds, max_output=1024)
    other = _profile(ds, max_output=512)
    policy = build_request_budget_policy(profile=other, digest_service=ds)
    with pytest.raises(LLMRequestBudgetError):
        evaluate_token_budget(profile=profile, policy=policy, rendered_input_tokens=10)
