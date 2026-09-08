"""LLM request budget policy and the token budget equation (SystemDesign §6.3, D8).

``reserved_output_tokens`` equals the mission-fixed ``LocalLLMProfile.max_output_tokens``
and is also sent as the real request's output cap. The safety margin defaults to (and
is at least) 256 tokens. Before any network I/O the gateway evaluates::

    rendered_input_tokens + reserved_output_tokens + safety_margin_tokens
        <= max_context_tokens

with the fixed tokenizer / chat template / schema rendering. A required-input-only
overflow, a tokenizer mismatch, or an unmeasurable request is rejected with zero
network calls.
"""

from __future__ import annotations

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMRequestBudgetError
from redteam_agent.llm.profile import LocalLLMProfile
from redteam_agent.models.base import StrictImmutableBoundaryModel

DEFAULT_SAFETY_MARGIN_TOKENS = 256


class LLMRequestBudgetPolicy(StrictImmutableBoundaryModel):
    policy_revision: str = Field(min_length=1)
    reserved_output_tokens: int = Field(gt=0)
    safety_margin_tokens: int = Field(default=DEFAULT_SAFETY_MARGIN_TOKENS, ge=256)
    request_timeout_seconds: int = Field(default=60, gt=0)
    policy_digest: str = Field(min_length=1)


def build_request_budget_policy(
    *,
    profile: LocalLLMProfile,
    policy_revision: str = "llm-request-budget-v1",
    safety_margin_tokens: int = DEFAULT_SAFETY_MARGIN_TOKENS,
    request_timeout_seconds: int = 60,
    digest_service: DigestService,
) -> LLMRequestBudgetPolicy:
    """Build a budget policy whose reserved output equals the profile's max output."""
    fields = {
        "policy_revision": policy_revision,
        "reserved_output_tokens": profile.max_output_tokens,
        "safety_margin_tokens": safety_margin_tokens,
        "request_timeout_seconds": request_timeout_seconds,
    }
    policy_digest = digest_service.compute("llm_request_budget_policy_digest", fields)
    return LLMRequestBudgetPolicy(**fields, policy_digest=policy_digest)  # type: ignore[arg-type]


def evaluate_token_budget(
    *,
    profile: LocalLLMProfile,
    policy: LLMRequestBudgetPolicy,
    rendered_input_tokens: int,
) -> int:
    """Return the total budgeted tokens, or raise if the request is over budget.

    ``rendered_input_tokens < 0`` denotes an unmeasurable request (fail closed).
    """
    if rendered_input_tokens < 0:
        raise LLMRequestBudgetError("rendered input is unmeasurable")
    if policy.reserved_output_tokens != profile.max_output_tokens:
        raise LLMRequestBudgetError("reserved output tokens must equal the profile max output")
    total = rendered_input_tokens + policy.reserved_output_tokens + policy.safety_margin_tokens
    if total > profile.max_context_tokens:
        raise LLMRequestBudgetError("rendered input plus reserved output plus margin exceeds max context")
    return total


__all__ = [
    "DEFAULT_SAFETY_MARGIN_TOKENS",
    "LLMRequestBudgetPolicy",
    "build_request_budget_policy",
    "evaluate_token_budget",
]
