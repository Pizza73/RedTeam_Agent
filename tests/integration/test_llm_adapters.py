"""Integration tests for the Local LLM planner/analyzer adapters (SystemDesign §6.2/§8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import support_phase2 as fake
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    LLMOutputValidationError,
    LLMProfileMismatchError,
    PydanticBoundaryValidationError,
)
from redteam_agent.llm.adapters import (
    LocalLLMPlanner,
    validate_analysis_result,
    validate_planner_output,
)
from redteam_agent.llm.budget import build_request_budget_policy
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.plan.models import PlannerActionOutput, PlannerContextRequest
from redteam_agent.runtime.clock import ManualClock
from support_phase2 import ApproxChatTokenCounter

_NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)


def _planner(ds, client, profile, clock):
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    return LocalLLMPlanner(
        profile=profile, policy=policy, client=client,
        token_counter=ApproxChatTokenCounter(profile.tokenizer_revision), clock=clock, digest_service=ds,
    )


def test_validate_functions_accept_valid_reject_malformed() -> None:
    assert isinstance(validate_planner_output(fake.VALID_PLANNER_OUTPUT), PlannerContextRequest)
    assert isinstance(validate_planner_output(fake.VALID_PLANNER_ACTION), PlannerActionOutput)
    assert validate_analysis_result(fake.VALID_ANALYSIS_OUTPUT).observation_id == "obs-1"
    with pytest.raises(PydanticBoundaryValidationError):
        validate_planner_output(fake.INVALID_UNKNOWN_FIELD)


def test_planner_invocation_returns_valid_output() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response(fake.VALID_PLANNER_ACTION)))
    envelope = fake.minimal_planner_envelope(ds, authorized_context={"note": "redacted"})
    invocation = _planner(ds, client, profile, clock).build_invocation(
        envelope, deadline=clock.now() + timedelta(seconds=30)
    )
    invocation.before_attempt(0)
    output = invocation(envelope)
    assert isinstance(output, PlannerActionOutput)


def test_planner_malformed_output_raises_output_validation() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response(fake.INVALID_UNKNOWN_FIELD)))
    envelope = fake.minimal_planner_envelope(ds, authorized_context={"note": "redacted"})
    invocation = _planner(ds, client, profile, clock).build_invocation(
        envelope, deadline=clock.now() + timedelta(seconds=30)
    )
    invocation.before_attempt(0)
    with pytest.raises(LLMOutputValidationError):
        invocation(envelope)


def test_planner_rejects_changed_envelope() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response(fake.VALID_PLANNER_ACTION)))
    envelope = fake.minimal_planner_envelope(ds, authorized_context={"note": "redacted"})
    other = fake.minimal_planner_envelope(ds, authorized_context={"note": "different"})
    invocation = _planner(ds, client, profile, clock).build_invocation(
        envelope, deadline=clock.now() + timedelta(seconds=30)
    )
    with pytest.raises(LLMProfileMismatchError):
        invocation(other)


def test_prompt_contains_only_redacted_context() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    captured: dict[str, str] = {}

    def handler(request):  # type: ignore[no-untyped-def]
        captured["body"] = request.content.decode("utf-8")
        return fake.native_response(fake.VALID_PLANNER_OUTPUT)

    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=fake.CountingTransport(handler))
    envelope = fake.minimal_planner_envelope(ds, authorized_context={"note": "only-redacted-marker"})
    invocation = _planner(ds, client, profile, clock).build_invocation(
        envelope, deadline=clock.now() + timedelta(seconds=30)
    )
    invocation.before_attempt(0)
    invocation(envelope)
    assert "only-redacted-marker" in captured["body"]
    # The system prompt instructs the model to treat context as untrusted data.
    assert "untrusted" in captured["body"]


def test_staged_recombination_revalidates_final_schema() -> None:
    from redteam_agent.errors import LLMOutputValidationError
    from redteam_agent.llm.adapters import recombine_and_revalidate_proposal
    from redteam_agent.plan.models import ExecutionPlanProposal

    objective_stage = {
        "objective": "scan authorized host", "phase": "DISCOVERY",
        "tool_ref": {"tool_id": "net-scan", "registry_revision": 1},
        "requested_targets": [{"type": "host", "host_id": "host-1"}], "session_id": None,
    }
    arguments_stage = {"arguments": {"destinations": ["10.0.0.1"]}}
    proposal = recombine_and_revalidate_proposal(
        objective_stage=objective_stage, arguments_stage=arguments_stage
    )
    assert isinstance(proposal, ExecutionPlanProposal)

    # A partial/invalid stage (missing arguments) can never yield a proposal.
    with pytest.raises(LLMOutputValidationError):
        recombine_and_revalidate_proposal(objective_stage=objective_stage, arguments_stage={})


def test_planner_invocation_records_server_reported_usage() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    client = VLLMChatClient(
        base_url="http://vllm.local/v1",
        transport=fake.transport_returning(
            fake.native_response(
                fake.VALID_PLANNER_ACTION,
                usage=fake.usage_payload(prompt_tokens=321, completion_tokens=64),
            )
        ),
    )
    envelope = fake.minimal_planner_envelope(ds, authorized_context={"note": "redacted"})
    invocation = _planner(ds, client, profile, clock).build_invocation(
        envelope, deadline=clock.now() + timedelta(seconds=30)
    )
    assert invocation.usage_records == ()
    invocation.before_attempt(0)
    invocation(envelope)
    assert invocation.usage_records == ((321, 64),)


def test_planner_invocation_records_missing_usage_as_none_not_zero() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    client = VLLMChatClient(
        base_url="http://vllm.local/v1",
        transport=fake.transport_returning(fake.native_response(fake.VALID_PLANNER_ACTION)),
    )
    envelope = fake.minimal_planner_envelope(ds, authorized_context={"note": "redacted"})
    invocation = _planner(ds, client, profile, clock).build_invocation(
        envelope, deadline=clock.now() + timedelta(seconds=30)
    )
    invocation.before_attempt(0)
    invocation(envelope)
    assert invocation.usage_records == ((None, None),)


def test_planner_invocation_accumulates_usage_across_retry_attempts() -> None:
    # A gateway-driven output-validation retry re-invokes the SAME invocation object
    # (it re-uses the request envelope); every real network round trip it makes --
    # including the one whose output later fails validation -- must be accounted for.
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    client = VLLMChatClient(
        base_url="http://vllm.local/v1",
        transport=fake.transport_sequence(
            [
                fake.native_response(
                    fake.INVALID_UNKNOWN_FIELD,
                    usage=fake.usage_payload(prompt_tokens=100, completion_tokens=10),
                ),
                fake.native_response(
                    fake.VALID_PLANNER_ACTION,
                    usage=fake.usage_payload(prompt_tokens=100, completion_tokens=20),
                ),
            ]
        ),
    )
    envelope = fake.minimal_planner_envelope(ds, authorized_context={"note": "redacted"})
    invocation = _planner(ds, client, profile, clock).build_invocation(
        envelope, deadline=clock.now() + timedelta(seconds=30)
    )
    invocation.before_attempt(0)
    with pytest.raises(LLMOutputValidationError):
        invocation(envelope)
    invocation.before_attempt(1)
    output = invocation(envelope)
    assert isinstance(output, PlannerActionOutput)
    assert invocation.usage_records == ((100, 10), (100, 20))


def test_real_adapter_not_callable_without_preflight() -> None:
    from redteam_agent.errors import LLMRequestBudgetError

    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.CountingTransport(
                                lambda r: fake.native_response(fake.VALID_PLANNER_ACTION)))
    envelope = fake.minimal_planner_envelope(ds, authorized_context={"note": "redacted"})
    invocation = _planner(ds, client, profile, clock).build_invocation(
        envelope, deadline=clock.now() + timedelta(seconds=30)
    )
    # No before_attempt() ran: the network must not be reached.
    with pytest.raises(LLMRequestBudgetError):
        invocation(envelope)
    assert client._transport.calls == 0  # type: ignore[attr-defined]
