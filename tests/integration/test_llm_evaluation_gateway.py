"""Tests for the application-owned evaluation Gateway (SystemDesign §6.3).

Every model-facing evaluation request reserves a durable attempt record before the
token preflight, enforces the finite run call/token budget and absolute deadline, does
zero network I/O on a failed preflight/budget/deadline, and verifies an existing
attempt record's integrity before mutating its outcome.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest

import support_phase2 as fake
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    DigestIntegrityError,
    LLMEvaluationError,
    LLMProfileMismatchError,
    LLMRequestBudgetError,
    LLMTransportError,
)
from redteam_agent.llm.adapters import AttemptBinding
from redteam_agent.llm.budget import build_request_budget_policy
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.evaluation_gateway import EvaluationGateway, EvaluationRunBudget
from redteam_agent.llm.structured_output import build_chat_request
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.storage.database import Database
from support_phase2 import ApproxChatTokenCounter

_NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
_NS = "llm_eval_attempt"


def _binding(ds, profile, clock, *, deadline):
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    request = build_chat_request(
        schema_name="analysis_result", structured_output_mode=profile.structured_output_mode,
        tool_output_support=profile.tool_output_support,
        system_message_handling=profile.system_message_handling,
        system_instructions="s", user_content="u", model=profile.model_name,
        max_tokens=policy.reserved_output_tokens, temperature=0.1,
    )
    return AttemptBinding(
        profile=profile, policy=policy, token_counter=ApproxChatTokenCounter(profile.tokenizer_revision),
        request=request, schema_name="analysis_result", deadline=deadline, clock=clock,
        digest_service=ds, binding_checker=None,
    )


def _client(counting: fake.CountingTransport) -> VLLMChatClient:
    return VLLMChatClient(base_url="http://127.0.0.1:8000/v1", transport=counting)


def test_completed_request_records_attempt() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    db = Database(":memory:")
    profile = fake.local_profile(ds)
    counting = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    gateway = EvaluationGateway(database=db, digest_service=ds, clock=clock, run_id="run")
    binding = _binding(ds, profile, clock, deadline=clock.now() + timedelta(seconds=30))
    result = gateway.execute(binding=binding, client=_client(counting),
                             run_budget=EvaluationRunBudget(max_calls=8, max_total_tokens=10_000_000,
                                                            deadline=clock.now() + timedelta(seconds=60),
                                                            clock=clock))
    assert result.content is not None
    assert counting.calls == 1
    row = db.occ_get(_NS, "run:0")
    assert row is not None
    assert json.loads(row[1])["outcome"] == "completed"


def test_zero_network_on_run_token_budget_exhaustion() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    db = Database(":memory:")
    profile = fake.local_profile(ds)
    counting = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    gateway = EvaluationGateway(database=db, digest_service=ds, clock=clock, run_id="run")
    binding = _binding(ds, profile, clock, deadline=clock.now() + timedelta(seconds=30))
    tiny = EvaluationRunBudget(max_calls=8, max_total_tokens=1,
                               deadline=clock.now() + timedelta(seconds=60), clock=clock)
    with pytest.raises(LLMRequestBudgetError):
        gateway.execute(binding=binding, client=_client(counting), run_budget=tiny)
    assert counting.calls == 0
    assert json.loads(db.occ_get(_NS, "run:0")[1])["outcome"] == "budget_rejected"


def test_zero_network_on_deadline() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    db = Database(":memory:")
    profile = fake.local_profile(ds)
    counting = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    gateway = EvaluationGateway(database=db, digest_service=ds, clock=clock, run_id="run")
    binding = _binding(ds, profile, clock, deadline=clock.now() + timedelta(seconds=30))
    past = EvaluationRunBudget(max_calls=8, max_total_tokens=10_000_000,
                               deadline=clock.now() - timedelta(seconds=1), clock=clock)
    with pytest.raises(LLMRequestBudgetError):
        gateway.execute(binding=binding, client=_client(counting), run_budget=past)
    assert counting.calls == 0
    assert json.loads(db.occ_get(_NS, "run:0")[1])["outcome"] == "deadline_reached"


def test_zero_network_on_preflight_token_overflow() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    db = Database(":memory:")
    # A profile whose max context is too small for reserved output + margin overflows the
    # preflight budget equation, so no request reaches the network.
    profile = fake.local_profile(ds, max_context_tokens=300, max_output_tokens=256)
    counting = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    gateway = EvaluationGateway(database=db, digest_service=ds, clock=clock, run_id="run")
    binding = _binding(ds, profile, clock, deadline=clock.now() + timedelta(seconds=30))
    with pytest.raises(LLMRequestBudgetError):
        gateway.execute(binding=binding, client=_client(counting),
                        run_budget=EvaluationRunBudget(max_calls=8, max_total_tokens=10_000_000,
                                                       deadline=clock.now() + timedelta(seconds=60),
                                                       clock=clock))
    assert counting.calls == 0
    assert json.loads(db.occ_get(_NS, "run:0")[1])["outcome"] == "preflight_rejected"


def test_binding_rejection_finalizes_reserved_attempt() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    db = Database(":memory:")
    profile = fake.local_profile(ds)
    counting = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))

    class _Changed:
        def check(self) -> None:
            raise LLMProfileMismatchError("changed")

    binding = replace(
        _binding(ds, profile, clock, deadline=clock.now() + timedelta(seconds=30)),
        binding_checker=_Changed(),  # type: ignore[arg-type]
    )
    gateway = EvaluationGateway(database=db, digest_service=ds, clock=clock, run_id="run")
    with pytest.raises(LLMProfileMismatchError):
        gateway.execute(
            binding=binding,
            client=_client(counting),
            run_budget=EvaluationRunBudget(
                max_calls=8,
                max_total_tokens=10_000_000,
                deadline=clock.now() + timedelta(seconds=60),
                clock=clock,
            ),
        )
    assert counting.calls == 0
    assert json.loads(db.occ_get(_NS, "run:0")[1])["outcome"] == "preflight_rejected"


def test_update_verifies_attempt_integrity_before_mutation() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    db = Database(":memory:")
    profile = fake.local_profile(ds)
    counting = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    gateway = EvaluationGateway(database=db, digest_service=ds, clock=clock, run_id="run")
    binding = _binding(ds, profile, clock, deadline=clock.now() + timedelta(seconds=30))
    gateway.execute(binding=binding, client=_client(counting),
                    run_budget=EvaluationRunBudget(max_calls=8, max_total_tokens=10_000_000,
                                                   deadline=clock.now() + timedelta(seconds=60),
                                                   clock=clock))
    # Tamper the stored attempt record but keep its (now stale) digest.
    version, payload = db.occ_get(_NS, "run:0")
    tampered = json.loads(payload)
    tampered["outcome"] = "reserved"  # flip the recorded outcome without re-digesting
    from redteam_agent.storage.database import UnitOfWork

    with UnitOfWork(db):
        db.occ_update(_NS, "run:0", expected_version=version, new_version=version + 1,
                      json_text=json.dumps(tampered, sort_keys=True))
    with pytest.raises(DigestIntegrityError):
        gateway._update_attempt("run:0", "completed")


def test_missing_integrity_digest_fails_closed() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    db = Database(":memory:")
    gateway = EvaluationGateway(database=db, digest_service=ds, clock=clock, run_id="run")
    from redteam_agent.storage.database import UnitOfWork

    with UnitOfWork(db):
        db.occ_insert(_NS, "run:0", 1, json.dumps({"outcome": "reserved"}, sort_keys=True))
    with pytest.raises(LLMEvaluationError):
        gateway._update_attempt("run:0", "completed")


def test_transport_timeout_records_timeout_outcome() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    db = Database(":memory:")
    profile = fake.local_profile(ds)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("t", request=request)

    counting = fake.CountingTransport(handler)
    gateway = EvaluationGateway(database=db, digest_service=ds, clock=clock, run_id="run")
    binding = _binding(ds, profile, clock, deadline=clock.now() + timedelta(seconds=30))
    with pytest.raises(LLMTransportError):
        gateway.execute(binding=binding, client=_client(counting),
                        run_budget=EvaluationRunBudget(max_calls=8, max_total_tokens=10_000_000,
                                                       deadline=clock.now() + timedelta(seconds=60),
                                                       clock=clock))
    assert json.loads(db.occ_get(_NS, "run:0")[1])["outcome"] == "timeout"
    assert json.loads(db.occ_get(_NS, "run:0")[1])["attempt_metadata"] is not None
