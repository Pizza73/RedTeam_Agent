"""Integration tests for the gateway budget/binding enforcement (SystemDesign §6.3, D8).

Drives the shared gateway's ``invoke_analyzer`` with a real Local LLM invocation over
a fake vLLM server (test double), asserting network I/O happens only after the budget
and binding checks pass, and that retries stay within the bounded budget.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

import support_phase2 as fake
from redteam_agent.agent.llm_gateway import SharedLLMGateway
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AgentLoopError, LLMProfileMismatchError, LLMRequestBudgetError
from redteam_agent.llm.adapters import CurrentBindingChecker, LocalLLMAnalyzer
from redteam_agent.llm.budget import build_request_budget_policy
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.storage.database import Database
from support_phase2 import ApproxChatTokenCounter

_NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
_CTX = {"redacted": "authorized result context"}


def _analyzer(ds, client, profile, *, clock, binding_checker=None):
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    adapter = LocalLLMAnalyzer(
        profile=profile, policy=policy, client=client,
        token_counter=ApproxChatTokenCounter(profile.tokenizer_revision), clock=clock, digest_service=ds,
    )
    return adapter.build_invocation(
        execution_id="exec-1", result_digest="rd", authorized_context=_CTX,
        deadline=clock.now() + timedelta(seconds=30), binding_checker=binding_checker,
    )


def _invoke(gateway, invocation, *, operation_id="op-1"):
    return gateway.invoke_analyzer(
        mission_id="m1", mission_revision=1, operation_id=operation_id, execution_id="exec-1",
        result_digest="rd", context_grant_id="g1", context_grant_digest="gd",
        authorized_context=_CTX, invoke=invocation,
    )


def test_valid_output_succeeds_and_persists_redacted_metadata() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    result = _invoke(gateway, _analyzer(ds, client, profile, clock=clock))
    assert result.observation_id == "obs-1"
    assert transport.calls == 1
    row = gateway._db.occ_get("llm_gateway_attempt", "m1:1:analyzer:op-1:0")
    assert row is not None
    stored = json.loads(row[1])
    assert "attempt_metadata" in stored
    metadata = stored["attempt_metadata"]
    assert "rendered_request_digest" in metadata
    # No raw context echoed into the persisted metadata.
    assert "authorized result context" not in json.dumps(metadata)


def test_over_budget_rejects_with_zero_network_calls() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    # max_context barely above output+margin, so any rendered input overflows.
    profile = fake.local_profile(ds, max_context_tokens=1300, max_output_tokens=1024)
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    with pytest.raises(LLMRequestBudgetError):
        _invoke(gateway, _analyzer(ds, client, profile, clock=clock))
    assert transport.calls == 0


def test_tokenizer_mismatch_rejects_zero_network() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds, tokenizer_revision="tok-1")
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    adapter = LocalLLMAnalyzer(
        profile=profile, policy=policy, client=client,
        token_counter=ApproxChatTokenCounter("different-tokenizer"), clock=clock, digest_service=ds,
    )
    invocation = adapter.build_invocation(
        execution_id="exec-1", result_digest="rd", authorized_context=_CTX,
        deadline=clock.now() + timedelta(seconds=30),
    )
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    with pytest.raises(LLMRequestBudgetError):
        _invoke(gateway, invocation)
    assert transport.calls == 0


def test_deadline_passed_rejects_zero_network() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    policy = build_request_budget_policy(profile=profile, digest_service=ds)
    adapter = LocalLLMAnalyzer(
        profile=profile, policy=policy, client=client,
        token_counter=ApproxChatTokenCounter(profile.tokenizer_revision), clock=clock, digest_service=ds,
    )
    invocation = adapter.build_invocation(
        execution_id="exec-1", result_digest="rd", authorized_context=_CTX,
        deadline=clock.now() - timedelta(seconds=1),
    )
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    with pytest.raises(LLMRequestBudgetError):
        _invoke(gateway, invocation)
    assert transport.calls == 0


def test_binding_mismatch_fails_closed_zero_network() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)

    class _Changed(CurrentBindingChecker):
        def check(self) -> None:
            raise LLMProfileMismatchError("model changed mid-mission")

    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    with pytest.raises(LLMProfileMismatchError):
        _invoke(gateway, _analyzer(ds, client, profile, clock=clock, binding_checker=_Changed()))
    assert transport.calls == 0


def test_malformed_output_retries_within_budget_then_exhausts() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.INVALID_UNKNOWN_FIELD))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    with pytest.raises(AgentLoopError):
        _invoke(gateway, _analyzer(ds, client, profile, clock=clock))
    # 1 initial + 3 validation retries = 4 network attempts.
    assert transport.calls == SharedLLMGateway.MAX_OUTPUT_RETRIES + 1


def test_transport_unknown_is_not_retried() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)

    def _raise(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("t", request=request)

    transport = fake.CountingTransport(_raise)
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    with pytest.raises(AgentLoopError):
        _invoke(gateway, _analyzer(ds, client, profile, clock=clock))
    assert transport.calls == 1


def test_preflight_rejection_leaves_attempt_row_and_failed_operation() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    # Over-budget profile so the preflight rejects before any network I/O.
    profile = fake.local_profile(ds, max_context_tokens=1300, max_output_tokens=1024)
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    with pytest.raises(LLMRequestBudgetError):
        _invoke(gateway, _analyzer(ds, client, profile, clock=clock))
    assert transport.calls == 0
    # The attempt row exists and records the rejection.
    row = gateway._db.occ_get("llm_gateway_attempt", "m1:1:analyzer:op-1:0")
    assert row is not None
    assert json.loads(row[1])["outcome"] == "preflight_rejected"
    # The logical operation is recorded as FAILED.
    op = gateway._db.occ_get("llm_gateway_operation", "m1:1:analyzer:op-1")
    assert op is not None
    assert json.loads(op[1])["state"] == "FAILED"


def test_completed_attempt_row_records_outcome() -> None:
    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    _invoke(gateway, _analyzer(ds, client, profile, clock=clock))
    row = gateway._db.occ_get("llm_gateway_attempt", "m1:1:analyzer:op-1:0")
    assert row is not None
    assert json.loads(row[1])["outcome"] == "completed"


def test_attempt_update_verifies_integrity_before_mutation() -> None:
    # A tampered attempt row must not be silently overwritten on outcome update (fail closed).
    from redteam_agent.errors import DigestIntegrityError
    from redteam_agent.storage.database import UnitOfWork

    ds = DigestService()
    clock = ManualClock(_NOW)
    profile = fake.local_profile(ds)
    transport = fake.CountingTransport(lambda r: fake.native_response(fake.VALID_ANALYSIS_OUTPUT))
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=transport)
    gateway = SharedLLMGateway(database=Database(":memory:"), digest_service=ds, clock=clock)
    _invoke(gateway, _analyzer(ds, client, profile, clock=clock))
    key = "m1:1:analyzer:op-1:0"
    version, payload = gateway._db.occ_get("llm_gateway_attempt", key)
    tampered = json.loads(payload)
    tampered["outcome"] = "reserved"  # flip without re-digesting
    with UnitOfWork(gateway._db):
        gateway._db.occ_update("llm_gateway_attempt", key, expected_version=version,
                               new_version=version + 1, json_text=json.dumps(tampered, sort_keys=True))
    with pytest.raises(DigestIntegrityError):
        gateway._update_attempt(attempt_key=key, outcome="completed")
