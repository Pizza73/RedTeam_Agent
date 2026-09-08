"""Integration tests for the vLLM client + structured output (SystemDesign §7 / §6.2).

Uses a deterministic fake OpenAI-compatible server (httpx mock transport) — a test
double, never a real model.
"""

from __future__ import annotations

import json

import pytest

import support_phase2 as fake
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMTransportError
from redteam_agent.llm.client import CancellationToken, ChatCompletionRequest, ChatMessage, VLLMChatClient
from redteam_agent.llm.secrets import FileAPIKeySource
from redteam_agent.llm.structured_output import build_chat_request, extract_raw_output


def _request(ds: DigestService, mode: str = "native_json_schema") -> ChatCompletionRequest:
    profile = fake.local_profile(ds, structured_output_mode=mode)
    return build_chat_request(
        schema_name="analysis_result", structured_output_mode=mode,
        tool_output_support=True, system_message_handling="system_role",
        system_instructions="s", user_content="u", model=profile.model_name,
        max_tokens=profile.max_output_tokens, temperature=0.1,
    )


def test_native_structured_output_extracted() -> None:
    ds = DigestService()
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response(fake.VALID_ANALYSIS_OUTPUT)))
    result = client.complete(_request(ds), timeout_seconds=5)
    raw = extract_raw_output(result, "native_json_schema", "analysis_result")
    assert '"observation_id"' in raw


def test_tool_output_mode_extracted() -> None:
    ds = DigestService()
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.tool_response(fake.VALID_ANALYSIS_OUTPUT)))
    result = client.complete(_request(ds, "tool_output_json"), timeout_seconds=5)
    raw = extract_raw_output(result, "tool_output_json", "analysis_result")
    assert '"predicate"' in raw


def test_free_form_prose_is_not_parsed() -> None:
    ds = DigestService()
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response("")))
    result = client.complete(_request(ds), timeout_seconds=5)
    with pytest.raises(LLMTransportError):
        extract_raw_output(result, "native_json_schema", "analysis_result")


def test_missing_tool_call_rejected() -> None:
    ds = DigestService()
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response("{}")))
    result = client.complete(_request(ds, "tool_output_json"), timeout_seconds=5)
    with pytest.raises(LLMTransportError):
        extract_raw_output(result, "tool_output_json", "analysis_result")


def test_timeout_raises_transport_error() -> None:
    ds = DigestService()
    client = VLLMChatClient(base_url="http://vllm.local/v1", transport=fake.transport_timeout())
    with pytest.raises(LLMTransportError):
        client.complete(_request(ds), timeout_seconds=5)


def test_cancellation_before_send_and_discard_after() -> None:
    ds = DigestService()
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response(fake.VALID_ANALYSIS_OUTPUT)))
    token = CancellationToken()
    token.cancel()
    with pytest.raises(LLMTransportError):
        client.complete(_request(ds), timeout_seconds=5, cancel_token=token)


def test_http_error_status_rejected() -> None:
    ds = DigestService()
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response("{}", status=500)))
    with pytest.raises(LLMTransportError):
        client.complete(_request(ds), timeout_seconds=5)


def test_non_positive_timeout_rejected() -> None:
    ds = DigestService()
    client = VLLMChatClient(base_url="http://vllm.local/v1",
                            transport=fake.transport_returning(fake.native_response("{}")))
    with pytest.raises(LLMTransportError):
        client.complete(_request(ds), timeout_seconds=0)


def test_bad_base_url_rejected() -> None:
    with pytest.raises(LLMTransportError):
        VLLMChatClient(base_url="ftp://nope")


def test_message_roles_follow_handling() -> None:
    request = build_chat_request(
        schema_name="analysis_result", structured_output_mode="native_json_schema",
        tool_output_support=True, system_message_handling="merge_into_first_user",
        system_instructions="sys", user_content="user", model="m", max_tokens=10, temperature=0.1,
    )
    assert [m.role for m in request.messages] == ["user"]
    assert isinstance(request.messages[0], ChatMessage)


def test_api_key_is_sent_as_bearer_header_and_not_in_payload(tmp_path) -> None:
    ds = DigestService()
    key_file = tmp_path / "vllm.key"
    key_file.write_text("test-api-key\n")
    key_file.chmod(0o600)
    seen = []

    def handler(request):  # type: ignore[no-untyped-def]
        seen.append(request)
        return fake.native_response(fake.VALID_ANALYSIS_OUTPUT)

    import httpx

    client = VLLMChatClient(
        base_url="http://vllm.local/v1",
        api_key_source=FileAPIKeySource(key_file),
        transport=httpx.MockTransport(handler),
    )
    client.complete(_request(ds), timeout_seconds=5)
    assert seen[0].headers["authorization"] == "Bearer test-api-key"
    assert b"test-api-key" not in seen[0].content
    structured = json.loads(seen[0].content)["structured_outputs"]
    assert structured["disable_any_whitespace"] is True
    assert structured["json"]
    assert json.loads(seen[0].content)["guided_decoding_backend"] == "xgrammar"
