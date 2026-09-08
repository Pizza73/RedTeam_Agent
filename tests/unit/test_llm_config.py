"""Unit tests for the local LLM endpoint configuration (SystemDesign §7)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redteam_agent.llm.config import LocalLLMEndpointConfig


def test_defaults_pin_vllm_and_chat_completions() -> None:
    config = LocalLLMEndpointConfig(model="qwen")
    assert config.provider == "vllm"
    assert config.wire_api == "chat_completions"
    assert config.endpoint_available is False


def test_endpoint_available_when_base_url_set() -> None:
    config = LocalLLMEndpointConfig(model="qwen", base_url="http://127.0.0.1:8000/v1")
    assert config.endpoint_available is True


def test_non_http_base_url_rejected() -> None:
    with pytest.raises(ValidationError):
        LocalLLMEndpointConfig(model="qwen", base_url="ftp://nope")
