"""Unit tests for the discriminated agent model profile (SystemDesign §7)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import DigestIntegrityError, DuplicateJsonKeyError, PydanticBoundaryValidationError
from redteam_agent.llm.profile import (
    LocalLLMProfile,
    MockAgentProfile,
    build_local_llm_profile,
    build_mock_agent_profile,
    mock_agent_profile,
    parse_agent_profile,
    verify_profile_digest,
)


def _local(ds: DigestService, **overrides: object) -> LocalLLMProfile:
    kwargs: dict[str, object] = {
        "profile_revision": "p1",
        "max_context_tokens": 4096,
        "max_output_tokens": 1024,
        "model_name": "qwen",
        "model_hash": "h1",
        "chat_template_digest": None,
        "tokenizer_revision": "tok-1",
        "runtime_version": "vllm-0.1",
    }
    kwargs.update(overrides)
    return build_local_llm_profile(digest_service=ds, **kwargs)  # type: ignore[arg-type]


def test_mock_and_local_are_discriminated() -> None:
    ds = DigestService()
    mock = build_mock_agent_profile(digest_service=ds)
    local = _local(ds)
    assert mock.profile_type == "mock"
    assert local.profile_type == "vllm"
    assert isinstance(parse_agent_profile(mock.model_dump_json()), MockAgentProfile)
    assert isinstance(parse_agent_profile(local.model_dump_json()), LocalLLMProfile)


def test_profile_digest_excludes_itself_and_verifies() -> None:
    ds = DigestService()
    local = _local(ds)
    verify_profile_digest(local, ds)
    tampered = local.model_copy(update={"model_hash": "other"})
    with pytest.raises(DigestIntegrityError):
        verify_profile_digest(tampered, ds)


def test_local_rejects_output_over_context() -> None:
    ds = DigestService()
    with pytest.raises(ValidationError):
        _local(ds, max_context_tokens=100, max_output_tokens=200)


def test_local_rejects_unlisted_modes() -> None:
    ds = DigestService()
    with pytest.raises(ValidationError):
        _local(ds, structured_output_mode="freeform_prose")
    with pytest.raises(ValidationError):
        _local(ds, system_message_handling="delete_system")


def test_tool_output_mode_requires_support() -> None:
    ds = DigestService()
    with pytest.raises(ValidationError):
        build_local_llm_profile(
            digest_service=ds, profile_revision="p", structured_output_mode="tool_output_json",
            tool_output_support=False, max_context_tokens=4096, max_output_tokens=1024,
            model_name="q", model_hash="h", chat_template_digest=None, tokenizer_revision="t",
            runtime_version="r",
        )


def test_parse_rejects_unknown_field_and_duplicate_keys() -> None:
    ds = DigestService()
    payload = json.loads(mock_agent_profile(ds).model_dump_json())
    payload["extra"] = 1
    with pytest.raises(PydanticBoundaryValidationError):
        parse_agent_profile(json.dumps(payload))
    good = mock_agent_profile(ds).model_dump_json()
    dup = "{" + '"profile_type": "mock", ' + good[1:]
    with pytest.raises(DuplicateJsonKeyError):
        parse_agent_profile(dup)


def test_mock_profile_is_usable_local_is_structural() -> None:
    ds = DigestService()
    assert build_mock_agent_profile(digest_service=ds).is_usable() is True
    assert _local(ds).is_usable() is True
