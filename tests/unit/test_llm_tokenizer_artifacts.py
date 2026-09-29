from __future__ import annotations

import hashlib
import json
import sys
from types import SimpleNamespace

import pytest

from redteam_agent.errors import LLMRequestBudgetError
from redteam_agent.llm.client import ChatCompletionRequest, ChatMessage
from redteam_agent.llm.tokenizer import HuggingFaceTokenCounter, verify_tokenizer_artifacts


def _manifest_digest(directory, names):  # type: ignore[no-untyped-def]
    rows = []
    for name in sorted(names):
        path = directory / name
        rows.append(
            {
                "path": name,
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def test_verify_tokenizer_artifacts_binds_tokenizer_and_template(tmp_path) -> None:
    (tmp_path / "tokenizer.json").write_text("{}")
    (tmp_path / "tokenizer_config.json").write_text("{}")
    (tmp_path / "chat_template.jinja").write_text("{{ messages }}")
    revision = _manifest_digest(tmp_path, ("tokenizer.json", "tokenizer_config.json"))
    template = hashlib.sha256(b"{{ messages }}").hexdigest()
    verify_tokenizer_artifacts(
        tmp_path,
        expected_tokenizer_revision=revision,
        expected_chat_template_digest=template,
    )
    (tmp_path / "tokenizer.json").write_text('{"changed":true}')
    with pytest.raises(LLMRequestBudgetError):
        verify_tokenizer_artifacts(
            tmp_path,
            expected_tokenizer_revision=revision,
            expected_chat_template_digest=template,
        )


def test_counter_requests_flat_transformers_token_sequence(monkeypatch, tmp_path) -> None:
    seen: dict[str, object] = {}

    class _Tokenizer:
        def apply_chat_template(self, messages, **kwargs):  # type: ignore[no-untyped-def]
            seen["messages"] = messages
            seen.update(kwargs)
            return [2, 10, 11]

    class _AutoTokenizer:
        @staticmethod
        def from_pretrained(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _Tokenizer()

    monkeypatch.setattr(
        "redteam_agent.llm.tokenizer.verify_tokenizer_artifacts",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setitem(sys.modules, "transformers", SimpleNamespace(AutoTokenizer=_AutoTokenizer))
    counter = HuggingFaceTokenCounter(
        model_directory=tmp_path.resolve(),
        tokenizer_revision="fixed-revision",
        chat_template_digest="fixed-template",
    )
    request = ChatCompletionRequest(
        model="model",
        messages=(ChatMessage(role="user", content="hello"),),
        max_tokens=16,
        temperature=0.0,
    )

    assert counter.count_request(request) == 3
    assert seen["tokenize"] is True
    assert seen["add_generation_prompt"] is True
    assert seen["return_dict"] is False
