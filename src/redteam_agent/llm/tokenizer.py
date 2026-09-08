"""Fixed-tokenizer token counting for the gateway budget equation (SystemDesign §6.3).

The budget equation MUST be evaluated by tokenizing the *actual complete chat request*
(system instructions, the full public tool / output JSON schema, the authorized
context, and the chat-template overhead) with the model's own tokenizer and chat
template, pinned by the mission's ``LocalLLMProfile`` via ``tokenizer_revision`` and
``chat_template_digest``. Counting an invented textual rendering of the request is not
sufficient, so the counter consumes a :class:`ChatCompletionRequest`, not a string.

Production prerequisite (stated, not shipped here): a real
:class:`TokenCounter` is the model's tokenizer applied through the exact fixed chat
template / structured-output schema / tool definitions. It must report the same
``tokenizer_revision`` as the mission-fixed profile; the gateway rejects, with zero
network I/O, any counter whose revision does not match. This module ships no
approximate or "conservative" production counter and makes no claim of exactness;
a deterministic test double that implements :meth:`TokenCounter.count_request` lives
under ``tests`` and is explicitly labelled test-only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Protocol

from redteam_agent.errors import LLMRequestBudgetError
from redteam_agent.llm.client import ChatCompletionRequest

_TOKENIZER_FILES = (
    "tokenizer.json",
    "tokenizer_config.json",
    "tokenizer.model",
    "special_tokens_map.json",
    "vocab.json",
    "merges.txt",
    "added_tokens.json",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tokenizer_manifest_digest(directory: Path, files: list[Path]) -> str:
    manifest = [
        {
            "path": path.relative_to(directory).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for path in sorted(files)
    ]
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode("utf-8")).hexdigest()


def verify_tokenizer_artifacts(
    directory: Path,
    *,
    expected_tokenizer_revision: str,
    expected_chat_template_digest: str | None,
) -> None:
    """Verify the exact tokenizer/template identity before loading executable templates."""
    if not directory.is_absolute() or not directory.is_dir():
        raise LLMRequestBudgetError("tokenizer artifact directory is unavailable")
    tokenizer_files = [directory / name for name in _TOKENIZER_FILES if (directory / name).is_file()]
    if not tokenizer_files:
        raise LLMRequestBudgetError("tokenizer artifact directory contains no tokenizer")
    if _tokenizer_manifest_digest(directory, tokenizer_files) != expected_tokenizer_revision:
        raise LLMRequestBudgetError("tokenizer artifact revision does not match the profile")
    external_template = directory / "chat_template.jinja"
    template_digest: str | None = None
    if external_template.is_file():
        template_digest = _sha256_file(external_template)
    else:
        config = directory / "tokenizer_config.json"
        try:
            body = json.loads(config.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise LLMRequestBudgetError("tokenizer chat template is unavailable") from None
        template = body.get("chat_template") if isinstance(body, dict) else None
        if isinstance(template, str):
            template_digest = hashlib.sha256(template.encode("utf-8")).hexdigest()
    if template_digest != expected_chat_template_digest:
        raise LLMRequestBudgetError("tokenizer chat template does not match the profile")


class HuggingFaceTokenCounter:
    """Exact local token counter using the pinned model tokenizer and chat template."""

    def __init__(
        self,
        *,
        model_directory: str | Path,
        tokenizer_revision: str,
        chat_template_digest: str | None,
    ) -> None:
        directory = Path(model_directory)
        verify_tokenizer_artifacts(
            directory,
            expected_tokenizer_revision=tokenizer_revision,
            expected_chat_template_digest=chat_template_digest,
        )
        try:
            from transformers import AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(
                directory,
                local_files_only=True,
                trust_remote_code=False,
            )
        except Exception:
            raise LLMRequestBudgetError("fixed tokenizer could not be loaded") from None
        self._revision = tokenizer_revision

    @property
    def tokenizer_revision(self) -> str:
        return self._revision

    def count_request(self, request: ChatCompletionRequest) -> int:
        messages = [{"role": message.role, "content": message.content} for message in request.messages]
        kwargs: dict[str, Any] = {
            "tokenize": True,
            "add_generation_prompt": True,
            # Transformers 5 returns a BatchEncoding by default.  The budget
            # boundary needs the exact flat input-id sequence, so request that
            # stable representation explicitly rather than depending on a
            # version-specific default.
            "return_dict": False,
        }
        if request.tools is not None:
            kwargs["tools"] = list(request.tools)
        try:
            encoded = self._tokenizer.apply_chat_template(messages, **kwargs)
        except Exception:
            raise LLMRequestBudgetError("fixed tokenizer could not render the chat request") from None
        if not isinstance(encoded, list) or any(not isinstance(item, int) for item in encoded):
            raise LLMRequestBudgetError("fixed tokenizer returned an invalid token sequence")
        return len(encoded)


class TokenCounter(Protocol):
    """Counts tokens of a complete chat request for a fixed tokenizer revision.

    Implementations tokenize the request the way it will actually be sent on the wire
    (chat template + tool/output schema + messages), so the budget check reflects the
    real request rather than an approximate textual rendering.
    """

    @property
    def tokenizer_revision(self) -> str:
        ...

    def count_request(self, request: ChatCompletionRequest) -> int:
        ...


__all__ = ["HuggingFaceTokenCounter", "TokenCounter", "verify_tokenizer_artifacts"]
