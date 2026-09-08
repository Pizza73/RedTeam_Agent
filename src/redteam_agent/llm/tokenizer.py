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

from typing import Protocol

from redteam_agent.llm.client import ChatCompletionRequest


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


__all__ = ["TokenCounter"]
