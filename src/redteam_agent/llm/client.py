"""A small explicit vLLM ``chat_completions`` client (SystemDesign §7 / §38).

The repository pins no Pydantic AI dependency, so this is the explicit
OpenAI-compatible HTTP client whose behaviour meets the documented contract:

* Wire API is fixed to ``chat_completions``; there is no implicit fallback to a
  Responses API, another model, or another schema mode.
* SDK-style automatic retries are disabled (``retries=0``); the gateway owns the
  separate validation / transport / graph retry budgets.
* A finite timeout is always set; a timed-out or cancelled request never yields a
  published proposal/analysis, only safe failure metadata.

Tests drive this through an ``httpx`` mock transport (a deterministic fake
OpenAI-compatible server), so the real request/response code path is exercised
without a real vLLM server.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import httpx

from redteam_agent.errors import LLMTransportError
from redteam_agent.llm.secrets import APIKeySource, authorization_headers


class CancellationToken:
    """A one-way cancellation flag checked before send and after receive."""

    __slots__ = ("_cancelled",)

    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def request_started(self) -> None:
        """Hook invoked immediately before the blocking HTTP send."""

    def request_finished(self) -> None:
        """Hook invoked after the HTTP call terminates."""

    @property
    def cancelled(self) -> bool:
        return self._cancelled


@dataclass(frozen=True)
class ChatMessage:
    role: Literal["system", "user", "assistant", "tool"]
    content: str


@dataclass(frozen=True)
class ChatCompletionRequest:
    model: str
    messages: tuple[ChatMessage, ...]
    max_tokens: int
    temperature: float
    response_format: dict[str, Any] | None = None
    tools: tuple[dict[str, Any], ...] | None = None
    tool_choice: dict[str, Any] | None = None
    structured_outputs: dict[str, Any] | None = None
    guided_decoding_backend: Literal["xgrammar"] | None = None
    seed: int | None = None


@dataclass(frozen=True)
class ChatCompletionResult:
    content: str | None
    tool_call_arguments: str | None
    finish_reason: str
    tool_call_name: str | None = None


class VLLMChatClient:
    """Synchronous OpenAI-compatible chat-completions client for a local vLLM."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key_source: APIKeySource | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not (base_url.startswith("http://") or base_url.startswith("https://")):
            raise LLMTransportError("vLLM base_url must be an http(s) URL", reason="config_error")
        self._base_url = base_url.rstrip("/")
        self._api_key_source = api_key_source
        # retries=0 disables httpx connection-level retries; there is no request retry.
        self._transport = transport
        self._direct_network = transport is None

    @property
    def uses_direct_network_transport(self) -> bool:
        """Whether this client owns the production, retry-disabled HTTP transport.

        Injected transports are useful for deterministic tests, but responses produced
        by them are test-double evidence.  Keeping this decision inside the client
        prevents a caller from upgrading a mock transport with an evidence label.
        """
        return self._direct_network

    @property
    def base_url(self) -> str:
        return self._base_url

    def complete(
        self,
        request: ChatCompletionRequest,
        *,
        timeout_seconds: float,
        cancel_token: CancellationToken | None = None,
    ) -> ChatCompletionResult:
        if timeout_seconds <= 0:
            raise LLMTransportError("request timeout must be positive", reason="config_error")
        if cancel_token is not None and cancel_token.cancelled:
            # Cancelled before the request was ever sent: this is NOT in-flight
            # cancellation evidence (no request reached the network).
            raise LLMTransportError("request cancelled before send", reason="cancelled_before_send")
        payload = self._payload(request)
        # A direct request owns its transport for exactly one call.  This avoids
        # sharing a transport that one short-lived httpx.Client may close while a
        # concurrent qualification worker is still using it.
        transport = (
            httpx.HTTPTransport(retries=0)
            if self._direct_network
            else self._transport
        )
        try:
            with httpx.Client(
                transport=transport,
                timeout=httpx.Timeout(timeout_seconds),
                headers=authorization_headers(self._api_key_source),
            ) as client:
                if cancel_token is not None:
                    cancel_token.request_started()
                try:
                    response = client.post(f"{self._base_url}/chat/completions", json=payload)
                finally:
                    if cancel_token is not None:
                        cancel_token.request_finished()
        except httpx.TimeoutException as exc:
            raise LLMTransportError("vLLM request timed out", reason="timeout") from exc
        except httpx.ConnectError as exc:
            raise LLMTransportError("vLLM connection error", reason="connect_error") from exc
        except httpx.HTTPError as exc:
            raise LLMTransportError("vLLM transport error", reason="protocol_error") from exc
        if cancel_token is not None and cancel_token.cancelled:
            # The request reached the network and a cancellation fired while it was in
            # flight: the (late) response is discarded and never published.
            raise LLMTransportError(
                "request cancelled in flight; late response discarded", reason="cancelled_in_flight"
            )
        if response.status_code != 200:
            raise LLMTransportError(f"vLLM returned HTTP {response.status_code}", reason="http_status")
        return self._parse(response)

    @staticmethod
    def _payload(request: ChatCompletionRequest) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": False,
        }
        if request.response_format is not None:
            payload["response_format"] = request.response_format
        if request.tools is not None:
            payload["tools"] = list(request.tools)
        if request.tool_choice is not None:
            payload["tool_choice"] = request.tool_choice
        if request.structured_outputs is not None:
            payload["structured_outputs"] = request.structured_outputs
        if request.guided_decoding_backend is not None:
            payload["guided_decoding_backend"] = request.guided_decoding_backend
        if request.seed is not None:
            payload["seed"] = request.seed
        return payload

    @staticmethod
    def _parse(response: httpx.Response) -> ChatCompletionResult:
        try:
            body = response.json()
        except ValueError as exc:
            raise LLMTransportError("vLLM response was not JSON", reason="malformed_response") from exc
        if not isinstance(body, dict):
            raise LLMTransportError("vLLM response was not a JSON object", reason="malformed_response")
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMTransportError("vLLM response had no choices", reason="malformed_response")
        first = choices[0]
        if not isinstance(first, dict):
            raise LLMTransportError("vLLM choice was malformed", reason="malformed_response")
        message = first.get("message")
        if not isinstance(message, dict):
            raise LLMTransportError("vLLM choice had no message", reason="malformed_response")
        finish_reason = str(first.get("finish_reason", ""))
        content = message.get("content")
        tool_call_arguments: str | None = None
        tool_call_name: str | None = None
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            call = tool_calls[0]
            if isinstance(call, dict):
                function = call.get("function")
                if isinstance(function, dict):
                    arguments = function.get("arguments")
                    if isinstance(arguments, str):
                        tool_call_arguments = arguments
                    name = function.get("name")
                    if isinstance(name, str):
                        tool_call_name = name
        return ChatCompletionResult(
            content=content if isinstance(content, str) else None,
            tool_call_arguments=tool_call_arguments,
            finish_reason=finish_reason,
            tool_call_name=tool_call_name,
        )


__all__ = [
    "CancellationToken",
    "ChatCompletionRequest",
    "ChatCompletionResult",
    "ChatMessage",
    "VLLMChatClient",
]
