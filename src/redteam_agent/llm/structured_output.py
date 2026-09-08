"""Structured-output request building and raw-output extraction (SystemDesign §6.1/§6.2).

Native JSON-schema-constrained decoding is the first choice. The only permitted
fallback is an explicitly configured, capability-tested tool-output JSON mode; there
is no implicit switch between them at runtime. Free-form prose is never accepted as a
structured proposal: if the chosen mode did not return a structured body, the caller
raises rather than parsing text.
"""

from __future__ import annotations

from typing import Any

from redteam_agent.errors import LLMTransportError
from redteam_agent.llm.client import ChatCompletionRequest, ChatCompletionResult, ChatMessage
from redteam_agent.llm.schemas import actual_schema_json_schema


def build_chat_request(
    *,
    schema_name: str,
    structured_output_mode: str,
    tool_output_support: bool,
    system_message_handling: str,
    system_instructions: str,
    user_content: str,
    model: str,
    max_tokens: int,
    temperature: float,
) -> ChatCompletionRequest:
    """Build a strict structured-output chat request for one actual schema."""
    schema = actual_schema_json_schema(schema_name)
    messages: tuple[ChatMessage, ...]
    if system_message_handling == "system_role":
        messages = (
            ChatMessage(role="system", content=system_instructions),
            ChatMessage(role="user", content=user_content),
        )
    elif system_message_handling == "merge_into_first_user":
        merged = f"{system_instructions}\n\n{user_content}"
        messages = (ChatMessage(role="user", content=merged),)
    else:
        raise LLMTransportError("unsupported system_message_handling", reason="config_error")

    if structured_output_mode == "native_json_schema":
        return ChatCompletionRequest(
            model=model, messages=messages, max_tokens=max_tokens, temperature=temperature,
            response_format={
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": schema, "strict": True},
            },
        )
    if structured_output_mode == "tool_output_json":
        if not tool_output_support:
            raise LLMTransportError("tool-output mode requires tool_output_support", reason="config_error")
        tool = {
            "type": "function",
            "function": {"name": schema_name, "description": f"emit a {schema_name}", "parameters": schema},
        }
        return ChatCompletionRequest(
            model=model, messages=messages, max_tokens=max_tokens, temperature=temperature,
            tools=(tool,), tool_choice={"type": "function", "function": {"name": schema_name}},
        )
    raise LLMTransportError("unsupported structured_output_mode", reason="config_error")


def extract_raw_output(
    result: ChatCompletionResult, structured_output_mode: str, schema_name: str
) -> str:
    """Extract the raw JSON body from a completion for the chosen mode.

    Never parses free-form prose: an absent structured body is a transport error. In
    tool-output mode the returned tool-call function name must equal the requested
    schema/tool name before its arguments are accepted, so arguments from an
    unexpected tool are never treated as the structured output.
    """
    if structured_output_mode == "native_json_schema":
        if result.content is None or not result.content.strip():
            raise LLMTransportError(
                "native structured output returned no content", reason="malformed_response"
            )
        return result.content
    if structured_output_mode == "tool_output_json":
        if result.tool_call_name != schema_name:
            raise LLMTransportError(
                "tool-output call name does not match the requested schema/tool",
                reason="malformed_response",
            )
        if result.tool_call_arguments is None or not result.tool_call_arguments.strip():
            raise LLMTransportError(
                "tool-output mode returned no tool call arguments", reason="malformed_response"
            )
        return result.tool_call_arguments
    raise LLMTransportError("unsupported structured_output_mode", reason="config_error")


def rendered_schema_payload(request: ChatCompletionRequest) -> dict[str, Any]:
    """A safe, redacted attempt-binding view of the request (no raw context echoed)."""
    return {
        "model": request.model,
        "message_roles": [m.role for m in request.messages],
        "message_token_lengths": [len(m.content) for m in request.messages],
        "structured_output": "native" if request.response_format is not None else "tool",
        "max_tokens": request.max_tokens,
    }


__all__ = [
    "build_chat_request",
    "extract_raw_output",
    "rendered_schema_payload",
]
