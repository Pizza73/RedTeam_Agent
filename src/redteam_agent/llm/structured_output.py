"""Structured-output request building and raw-output extraction (SystemDesign §6.1/§6.2).

Native JSON-schema-constrained decoding is the first choice. The only permitted
fallback is an explicitly configured, capability-tested tool-output JSON mode; there
is no implicit switch between them at runtime. Free-form prose is never accepted as a
structured proposal: if the chosen mode did not return a structured body, the caller
raises rather than parsing text.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from redteam_agent.errors import LLMTransportError
from redteam_agent.llm.client import ChatCompletionRequest, ChatCompletionResult, ChatMessage
from redteam_agent.llm.schemas import actual_schema_json_schema

STRUCTURED_OUTPUT_REQUEST_REVISION = "vllm-xgrammar-bounded-json-v2"


def _vllm_wire_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Preserve the application schema while avoiding two guided-decoding gaps.

    Some vLLM guided-decoding backends do not constrain Pydantic's ``const``
    discriminator fields through ``$ref`` / ``oneOf`` and also treat a defaulted
    discriminator as optional.  The strict application boundary requires those
    tags in order to select the union branch.  ``enum: [value]`` is equivalent to
    ``const: value`` here, and making such tag properties required only removes
    wire outputs that the application would reject as ``union_tag_not_found``.
    """

    def normalize(value: object) -> object:
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {
            key: normalize(item)
            for key, item in value.items()
            if key != "const"
        }
        if "const" in value:
            result["enum"] = [deepcopy(value["const"])]
        schema_type = value.get("type")
        if schema_type == "string" and "maxLength" not in result:
            # Keep capability near-limit probes meaningful (100 characters) while
            # preventing a constrained decoder from expanding an unconstrained
            # string until the request output limit.
            result["maxLength"] = 128
        if schema_type == "array":
            current_max = result.get("maxItems")
            if not isinstance(current_max, int) or current_max > 2:
                result["maxItems"] = 2
        if schema_type == "object" and isinstance(result.get("additionalProperties"), dict):
            current_properties = result.get("maxProperties")
            if not isinstance(current_properties, int) or current_properties > 8:
                result["maxProperties"] = 8
        properties = value.get("properties")
        if isinstance(properties, dict):
            discriminator_fields = [
                name
                for name, field_schema in properties.items()
                if isinstance(field_schema, dict) and "const" in field_schema
            ]
            if discriminator_fields:
                required = result.get("required")
                required_names = list(required) if isinstance(required, list) else []
                for name in discriminator_fields:
                    if name not in required_names:
                        required_names.append(name)
                result["required"] = required_names
            # xgrammar on vLLM 0.25 can otherwise remain indefinitely in the
            # whitespace state before an optional property or the closing brace
            # (observed with Gemma 4).  Requiring every declared property narrows
            # generation to a subset the unchanged strict Pydantic boundary accepts;
            # nullable/defaulted application fields are emitted explicitly as null.
            required = result.get("required")
            required_names = list(required) if isinstance(required, list) else []
            for name in properties:
                if name not in required_names:
                    required_names.append(name)
            result["required"] = required_names
        return result

    normalized = normalize(schema)
    if not isinstance(normalized, dict):  # pragma: no cover - schema input is typed
        raise LLMTransportError("actual schema normalization failed", reason="config_error")
    definitions = normalized.get("$defs")
    if isinstance(definitions, dict) and "JsonValue" in definitions:
        # ``JsonValue`` is recursively defined by the application boundary.  A
        # recursive generation grammar has no finite maximum output and caused
        # the real vLLM backend to continue until the HTTP deadline.  Planner
        # arguments only need a bounded JSON value on the wire; every value
        # admitted below is still accepted by the unchanged recursive boundary.
        scalar: list[dict[str, object]] = [
            {"type": "string", "maxLength": 128},
            {"type": "boolean"},
            {"type": "integer"},
            {"type": "number"},
            {"type": "null"},
        ]
        definitions["JsonValue"] = {
            "anyOf": [
                *deepcopy(scalar),
                {"type": "array", "maxItems": 2, "items": {"anyOf": deepcopy(scalar)}},
                {
                    "type": "object",
                    "maxProperties": 8,
                    "additionalProperties": {"anyOf": deepcopy(scalar)},
                },
            ]
        }
    return normalized


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
    seed: int | None = None,
    wire_schema_variant: str | None = None,
) -> ChatCompletionRequest:
    """Build a strict structured-output chat request for one actual schema."""
    source_schema = actual_schema_json_schema(schema_name)
    if wire_schema_variant == "planner_context_request":
        if schema_name != "planner_output":
            raise LLMTransportError("wire schema variant does not match schema", reason="config_error")
        source_schema["oneOf"] = [{"$ref": "#/$defs/PlannerContextRequest"}]
        source_schema["discriminator"] = {
            "propertyName": "output_type",
            "mapping": {"context_request": "#/$defs/PlannerContextRequest"},
        }
    elif wire_schema_variant is not None:
        raise LLMTransportError("unsupported wire schema variant", reason="config_error")
    schema = _vllm_wire_schema(source_schema)
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
            # vLLM 0.25 merges this per-request option with response_format's
            # JSON schema. Bounding whitespace prevents a valid JSON grammar
            # from spending the entire output budget on unconstrained newlines.
            structured_outputs={"json": schema, "disable_any_whitespace": True},
            # vLLM 0.25 still exposes this request field. Pinning xgrammar is
            # required because backend=auto may select a backend that ignores
            # the compact-whitespace option for this schema.
            guided_decoding_backend="xgrammar",
            seed=seed,
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
            seed=seed,
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
        "seed": request.seed,
    }


__all__ = [
    "STRUCTURED_OUTPUT_REQUEST_REVISION",
    "build_chat_request",
    "extract_raw_output",
    "rendered_schema_payload",
]
