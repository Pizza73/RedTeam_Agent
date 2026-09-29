from __future__ import annotations

import pytest

from redteam_agent.errors import LLMTransportError
from redteam_agent.llm.structured_output import build_chat_request


def _contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def test_native_wire_schema_requires_union_tags_and_uses_singleton_enum() -> None:
    request = build_chat_request(
        schema_name="planner_output",
        structured_output_mode="native_json_schema",
        tool_output_support=True,
        system_message_handling="system_role",
        system_instructions="system",
        user_content="user",
        model="model",
        max_tokens=128,
        temperature=0.0,
    )

    assert request.response_format is not None
    assert request.structured_outputs is not None
    assert request.structured_outputs["json"] == request.response_format["json_schema"]["schema"]
    assert request.structured_outputs["disable_any_whitespace"] is True
    assert request.guided_decoding_backend == "xgrammar"
    schema = request.response_format["json_schema"]["schema"]
    action = schema["$defs"]["PlannerActionOutput"]
    create = schema["$defs"]["HypothesisCreateProposal"]
    assert action["properties"]["output_type"]["enum"] == ["action"]
    assert "output_type" in action["required"]
    assert create["properties"]["operation"]["enum"] == ["create"]
    assert "operation" in create["required"]
    json_value = schema["$defs"]["JsonValue"]
    assert not _contains_key(json_value, "$ref")
    assert any(branch.get("maxItems") == 2 for branch in json_value["anyOf"])
    assert action["properties"]["next_iteration_hints"]["maxItems"] == 2
    assert schema["$defs"]["ExecutionPlanProposal"]["properties"]["objective"][
        "maxLength"
    ] == 128
    assert not _contains_key(schema, "const")


def test_native_wire_schema_does_not_cap_fixed_object_below_required_fields() -> None:
    request = build_chat_request(
        schema_name="analysis_result",
        structured_output_mode="native_json_schema",
        tool_output_support=True,
        system_message_handling="system_role",
        system_instructions="system",
        user_content="user",
        model="model",
        max_tokens=128,
        temperature=0.0,
    )
    assert request.response_format is not None
    schema = request.response_format["json_schema"]["schema"]
    assert len(schema["required"]) > 8
    assert set(schema["required"]) == set(schema["properties"])
    assert "maxProperties" not in schema


def test_quality_context_request_variant_narrows_the_actual_union() -> None:
    request = build_chat_request(
        schema_name="planner_output",
        structured_output_mode="native_json_schema",
        tool_output_support=True,
        system_message_handling="system_role",
        system_instructions="system",
        user_content="user",
        model="model",
        max_tokens=128,
        temperature=0.0,
        wire_schema_variant="planner_context_request",
    )
    assert request.response_format is not None
    schema = request.response_format["json_schema"]["schema"]
    assert schema["oneOf"] == [{"$ref": "#/$defs/PlannerContextRequest"}]
    assert schema["discriminator"]["mapping"] == {
        "context_request": "#/$defs/PlannerContextRequest"
    }

    with pytest.raises(LLMTransportError):
        build_chat_request(
            schema_name="analysis_result",
            structured_output_mode="native_json_schema",
            tool_output_support=True,
            system_message_handling="system_role",
            system_instructions="system",
            user_content="user",
            model="model",
            max_tokens=128,
            temperature=0.0,
            wire_schema_variant="planner_context_request",
        )
