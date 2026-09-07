"""Safe JSON Schema subset validator for tool arguments (R01)."""

from __future__ import annotations

import pytest

from redteam_agent.errors import ParameterSchemaError
from redteam_agent.tools.parameter_schema import validate_arguments, validate_schema_is_supported


def _obj(**properties):
    return {"type": "object", "properties": properties, "additionalProperties": False}


def test_accepts_declared_scalars() -> None:
    schema = _obj(
        name={"type": "string"},
        count={"type": "integer", "minimum": 0, "maximum": 10},
        ratio={"type": "number"},
        flag={"type": "boolean"},
        nothing={"type": "null"},
    )
    validate_arguments(schema, {"name": "x", "count": 5, "ratio": 1.5, "flag": True, "nothing": None})


def test_bool_is_not_integer() -> None:
    with pytest.raises(ParameterSchemaError):
        validate_arguments(_obj(count={"type": "integer"}), {"count": True})


def test_bool_is_not_number() -> None:
    with pytest.raises(ParameterSchemaError):
        validate_arguments(_obj(ratio={"type": "number"}), {"ratio": True})


def test_string_not_integer() -> None:
    with pytest.raises(ParameterSchemaError):
        validate_arguments(_obj(count={"type": "integer"}), {"count": "5"})


def test_minimum_and_maximum_bounds() -> None:
    schema = _obj(count={"type": "integer", "minimum": 1, "maximum": 3})
    with pytest.raises(ParameterSchemaError):
        validate_arguments(schema, {"count": 0})
    with pytest.raises(ParameterSchemaError):
        validate_arguments(schema, {"count": 4})


def test_unexpected_property_rejected_when_closed() -> None:
    with pytest.raises(ParameterSchemaError):
        validate_arguments(_obj(a={"type": "string"}), {"a": "x", "b": "y"})


def test_additional_properties_true_allows_extra() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": True}
    validate_arguments(schema, {"a": "x", "b": 99})


def test_missing_required_property_rejected() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": False}
    with pytest.raises(ParameterSchemaError):
        validate_arguments(schema, {})


def test_array_items_and_min_items() -> None:
    schema = _obj(xs={"type": "array", "items": {"type": "string"}, "minItems": 1})
    validate_arguments(schema, {"xs": ["a", "b"]})
    with pytest.raises(ParameterSchemaError):
        validate_arguments(schema, {"xs": []})
    with pytest.raises(ParameterSchemaError):
        validate_arguments(schema, {"xs": [1]})


def test_const_and_enum() -> None:
    validate_arguments(_obj(v={"const": "fixed"}), {"v": "fixed"})
    with pytest.raises(ParameterSchemaError):
        validate_arguments(_obj(v={"const": "fixed"}), {"v": "other"})
    validate_arguments(_obj(v={"enum": ["a", "b"]}), {"v": "b"})
    with pytest.raises(ParameterSchemaError):
        validate_arguments(_obj(v={"enum": ["a", "b"]}), {"v": "c"})


def test_null_type_requires_none() -> None:
    with pytest.raises(ParameterSchemaError):
        validate_arguments(_obj(v={"type": "null"}), {"v": 0})


def test_object_value_must_be_dict() -> None:
    with pytest.raises(ParameterSchemaError):
        validate_arguments({"type": "object", "properties": {}}, ["not", "a", "dict"])


def test_unsupported_keyword_fails_closed() -> None:
    with pytest.raises(ParameterSchemaError):
        validate_schema_is_supported({"type": "object", "patternProperties": {}})


def test_unsupported_type_fails_closed() -> None:
    with pytest.raises(ParameterSchemaError):
        validate_schema_is_supported({"type": "tuple"})


def test_supported_nested_schema_accepted() -> None:
    validate_schema_is_supported(
        {
            "type": "object",
            "properties": {"xs": {"type": "array", "items": {"type": "integer"}}},
            "additionalProperties": False,
        }
    )
