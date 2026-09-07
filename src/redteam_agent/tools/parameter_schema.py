"""Safe, versioned JSON Schema subset validator for tool arguments (R01).

Tool ``parameter_schema`` is validated at the authorization entry against the
*exact* registered schema, not just an extractor's private argument model. Only
a fixed, closed subset of JSON Schema is supported; any unknown keyword or type
is rejected (fail closed), never treated as "allow anything". Objects are closed
by default: ``additionalProperties`` defaults to ``false`` so an undeclared
argument (a hidden destination, an extra secret field) is rejected. No implicit
coercion: a string is not an integer, a bool is not an integer.
"""

from __future__ import annotations

from typing import Any

from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import ParameterSchemaError

SCHEMA_GRAMMAR_REVISION = "parameter-schema-v1"

_SUPPORTED_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})
_SUPPORTED_KEYWORDS = frozenset(
    {
        "type", "properties", "required", "additionalProperties", "items",
        "const", "enum", "minimum", "maximum", "minItems",
    }
)


def _check_keywords(schema: dict[str, Any]) -> None:
    unknown = set(schema) - _SUPPORTED_KEYWORDS
    if unknown:
        raise ParameterSchemaError(f"unsupported schema keyword count: {len(unknown)}")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate(schema: Any, value: Any, path: str) -> None:
    if not isinstance(schema, dict):
        raise ParameterSchemaError(f"schema node is not an object at {path}")
    _check_keywords(schema)

    if "const" in schema and value != schema["const"]:
        raise ParameterSchemaError(f"const mismatch at {path}")
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or value not in enum:
            raise ParameterSchemaError(f"enum mismatch at {path}")

    declared_type = schema.get("type")
    if declared_type is not None:
        if declared_type not in _SUPPORTED_TYPES:
            raise ParameterSchemaError(f"unsupported schema type at {path}")
        _validate_type(declared_type, schema, value, path)


def _validate_type(declared_type: str, schema: dict[str, Any], value: Any, path: str) -> None:
    if declared_type == "object":
        _validate_object(schema, value, path)
    elif declared_type == "array":
        _validate_array(schema, value, path)
    elif declared_type == "string":
        if not isinstance(value, str):
            raise ParameterSchemaError(f"expected string at {path}")
    elif declared_type == "integer":
        if not _is_int(value):
            raise ParameterSchemaError(f"expected integer at {path}")
        _validate_bounds(schema, value, path)
    elif declared_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ParameterSchemaError(f"expected number at {path}")
        _validate_bounds(schema, value, path)
    elif declared_type == "boolean":
        if not isinstance(value, bool):
            raise ParameterSchemaError(f"expected boolean at {path}")
    elif declared_type == "null" and value is not None:
        raise ParameterSchemaError(f"expected null at {path}")


def _validate_bounds(schema: dict[str, Any], value: Any, path: str) -> None:
    if "minimum" in schema and value < schema["minimum"]:
        raise ParameterSchemaError(f"value below minimum at {path}")
    if "maximum" in schema and value > schema["maximum"]:
        raise ParameterSchemaError(f"value above maximum at {path}")


def _validate_object(schema: dict[str, Any], value: Any, path: str) -> None:
    if not isinstance(value, dict):
        raise ParameterSchemaError(f"expected object at {path}")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ParameterSchemaError(f"invalid properties at {path}")
    for required in schema.get("required", []):
        if required not in value:
            raise ParameterSchemaError(f"missing required property at {path}.{required}")
    additional = schema.get("additionalProperties", False)
    if additional not in (True, False):
        raise ParameterSchemaError(f"additionalProperties must be a boolean at {path}")
    for key, item in value.items():
        if key in properties:
            _validate(properties[key], item, f"{path}.{key}")
        elif not additional:
            raise ParameterSchemaError(f"unexpected property at {path}.{key}")


def _validate_array(schema: dict[str, Any], value: Any, path: str) -> None:
    if not isinstance(value, list):
        raise ParameterSchemaError(f"expected array at {path}")
    if "minItems" in schema and len(value) < schema["minItems"]:
        raise ParameterSchemaError(f"array too short at {path}")
    item_schema = schema.get("items")
    if item_schema is not None:
        for index, item in enumerate(value):
            _validate(item_schema, item, f"{path}[{index}]")


def validate_arguments(parameter_schema: Any, arguments: Any) -> None:
    """Validate arguments against the tool's registered parameter schema."""
    _validate(thaw(parameter_schema), thaw(arguments), "$")


def validate_schema_is_supported(parameter_schema: Any) -> None:
    """Reject a parameter schema that uses unsupported keywords/types (fail closed)."""
    _assert_schema_supported(thaw(parameter_schema), "$")


def _assert_schema_supported(schema: Any, path: str) -> None:
    if not isinstance(schema, dict):
        raise ParameterSchemaError(f"schema node is not an object at {path}")
    _check_keywords(schema)
    declared_type = schema.get("type")
    if declared_type is not None and declared_type not in _SUPPORTED_TYPES:
        raise ParameterSchemaError(f"unsupported schema type at {path}")
    for key, sub in schema.get("properties", {}).items():
        _assert_schema_supported(sub, f"{path}.{key}")
    if isinstance(schema.get("items"), dict):
        _assert_schema_supported(schema["items"], f"{path}[]")
