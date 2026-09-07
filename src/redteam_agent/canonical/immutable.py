"""Deeply-immutable canonical JSON object type (SystemDesign §6 / §22).

``frozen=True`` on a model only freezes attribute *binding*; a nested ``dict``
or ``list`` reached through a field stays mutable. Security-sensitive JSON
payloads (tool arguments, parameter schemas, redacted approval arguments) must
be immutable all the way down. ``CanonicalJsonObject`` validates the value as a
strict JSON object and then deep-freezes it: objects become read-only mappings
and arrays become tuples. Serialization thaws back to plain JSON for storage and
digest input, and digests are still re-verified on write/read/use.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, Any

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

type JsonValue = str | bool | int | float | None | list[JsonValue] | dict[str, JsonValue]
"""A JSON value: the standard null/boolean/number/string/array/object set."""


def deep_freeze(value: Any) -> Any:
    """Recursively convert dicts to read-only mappings and lists to tuples."""
    if isinstance(value, MappingProxyType):
        return value
    if isinstance(value, dict):
        return MappingProxyType({key: deep_freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(deep_freeze(item) for item in value)
    return value


def thaw(value: Any) -> Any:
    """Recursively convert read-only mappings/tuples back to plain dict/list."""
    if isinstance(value, MappingProxyType):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


class _CanonicalJsonObject:
    """Pydantic annotation that validates a strict JSON object and deep-freezes it."""

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        base = handler.generate_schema(dict[str, JsonValue])
        return core_schema.no_info_before_validator_function(
            thaw,  # accept previously-frozen values on re-validation
            core_schema.no_info_after_validator_function(deep_freeze, base),
            serialization=core_schema.plain_serializer_function_ser_schema(thaw),
        )


CanonicalJsonObject = Annotated[Any, _CanonicalJsonObject()]
"""A strict, deeply-immutable JSON object field on a boundary model."""
