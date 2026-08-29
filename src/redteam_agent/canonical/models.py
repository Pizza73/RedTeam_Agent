"""Deeply immutable representation of a JSON object."""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping
from typing import Any, cast

from pydantic_core import core_schema

type JsonScalar = None | bool | int | float | str
type FrozenJsonValue = JsonScalar | tuple[FrozenJsonValue, ...] | CanonicalJsonObject


def _freeze(value: Any) -> FrozenJsonValue:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are forbidden in canonical JSON")
        return 0 if value == 0 else value
    if isinstance(value, CanonicalJsonObject):
        return value
    if isinstance(value, dict):
        return CanonicalJsonObject(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _thaw(value: FrozenJsonValue) -> Any:
    if isinstance(value, CanonicalJsonObject):
        return value.to_dict()
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


class CanonicalJsonObject(Mapping[str, FrozenJsonValue]):
    """Sorted, recursively immutable JSON object.

    It deliberately accepts only a real ``dict`` at validation boundaries. Arbitrary
    Mapping implementations, bytes, sets, datetime values and Python objects are not
    silently converted.
    """

    __slots__ = ("_items", "_mapping")

    def __init__(self, value: dict[str, Any]) -> None:
        if not isinstance(value, dict):
            raise TypeError("CanonicalJsonObject requires a dict")
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        self._items = tuple((key, _freeze(value[key])) for key in sorted(value))
        self._mapping = dict(self._items)

    def __getitem__(self, key: str) -> FrozenJsonValue:
        return self._mapping[key]

    def __iter__(self) -> Iterator[str]:
        return iter(key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"CanonicalJsonObject({self.to_dict()!r})"

    def __hash__(self) -> int:
        return hash(self._items)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CanonicalJsonObject):
            return self._items == other._items
        return False

    def to_dict(self) -> dict[str, Any]:
        return {key: _thaw(value) for key, value in self._items}

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: Any
    ) -> core_schema.CoreSchema:
        del source_type, handler

        def validate(value: Any) -> CanonicalJsonObject:
            if isinstance(value, cls):
                return value
            if not isinstance(value, dict):
                raise TypeError("CanonicalJsonObject requires a JSON object")
            return cls(value)

        return core_schema.no_info_plain_validator_function(
            validate,
            json_schema_input_schema=core_schema.dict_schema(
                keys_schema=core_schema.str_schema(strict=True),
                values_schema=core_schema.any_schema(),
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda value: value.to_dict(),
                return_schema=core_schema.dict_schema(),
                when_used="always",
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: Any, handler: Any) -> dict[str, Any]:
        generated = cast(dict[str, Any], handler(schema))
        generated.update({"type": "object", "additionalProperties": True})
        return generated
