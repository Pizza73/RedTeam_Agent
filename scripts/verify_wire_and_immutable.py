"""Probe pydantic v2 wire/strict behaviour to design the trust boundary.

Questions this answers (run: .venv/bin/python scripts/verify_wire_and_immutable.py):

* Does ``model_validate_json`` under ``strict=True`` accept JSON-native forms
  (ISO string -> datetime, array -> tuple/frozenset) while still rejecting
  ``"3" -> int`` and unknown fields?
* Can a custom type deep-freeze a JSON object (before+after validators) while
  keeping strict value validation and round-tripping through model_validate?

Exits non-zero on any surprise so the design is not built on a false premise.
"""

from __future__ import annotations

import sys
from datetime import datetime
from types import MappingProxyType
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, GetCoreSchemaHandler, ValidationError
from pydantic_core import core_schema

type JsonValue = str | bool | int | float | None | list[JsonValue] | dict[str, JsonValue]


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({k: _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(v) for v in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value


class _Frozen:
    @classmethod
    def __get_pydantic_core_schema__(cls, source: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        base = handler.generate_schema(dict[str, JsonValue])
        return core_schema.no_info_before_validator_function(
            _thaw,
            core_schema.no_info_after_validator_function(_deep_freeze, base),
            serialization=core_schema.plain_serializer_function_ser_schema(_thaw),
        )


CanonicalJsonObject = Annotated[Any, _Frozen()]


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    when: datetime
    ports: tuple[int, ...]
    caps: frozenset[str]
    n: int
    obj: CanonicalJsonObject


def _check(label: str, cond: bool, failures: list[str]) -> None:
    if not cond:
        failures.append(label)


def main() -> int:
    failures: list[str] = []

    good = (
        '{"when": "2026-01-02T03:04:05Z", "ports": [80, 443], '
        '"caps": ["a", "b"], "n": 5, "obj": {"k": [1, 2], "d": {"x": "y"}}}'
    )
    model = WireModel.model_validate_json(good)
    _check("datetime parsed", isinstance(model.when, datetime), failures)
    _check("tuple parsed", model.ports == (80, 443), failures)
    _check("frozenset parsed", model.caps == frozenset({"a", "b"}), failures)

    # obj is deeply immutable.
    try:
        model.obj["k"][0] = 99  # type: ignore[index]
        failures.append("nested list was mutable")
    except (TypeError, AttributeError):
        pass
    try:
        model.obj["new"] = 1  # type: ignore[index]
        failures.append("nested object was mutable")
    except TypeError:
        pass

    # Round-trip via model_dump -> model_validate keeps immutability + equality.
    dumped = model.model_dump(mode="python")
    _check("dump obj thawed to dict", isinstance(dumped["obj"], dict), failures)
    revalidated = WireModel.model_validate(dumped)
    _check("roundtrip equal", revalidated == model, failures)

    # str -> int is still rejected under strict.
    try:
        WireModel.model_validate_json(good.replace('"n": 5', '"n": "5"'))
        failures.append("str->int coercion accepted")
    except ValidationError:
        pass

    # unknown field rejected.
    try:
        WireModel.model_validate_json(good[:-1] + ', "extra": 1}')
        failures.append("unknown field accepted")
    except ValidationError:
        pass

    if failures:
        for line in failures:
            print(f"FAIL: {line}")
        return 1
    print("OK: wire + deep-immutable boundary behaviour confirmed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
