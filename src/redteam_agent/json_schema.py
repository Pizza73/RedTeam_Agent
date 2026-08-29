"""Typed, fail-closed boundary around the runtime JSON Schema dependency."""

from __future__ import annotations

from collections.abc import Iterable
from importlib import import_module
from typing import Protocol, cast


class JsonSchemaDefinitionError(ValueError):
    """A trusted schema definition is malformed or unsupported."""


class JsonSchemaEvaluationError(ValueError):
    """A schema could not be evaluated safely."""


class _Validator(Protocol):
    def iter_errors(self, instance: object) -> Iterable[object]: ...


class _ValidatorFactory(Protocol):
    def __call__(self, schema: object) -> _Validator: ...

    def check_schema(self, schema: object) -> None: ...


def _draft_2020_12_validator() -> _ValidatorFactory:
    module = import_module("jsonschema")
    return cast(_ValidatorFactory, module.Draft202012Validator)


def validate_json_schema_definition(schema: object) -> None:
    try:
        _draft_2020_12_validator().check_schema(schema)
    except Exception as exc:
        raise JsonSchemaDefinitionError("invalid JSON Schema definition") from exc


def is_json_schema_instance_valid(schema: object, instance: object) -> bool:
    try:
        return not any(_draft_2020_12_validator()(schema).iter_errors(instance))
    except Exception as exc:
        raise JsonSchemaEvaluationError("JSON Schema evaluation failed") from exc
