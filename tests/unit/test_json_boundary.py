"""Trust-boundary JSON parsing tests (H-02, wire positives, G redaction)."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ConfigDict

from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.canonical.json_boundary import (
    load_model_from_json,
    parse_json_no_duplicate_keys,
)
from redteam_agent.errors import DuplicateJsonKeyError, PydanticBoundaryValidationError
from redteam_agent.models.base import StrictImmutableBoundaryModel


class _Wire(StrictImmutableBoundaryModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    n: int
    when: datetime
    ports: tuple[int, ...]
    obj: CanonicalJsonObject


_GOOD = '{"n": 5, "when": "2026-01-02T03:04:05Z", "ports": [80, 443], "obj": {"k": [1, 2]}}'


def test_wire_positive_roundtrip() -> None:
    model = load_model_from_json(_Wire, _GOOD)
    assert model.n == 5
    assert isinstance(model.when, datetime)
    assert model.ports == (80, 443)
    assert model.obj["k"] == (1, 2)


def test_top_level_duplicate_key_rejected() -> None:
    with pytest.raises(DuplicateJsonKeyError):
        parse_json_no_duplicate_keys('{"a": 1, "a": 2}')


def test_nested_duplicate_key_rejected() -> None:
    with pytest.raises(DuplicateJsonKeyError):
        parse_json_no_duplicate_keys('{"outer": {"b": 1, "b": 2}}')


def test_duplicate_key_rejected_via_model_loader() -> None:
    with pytest.raises(DuplicateJsonKeyError):
        load_model_from_json(_Wire, '{"n": 1, "n": 2, "when": "2026-01-02T03:04:05Z", "ports": [], "obj": {}}')


def test_numeric_string_coercion_rejected() -> None:
    with pytest.raises(PydanticBoundaryValidationError):
        load_model_from_json(_Wire, '{"n": "5", "when": "2026-01-02T03:04:05Z", "ports": [], "obj": {}}')


def test_unknown_field_rejected() -> None:
    with pytest.raises(PydanticBoundaryValidationError):
        load_model_from_json(
            _Wire, '{"n": 1, "when": "2026-01-02T03:04:05Z", "ports": [], "obj": {}, "extra": 1}'
        )


def test_validation_error_does_not_leak_field_names_or_values() -> None:
    secret = "SUPERSECRETVALUE"
    # The unknown field key and value both carry secret material.
    payload = f'{{"n": 1, "when": "2026-01-02T03:04:05Z", "ports": [], "obj": {{}}, "{secret}_key": "{secret}"}}'
    with pytest.raises(PydanticBoundaryValidationError) as exc_info:
        load_model_from_json(_Wire, payload)
    message = str(exc_info.value)
    assert secret not in message
    # The chained cause must also not carry the raw input.
    assert exc_info.value.__cause__ is None


def test_malformed_json_reports_position_only() -> None:
    with pytest.raises(PydanticBoundaryValidationError) as exc_info:
        parse_json_no_duplicate_keys('{"n": SECRETTOKEN}')
    assert "SECRETTOKEN" not in str(exc_info.value)
