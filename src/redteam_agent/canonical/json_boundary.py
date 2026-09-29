"""Trust-boundary JSON parsing (H-02) and the wire validation entry point.

``json.loads`` (and pydantic's own JSON parser) silently collapse duplicate
object keys, keeping the last value. At a real trust boundary that is a parser
differential: a value can be hidden from a validator that only sees the
survivor. :func:`parse_json_no_duplicate_keys` rejects duplicate keys at every
nesting level, and :func:`load_model_from_json` is the single entry point for
turning untrusted JSON text into a validated strict boundary model.

Error messages here are deliberately content-free: they never echo the raw
input, offending key names, or field values, so malformed input (which may
contain secrets) cannot leak into exceptions or logs.
"""

from __future__ import annotations

import json
from typing import Any, cast

from pydantic import BaseModel

from redteam_agent.canonical.immutable import CanonicalJsonObject, JsonValue
from redteam_agent.errors import DuplicateJsonKeyError, PydanticBoundaryValidationError

__all__ = [
    "CanonicalJsonObject",
    "JsonValue",
    "load_model_from_json",
    "parse_json_no_duplicate_keys",
]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that fails closed on any repeated key.

    The offending key is intentionally not included in the error to avoid
    leaking attacker-controlled content.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError("duplicate JSON key at trust boundary")
        result[key] = value
    return result


def parse_json_no_duplicate_keys(raw: str | bytes) -> JsonValue:
    """Parse untrusted JSON text, rejecting duplicate keys at any depth."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PydanticBoundaryValidationError("trust-boundary JSON is not valid UTF-8") from exc
    try:
        return cast("JsonValue", json.loads(raw, object_pairs_hook=_reject_duplicate_pairs))
    except DuplicateJsonKeyError:
        raise
    except json.JSONDecodeError as exc:
        # Report position only, never the surrounding input text.
        raise PydanticBoundaryValidationError(f"malformed JSON at line {exc.lineno} column {exc.colno}") from None


def _redact_validation_error(exc: Any) -> str:
    """Summarize a pydantic ValidationError by error-type counts only.

    Neither field names/paths (which for an unknown extra field is attacker
    controlled) nor input values are included, so malformed input that may carry
    secret material cannot leak into exceptions or logs.
    """
    counts: dict[str, int] = {}
    for error in exc.errors(include_url=False):
        error_type = str(error.get("type", "invalid"))
        counts[error_type] = counts.get(error_type, 0) + 1
    summary = ", ".join(f"{error_type} x{count}" for error_type, count in sorted(counts.items()))
    return f"boundary validation failed: {summary}"


def load_model_from_json[ModelT: BaseModel](model_cls: type[ModelT], raw: str | bytes) -> ModelT:
    """Validate untrusted JSON text into a strict boundary model.

    Duplicate keys are rejected *before* pydantic sees the data; JSON-native
    validation then accepts wire forms (ISO datetime strings, arrays for
    tuples/frozensets) while strict mode still rejects unknown fields and
    numeric-string coercion.
    """
    from pydantic import ValidationError

    parse_json_no_duplicate_keys(raw)  # raises on duplicate keys
    try:
        return model_cls.model_validate_json(raw)
    except ValidationError as exc:
        raise PydanticBoundaryValidationError(_redact_validation_error(exc)) from None
