"""RedTeam Canonical JSON v1.

The format is a fixed, restricted JCS-equivalent profile: UTF-8, sorted object keys,
minimal separators, finite JSON numbers only, and no implicit Python-object conversion.
Datetime conversion is allowed only when a caller explicitly passes a datetime or dumps
a typed model through the digest helpers; it is normalized to UTC RFC 3339 with a ``Z``.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from typing import Any

from .models import CanonicalJsonObject


def _datetime_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("canonical datetime must be timezone-aware")
    normalized = value.astimezone(UTC)
    if normalized.microsecond:
        text = normalized.isoformat(timespec="microseconds")
    else:
        text = normalized.isoformat(timespec="seconds")
    return text.replace("+00:00", "Z")


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and Infinity are forbidden")
        return 0 if value == 0 else value
    if isinstance(value, datetime):
        return _datetime_text(value)
    if isinstance(value, CanonicalJsonObject):
        return _canonical_value(value.to_dict())
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        return {key: _canonical_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for an explicitly converted value."""

    converted = _canonical_value(value)
    return json.dumps(
        converted,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_loads(data: str | bytes) -> Any:
    """Parse JSON while rejecting duplicate object keys and non-finite constants."""

    if isinstance(data, bytes):
        # ``json.loads(bytes)`` also auto-detects UTF-16/32.  Security-boundary
        # JSON is deliberately UTF-8 only so one byte stream has one decoding.
        data = data.decode("utf-8", errors="strict")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(
        data,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )
