"""Deterministic canonical JSON serialization for digest computation.

The goal is that the same logical value always produces the same bytes,
regardless of Python dict insertion order or set iteration order. Object keys
are sorted; arrays preserve order (list/tuple order can be semantically
meaningful); sets/frozensets are order-independent and are sorted by the
canonical encoding of their elements.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from redteam_agent.errors import CanonicalJsonError


def _encode_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        # Naive datetimes are ambiguous; require an explicit timezone.
        raise CanonicalJsonError("datetime without timezone cannot be canonicalized")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):  # pragma: no cover - handled above, defensive
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalJsonError("non-finite float cannot be canonicalized")
        # ``repr`` gives the shortest round-trippable representation.
        return repr(value)
    if isinstance(value, datetime):
        return json.dumps(_encode_datetime(value))
    if isinstance(value, Mapping):
        items = []
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise CanonicalJsonError(f"non-string object key: {key!r}")
            items.append(f"{json.dumps(key, ensure_ascii=False)}:{_encode(value[key])}")
        return "{" + ",".join(items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, (set, frozenset)):
        encoded = sorted(_encode(item) for item in value)
        return "[" + ",".join(encoded) + "]"
    raise CanonicalJsonError(f"unsupported type for canonical JSON: {type(value).__name__}")


def canonical_dumps(value: Any) -> bytes:
    """Serialize ``value`` to deterministic canonical JSON bytes (UTF-8)."""
    return _encode(value).encode("utf-8")
