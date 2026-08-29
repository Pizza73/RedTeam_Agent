"""Domain-separated SHA-256 helpers."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable
from enum import Enum
from typing import Any, cast

from pydantic import BaseModel

from redteam_agent.errors import DigestIntegrityError

from .json import canonicalize
from .models import CanonicalJsonObject


def _explicit_digest_value(value: Any) -> Any:
    """Explicit model/set conversion before the strict canonical JSON API.

    A frozenset is known by the typed model to be unordered, so it is sorted here.
    Mutable sets and arbitrary objects remain forbidden.
    """

    if isinstance(value, BaseModel):
        return _explicit_digest_value(value.model_dump(mode="python"))
    if isinstance(value, CanonicalJsonObject):
        return _explicit_digest_value(value.to_dict())
    if isinstance(value, Enum):
        return _explicit_digest_value(value.value)
    if isinstance(value, frozenset):
        converted = [_explicit_digest_value(item) for item in value]
        return sorted(converted, key=canonicalize)
    if isinstance(value, dict):
        return {key: _explicit_digest_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_explicit_digest_value(item) for item in value]
    return value


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(_explicit_digest_value(value))).hexdigest()


def stable_id(prefix: str, value: Any) -> str:
    if not prefix or not prefix.replace("_", "").replace("-", "").isalnum():
        raise ValueError("stable ID prefix must be non-empty and token-safe")
    suffix = hashlib.sha256(canonicalize(_explicit_digest_value(value))).hexdigest()[:32]
    return f"{prefix}_{suffix}"


def model_payload(model: BaseModel, *, exclude: Iterable[str] = ()) -> dict[str, Any]:
    """Explicitly convert a typed model and omit self-referential digest fields."""

    return cast(
        dict[str, Any],
        _explicit_digest_value(model.model_dump(mode="python", exclude=set(exclude))),
    )


def digest_model(model: BaseModel, *, exclude: Iterable[str] = ()) -> str:
    return sha256_digest(model_payload(model, exclude=exclude))


def verify_model_digest(
    model: BaseModel,
    stored_digest: str,
    *,
    exclude: Iterable[str],
) -> None:
    actual = digest_model(model, exclude=exclude)
    if not hmac.compare_digest(actual, stored_digest):
        raise DigestIntegrityError("canonical digest verification failed")
