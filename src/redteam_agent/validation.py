"""Translate Pydantic errors into typed boundary errors when requested by services."""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .canonical import canonical_loads, canonicalize
from .errors import BoundaryJsonParseError, PydanticBoundaryValidationError

BoundaryT = TypeVar("BoundaryT", bound=BaseModel)


def validate_boundary(model_type: type[BoundaryT], value: Any) -> BoundaryT:
    try:
        return model_type.model_validate(value)
    except ValidationError as exc:
        raise PydanticBoundaryValidationError(str(exc)) from exc


def parse_boundary_json(
    raw: str | bytes,
    model_type: type[BoundaryT],
) -> BoundaryT:
    """Parse every external/LLM JSON boundary with duplicate-key detection.

    Calling ``BaseModel.model_validate_json`` at a trust boundary is forbidden: JSON
    parsers commonly retain the last duplicate key.  This entry point rejects both
    top-level and nested duplicates before strict Pydantic validation.
    """

    try:
        value = canonical_loads(raw)
        return model_type.model_validate_json(canonicalize(value))
    except ValidationError as exc:
        raise PydanticBoundaryValidationError(str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise BoundaryJsonParseError(str(exc)) from exc
