"""Strict models for untrusted and authorization boundaries."""

from pydantic import BaseModel, ConfigDict


class StrictBoundaryModel(BaseModel):
    """Reject unknown fields and implicit coercion at a trust boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)


class StrictImmutableBoundaryModel(StrictBoundaryModel):
    """Strict boundary model whose direct attributes cannot be reassigned."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
