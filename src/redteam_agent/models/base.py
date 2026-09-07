"""Strict boundary base models (SystemDesign §6).

``StrictBoundaryModel`` rejects unknown fields (``extra='forbid'``) and implicit
type coercion (``strict=True``). ``StrictImmutableBoundaryModel`` additionally
freezes instances. These are applied to every trust-boundary model *and* its
nested models, so a nested object cannot smuggle unknown fields past a strict
outer model.
"""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict

from redteam_agent.canonical.json_boundary import load_model_from_json

_Self = TypeVar("_Self", bound="StrictBoundaryModel")


class StrictBoundaryModel(BaseModel):
    """A model that forbids unknown fields and implicit coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)

    @classmethod
    def from_untrusted_json(cls: type[_Self], raw: str | bytes) -> _Self:
        """Parse untrusted JSON text at the trust boundary.

        Rejects duplicate JSON keys (any depth), unknown fields and coercion.
        """
        return load_model_from_json(cls, raw)

    def integrity_payload(self) -> dict[str, Any]:
        """Return a canonicalizable mapping of this model's fields."""
        return self.model_dump(mode="python")


class StrictImmutableBoundaryModel(StrictBoundaryModel):
    """A frozen strict boundary model."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
