"""Strict boundary base models (SystemDesign §6).

``StrictBoundaryModel`` rejects unknown fields (``extra='forbid'``) and implicit
type coercion (``strict=True``). ``StrictImmutableBoundaryModel`` additionally
freezes instances. These are applied to every trust-boundary model *and* its
nested models, so a nested object cannot smuggle unknown fields past a strict
outer model.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
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


def _deep_validation_input(value: Any) -> Any:
    """Copy nested models into primitive validation input without serializing.

    Pydantic may trust an already-created nested model instance during
    ``model_validate``.  ``model_copy(update=...)`` can therefore hide an
    invalid nested value unless every model layer is expanded first.  This
    conversion deliberately avoids Pydantic serialization, whose warnings may
    echo the invalid value.
    """
    if isinstance(value, BaseModel):
        return {
            name: _deep_validation_input(item)
            for name, item in value.__dict__.items()
            if not name.startswith("_")
        }
    if isinstance(value, MappingProxyType):
        return {key: _deep_json_input(item) for key, item in value.items()}
    if isinstance(value, Mapping):
        return {key: _deep_validation_input(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_deep_validation_input(item) for item in value)
    if isinstance(value, list):
        return [_deep_validation_input(item) for item in value]
    if isinstance(value, frozenset):
        return frozenset(_deep_validation_input(item) for item in value)
    if isinstance(value, set):
        return {_deep_validation_input(item) for item in value}
    return value


def _deep_json_input(value: Any) -> Any:
    """Thaw a CanonicalJsonObject while preserving JSON array semantics."""
    if isinstance(value, Mapping):
        return {key: _deep_json_input(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_deep_json_input(item) for item in value]
    return value


def strict_revalidate[ModelT: BaseModel](model: ModelT) -> ModelT:
    """Strictly revalidate a model and all nested model instances."""
    return type(model).model_validate(_deep_validation_input(model))
