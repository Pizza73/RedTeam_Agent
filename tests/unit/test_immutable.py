"""Deep-immutability of CanonicalJsonObject (SystemDesign §22, Codex point 4)."""

from __future__ import annotations

import pytest
from pydantic import ConfigDict

from redteam_agent.canonical.immutable import deep_freeze, thaw
from redteam_agent.canonical.json_boundary import CanonicalJsonObject
from redteam_agent.models.base import StrictImmutableBoundaryModel


class _Holder(StrictImmutableBoundaryModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    obj: CanonicalJsonObject


def test_nested_object_is_immutable() -> None:
    holder = _Holder.model_validate({"obj": {"a": {"b": 1}}})
    with pytest.raises(TypeError):
        holder.obj["a"]["b"] = 2  # type: ignore[index]
    with pytest.raises(TypeError):
        holder.obj["c"] = 3  # type: ignore[index]


def test_nested_list_becomes_immutable_tuple() -> None:
    holder = _Holder.model_validate({"obj": {"items": [1, 2, 3]}})
    assert holder.obj["items"] == (1, 2, 3)
    with pytest.raises((TypeError, AttributeError)):
        holder.obj["items"][0] = 9  # type: ignore[index]


def test_deep_freeze_thaw_roundtrip() -> None:
    original = {"a": [1, {"b": 2}], "c": "x"}
    frozen = deep_freeze(original)
    assert thaw(frozen) == original


def test_dump_thaws_for_serialization() -> None:
    holder = _Holder.model_validate({"obj": {"a": [1, 2]}})
    dumped = holder.model_dump(mode="python")
    assert dumped["obj"] == {"a": [1, 2]}
    assert isinstance(dumped["obj"], dict)
