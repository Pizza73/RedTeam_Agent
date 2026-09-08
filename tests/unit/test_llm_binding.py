"""Unit tests for the current-mission binding check (SystemDesign §6.3 / §7)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from redteam_agent.errors import LLMProfileMismatchError
from redteam_agent.llm.binding import MissionBindingChecker
from redteam_agent.runtime.clock import ManualClock


@dataclass(frozen=True)
class _Mission:
    state: str
    mission_revision: int
    authorization_epoch: int
    llm_profile_digest: str


@dataclass(frozen=True)
class _Context:
    mission: _Mission


class _Resolver:
    def __init__(self, mission: _Mission) -> None:
        self._mission = mission

    def resolve(self, mission_id: str, *, now: datetime) -> _Context:
        return _Context(mission=self._mission)


def _checker(mission: _Mission) -> MissionBindingChecker:
    return MissionBindingChecker(
        context_resolver=_Resolver(mission), clock=ManualClock(datetime(2026, 9, 7, tzinfo=UTC)),
        mission_id="m1", expected_profile_digest="pd", expected_revision=2, expected_epoch=3,
    )


def test_matching_binding_passes() -> None:
    _checker(_Mission("RUNNING", 2, 3, "pd")).check()


@pytest.mark.parametrize("mission", [
    _Mission("PAUSED", 2, 3, "pd"),
    _Mission("RUNNING", 9, 3, "pd"),
    _Mission("RUNNING", 2, 9, "pd"),
    _Mission("RUNNING", 2, 3, "changed"),
])
def test_mismatch_fails_closed(mission: _Mission) -> None:
    with pytest.raises(LLMProfileMismatchError):
        _checker(mission).check()
