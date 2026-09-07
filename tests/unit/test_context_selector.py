"""Deterministic context selector ranking and caps (SystemDesign §18)."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.context.models import ContextResourceIndexRecord
from redteam_agent.context.selector import ContextSelector
from redteam_agent.errors import ContextSelectionError
from redteam_agent.policy.scope_models import NamedTargetReference


class _Reader:
    def __init__(self, records: tuple[ContextResourceIndexRecord, ...]) -> None:
        self._records = records

    def query_by_mission(self, mission_id: str) -> tuple[ContextResourceIndexRecord, ...]:
        return self._records


def _record(resource_id: str, *, offset_minutes: int = 0, target: str | None = None, resource_type: str = "artifact"):
    refs: tuple = ()
    if target is not None:
        refs = (NamedTargetReference(type="hostname", value=target),)
    return ContextResourceIndexRecord(
        resource_id=resource_id,
        resource_type=resource_type,  # type: ignore[arg-type]
        mission_id=support.MISSION_ID,
        target_references=refs,
        verification_state="verified",
        observed_at=support.T0 + timedelta(minutes=offset_minutes),
        classification="internal",
        summary_metadata={},
        origin_record_id=resource_id,
        origin_record_version="1",
        origin_record_digest="d",
    )


def test_target_match_ranks_before_mission_scoped() -> None:
    records = (_record("a"), _record("b", target="host-x"))
    selector = ContextSelector(_Reader(records))
    ranked = selector.select(support.MISSION_ID, frozenset({"host-x"}))
    assert [r.candidate.resource_id for r in ranked] == ["b", "a"]
    assert ranked[0].selection_reason_codes == ("TARGET_MATCH",)
    assert ranked[1].selection_reason_codes == ("MISSION_SCOPED",)


def test_newer_record_ranks_first_within_tier() -> None:
    records = (_record("old", offset_minutes=0), _record("new", offset_minutes=10))
    selector = ContextSelector(_Reader(records))
    ranked = selector.select(support.MISSION_ID, frozenset())
    assert [r.candidate.resource_id for r in ranked] == ["new", "old"]


def test_per_type_cap_enforced_and_not_widenable() -> None:
    records = tuple(_record(f"r{i}", offset_minutes=i) for i in range(5))
    selector = ContextSelector(_Reader(records), per_type_limit=2)
    ranked = selector.select(support.MISSION_ID, frozenset())
    assert len(ranked) == 2


def test_cross_mission_record_fails_closed() -> None:
    bad = _record("x").model_copy(update={"mission_id": "other-mission"})
    selector = ContextSelector(_Reader((bad,)))
    with pytest.raises(ContextSelectionError):
        selector.select(support.MISSION_ID, frozenset())


def test_reader_failure_is_wrapped() -> None:
    class _Boom:
        def query_by_mission(self, mission_id: str):
            raise RuntimeError("index down")

    with pytest.raises(ContextSelectionError):
        ContextSelector(_Boom()).select(support.MISSION_ID, frozenset())
