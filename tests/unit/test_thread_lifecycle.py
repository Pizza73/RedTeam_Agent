"""thread_id lifecycle: new run/thread per revision, verify mismatch (SystemDesign §17.2)."""

from __future__ import annotations

import pytest

from redteam_agent.errors import MissionRevisionConflictError
from redteam_agent.execution.thread import compute_thread_id, new_run_thread, verify_thread_id


def test_thread_id_format() -> None:
    assert compute_thread_id(mission_id="m1", mission_revision=2, run_id="run-x") == "m1:2:run-x"


def test_revision_change_changes_run_and_thread() -> None:
    r1 = new_run_thread(mission_id="m1", mission_revision=1, run_seed="seed")
    r2 = new_run_thread(mission_id="m1", mission_revision=2, run_seed="seed")
    assert r1.run_id != r2.run_id
    assert r1.thread_id != r2.thread_id
    assert ":" not in r1.run_id
    assert r1.thread_id == f"m1:1:{r1.run_id}"
    assert r2.thread_id == f"m1:2:{r2.run_id}"


def test_colon_in_id_rejected() -> None:
    with pytest.raises(MissionRevisionConflictError):
        compute_thread_id(mission_id="m:1", mission_revision=1, run_id="run")
    with pytest.raises(MissionRevisionConflictError):
        compute_thread_id(mission_id="m1", mission_revision=1, run_id="run:x")


def test_verify_rejects_wrong_mission_or_revision() -> None:
    thread = compute_thread_id(mission_id="m1", mission_revision=3, run_id="run-1")
    assert verify_thread_id(thread_id=thread, mission_id="m1", mission_revision=3) == "run-1"
    with pytest.raises(MissionRevisionConflictError):
        verify_thread_id(thread_id=thread, mission_id="m2", mission_revision=3)
    with pytest.raises(MissionRevisionConflictError):
        verify_thread_id(thread_id=thread, mission_id="m1", mission_revision=4)


def test_verify_rejects_malformed_thread_id() -> None:
    with pytest.raises(MissionRevisionConflictError):
        verify_thread_id(thread_id="m1:3", mission_id="m1", mission_revision=3)
