"""LangGraph run_id / thread_id lifecycle (SystemDesign §17.2).

``thread_id = mission_id : mission_revision : run_id``. Mission id and run id use
an application id grammar that excludes ``:``; the revision is a canonical
non-negative decimal. A mission-revision change yields a new run id and thread
id; a checkpoint's thread id is verified against the current mission id/revision
and fails closed on mismatch (``MissionRevisionConflictError``).
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.errors import MissionRevisionConflictError


def _validate_id_token(label: str, value: str) -> None:
    if value == "" or ":" in value:
        raise MissionRevisionConflictError(f"{label} must be non-empty and must not contain ':'")


def _canonical_revision(mission_revision: int) -> str:
    if mission_revision < 0:
        raise MissionRevisionConflictError("mission_revision must be a non-negative integer")
    return str(mission_revision)


def compute_thread_id(*, mission_id: str, mission_revision: int, run_id: str) -> str:
    _validate_id_token("mission_id", mission_id)
    _validate_id_token("run_id", run_id)
    return f"{mission_id}:{_canonical_revision(mission_revision)}:{run_id}"


@dataclass(frozen=True)
class RunThread:
    mission_id: str
    mission_revision: int
    run_id: str
    thread_id: str


def new_run_thread(*, mission_id: str, mission_revision: int, run_seed: str) -> RunThread:
    """Allocate a fresh run id + thread id for a (mission, revision).

    The run id is derived deterministically from the mission, revision and a seed
    so a revision change necessarily changes both the run id and the thread id;
    the old revision's checkpoint is never implicitly copied or resumed.
    """
    _validate_id_token("mission_id", mission_id)
    _validate_id_token("run_seed", run_seed)
    run_id = f"run-{mission_id}-{_canonical_revision(mission_revision)}-{run_seed}"
    thread_id = compute_thread_id(mission_id=mission_id, mission_revision=mission_revision, run_id=run_id)
    return RunThread(
        mission_id=mission_id, mission_revision=mission_revision, run_id=run_id, thread_id=thread_id
    )


def verify_thread_id(*, thread_id: str, mission_id: str, mission_revision: int) -> str:
    """Verify a checkpoint thread id belongs to the current mission id/revision.

    Returns the run id on success; raises ``MissionRevisionConflictError`` on any
    mismatch (SystemDesign §17.2).
    """
    parts = thread_id.split(":")
    if len(parts) != 3:
        raise MissionRevisionConflictError("thread_id is not mission_id:mission_revision:run_id")
    thread_mission_id, thread_revision, run_id = parts
    if thread_mission_id != mission_id:
        raise MissionRevisionConflictError("thread_id mission mismatch")
    if thread_revision != _canonical_revision(mission_revision):
        raise MissionRevisionConflictError("thread_id mission revision mismatch")
    if run_id == "":
        raise MissionRevisionConflictError("thread_id run id is empty")
    return run_id
