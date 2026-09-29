"""Phase 0B mission constraints: no direct COMPLETED, FINALIZING skeleton, epochs."""

from __future__ import annotations

import pytest

import support
import support_phase0b as p0b
from redteam_agent.errors import MissionLifecycleError


def _running(kernel: object):  # type: ignore[no-untyped-def]
    seeded = p0b.seed_authorized(kernel)  # type: ignore[arg-type]
    return seeded.seeded.running_state


def test_goal_achieved_cannot_go_directly_to_completed() -> None:
    kernel = p0b.make_kernel()
    running = _running(kernel)
    mm = kernel.phase0a.mission_manager
    # Even if a goal is achieved, RUNNING -> COMPLETED is illegal; it must finalize.
    with pytest.raises(MissionLifecycleError):
        mm.complete_mission(
            support.MISSION_ID, expected_version=running.mission_state_version,
            actor_token=support.OPERATOR_ACTOR_TOKEN,
        )


def test_finalizing_skeleton_running_to_finalizing_to_completed() -> None:
    kernel = p0b.make_kernel()
    running = _running(kernel)
    mm = kernel.phase0a.mission_manager
    finalizing = mm.begin_finalization(
        support.MISSION_ID, expected_version=running.mission_state_version,
        actor_token=support.OPERATOR_ACTOR_TOKEN,
    )
    assert finalizing.state == "FINALIZING"
    # FINALIZING rotates the authorization epoch (a revocation boundary).
    assert finalizing.authorization_epoch == running.authorization_epoch + 1
    completed = mm.complete_mission(
        support.MISSION_ID, expected_version=finalizing.mission_state_version,
        actor_token=support.OPERATOR_ACTOR_TOKEN,
    )
    assert completed.state == "COMPLETED"


def test_pause_resume_rotates_epoch() -> None:
    kernel = p0b.make_kernel()
    running = _running(kernel)
    mm = kernel.phase0a.mission_manager
    paused = mm.pause_mission(
        support.MISSION_ID, expected_version=running.mission_state_version,
        actor_token=support.OPERATOR_ACTOR_TOKEN,
    )
    assert paused.authorization_epoch == running.authorization_epoch + 1
    resumed = mm.resume_mission(
        support.MISSION_ID, expected_version=paused.mission_state_version,
        actor_token=support.OPERATOR_ACTOR_TOKEN,
    )
    assert resumed.authorization_epoch == paused.authorization_epoch + 1
