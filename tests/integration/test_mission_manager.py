"""Mission Manager lifecycle, OCC, epoch and startup-gating tests (B-03 / C)."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import (
    MissionLifecycleError,
    MissionStateVersionConflictError,
    MissionValidationError,
)
from redteam_agent.runtime.clock import ManualClock


def _kernel(clock=None):
    return build_test_kernel(clock=clock or ManualClock(support.T0))


def _seed_draft(kernel, *, register_profile=True, revision=None):
    ds = kernel.digest_service
    profile = support.make_profile(ds)
    if register_profile:
        kernel.profile_repository.save(profile)
    revision = revision or support.mission_revision(ds, profile=profile)
    kernel.mission_manager.create_mission(revision)
    return revision


def test_full_lifecycle_versions_and_epoch() -> None:
    kernel = _kernel()
    _seed_draft(kernel)
    validated = kernel.mission_manager.validate_mission(support.MISSION_ID, expected_version=0)
    assert (validated.state, validated.mission_state_version, validated.authorization_epoch) == ("VALIDATED", 1, 0)
    running = kernel.mission_manager.start_mission(support.MISSION_ID, expected_version=1)
    assert (running.state, running.mission_state_version, running.authorization_epoch) == ("RUNNING", 2, 0)
    paused = kernel.mission_manager.pause_mission(support.MISSION_ID, expected_version=2)
    assert (paused.state, paused.mission_state_version, paused.authorization_epoch) == ("PAUSED", 3, 1)
    resumed = kernel.mission_manager.resume_mission(support.MISSION_ID, expected_version=3)
    assert (resumed.state, resumed.authorization_epoch) == ("RUNNING", 2)


def test_occ_conflict_rejected() -> None:
    kernel = _kernel()
    _seed_draft(kernel)
    with pytest.raises(MissionStateVersionConflictError):
        kernel.mission_manager.validate_mission(support.MISSION_ID, expected_version=5)


def test_illegal_transition_rejected() -> None:
    kernel = _kernel()
    _seed_draft(kernel)
    # DRAFT -> RUNNING is not a legal edge (must validate first).
    with pytest.raises(MissionLifecycleError):
        kernel.mission_manager.start_mission(support.MISSION_ID, expected_version=0)


def test_invalidate_authorization_rotates_epoch_keeps_state() -> None:
    kernel = _kernel()
    _seed_draft(kernel)
    kernel.mission_manager.validate_mission(support.MISSION_ID, expected_version=0)
    kernel.mission_manager.start_mission(support.MISSION_ID, expected_version=1)
    invalidated = kernel.mission_manager.invalidate_authorization(support.MISSION_ID, expected_version=2)
    assert invalidated.state == "RUNNING"
    assert invalidated.authorization_epoch == 1


def test_start_before_validity_window_rejected() -> None:
    kernel = _kernel()
    revision = support.mission_revision(
        kernel.digest_service, profile=support.make_profile(kernel.digest_service),
        valid_from=support.T0 + timedelta(hours=1),
    )
    _seed_draft(kernel, revision=revision)
    kernel.mission_manager.validate_mission(support.MISSION_ID, expected_version=0)
    with pytest.raises(MissionLifecycleError):
        kernel.mission_manager.start_mission(support.MISSION_ID, expected_version=1)


def test_start_after_validity_window_rejected() -> None:
    clock = ManualClock(support.T0)
    kernel = _kernel(clock)
    revision = _seed_draft(kernel)
    kernel.mission_manager.validate_mission(support.MISSION_ID, expected_version=0)
    clock.set(revision.valid_until + timedelta(seconds=1))
    with pytest.raises(MissionLifecycleError):
        kernel.mission_manager.start_mission(support.MISSION_ID, expected_version=1)


def test_unregistered_profile_blocks_validation() -> None:
    kernel = _kernel()
    _seed_draft(kernel, register_profile=False)
    with pytest.raises(MissionValidationError):
        kernel.mission_manager.validate_mission(support.MISSION_ID, expected_version=0)


def test_transition_is_atomic_with_audit_event(monkeypatch) -> None:
    kernel = _kernel()
    _seed_draft(kernel)
    kernel.mission_manager.validate_mission(support.MISSION_ID, expected_version=0)
    running = kernel.mission_manager.start_mission(support.MISSION_ID, expected_version=1)
    events_before = len(kernel.event_repository.events_for(support.MISSION_ID))

    # Force the co-committed audit append to fail; the state write must roll back.
    def _boom(*_args, **_kwargs):
        raise RuntimeError("audit append failed")

    monkeypatch.setattr(kernel.event_repository, "append", _boom)
    with pytest.raises(RuntimeError):
        kernel.mission_manager.pause_mission(support.MISSION_ID, expected_version=2)

    current = kernel.state_repository.get(support.MISSION_ID)
    assert current is not None
    assert current.state == "RUNNING"
    assert current.mission_state_version == running.mission_state_version
    assert len(kernel.event_repository.events_for(support.MISSION_ID)) == events_before


def test_lifecycle_events_appended_per_transition() -> None:
    kernel = _kernel()
    _seed_draft(kernel)
    kernel.mission_manager.validate_mission(support.MISSION_ID, expected_version=0)
    kernel.mission_manager.start_mission(support.MISSION_ID, expected_version=1)
    events = kernel.event_repository.events_for(support.MISSION_ID)
    # created + validated + started
    assert [e.reason for e in events] == ["created", "validated", "started"]
