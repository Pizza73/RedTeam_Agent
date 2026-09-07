"""Monotonic clock integrity + lease timing policy (SystemDesign §10.3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redteam_agent.errors import ClockIntegrityError, LeaseError
from redteam_agent.leases.models import LeasePolicy
from redteam_agent.runtime.clock import ClockIntegrityGuard, ManualMonotonicClock

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def test_default_lease_policy_60s_20s_and_3x() -> None:
    policy = LeasePolicy()
    assert policy.lease_duration_seconds == 60 and policy.heartbeat_interval_seconds == 20
    assert policy.lease_duration_seconds >= 3 * policy.heartbeat_interval_seconds


def test_lease_policy_rejects_large_heartbeat() -> None:
    with pytest.raises(LeaseError):
        LeasePolicy(lease_duration_seconds=90, heartbeat_interval_seconds=25)


def test_lease_policy_rejects_short_duration() -> None:
    with pytest.raises(LeaseError):
        LeasePolicy(lease_duration_seconds=40, heartbeat_interval_seconds=20)


def test_clock_guard_accepts_forward_time() -> None:
    clock = ManualMonotonicClock(T0, 0)
    guard = ClockIntegrityGuard(clock)
    clock.advance(seconds=30)
    reading = guard.read()
    assert reading.utc == T0 + timedelta(seconds=30)


def test_clock_guard_rejects_utc_rollback() -> None:
    clock = ManualMonotonicClock(T0, 0)
    guard = ClockIntegrityGuard(clock)
    clock.advance(seconds=30)
    guard.read()
    clock.set(utc=T0)  # rollback below high-water
    with pytest.raises(ClockIntegrityError):
        guard.read()


def test_clock_guard_rejects_divergence() -> None:
    clock = ManualMonotonicClock(T0, 0)
    guard = ClockIntegrityGuard(clock, max_divergence_seconds=5)
    clock.set(utc=T0 + timedelta(seconds=100), monotonic_ns=0)  # wall jumped, monotonic did not
    with pytest.raises(ClockIntegrityError):
        guard.read()
