"""Trusted clock (SystemDesign §10.3 / §22).

Security-sensitive components read the current time from a clock injected by the
composition root, never from a caller argument. Phase 0A ships a system UTC
clock and a manual clock test double. The production monotonic/TPM-bound clock
is a later phase; this boundary keeps that swap possible without letting a
caller supply ``now``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from redteam_agent.errors import ClockIntegrityError


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current timezone-aware UTC time."""
        ...


@dataclass(frozen=True)
class ClockReading:
    """One atomic read of audit UTC and the host-boot monotonic deadline clock."""

    utc: datetime
    monotonic_ns: int


class SystemUtcClock:
    """Wall-clock UTC time. Audit/cap metadata only in later phases."""

    def now(self) -> datetime:
        return datetime.now(tz=UTC)


class ManualClock:
    """A controllable clock for tests. Not for production use."""

    def __init__(self, current: datetime) -> None:
        if current.tzinfo is None:
            raise ValueError("ManualClock requires a timezone-aware datetime")
        self._current = current.astimezone(UTC)

    def now(self) -> datetime:
        return self._current

    def set(self, current: datetime) -> None:
        if current.tzinfo is None:
            raise ValueError("ManualClock requires a timezone-aware datetime")
        self._current = current.astimezone(UTC)


class MonotonicClock(Protocol):
    def read(self) -> ClockReading: ...
    def now(self) -> datetime: ...


class SystemMonotonicClock:
    """Audit UTC + a host-boot monotonic deadline (Linux ``CLOCK_BOOTTIME``)."""

    def __init__(self) -> None:
        # CLOCK_BOOTTIME advances across suspend and is shared within a host boot;
        # fall back to CLOCK_MONOTONIC where BOOTTIME is unavailable.
        self._clock_id = getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC)

    def read(self) -> ClockReading:
        return ClockReading(utc=datetime.now(tz=UTC), monotonic_ns=time.clock_gettime_ns(self._clock_id))

    def now(self) -> datetime:
        return self.read().utc


class ManualMonotonicClock:
    """A controllable monotonic clock for tests (set UTC and monotonic independently)."""

    def __init__(self, utc: datetime, monotonic_ns: int = 0) -> None:
        if utc.tzinfo is None:
            raise ValueError("ManualMonotonicClock requires a timezone-aware datetime")
        self._utc = utc.astimezone(UTC)
        self._monotonic_ns = monotonic_ns

    def read(self) -> ClockReading:
        return ClockReading(utc=self._utc, monotonic_ns=self._monotonic_ns)

    def now(self) -> datetime:
        return self._utc

    def advance(self, *, seconds: float) -> None:
        """Advance both UTC and monotonic consistently (normal time passing)."""
        from datetime import timedelta

        self._utc = self._utc + timedelta(seconds=seconds)
        self._monotonic_ns += int(seconds * 1_000_000_000)

    def set(self, *, utc: datetime | None = None, monotonic_ns: int | None = None) -> None:
        if utc is not None:
            self._utc = utc.astimezone(UTC)
        if monotonic_ns is not None:
            self._monotonic_ns = monotonic_ns


class ClockIntegrityGuard:
    """Detect UTC rollback below a high-water mark and wall/monotonic divergence.

    A security-sensitive caller reads through the guard. The guard keeps a UTC
    high-water mark and a reference point; a UTC reading below the high-water mark, or a
    ``|utc_delta - monotonic_delta|`` beyond the tolerance, raises
    :class:`ClockIntegrityError` so new authorization, claim, lease and renewal stop.
    """

    def __init__(self, clock: MonotonicClock, *, max_divergence_seconds: float = 5.0) -> None:
        self._clock = clock
        self._tolerance_ns = int(max_divergence_seconds * 1_000_000_000)
        first = clock.read()
        self._high_water_utc = first.utc
        self._ref_utc = first.utc
        self._ref_monotonic_ns = first.monotonic_ns

    @property
    def high_water_utc(self) -> datetime:
        return self._high_water_utc

    def read(self) -> ClockReading:
        reading = self._clock.read()
        if reading.utc < self._high_water_utc:
            raise ClockIntegrityError("UTC rolled back below the persisted high-water mark")
        utc_delta_ns = int((reading.utc - self._ref_utc).total_seconds() * 1_000_000_000)
        monotonic_delta_ns = reading.monotonic_ns - self._ref_monotonic_ns
        if abs(utc_delta_ns - monotonic_delta_ns) > self._tolerance_ns:
            raise ClockIntegrityError("wall-clock and monotonic clock diverged beyond tolerance")
        if reading.utc > self._high_water_utc:
            self._high_water_utc = reading.utc
        return reading
