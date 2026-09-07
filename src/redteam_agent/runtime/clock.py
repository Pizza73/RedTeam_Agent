"""Trusted clock (SystemDesign §10.3 / §22).

Security-sensitive components read the current time from a clock injected by the
composition root, never from a caller argument. Phase 0A ships a system UTC
clock and a manual clock test double. The production monotonic/TPM-bound clock
is a later phase; this boundary keeps that swap possible without letting a
caller supply ``now``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current timezone-aware UTC time."""
        ...


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
