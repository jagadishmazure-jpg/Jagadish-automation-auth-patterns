"""Injectable clocks so expiry behaviour is deterministic in tests.

Production code uses :class:`Clock` (wall time); every time-sensitive module
accepts a clock, and tests pass :class:`FakeClock` and advance it explicitly.
"""
from datetime import datetime, timedelta, timezone


class Clock:
    """Wall-clock time source."""

    def now(self):
        return datetime.now(timezone.utc)


class FakeClock(Clock):
    """Manually advanced clock for deterministic tests and demos."""

    def __init__(self, start=None):
        self._now = start or datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def now(self):
        return self._now

    def advance(self, seconds=0, minutes=0, hours=0, days=0):
        self._now += timedelta(seconds=seconds, minutes=minutes,
                               hours=hours, days=days)
        return self._now
