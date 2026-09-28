"""Where the campaign's time comes from, and why production may only use one source.

The pending-credential and enrollment-session ages are the whole point of the
campaign: a row that says "aged 450 seconds" is only evidence if 450 seconds of the
service's own time elapsed. The local shadow ages an owned instance by advancing that
instance's virtual clock, and a rehearsal against an injected transport may do the
same, but production time cannot be advanced. A production run therefore waits in real
wall-clock time, and the descriptor refuses to bind a simulated sleeper to production
so that a shortened rehearsal can never be mistaken for a production observation.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from typing import Any

WALL_CLOCK = "wall-clock"
VIRTUAL_CLOCK = "virtual-clock"
TIMING_MODES = (WALL_CLOCK, VIRTUAL_CLOCK)
# A wait longer than this is not one the campaign declares: the largest due offset
# is 1800 seconds and the TOTP rollover 30, so a request to wait longer is a bug or
# a corrupted checkpoint, and refusing it keeps a resumed process from sleeping away
# the whole wall budget on one step.
MAX_SINGLE_WAIT_SECONDS = 1900.0


def _instant(value: Any) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError("finite non-negative instant required")
    converted = float(value)
    if not math.isfinite(converted) or converted < 0:
        raise ValueError("finite non-negative instant required")
    return converted


class WallClockSleeper:
    """Real time. The only source a production descriptor accepts.

    `sleep_until` blocks in bounded slices so an `on_tick` callback can persist a
    checkpoint while the wait is in progress; a process that dies mid-wait leaves a
    checkpoint whose due instants are absolute, so the resumed process waits only for
    the remainder.
    """

    mode = WALL_CLOCK

    def __init__(self, slice_seconds: float = 5.0) -> None:
        if type(slice_seconds) not in (int, float) or not 0 < slice_seconds <= 60:
            raise ValueError("bounded wall-clock slice required")
        self._slice = float(slice_seconds)

    def now(self) -> float:
        return time.time()

    def sleep_until(
        self, due: float, on_tick: Callable[[float], None] | None = None
    ) -> float:
        due = _instant(due)
        remaining = due - self.now()
        if remaining > MAX_SINGLE_WAIT_SECONDS:
            raise ValueError("wait exceeds the campaign's largest declared age")
        while True:
            now = self.now()
            if now >= due:
                return now
            time.sleep(min(self._slice, due - now))
            if on_tick is not None:
                on_tick(self.now())


class VirtualClockSleeper:
    """A clock that jumps. For the local shadow and rehearsals only, never production.

    The clock starts at a fixed instant so a rehearsal is reproducible, and a wait
    completes instantly by setting the clock to the due instant. An injected transport
    that shares this clock therefore ages its resources exactly as the run expects.
    """

    mode = VIRTUAL_CLOCK

    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self._now = _instant(start)

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> float:
        seconds = _instant(seconds)
        self._now += seconds
        return self._now

    def sleep_until(
        self, due: float, on_tick: Callable[[float], None] | None = None
    ) -> float:
        due = _instant(due)
        if due - self._now > MAX_SINGLE_WAIT_SECONDS:
            raise ValueError("wait exceeds the campaign's largest declared age")
        self._now = max(self._now, due)
        if on_tick is not None:
            on_tick(self._now)
        return self._now


def timing_mode(sleeper: Any) -> str:
    """The declared mode of a sleeper, refusing anything that is not one of the two."""
    mode = getattr(sleeper, "mode", None)
    if (
        mode not in TIMING_MODES
        or not callable(getattr(sleeper, "now", None))
        or not (callable(getattr(sleeper, "sleep_until", None)))
    ):
        raise ValueError("campaign sleeper with a declared timing mode required")
    if mode == WALL_CLOCK and type(sleeper) is not WallClockSleeper:
        # A look-alike that claims wall-clock time but is not the real sleeper could
        # shorten production ages while reporting them at full length.
        raise ValueError("wall-clock timing requires the real wall-clock sleeper")
    return mode


def require_wall_clock(sleeper: Any) -> WallClockSleeper:
    """Production time must be wall-clock time; a simulated sleeper is refused by name."""
    if timing_mode(sleeper) != WALL_CLOCK:
        raise ValueError(
            "production timing requires a wall-clock sleeper; a simulated sleeper "
            "cannot age a production credential"
        )
    return sleeper
