"""Production time is wall-clock time; a simulated sleeper is refused by name."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from mfa_timing import (
    MAX_SINGLE_WAIT_SECONDS,
    VirtualClockSleeper,
    WallClockSleeper,
    require_wall_clock,
    timing_mode,
)


def test_the_virtual_clock_jumps_and_ticks_once():
    clock = VirtualClockSleeper(start=1000.0)
    ticks = []
    assert clock.sleep_until(1450.0, on_tick=ticks.append) == 1450.0
    assert clock.now() == 1450.0 and ticks == [1450.0]
    assert clock.sleep_until(100.0) == 1450.0
    with pytest.raises(ValueError, match="largest declared age"):
        clock.sleep_until(1450.0 + MAX_SINGLE_WAIT_SECONDS + 1)


def test_the_wall_clock_sleeper_waits_in_real_time_and_ticks():
    sleeper = WallClockSleeper(slice_seconds=0.05)
    ticks = []
    started = time.time()
    ended = sleeper.sleep_until(started + 0.12, on_tick=ticks.append)
    assert ended >= started + 0.12
    assert len(ticks) >= 2
    with pytest.raises(ValueError, match="largest declared age"):
        sleeper.sleep_until(time.time() + MAX_SINGLE_WAIT_SECONDS + 1)


def test_only_the_real_wall_clock_sleeper_is_production_time():
    assert timing_mode(WallClockSleeper()) == "wall-clock"
    assert timing_mode(VirtualClockSleeper()) == "virtual-clock"
    assert require_wall_clock(WallClockSleeper()).mode == "wall-clock"
    with pytest.raises(ValueError, match="simulated sleeper cannot age"):
        require_wall_clock(VirtualClockSleeper())

    class Claims:
        mode = "wall-clock"

        def now(self):
            return 0.0

        def sleep_until(self, due, on_tick=None):
            return due

    with pytest.raises(ValueError, match="real wall-clock sleeper"):
        timing_mode(Claims())
    with pytest.raises(ValueError, match="declared timing mode"):
        timing_mode(object())
