"""A local replay on the emulator's virtual clock that reproduces the token ages of a production recording.

A program that waits (idle limits, a token's total lifetime) cannot be compared with a production recording by sleeping the declared seconds: production
spent about a second on every request as well, so its tokens were older than the declared waits add up to. The replay here advances the emulator's virtual
clock instead of sleeping, and makes each wait as long as production's step between the two dispatches, less what the local request itself took, so the
local token age at every wait equals the recorded one to within a second."""

import datetime
import json
import time
import urllib.request

from txn_program_collector import Collector

# A recorded step longer than this is a corrupt recording, not a wait: the whole observation phase is a few minutes.
MAX_WAIT_SECONDS = 600


def production_age_steps(steps):
    """Per site, the seconds between the dispatch of the request before it and its own dispatch, in the production recording's order."""
    result, previous = {}, None
    for step in steps:
        timing = step["timing"]
        if step["site"] in result or (previous is not None and step["site"] == previous["site"]):
            raise ValueError("a site repeats in the recording")
        if previous is not None:
            gap = timing["dispatchMonotonic"] - previous["timing"]["dispatchMonotonic"]
            if gap < 0 or timing["responseMonotonic"] < timing["dispatchMonotonic"]:
                raise ValueError("the production clock moved backwards")
            result[step["site"]] = gap
        previous = step
    return result


def production_idle_gaps(steps):
    """Per site, the seconds between the response before it and its own dispatch: the least the production token idled before that request."""
    result, previous = {}, None
    for step in steps:
        timing = step["timing"]
        if previous is not None:
            gap = timing["dispatchMonotonic"] - previous["timing"]["responseMonotonic"]
            if gap < 0:
                raise ValueError("the production clock moved backwards")
            result[step["site"]] = gap
        previous = step
    return result


def paced_wait(declared, production_step, local_duration):
    """The local wait for one step: the production step less the local duration of the request before it, never below the declared wait."""
    if production_step is None:
        return declared
    if production_step > MAX_WAIT_SECONDS:
        raise ValueError("a production step is too long to be a wait")
    return max(declared, production_step - local_duration)


class VirtualClock:
    """The emulator's virtual clock as a recording sees it. Without a start it is real time plus every second the waits advanced it. A fireemu started with
    `daemon.clockStart` has a clock that only moves when it is advanced, so given that start the recording's clocks do too: UTC is the start plus what was advanced,
    and monotonic is a fixed origin plus what the waits advanced."""

    def __init__(self, control, token, start=None):
        self.control, self.token, self.start = control.rstrip("/"), token, start
        self.skew = 0.0       # what the recording's monotonic clock was moved by
        self.utc_skew = 0.0   # what the time it writes as now was moved by (a hidden advance moves only this)

    def now(self):
        return (1000.0 if self.start else time.monotonic()) + self.skew

    def utc(self):
        base = self.start or datetime.datetime.now(datetime.timezone.utc)
        return (base + datetime.timedelta(seconds=self.utc_skew)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def advance(self, seconds, *, hidden=False):
        """Move the emulator's clock. A hidden advance leaves the recording's monotonic clock alone, so its own deadlines do not see it."""
        request = urllib.request.Request(self.control + "/sessions/default/clock:advance", data=json.dumps({"seconds": seconds}).encode(),
                                         method="POST", headers={"content-type": "application/json", "authorization": "Bearer " + self.token})
        urllib.request.urlopen(request, timeout=10).read()
        self.utc_skew += seconds
        if not hidden:
            self.skew += seconds

    def sleep(self, seconds):
        self.advance(max(1, int(round(seconds))))


def advancing(base, clock, seconds, after):
    """`base` (a collector class) that advances the emulator's clock once, hidden, right after the first answer of the step `after`; `base` itself when nothing is asked for."""
    if not seconds or not after:
        return base

    class Advancing(base):
        moved = False

        def _rpc(self, site, *args, **kwargs):
            result = super()._rpc(site, *args, **kwargs)
            if site == after and not self.moved:
                self.moved = True
                clock.advance(seconds, hidden=True)
            return result

    return Advancing


class PacedCollector(Collector):
    """The framework collector with each wait stretched to the production step; everything else is the framework's."""

    def __init__(self, *args, production_steps, **kwargs):
        super().__init__(*args, **kwargs)
        self.production_steps = production_steps

    def _wait(self, step):
        previous = self.rows[-1] if self.rows else None
        if previous is None:
            raise ValueError("a wait needs a preceding request")
        timing = previous["timing"]
        duration = timing["responseMonotonic"] - timing["dispatchMonotonic"]
        seconds = paced_wait(step["waitSeconds"], self.production_steps.get(step["id"]), duration)
        return super()._wait({**step, "waitSeconds": seconds})


def paced_grpc(base):
    """The native gRPC collector `base` with each idle wait stretched to the recorded idle; the wait it records keeps the declared seconds, which is what the
    family's projection derives from."""

    class Paced(base):
        def __init__(self, production_gaps, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.production_gaps = production_gaps

        def _wait(self, site, seconds):
            stretched = paced_wait(seconds, self.production_gaps.get(site), 0.0)
            super()._wait(site, stretched)
            self.waits[-1]["seconds"] = seconds

    return Paced
