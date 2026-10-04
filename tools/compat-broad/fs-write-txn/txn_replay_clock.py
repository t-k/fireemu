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


def dispatch_gaps(steps, sites):
    """Per named site, the seconds between the dispatch of the step before it and its own dispatch (the age its wait reached); the first step has none."""
    result = {}
    for previous, step in zip(steps, steps[1:]):
        if step["site"] in sites:
            result[step["site"]] = step["timing"]["dispatchMonotonic"] - previous["timing"]["dispatchMonotonic"]
    return result


def achieved_ages(production, local, sites=None):
    """Per site, the age (or idle) the recording had and the replay reached, so the record shows what a boundary row was compared at."""
    rows = []
    for site, value in production.items():
        if sites is not None and site not in sites:
            continue
        if site not in local:
            raise ValueError("a recorded site has no local age")
        rows.append({"site": site, "production": value, "local": local[site], "difference": round(local[site] - value, 3)})
    return rows


def paced_wait(declared, production_step, local_duration):
    """The local wait for one step: the production step less the local duration of the request before it, never below the declared wait."""
    if production_step is None:
        return declared
    if production_step > MAX_WAIT_SECONDS:
        raise ValueError("a production step is too long to be a wait")
    return max(declared, production_step - local_duration)


class VirtualClock:
    """Real time plus every second the waits advanced the emulator's virtual clock."""

    def __init__(self, control, token):
        self.control, self.token, self.skew = control.rstrip("/"), token, 0.0

    def now(self):
        return time.monotonic() + self.skew

    def utc(self):
        moment = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.skew)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def sleep(self, seconds):
        """Advance the emulator's clock by exactly this wait: the control API takes whole milliseconds, so a long program's token ages do not drift."""
        if seconds <= 0:
            return
        millis = max(1, int(round(seconds * 1000)))
        request = urllib.request.Request(self.control + "/sessions/default/clock:advance", data=json.dumps({"millis": millis}).encode(),
                                         method="POST", headers={"content-type": "application/json", "authorization": "Bearer " + self.token})
        urllib.request.urlopen(request, timeout=10).read()
        self.skew += millis / 1000


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
