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


def _begin_site_of(plan_steps):
    """Per step with a token, the site of the begin that issued it: the latest earlier step that outputs that token."""
    begins, result = {}, {}
    for step in plan_steps:
        if isinstance(step.get("tokenInput"), str) and step["tokenInput"] in begins:
            result[step["id"]] = begins[step["tokenInput"]]
        if isinstance(step.get("tokenOutput"), str):
            begins[step["tokenOutput"]] = step["id"]
    return result


def token_ages(plan_steps, before_times, after_times):
    """Per step that names a token, the seconds between the emulator's clock after the begin's answer and its clock before this request: the age the emulator
    itself saw, whatever the replay's own timestamps say."""
    ages = {}
    for site, begin in _begin_site_of(plan_steps).items():
        if site in before_times and begin in after_times:
            ages[site] = before_times[site] - after_times[begin]
    return ages


def production_token_ages(plan_steps, steps):
    """The same ages from a recording: its dispatch of the request less its response to the begin."""
    rows = {step["site"]: step for step in steps}
    ages = {}
    for site, begin in _begin_site_of(plan_steps).items():
        if site in rows and begin in rows:
            ages[site] = rows[site]["timing"]["dispatchMonotonic"] - rows[begin]["timing"]["responseMonotonic"]
    return ages


#: Strict's limits a token's age (or an idle) can fall on either side of: the idle limit, the total lifetime and the memory of an expired token.
STRICT_AGE_LIMITS = (120.0, 270.0, 300.0)


def judge_token_ages(production, emulator, *, tolerance, minimum, limits=STRICT_AGE_LIMITS):
    """A row per recorded token age of at least `minimum` seconds. It matches only when the emulator's age lies within `tolerance` of the recorded one (inclusive) and
    on the same side of every strict limit (a recorded age at a limit is over it): an age that would flip a row's answer is refused whatever its distance."""
    rows = []
    for site, recorded in production.items():
        if recorded < minimum:
            continue
        seen = emulator.get(site)
        difference = None if seen is None else round(seen - recorded, 3)
        match = seen is not None and abs(seen - recorded) <= tolerance and all((recorded >= limit) == (seen >= limit) for limit in limits)
        rows.append({"site": site, "production": recorded, "emulator": seen, "difference": difference, "match": match})
    return rows


def apply_age_rows(result, rows):
    """Store the judged age rows in a replay's result and count every failed one as a mismatch: a replay whose age is off is refused like one whose answers differ."""
    result["tokenAges"] = rows
    result["mismatches"] += sum(not row["match"] for row in rows)


def idle_before(marks, sites):
    """Per named site, the emulator's own idle before it: its clock before this request less its clock after the answer to the request before (the first request has none)."""
    result = {}
    for previous, site in zip(marks.order, marks.order[1:]):
        if site in sites and site in marks.before_times and previous in marks.after_times:
            result[site] = marks.before_times[site] - marks.after_times[previous]
    return result


class EmulatorMarks:
    """The emulator's own clock read just before each dispatch and just after each answer (nothing when there is no emulator clock to read)."""

    def __init__(self, emulator_clock):
        self.emulator_clock = emulator_clock
        self.before_times, self.after_times = {}, {}
        self.order = []

    def before(self, site):
        if self.emulator_clock is not None:
            self.before_times[site] = self.emulator_clock()
            self.order.append(site)

    def after(self, site):
        if self.emulator_clock is not None:
            self.after_times[site] = self.emulator_clock()


def pacing_advance(*, gap, last_dispatch, now):
    """How far a frozen clock has to move before a request so that it is dispatched `gap` seconds after the request before it: what a wait has not already advanced."""
    if gap is None or last_dispatch is None:
        return 0.0
    return max(0.0, last_dispatch + gap - now)


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

    def __init__(self, control, token, start=None, frozen=False):
        self.control, self.token, self.start = control.rstrip("/"), token, start
        # a frozen clock reads real time once (or takes the start it is given) and then moves only by what was advanced: the emulator's own clock is frozen too
        self.frozen = frozen or start is not None
        self._base = 1000.0 if start is not None else time.monotonic()
        self._base_utc = start if start is not None else datetime.datetime.now(datetime.timezone.utc)
        self.skew = 0.0       # what the recording's monotonic clock was moved by
        self.utc_skew = 0.0   # what the time it writes as now was moved by (a hidden advance moves only this)

    def now(self):
        return (self._base if self.frozen else time.monotonic()) + self.skew

    def utc(self):
        base = self._base_utc if self.frozen else datetime.datetime.now(datetime.timezone.utc)
        return (base + datetime.timedelta(seconds=self.utc_skew)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def emulator_now(self):
        """The emulator's own clock, read from the control API (seconds since the epoch)."""
        request = urllib.request.Request(self.control + "/sessions/default", headers={"authorization": "Bearer " + self.token})
        value = json.loads(urllib.request.urlopen(request, timeout=10).read())["clock"]
        text = value["clock"] if isinstance(value, dict) else value
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()

    def advance(self, seconds, *, hidden=False):
        """Move the emulator's clock by exactly this many seconds (the control API takes whole milliseconds, so a long program's token ages do not drift). A hidden advance
        leaves the recording's monotonic clock alone, so its own deadlines do not see it."""
        if seconds <= 0:
            return
        millis = max(1, int(round(seconds * 1000)))
        request = urllib.request.Request(self.control + "/sessions/default/clock:advance", data=json.dumps({"millis": millis}).encode(),
                                         method="POST", headers={"content-type": "application/json", "authorization": "Bearer " + self.token})
        urllib.request.urlopen(request, timeout=10).read()
        self.utc_skew += millis / 1000
        if not hidden:
            self.skew += millis / 1000

    def sleep(self, seconds):
        self.advance(seconds)


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


#: Real seconds a concurrent outside writer is given to reach the emulator (its worker starts a process and connects) before the replay moves the frozen clock: a clock that
#: moves faster than the writer arrives would release the holder before the writer ever met its locks.
CONCURRENT_SETTLE_SECONDS = 5.0


def settling(base, seconds=CONCURRENT_SETTLE_SECONDS, sleep=time.sleep):
    """`base` (a collector class) that, right after it sends a concurrent writer, waits `seconds` of real time (the emulator's clock is frozen: nothing ages) before it goes on."""
    if not seconds:
        return base

    class Settling(base):
        def _start_concurrent(self, step):
            result = super()._start_concurrent(step)
            sleep(seconds)
            return result

    return Settling


class PacedCollector(Collector):
    """The framework collector with each wait stretched to the production step; everything else is the framework's."""

    def __init__(self, *args, production_steps, emulator_clock=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.production_steps = production_steps
        self.marks = EmulatorMarks(emulator_clock)

    last_dispatch = None

    def _begin_rpc(self, site, transport, method, request, phase, *, step=None, concurrent=False):
        sequential = not concurrent and not (step and step.get("concurrentWith"))
        if sequential and getattr(self.sleep, "__self__", None) is not None and getattr(self.sleep.__self__, "frozen", False):
            # a frozen clock moves only by what is advanced: bring this request to the recorded gap after the request before it
            advance = pacing_advance(gap=self.production_steps.get(site), last_dispatch=self.last_dispatch, now=self.monotonic())
            if advance > 0:
                self.sleep(advance)
        context = super()._begin_rpc(site, transport, method, request, phase, step=step, concurrent=concurrent)
        self.marks.before(site)
        if sequential:
            self.last_dispatch = context["timing"]["dispatchMonotonic"]
        return context

    def _end_rpc(self, context, result, response_timing=None):
        self.marks.after(context["site"])
        return super()._end_rpc(context, result, response_timing)

    def _wait(self, step):
        previous = self.rows[-1] if self.rows else None
        if previous is None:
            raise ValueError("a wait needs a preceding request")
        timing = previous["timing"]
        duration = timing["responseMonotonic"] - timing["dispatchMonotonic"]
        seconds = paced_wait(step["waitSeconds"], self.production_steps.get(step["id"]), duration)
        return super()._wait({**step, "waitSeconds": seconds})


class MarkedWire:
    """A native wire that marks the emulator's clock around each send, at the site the collector says it is at."""

    def __init__(self, wire, marks, collector):
        self.wire, self.marks, self.collector = wire, marks, collector

    def send(self, *args, **kwargs):
        site = self.collector.pending["site"]
        self.marks.before(site)
        result = self.wire.send(*args, **kwargs)
        self.marks.after(site)
        return result

    def __getattr__(self, name):
        return getattr(self.wire, name)


def paced_grpc(base):
    """The native gRPC collector `base` with each idle wait stretched to the recorded idle; the wait it records keeps the declared seconds, which is what the
    family's projection derives from."""

    class Paced(base):
        def __init__(self, production_gaps, *args, emulator_clock=None, **kwargs):
            super().__init__(*args, **kwargs)
            self.production_gaps = production_gaps
            self.marks = EmulatorMarks(emulator_clock)
            if emulator_clock is not None:
                self.wire = MarkedWire(self.wire, self.marks, self)

        last_response = None

        def _rpc(self, site, *args, **kwargs):
            if getattr(self.sleep, "__self__", None) is not None and getattr(self.sleep.__self__, "frozen", False):
                # a frozen clock moves only by what is advanced: bring this request to the idle the recording had before it
                advance = pacing_advance(gap=self.production_gaps.get(site), last_dispatch=self.last_response, now=self.monotonic())
                if advance > 0:
                    self.sleep(advance)
            result = super()._rpc(site, *args, **kwargs)
            self.last_response = self.monotonic()
            return result

        def _wait(self, site, seconds):
            stretched = paced_wait(seconds, self.production_gaps.get(site), 0.0)
            super()._wait(site, stretched)
            self.waits[-1]["seconds"] = seconds

    return Paced
