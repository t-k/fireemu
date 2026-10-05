"""Pacing for a local replay on the emulator's virtual clock: a replay reproduces the token ages of a production recording."""

import json

import pytest

import txn_replay_clock as clock


def row(site, dispatch, response):
    return {"site": site, "timing": {"dispatchMonotonic": dispatch, "responseMonotonic": response}}


def test_a_wait_reproduces_the_production_age_step_between_two_dispatches():
    recording = [row("a", 100.0, 101.2), row("b", 125.3, 126.5), row("c", 150.7, 151.9)]
    gaps = clock.production_age_steps(recording)
    assert gaps == {"b": pytest.approx(25.3), "c": pytest.approx(25.4)}


def test_the_first_request_has_no_step_and_a_repeated_site_is_refused():
    assert "a" not in clock.production_age_steps([row("a", 1.0, 2.0), row("b", 3.0, 4.0)])
    with pytest.raises(ValueError):
        clock.production_age_steps([row("a", 1.0, 2.0), row("a", 3.0, 4.0)])


def test_a_backward_production_clock_is_refused():
    with pytest.raises(ValueError):
        clock.production_age_steps([row("a", 5.0, 6.0), row("b", 4.0, 7.0)])


def test_the_local_wait_is_the_production_step_less_the_local_duration_and_never_below_the_declared_wait():
    assert clock.paced_wait(declared=24, production_step=25.3, local_duration=0.1) == pytest.approx(25.2)
    # a production step shorter than the declared wait cannot shorten it
    assert clock.paced_wait(declared=24, production_step=23.0, local_duration=0.0) == 24
    # no recorded step for the site: the declared wait
    assert clock.paced_wait(declared=24, production_step=None, local_duration=0.0) == 24


def test_a_wait_is_bounded_so_a_corrupt_recording_cannot_stall_the_replay():
    with pytest.raises(ValueError):
        clock.paced_wait(declared=24, production_step=10_000.0, local_duration=0.0)


def test_the_idle_gap_of_a_site_is_its_dispatch_less_the_response_before_it():
    recording = [row("a", 100.0, 101.2), row("b", 125.3, 126.5), row("c", 150.7, 151.9)]
    gaps = clock.production_idle_gaps(recording)
    assert gaps == {"b": pytest.approx(24.1), "c": pytest.approx(24.2)}


def test_a_negative_idle_gap_is_refused():
    with pytest.raises(ValueError):
        clock.production_idle_gaps([row("a", 1.0, 5.0), row("b", 4.0, 6.0)])


class FakeBase:
    """The wait of the native gRPC collectors: it takes the site and the seconds and records both."""

    def __init__(self):
        self.waits, self.calls = [], []

    def _wait(self, site, seconds):
        self.calls.append((site, seconds))
        self.waits.append({"site": site, "seconds": seconds})


def test_a_paced_grpc_wait_stretches_the_idle_and_still_records_the_declared_seconds():
    paced = clock.paced_grpc(FakeBase)({"idle-120/commit": 120.54, "idle-65/commit": 64.0})
    paced._wait("idle-120/commit", 120)
    paced._wait("idle-65/commit", 65)
    paced._wait("other", 7)
    # stretched to the recorded idle, never shortened below the declared wait, declared when no gap was recorded
    assert paced.calls == [("idle-120/commit", pytest.approx(120.54)), ("idle-65/commit", 65), ("other", 7)]
    # what the projection derives from is the declared seconds
    assert [wait["seconds"] for wait in paced.waits] == [120, 65, 7]


def test_a_site_repeated_later_in_the_recording_is_refused():
    with pytest.raises(ValueError):
        clock.production_age_steps([row("x", 1.0, 2.0), row("b", 3.0, 4.0), row("c", 5.0, 6.0), row("b", 7.0, 8.0)])


def test_a_response_before_its_own_dispatch_is_refused_but_a_zero_duration_is_not():
    with pytest.raises(ValueError):
        clock.production_age_steps([row("a", 1.0, 2.0), row("b", 5.0, 4.0)])
    assert clock.production_age_steps([row("a", 1.0, 2.0), row("b", 5.0, 5.0)]) == {"b": pytest.approx(4.0)}


def test_two_dispatches_at_the_same_instant_are_a_zero_step():
    assert clock.production_age_steps([row("a", 1.0, 2.0), row("b", 1.0, 1.5)]) == {"b": 0.0}
    assert clock.production_idle_gaps([row("a", 1.0, 2.0), row("b", 2.0, 3.0)]) == {"b": 0.0}


def test_the_bound_on_a_wait_is_inclusive():
    assert clock.paced_wait(declared=24, production_step=clock.MAX_WAIT_SECONDS, local_duration=0.0) == clock.MAX_WAIT_SECONDS
    with pytest.raises(ValueError):
        clock.paced_wait(declared=24, production_step=clock.MAX_WAIT_SECONDS + 0.01, local_duration=0.0)


class Control:
    """The emulator's control endpoint: every clock advance it was asked for."""

    def __init__(self):
        self.calls = []

    def __call__(self, request, timeout=None):
        import json as _json

        self.calls.append((request.full_url, _json.loads(request.data), request.get_header("Authorization")))

        class Answer:
            @staticmethod
            def read():
                return b"{}"

        return Answer()


@pytest.fixture
def control(monkeypatch):
    fake = Control()
    monkeypatch.setattr(clock.urllib.request, "urlopen", fake)
    return fake


def test_a_clock_without_a_start_is_real_time_plus_every_advance(control):
    virtual = clock.VirtualClock("http://127.0.0.1:1/v1/", "tok")
    before = virtual.now()
    virtual.sleep(2.4)
    virtual.sleep(0.2)
    virtual.sleep(2.6)
    # a wait advances by its exact milliseconds, and the clock reads that much later
    assert [call[1] for call in control.calls] == [{"millis": 2400}, {"millis": 200}, {"millis": 2600}]
    assert control.calls[0][0] == "http://127.0.0.1:1/v1/sessions/default/clock:advance" and control.calls[0][2] == "Bearer tok"
    assert 5.2 <= virtual.now() - before < 6.2
    assert virtual.utc().endswith("Z") and len(virtual.utc()) == 27


def test_a_clock_with_a_start_moves_only_when_it_is_advanced(control):
    import datetime

    start = datetime.datetime(2026, 10, 4, tzinfo=datetime.timezone.utc)
    virtual = clock.VirtualClock("http://c", "tok", start)
    assert virtual.now() == virtual.now() == 1000.0 and virtual.utc() == "2026-10-04T00:00:00.000000Z"
    virtual.sleep(5)
    assert virtual.now() == 1005.0 and virtual.utc() == "2026-10-04T00:00:05.000000Z"
    # a hidden advance moves the emulator's clock and what the recording writes as the time now, not the recording's own monotonic clock (its deadlines)
    virtual.advance(3700, hidden=True)
    assert virtual.now() == 1005.0 and virtual.utc() == "2026-10-04T01:01:45.000000Z"
    assert [call[1] for call in control.calls] == [{"millis": 5000}, {"millis": 3_700_000}]
    virtual.advance(10)
    assert virtual.now() == 1015.0 and virtual.utc() == "2026-10-04T01:01:55.000000Z"


def test_a_collector_that_advances_the_clock_once_after_a_named_step(control):
    import datetime

    class Base:
        def __init__(self):
            self.sites = []
            self.advances_seen = {}

        def _rpc(self, site, *args, **kwargs):
            self.sites.append(site)
            self.advances_seen.setdefault(site, len(control.calls))   # what the emulator's clock had been asked for when this step's request went out
            return f"answer {site}"

    virtual = clock.VirtualClock("http://c", "tok", datetime.datetime(2026, 10, 4, tzinfo=datetime.timezone.utc))
    collector = clock.advancing(Base, virtual, 3700, "b")()
    after = []
    for site in ("a", "b", "c", "b"):
        assert collector._rpc(site) == f"answer {site}"
        after.append(len(control.calls))
    assert collector.sites == ["a", "b", "c", "b"]
    # the clock moves once, hidden, after the answer to the named step: not before its request, and not after another step's
    assert collector.advances_seen["b"] == 0 and after == [0, 1, 1, 1]
    assert [call[1] for call in control.calls] == [{"millis": 3_700_000}] and virtual.now() == 1000.0 and virtual.utc() == "2026-10-04T01:01:40.000000Z"


def test_no_advance_is_asked_for_without_both_a_step_and_a_length(control):
    class Base:
        def _rpc(self, site, *args, **kwargs):
            return site

    virtual = clock.VirtualClock("http://c", "tok")
    assert clock.advancing(Base, virtual, 0, "b") is Base and clock.advancing(Base, virtual, 3700, None) is Base


# --- the virtual clock advances exactly what a wait asks for (the control API takes whole milliseconds), so token ages do not drift one second per wait ---

class Posts:
    def __init__(self):
        self.bodies = []

    def __call__(self, request, timeout=None):
        self.bodies.append(json.loads(request.data))
        return type("Response", (), {"read": lambda self: b"{}"})()


def clock_with(monkeypatch):
    posts = Posts()
    monkeypatch.setattr(clock.urllib.request, "urlopen", posts)
    return clock.VirtualClock("http://127.0.0.1:1", "t"), posts


def test_a_wait_advances_the_emulator_by_exactly_its_milliseconds(monkeypatch):
    virtual, posts = clock_with(monkeypatch)
    virtual.sleep(0.4)
    virtual.sleep(30.25)
    virtual.sleep(1)
    assert posts.bodies == [{"millis": 400}, {"millis": 30250}, {"millis": 1000}]
    assert virtual.skew == pytest.approx(31.65)


def test_a_wait_of_nothing_sends_nothing_and_a_sub_millisecond_wait_is_one_millisecond(monkeypatch):
    virtual, posts = clock_with(monkeypatch)
    virtual.sleep(0)
    virtual.sleep(-1)
    assert posts.bodies == [] and virtual.skew == 0
    virtual.sleep(0.0004)
    assert posts.bodies == [{"millis": 1}] and virtual.skew == pytest.approx(0.001)


def test_many_fractional_waits_never_drift_from_their_sum_by_more_than_a_millisecond_per_wait(monkeypatch):
    import random

    rng = random.Random(20261005)
    waits = [rng.uniform(0.01, 40) for _ in range(200)]
    virtual, posts = clock_with(monkeypatch)
    for seconds in waits:
        virtual.sleep(seconds)
    sent = sum(body["millis"] for body in posts.bodies) / 1000
    assert abs(sent - sum(waits)) <= 0.0005 * len(waits) + 1e-9 and virtual.skew == pytest.approx(sent)
    # the whole-second rule this replaces, applied to the one-second slices the collector sleeps a wait in, drifted upward by about half a second per wait
    def old_rule(seconds):
        total, remaining = 0, seconds
        while remaining > 1e-9:
            piece = min(1, remaining)
            total += max(1, int(round(piece)))
            remaining -= piece
        return total

    assert sum(old_rule(seconds) for seconds in waits) - sum(waits) > 20


def test_the_achieved_ages_pair_the_recorded_and_the_local_value_per_site_with_their_difference():
    rows = clock.achieved_ages({"a": 121.5, "b": 30.0}, {"a": 121.5, "b": 30.2, "c": 9.0})
    assert rows == [{"site": "a", "production": 121.5, "local": 121.5, "difference": 0.0}, {"site": "b", "production": 30.0, "local": 30.2, "difference": 0.2}]


def test_an_achieved_age_with_no_local_value_is_refused_and_a_site_filter_limits_the_rows():
    with pytest.raises(ValueError, match="no local"):
        clock.achieved_ages({"a": 1.0}, {})
    assert [row["site"] for row in clock.achieved_ages({"a": 1.0, "b": 2.0}, {"a": 1.0, "b": 2.0}, sites={"b"})] == ["b"]


def timed_steps():
    return [{"site": "s0", "timing": {"dispatchMonotonic": 10.0, "responseMonotonic": 11.0}}, {"site": "s1", "timing": {"dispatchMonotonic": 71.5, "responseMonotonic": 72.0}},
            {"site": "s2", "timing": {"dispatchMonotonic": 80.0, "responseMonotonic": 81.0}}]


def test_the_dispatch_gap_of_a_site_is_the_time_since_the_dispatch_of_the_step_before_it():
    assert clock.dispatch_gaps(timed_steps(), {"s1", "s2"}) == {"s1": 61.5, "s2": 8.5}
    assert clock.dispatch_gaps(timed_steps(), {"s0", "s1"}) == {"s1": 61.5}   # the first step waited for nothing
    assert clock.dispatch_gaps(timed_steps(), set()) == {}


# --- the age the emulator itself saw: the replay reads the emulator's clock around every request, so a begin that reached it late is not hidden by Python-side timestamps ---

PLAN_STEPS = [
    {"id": "begin", "tokenInput": None, "tokenOutput": "t"},
    {"id": "read", "tokenInput": "t", "tokenOutput": None},
    {"id": "other-begin", "tokenInput": None, "tokenOutput": "u"},
    {"id": "late-read", "tokenInput": "t", "tokenOutput": None},
    {"id": "late-other", "tokenInput": "u", "tokenOutput": None},
    {"id": "plain", "tokenInput": None, "tokenOutput": None},
]


def test_the_emulator_side_age_of_a_token_is_the_time_before_a_request_less_the_time_after_its_begin():
    before = {"begin": 0.0, "read": 31.0, "other-begin": 40.0, "late-read": 285.0, "late-other": 290.0, "plain": 300.0}
    after = {"begin": 1.0, "read": 31.5, "other-begin": 41.0, "late-read": 285.5, "late-other": 290.5, "plain": 300.5}
    assert clock.token_ages(PLAN_STEPS, before, after) == {"read": 30.0, "late-read": 284.0, "late-other": 249.0}


def test_a_step_whose_begin_was_not_marked_has_no_age():
    assert clock.token_ages(PLAN_STEPS, {"read": 5.0}, {}) == {}


def test_the_production_age_uses_the_recorded_dispatch_and_response_of_the_same_sites():
    steps = [
        {"site": "begin", "timing": {"dispatchMonotonic": 10.0, "responseMonotonic": 11.0}},
        {"site": "read", "timing": {"dispatchMonotonic": 41.0, "responseMonotonic": 42.0}},
        {"site": "other-begin", "timing": {"dispatchMonotonic": 50.0, "responseMonotonic": 51.0}},
        {"site": "late-read", "timing": {"dispatchMonotonic": 295.0, "responseMonotonic": 296.0}},
    ]
    assert clock.production_token_ages(PLAN_STEPS, steps) == {"read": 30.0, "late-read": 284.0}


def test_token_ages_are_judged_against_the_recorded_ones_within_a_tolerance_from_a_minimum_age():
    production = {"read": 30.0, "mid": 120.0, "late-read": 284.0}
    emulator = {"read": 20.0, "mid": 121.5, "late-read": 271.0}
    rows = clock.judge_token_ages(production, emulator, tolerance=2.0, minimum=100.0)
    # the young token is not judged; the middle one is within the tolerance; the late one is 13 s younger on the emulator: refused
    assert [(row["site"], row["match"]) for row in rows] == [("mid", True), ("late-read", False)]
    assert rows[1] == {"site": "late-read", "production": 284.0, "emulator": 271.0, "difference": -13.0, "match": False}


def test_a_recorded_token_age_the_emulator_never_saw_is_a_mismatch():
    rows = clock.judge_token_ages({"late-read": 284.0}, {}, tolerance=2.0, minimum=100.0)
    assert rows == [{"site": "late-read", "production": 284.0, "emulator": None, "difference": None, "match": False}]


def test_the_tolerance_is_inclusive_and_symmetric():
    rows = clock.judge_token_ages({"a": 200.0, "b": 200.0, "c": 200.0}, {"a": 202.0, "b": 198.0, "c": 202.001}, tolerance=2.0, minimum=100.0)
    assert [row["match"] for row in rows] == [True, True, False]


class FakeEmulatorClock:
    def __init__(self, readings):
        self.readings = list(readings)

    def __call__(self):
        return self.readings.pop(0)


def test_the_paced_collector_marks_the_emulator_clock_before_a_dispatch_and_after_its_answer(monkeypatch):
    marks = clock.EmulatorMarks(FakeEmulatorClock([1.0, 2.0, 3.0, 4.0]))
    marks.before("begin")
    marks.after("begin")
    marks.before("read")
    marks.after("read")
    assert marks.before_times == {"begin": 1.0, "read": 3.0} and marks.after_times == {"begin": 2.0, "read": 4.0}
    # without an emulator clock nothing is marked
    silent = clock.EmulatorMarks(None)
    silent.before("x")
    silent.after("x")
    assert silent.before_times == {} and silent.after_times == {}


def test_the_marks_keep_the_order_of_the_requests_and_give_the_emulator_side_idle_before_a_site():
    marks = clock.EmulatorMarks(FakeEmulatorClock([0.0, 1.0, 10.0, 11.0, 131.0, 132.0]))
    for site in ("a", "b", "c"):
        marks.before(site)
        marks.after(site)
    assert marks.order == ["a", "b", "c"]
    assert clock.idle_before(marks, {"b", "c"}) == {"b": 9.0, "c": 120.0}
    assert clock.idle_before(marks, {"a"}) == {}   # the first request idled for nothing


class FakeWire:
    def __init__(self):
        self.calls = []

    def send(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"code": 0}


def test_a_marked_wire_reads_the_emulator_clock_around_each_send_and_names_the_site_the_collector_is_at():
    marks = clock.EmulatorMarks(FakeEmulatorClock([5.0, 6.0]))
    collector = type("C", (), {"pending": {"site": "idle/commit"}})()
    wire = clock.MarkedWire(FakeWire(), marks, collector)
    assert wire.send("Commit", {"x": 1}, nonce="n") == {"code": 0}
    assert marks.before_times == {"idle/commit": 5.0} and marks.after_times == {"idle/commit": 6.0}
    assert wire.wire.calls == [(("Commit", {"x": 1}), {"nonce": "n"})]
    # any other attribute of the wire is the wire's own
    assert wire.calls == wire.wire.calls


# --- a frozen replay clock: it moves only by the waits, so real time spent under load cannot age a token the emulator's own frozen clock does not age ---

def test_a_frozen_clock_moves_only_by_what_was_advanced(monkeypatch):
    posts = Posts()
    monkeypatch.setattr(clock.urllib.request, "urlopen", posts)
    frozen = clock.VirtualClock("http://127.0.0.1:1", "t", frozen=True)
    first, first_utc = frozen.now(), frozen.utc()
    assert frozen.now() == first and frozen.utc() == first_utc   # real time passing changes nothing
    frozen.sleep(30.25)
    assert frozen.now() == pytest.approx(first + 30.25)
    import datetime as dt

    parse = lambda text: dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")   # noqa: E731
    assert (parse(frozen.utc()) - parse(first_utc)).total_seconds() == pytest.approx(30.25)
    # the unfrozen clock still follows real time as well
    live = clock.VirtualClock("http://127.0.0.1:1", "t")
    a = live.now()
    import time

    time.sleep(0.01)
    assert live.now() > a


def test_the_advance_that_paces_a_dispatch_is_what_is_missing_to_the_recorded_gap():
    assert clock.pacing_advance(gap=61.5, last_dispatch=100.0, now=100.0) == pytest.approx(61.5)
    assert clock.pacing_advance(gap=61.5, last_dispatch=100.0, now=130.0) == pytest.approx(31.5)   # a wait already advanced part of it
    assert clock.pacing_advance(gap=61.5, last_dispatch=100.0, now=170.0) == 0.0   # never backwards
    assert clock.pacing_advance(gap=None, last_dispatch=100.0, now=100.0) == 0.0   # a request the recording did not have
    assert clock.pacing_advance(gap=61.5, last_dispatch=None, now=100.0) == 0.0   # the first request


def test_the_emulator_clock_is_read_from_the_control_session_document(monkeypatch):
    # the shape the control API answers: the clock sits inside the clock object, in whole seconds
    body = json.dumps({"clock": {"backwardsSets": 0, "clock": "2026-08-29T12:01:00Z"}, "edition": "standard", "session": "default"}).encode()

    def fake(request, timeout=None):
        assert request.full_url == "http://127.0.0.1:1/sessions/default" and request.get_header("Authorization") == "Bearer t"
        return type("Response", (), {"read": lambda self: body})()

    monkeypatch.setattr(clock.urllib.request, "urlopen", fake)
    assert clock.VirtualClock("http://127.0.0.1:1", "t").emulator_now() == 1788004860.0
    # a bare timestamp is read too
    body = json.dumps({"clock": "2026-08-29T12:01:00.500Z"}).encode()
    assert clock.VirtualClock("http://127.0.0.1:1", "t").emulator_now() == 1788004860.5


def test_a_token_that_was_begun_again_is_aged_from_its_latest_begin_and_a_step_that_replaces_it_from_the_one_before():
    steps = [
        {"id": "begin-1", "tokenInput": None, "tokenOutput": "t"},
        {"id": "read-1", "tokenInput": "t", "tokenOutput": None},
        {"id": "begin-2", "tokenInput": None, "tokenOutput": "t"},
        {"id": "read-2", "tokenInput": "t", "tokenOutput": None},
        {"id": "retry", "tokenInput": "t", "tokenOutput": "t"},
        {"id": "read-3", "tokenInput": "t", "tokenOutput": None},
    ]
    before = {"read-1": 10.0, "read-2": 100.0, "retry": 150.0, "read-3": 200.0}
    after = {"begin-1": 1.0, "begin-2": 50.0, "retry": 160.0}
    assert clock.token_ages(steps, before, after) == {"read-1": 9.0, "read-2": 50.0, "retry": 100.0, "read-3": 40.0}


def test_the_recorded_age_of_a_step_whose_begin_was_not_recorded_is_left_out_rather_than_refused():
    steps = [{"site": "read", "timing": {"dispatchMonotonic": 50.0, "responseMonotonic": 51.0}}]
    assert clock.production_token_ages(PLAN_STEPS, steps) == {}


def test_a_recorded_age_of_exactly_the_minimum_is_judged_and_the_difference_is_rounded_to_milliseconds():
    rows = clock.judge_token_ages({"a": 100.0, "b": 99.999}, {"a": 100.0004, "b": 99.0}, tolerance=2.0, minimum=100.0)
    assert [row["site"] for row in rows] == ["a"] and rows[0]["difference"] == 0.0
    rows = clock.judge_token_ages({"a": 200.0}, {"a": 200.123456789}, tolerance=2.0, minimum=100.0)
    assert rows[0]["difference"] == 0.123


# --- the emulator-side age must fall on the same side of strict's limits as the recorded one, and a failed age row is a mismatch ---

def test_an_age_on_the_other_side_of_a_strict_limit_is_refused_even_inside_the_tolerance():
    # recorded 120.54 s (refused in production, over the 120 s idle limit); the emulator saw 119.9 s: 0.64 s apart, but it would accept
    rows = clock.judge_token_ages({"commit": 120.54, "keep": 110.7, "life": 283.0, "memory": 305.0}, {"commit": 119.9, "keep": 110.8, "life": 269.5, "memory": 299.0}, tolerance=4.0, minimum=100.0)
    assert [(row["site"], row["match"]) for row in rows] == [("commit", False), ("keep", True), ("life", False), ("memory", False)]
    # the same side keeps them
    rows = clock.judge_token_ages({"commit": 120.54, "life": 283.0, "memory": 305.0}, {"commit": 120.58, "life": 284.2, "memory": 305.5}, tolerance=4.0, minimum=100.0)
    assert all(row["match"] for row in rows)


def test_the_limits_are_the_idle_lifetime_and_memory_of_strict_and_a_recorded_age_at_a_limit_is_over_it():
    assert clock.STRICT_AGE_LIMITS == (120.0, 270.0, 300.0)
    rows = clock.judge_token_ages({"a": 120.0, "b": 270.0}, {"a": 120.0, "b": 269.999}, tolerance=4.0, minimum=100.0)
    assert [row["match"] for row in rows] == [True, False]   # at the limit counts as over; the emulator a hair under it does not


def test_the_limits_can_be_replaced_for_a_program_with_others():
    rows = clock.judge_token_ages({"a": 50.0}, {"a": 49.0}, tolerance=4.0, minimum=10.0, limits=(49.5,))
    assert [row["match"] for row in rows] == [False]
    assert clock.judge_token_ages({"a": 50.0}, {"a": 49.0}, tolerance=4.0, minimum=10.0, limits=())[0]["match"] is True


def test_applying_the_age_rows_stores_them_and_counts_every_failed_row_as_a_mismatch():
    result = {"mismatches": 2}
    rows = [{"match": True}, {"match": False}, {"match": False}]
    clock.apply_age_rows(result, rows)
    assert result["tokenAges"] == rows and result["mismatches"] == 4
    clean = {"mismatches": 0}
    clock.apply_age_rows(clean, [])
    assert clean == {"mismatches": 0, "tokenAges": []}   # a replay with no long-lived token still says it checked
