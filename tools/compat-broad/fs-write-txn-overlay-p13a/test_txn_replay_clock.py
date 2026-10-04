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
