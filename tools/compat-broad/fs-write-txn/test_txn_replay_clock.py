"""Pacing for a local replay on the emulator's virtual clock: a replay reproduces the token ages of a production recording."""

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
    # a wait advances a whole number of seconds, at least one, and the clock reads that much later
    assert [call[1] for call in control.calls] == [{"seconds": 2}, {"seconds": 1}]
    assert control.calls[0][0] == "http://127.0.0.1:1/v1/sessions/default/clock:advance" and control.calls[0][2] == "Bearer tok"
    assert 3.0 <= virtual.now() - before < 4.0
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
    assert [call[1] for call in control.calls] == [{"seconds": 5}, {"seconds": 3700}]
    virtual.advance(10)
    assert virtual.now() == 1015.0 and virtual.utc() == "2026-10-04T01:01:55.000000Z"


def test_a_collector_that_advances_the_clock_once_after_a_named_step(control):
    import datetime

    class Base:
        def __init__(self):
            self.sites = []

        def _rpc(self, site, *args, **kwargs):
            self.sites.append(site)
            return f"answer {site}"

    virtual = clock.VirtualClock("http://c", "tok", datetime.datetime(2026, 10, 4, tzinfo=datetime.timezone.utc))
    collector = clock.advancing(Base, virtual, 3700, "b")()
    assert [collector._rpc(site) for site in ("a", "b", "c", "b")] == ["answer a", "answer b", "answer c", "answer b"]
    assert collector.sites == ["a", "b", "c", "b"]
    # one advance, after the first answer of the named step, and a hidden one
    assert [call[1] for call in control.calls] == [{"seconds": 3700}] and virtual.now() == 1000.0 and virtual.utc() == "2026-10-04T01:01:40.000000Z"


def test_no_advance_is_asked_for_without_both_a_step_and_a_length(control):
    class Base:
        def _rpc(self, site, *args, **kwargs):
            return site

    virtual = clock.VirtualClock("http://c", "tok")
    assert clock.advancing(Base, virtual, 0, "b") is Base and clock.advancing(Base, virtual, 3700, None) is Base
