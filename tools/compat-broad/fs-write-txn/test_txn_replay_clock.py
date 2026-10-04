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
