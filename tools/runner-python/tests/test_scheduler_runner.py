"""Scheduled runs through the real runner and the real SDK, in both profiles.

The rows are a PICT pairwise matrix over profile, season, fraction, outcome and function (the seed rows forced in:
each profile with a whole-second summer time, a winter and a clock-change instant, and a raising handler in both
profiles). The oracle is independent of the adapter: the handler sees the instant the daemon scheduled, written in
Los Angeles time in the strict profile and in UTC in the emulator profile, and a raising handler fails the attempt.
"""

import datetime

import pytest

from harness import Runner

JOB = "projects/demo-proj/locations/us-central1/jobs/firebase-schedule-{name}-us-central1"
INSTANTS = {"summer": "2026-10-05T08:45:00", "winter": "2026-01-05T08:45:00", "dst_edge": "2026-03-08T10:00:00"}
FRACTIONS = {"none": "", "millis": ".250", "micros": ".000250"}
LOS_ANGELES_OFFSET = {"summer": -7, "winter": -8, "dst_edge": -7}

ROWS = [
    ("emulator", "summer", "none", "ok", "sch_ok"),
    ("strict", "summer", "none", "ok", "sch_ok"),
    ("strict", "winter", "millis", "ok", "sch_retry"),
    ("strict", "dst_edge", "micros", "ok", "sch_ok"),
    ("emulator", "summer", "none", "raises", "sch_ok"),
    ("strict", "summer", "none", "raises", "sch_ok"),
    ("emulator", "dst_edge", "millis", "raises", "sch_retry"),
    ("strict", "summer", "millis", "raises", "sch_ok"),
    ("emulator", "summer", "micros", "raises", "sch_retry"),
    ("strict", "dst_edge", "none", "raises", "sch_retry"),
    ("emulator", "winter", "micros", "raises", "sch_ok"),
    ("strict", "winter", "none", "ok", "sch_ok"),
]


@pytest.fixture(scope="module")
def runners():
    started = {"emulator": Runner(), "strict": Runner(extra_env={"FIREEMU_HTTP_PROFILE": "strict"})}
    for process in started.values():
        process.hello()
    yield started
    for process in started.values():
        process.kill()


def frame(function, instant):
    return {
        "specversion": "1.0",
        "id": "sched-1",
        "source": "//cloudscheduler.googleapis.com/projects/demo-proj/locations/us-central1/jobs/x",
        "type": "google.cloud.scheduler.job.v1.executed",
        "time": instant,
        "datacontenttype": "application/json",
        "data": {"jobName": JOB.format(name=function), "scheduleTime": instant},
    }


@pytest.mark.parametrize("profile, season, fraction, outcome, function", ROWS)
def test_each_row_is_delivered_with_the_profiles_time_or_fails_the_attempt(runners, profile, season, fraction, outcome, function):
    process = runners[profile]
    target = "sch_boom" if outcome == "raises" else function
    instant = INSTANTS[season] + FRACTIONS[fraction] + "Z"
    result = process.invoke(f"sched-{len(process.frames)}", target, "schedule", frame(target, instant))
    entries = [entry for entry in process.seen() if entry["function"] == target and entry["job_name"] == f"firebase-schedule-{target}-us-central1"]
    assert entries, "the handler never ran"
    if outcome == "raises":
        assert result["ok"] is False and result["error"] == "the scheduled function answered 500: scheduled boom"
        return
    assert result["ok"] is True
    seen_time = datetime.datetime.fromisoformat(entries[-1]["schedule_time"])
    moment = datetime.datetime.fromisoformat(instant.replace("Z", "+00:00"))
    assert seen_time == moment
    expected_offset = datetime.timedelta(hours=LOS_ANGELES_OFFSET[season]) if profile == "strict" else datetime.timedelta(0)
    assert seen_time.utcoffset() == expected_offset


def test_a_schedule_frame_for_a_function_that_is_not_scheduled_is_refused(runners):
    result = runners["strict"].invoke("sched-wrong", "hello", "schedule", frame("hello", "2026-10-05T08:45:00Z"))
    assert result["ok"] is False and result["error"] == "trigger does not match the function manifest"


def test_a_scheduled_run_without_a_time_fails_the_attempt_and_runs_nothing(runners):
    process = runners["strict"]
    before = len([e for e in process.seen() if e["function"] == "sch_ok"])
    ev = frame("sch_ok", "2026-10-05T08:45:00Z")
    del ev["data"]["scheduleTime"]
    result = process.invoke("sched-notime", "sch_ok", "schedule", ev)
    assert result["ok"] is False and "RFC 3339" in result["error"]
    assert len([e for e in process.seen() if e["function"] == "sch_ok"]) == before
