"""Scheduled runs: the daemon's event becomes the request Cloud Scheduler sends, and the SDK wrapper answers it."""

import pytest

from fireemu_runner.scheduler import SchedulerFailure, deliver_schedule, scheduler_headers

JOB = "projects/demo-proj/locations/us-central1/jobs/firebase-schedule-sch_ok-us-central1"


def data(time="2026-10-05T08:45:00Z", job=JOB):
    return {"jobName": job, "scheduleTime": time}


# --- the headers ----------------------------------------------------------------------------------


def test_the_headers_are_the_ones_cloud_scheduler_sends_with_the_job_id_not_its_resource_name(monkeypatch):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    headers = scheduler_headers(data())
    assert headers == {
        "x-cloudscheduler": "true",
        "x-cloudscheduler-jobname": "firebase-schedule-sch_ok-us-central1",
        "x-cloudscheduler-scheduletime": "2026-10-05T01:45:00-07:00",
        "user-agent": "Google-Cloud-Scheduler",
        "content-length": "0",
    }


@pytest.mark.parametrize(
    "instant, local",
    [
        ("2026-10-05T08:45:00Z", "2026-10-05T01:45:00-07:00"),  # daylight saving time
        ("2026-01-05T08:45:00Z", "2026-01-05T00:45:00-08:00"),  # standard time
        ("2026-10-05T08:45:00.250Z", "2026-10-05T01:45:00.25-07:00"),  # trailing zeros of the fraction are dropped
        ("2026-10-05T08:45:00.000001Z", "2026-10-05T01:45:00.000001-07:00"),
        ("2026-10-05T08:45:00.000000000Z", "2026-10-05T01:45:00-07:00"),
        ("2026-03-08T09:59:59Z", "2026-03-08T01:59:59-08:00"),  # the second before the clocks move
        ("2026-03-08T10:00:00Z", "2026-03-08T03:00:00-07:00"),
        ("2026-11-01T08:59:59Z", "2026-11-01T01:59:59-07:00"),
        ("2026-11-01T09:00:00Z", "2026-11-01T01:00:00-08:00"),
    ],
)
def test_the_strict_profile_writes_the_schedule_time_in_los_angeles_as_production_does(monkeypatch, instant, local):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    assert scheduler_headers(data(instant))["x-cloudscheduler-scheduletime"] == local


@pytest.mark.parametrize("instant", ["2026-10-05T08:45:00Z", "2026-10-05T08:45:00.250Z"])
def test_the_emulator_profile_passes_the_schedule_time_as_the_daemon_gave_it(monkeypatch, instant):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "emulator")
    assert scheduler_headers(data(instant))["x-cloudscheduler-scheduletime"] == instant


def test_no_profile_is_the_emulator_profile(monkeypatch):
    monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    assert scheduler_headers(data())["x-cloudscheduler-scheduletime"] == "2026-10-05T08:45:00Z"


@pytest.mark.parametrize("job, id_", [("firebase-schedule-x-us-central1", "firebase-schedule-x-us-central1"), ("a/b/jobs/last", "last")])
def test_a_job_name_without_a_resource_path_is_its_own_id(job, id_):
    assert scheduler_headers(data(job=job))["x-cloudscheduler-jobname"] == id_


@pytest.mark.parametrize(
    "bad",
    [
        {"scheduleTime": "2026-10-05T08:45:00Z"},
        {"jobName": "", "scheduleTime": "2026-10-05T08:45:00Z"},
        {"jobName": 3, "scheduleTime": "2026-10-05T08:45:00Z"},
        {"jobName": JOB},
        {"jobName": JOB, "scheduleTime": "yesterday"},
        {"jobName": JOB, "scheduleTime": "2026-02-30T08:45:00Z"},
        {"jobName": JOB, "scheduleTime": "2026-10-05T08:45:00+09:00"},
        {"jobName": JOB, "scheduleTime": 5},
    ],
)
def test_a_run_without_a_job_or_a_valid_utc_time_is_refused(monkeypatch, bad):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    with pytest.raises(SchedulerFailure) as error:
        scheduler_headers(bad)
    assert str(error.value) in ("the scheduled run names no job name", f"the scheduled time is not an RFC 3339 UTC instant: {bad.get('scheduleTime')!r}")


def test_data_that_is_not_an_object_is_refused():
    for bad in (None, "x", [1]):
        with pytest.raises(SchedulerFailure) as error:
            scheduler_headers(bad)
        assert str(error.value) == "the scheduled run names no job name"


# --- delivery through the real SDK wrapper --------------------------------------------------------


def seen(discovered):
    return discovered["sch_ok"].__wrapped__.__globals__["SEEN"]


def test_the_wrapper_gets_the_job_and_the_time_in_its_event(discovered, monkeypatch):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    deliver_schedule(discovered["sch_ok"], data("2026-10-05T08:45:00.250Z"))
    entry = [e for e in seen(discovered) if e["function"] == "sch_ok"][-1]
    assert entry["job_name"] == "firebase-schedule-sch_ok-us-central1"
    assert entry["schedule_time"] == "2026-10-05T01:45:00.250000-07:00"


def test_the_emulator_profile_hands_the_wrapper_the_utc_time(discovered, monkeypatch):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "emulator")
    deliver_schedule(discovered["sch_ok"], data("2026-10-05T08:45:00Z"))
    entry = [e for e in seen(discovered) if e["function"] == "sch_ok"][-1]
    assert entry["schedule_time"] == "2026-10-05T08:45:00+00:00"


def test_a_handler_that_raises_is_a_failed_attempt_carrying_the_sdks_answer(discovered):
    with pytest.raises(SchedulerFailure) as error:
        deliver_schedule(discovered["sch_boom"], data())
    assert str(error.value) == "the scheduled function answered 500: scheduled boom"


def test_an_answer_below_400_is_a_success_and_one_from_400_is_not():
    class Answer:
        def __init__(self, status, body=""):
            self.status_code = status
            self._body = body

        def get_data(self, as_text=False):
            return self._body

    for status in (200, 204, 302, 399):
        deliver_schedule(lambda request, status=status: Answer(status), data())
    for status in (400, 404, 500, 503):
        with pytest.raises(SchedulerFailure, match=f"answered {status}"):
            deliver_schedule(lambda request, status=status: Answer(status, "x"), data())


def test_a_wrapper_that_raises_instead_of_answering_is_an_error_for_the_dispatcher():
    def broken(request):
        raise RuntimeError("wrapper broke")

    with pytest.raises(RuntimeError, match="wrapper broke"):
        deliver_schedule(broken, data())


def test_a_long_answer_is_cut_in_the_message():
    class Answer:
        status_code = 500

        def get_data(self, as_text=False):
            return "z" * 10000

    with pytest.raises(SchedulerFailure) as error:
        deliver_schedule(lambda request: Answer(), data())
    assert len(str(error.value)) < 600


def test_the_request_is_a_post_to_the_root_with_an_empty_body():
    seen = {}

    def function(request):
        seen.update(method=request.method, path=request.path, body=request.get_data())

        class Answer:
            status_code = 200

        return Answer()

    deliver_schedule(function, data())
    assert seen == {"method": "POST", "path": "/", "body": b""}


def test_an_answer_without_a_body_is_just_its_status():
    class Answer:
        status_code = 503

        def get_data(self, as_text=False):
            return ""

    with pytest.raises(SchedulerFailure) as error:
        deliver_schedule(lambda request: Answer(), data())
    assert str(error.value) == "the scheduled function answered 503"
