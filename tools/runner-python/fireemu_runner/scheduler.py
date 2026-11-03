"""Scheduled runs: the request Cloud Scheduler sends a Gen2 function, built in process.

A Gen2 `on_schedule` function is an HTTP function. Production's Scheduler calls it with `POST /`, the job id in
`X-CloudScheduler-JobName` and the schedule time in `X-CloudScheduler-ScheduleTime`, and judges the attempt by the
status the SDK wrapper answers: 200, or 500 when the handler raised (the wrapper logs the error and answers its
message, `scheduler_fn.py:99-137`). The Node runner does the same in the strict profile
(`tools/runner-node/schedule-delivery.mjs`, recorded in run 156715222b86ea44).
"""

import datetime
import os
import re
from zoneinfo import ZoneInfo

import flask
from werkzeug.test import EnvironBuilder

_INSTANT = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z$")
_LOS_ANGELES = ZoneInfo("America/Los_Angeles")
_MAX_ANSWER_CHARS = 256
_app = None


class SchedulerFailure(Exception):
    """A scheduled attempt that failed: the run was malformed or the function answered 400 or more."""


def _flask_app() -> flask.Flask:
    global _app
    if _app is None:
        _app = flask.Flask("fireemu-scheduler")
    return _app


def _schedule_time(instant) -> str:
    """The schedule time as the header carries it: Los Angeles with its offset in the strict profile (whatever the
    job's own zone, as recorded), the daemon's UTC instant otherwise."""
    match = _INSTANT.match(instant) if isinstance(instant, str) else None
    if match is None:
        raise SchedulerFailure(f"the scheduled time is not an RFC 3339 UTC instant: {instant!r}")
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    try:
        moment = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    except ValueError:
        raise SchedulerFailure(f"the scheduled time is not an RFC 3339 UTC instant: {instant!r}") from None
    if os.environ.get("FIREEMU_HTTP_PROFILE", "emulator") != "strict":
        return instant
    local = moment.astimezone(_LOS_ANGELES)
    fraction = (match.group(7) or "").rstrip("0")
    offset = local.strftime("%z")
    return local.strftime("%Y-%m-%dT%H:%M:%S") + (f".{fraction}" if fraction else "") + f"{offset[:3]}:{offset[3:]}"


def scheduler_headers(data) -> dict:
    """The headers of the request for one scheduled run (`{jobName, scheduleTime}`)."""
    job = data.get("jobName") if isinstance(data, dict) else None
    if not isinstance(job, str) or not job:
        raise SchedulerFailure("the scheduled run names no job name")
    return {
        "x-cloudscheduler": "true",
        "x-cloudscheduler-jobname": job.rsplit("/", 1)[-1],
        "x-cloudscheduler-scheduletime": _schedule_time(data.get("scheduleTime")),
        "user-agent": "Google-Cloud-Scheduler",
        "content-length": "0",
    }


def deliver_schedule(function, data) -> None:
    """Calls the SDK wrapper with the scheduler's request. Returns when it answers below 400; raises otherwise."""
    environ = EnvironBuilder(method="POST", path="/", headers=scheduler_headers(data)).get_environ()
    with _flask_app().request_context(environ):
        response = function(flask.request)
    if response.status_code >= 400:
        body = response.get_data(as_text=True)[:_MAX_ANSWER_CHARS]
        raise SchedulerFailure(f"the scheduled function answered {response.status_code}" + (f": {body}" if body else ""))
