"""Invocation frames in process: the checks, the answer, the identity variables and the bounds."""

import os
import threading
import time

import pytest

from fireemu_runner import dispatch
from fireemu_runner.dispatch import Dispatcher

FS = "google.cloud.firestore.document.v1."


class Collected:
    """A writer that keeps the frames and lets a test wait for one."""

    def __init__(self):
        self.frames = []
        self._cond = threading.Condition()

    def write(self, message):
        with self._cond:
            self.frames.append(message)
            self._cond.notify_all()

    def wait_for(self, predicate, timeout=10):
        with self._cond:
            assert self._cond.wait_for(lambda: any(predicate(f) for f in self.frames), timeout), self.frames
            return next(f for f in self.frames if predicate(f))

    def result(self, invocation):
        return self.wait_for(lambda f: f["type"] == "result" and f["invocationId"] == invocation)


def spec(name="f", trigger="firestore", entry_point=None):
    return {"name": name, "entryPoint": entry_point or name, "generation": 2, "trigger": {"type": trigger}}


def event():
    return {
        "specversion": "1.0",
        "id": "e-1",
        "source": "//firestore.googleapis.com/projects/demo-proj/databases/(default)",
        "type": FS + "created",
        "time": "2026-01-01T00:00:00Z",
        "subject": "documents/a/b",
        "data": {},
    }


def invoke(dispatcher, invocation="i-1", function="f", trigger="firestore", **extra):
    message = {"type": "invoke", "invocationId": invocation, "function": function, "trigger": trigger, "event": event(), **extra}
    assert dispatcher.reserve()
    dispatcher.start(message)
    return message


def build(functions, specs=None):
    writer = Collected()
    return Dispatcher(functions, {"functions": specs if specs is not None else [spec()]}, writer), writer


def test_a_matching_invoke_runs_the_function_with_a_cloud_event_and_answers_ok():
    received = []
    dispatcher, writer = build({"f": received.append})
    invoke(dispatcher)
    assert writer.result("i-1") == {"type": "result", "invocationId": "i-1", "ok": True}
    assert received[0]["id"] == "e-1" and received[0]["type"] == FS + "created"


def test_the_function_identity_variables_name_the_invocation_before_the_handler_runs(monkeypatch):
    # Earlier tests leave these set; the runner must be the one that sets them.
    for key in ("FUNCTION_TARGET", "FUNCTION_SIGNATURE_TYPE", "K_SERVICE"):
        monkeypatch.delenv(key, raising=False)
    seen = {}

    def handler(_):
        seen.update({key: os.environ.get(key) for key in ("FUNCTION_TARGET", "FUNCTION_SIGNATURE_TYPE", "K_SERVICE")})

    dispatcher, writer = build({"entry": handler}, [spec(name="named", entry_point="entry")])
    invoke(dispatcher, function="named")
    assert writer.result("i-1")["ok"]
    assert seen == {"FUNCTION_TARGET": "entry", "FUNCTION_SIGNATURE_TYPE": "cloudevent", "K_SERVICE": "named"}


@pytest.mark.parametrize(
    "extra, function, trigger, error",
    [
        ({}, "other", "firestore", "unknown function"),
        ({"entryPoint": "x"}, "f", "firestore", "entry point does not match the function manifest"),
        ({}, "f", "pubsub", "trigger does not match the function manifest"),
        ({}, "h", "http", "trigger does not match the function manifest"),
    ],
)
def test_a_frame_that_does_not_match_the_manifest_is_refused_and_nothing_runs(extra, function, trigger, error):
    ran = []
    dispatcher, writer = build({"f": ran.append, "h": ran.append}, [spec(), spec(name="h", trigger="http")])
    invoke(dispatcher, function=function, trigger=trigger, **extra)
    assert writer.result("i-1") == {"type": "result", "invocationId": "i-1", "ok": False, "error": error}
    assert ran == []


def test_a_manifest_function_without_a_callable_is_refused():
    dispatcher, writer = build({}, [spec()])
    invoke(dispatcher)
    assert writer.result("i-1")["error"] == "missing function entry point"


def test_a_raising_handler_is_a_failed_result_and_a_log_frame_with_the_traceback():
    def handler(_):
        raise RuntimeError("handler broke")

    dispatcher, writer = build({"f": handler})
    invoke(dispatcher)
    assert writer.result("i-1") == {"type": "result", "invocationId": "i-1", "ok": False, "error": "handler broke"}
    log = writer.wait_for(lambda f: f["type"] == "log")
    assert log["level"] == "error" and log["invocationId"] == "i-1" and log["functionName"] == "f" and log["user"] is False
    assert log["message"].startswith("f: Traceback") and "RuntimeError: handler broke" in log["message"]


def test_a_handler_that_exits_still_answers_the_daemon():
    def handler(_):
        raise SystemExit(3)

    dispatcher, writer = build({"f": handler})
    invoke(dispatcher)
    assert writer.result("i-1")["ok"] is False


def test_an_error_without_a_message_is_named_by_its_class_and_a_long_one_is_cut():
    def silent(_):
        raise KeyError()

    def verbose(_):
        raise ValueError("x" * 10000)

    dispatcher, writer = build({"silent": silent, "verbose": verbose}, [spec("silent"), spec("verbose")])
    invoke(dispatcher, "a", "silent")
    invoke(dispatcher, "b", "verbose")
    assert writer.result("a")["error"] == "KeyError"
    long = writer.result("b")["error"]
    assert len(long) == 4096 and long.endswith("…")
    log = writer.wait_for(lambda f: f["type"] == "log" and f["invocationId"] == "b")
    assert len(log["message"]) < 256 * 1024


def test_an_oversized_diagnostic_is_cut_to_the_log_bound():
    def handler(_):
        raise ValueError("y" * (300 * 1024))

    dispatcher, writer = build({"f": handler})
    invoke(dispatcher)
    log = writer.wait_for(lambda f: f["type"] == "log")
    assert len(log["message"]) == 256 * 1024 and log["message"].endswith("…")


def test_an_event_the_adapter_cannot_build_is_a_failed_result():
    dispatcher, writer = build({"f": lambda _: None})
    message = {"type": "invoke", "invocationId": "i-1", "function": "f", "trigger": "firestore", "event": {"data": {}}}
    dispatcher.reserve()
    dispatcher.start(message)
    result = writer.result("i-1")
    assert result["ok"] is False and "specversion" in result["error"]


def test_the_active_count_returns_to_zero_after_each_outcome_and_the_limit_holds(monkeypatch):
    monkeypatch.setattr(dispatch, "MAX_ACTIVE_INVOCATIONS", 2)
    release = threading.Event()
    dispatcher, writer = build({"f": lambda _: release.wait(10)})
    assert dispatcher.reserve() and dispatcher.reserve()
    assert not dispatcher.reserve()
    dispatcher._active = 0  # the two reservations above only tested the limit
    first = invoke(dispatcher, "a")
    second = invoke(dispatcher, "b")
    assert not dispatcher.reserve()
    release.set()
    writer.result("a")
    writer.result("b")
    deadline = time.monotonic() + 5
    while dispatcher._active and time.monotonic() < deadline:
        time.sleep(0.01)
    assert dispatcher._active == 0
    assert dispatcher.reserve()
    assert first and second


def test_a_failing_log_write_cannot_suppress_the_result():
    class FlakyWriter(Collected):
        def write(self, message):
            if message["type"] == "log":
                raise OSError("pipe closed")
            super().write(message)

    def handler(_):
        raise RuntimeError("boom")

    writer = FlakyWriter()
    dispatcher = Dispatcher({"f": handler}, {"functions": [spec()]}, writer)
    invoke(dispatcher)
    assert writer.result("i-1")["ok"] is False


def test_each_invocation_runs_on_its_own_named_daemon_thread():
    seen = {}

    def handler(_):
        thread = threading.current_thread()
        seen.update(name=thread.name, daemon=thread.daemon)

    dispatcher, writer = build({"f": handler})
    invoke(dispatcher, "run-7")
    assert writer.result("run-7")["ok"]
    assert seen == {"name": "invoke-run-7", "daemon": True}


def test_an_error_message_of_exactly_the_bound_is_kept_whole_and_one_more_is_cut():
    assert dispatch._bound("a" * 4096, 4096) == "a" * 4096
    assert dispatch._bound("a" * 4097, 4096) == "a" * 4095 + "…"
    assert dispatch._bound("", 4096) == ""


def test_the_traceback_is_joined_without_a_separator():
    def handler(_):
        raise RuntimeError("two\nlines")

    dispatcher, writer = build({"f": handler})
    invoke(dispatcher)
    log = writer.wait_for(lambda f: f["type"] == "log")
    assert "XX" not in log["message"]
    assert log["message"].count("Traceback (most recent call last):") == 1
    assert log["message"].endswith("RuntimeError: two\nlines\n")


# --- scheduled runs (slice 2b) -----------------------------------------------------------------------


def schedule_message(invocation="s-1", data=None, function="f"):
    event_data = {"jobName": "projects/p/locations/l/jobs/job-1", "scheduleTime": "2026-10-05T08:45:00Z"} if data is None else data
    return {
        "type": "invoke", "invocationId": invocation, "function": function, "trigger": "schedule",
        "event": {"specversion": "1.0", "id": "e-1", "type": "google.cloud.scheduler.job.v1.executed", "data": event_data},
    }


def run_schedule(function, message=None, **spec_kwargs):
    dispatcher, writer = build({"f": function}, [spec(trigger="schedule", **spec_kwargs)])
    dispatcher.reserve()
    dispatcher.start(message or schedule_message())
    return writer


def test_a_scheduled_run_calls_the_function_with_the_schedulers_request_and_answers_ok(monkeypatch):
    monkeypatch.delenv("FUNCTION_SIGNATURE_TYPE", raising=False)
    seen = {}

    def function(request):
        seen.update(job=request.headers["X-CloudScheduler-JobName"], method=request.method, signature=os.environ["FUNCTION_SIGNATURE_TYPE"])

        class Answer:
            status_code = 200

        return Answer()

    writer = run_schedule(function)
    assert writer.result("s-1") == {"type": "result", "invocationId": "s-1", "ok": True}
    assert seen == {"job": "job-1", "method": "POST", "signature": "http"}


def test_a_scheduled_function_that_answers_500_is_a_failed_attempt_with_the_answer():
    class Answer:
        status_code = 500

        def get_data(self, as_text=False):
            return "it broke"

    writer = run_schedule(lambda request: Answer())
    assert writer.result("s-1") == {"type": "result", "invocationId": "s-1", "ok": False, "error": "the scheduled function answered 500: it broke"}


@pytest.mark.parametrize("data", [None, {}, {"jobName": "j"}, "text"])
def test_a_scheduled_run_without_a_job_and_time_is_a_failed_result_and_runs_nothing(data):
    ran = []
    message = schedule_message(data=data)
    if data is None:
        message["event"] = {"specversion": "1.0"}
    writer = run_schedule(ran.append, message)
    assert writer.result("s-1")["ok"] is False and ran == []


def test_a_schedule_frame_for_a_function_the_manifest_serves_otherwise_is_refused():
    ran = []
    dispatcher, writer = build({"f": ran.append}, [spec(trigger="firestore")])
    dispatcher.reserve()
    dispatcher.start(schedule_message())
    assert writer.result("s-1")["error"] == "trigger does not match the function manifest" and ran == []


def test_a_failed_scheduled_attempt_logs_its_one_line_not_a_runner_traceback():
    # The SDK wrapper already logged the user's exception; the runner adds the status the Scheduler judged by.
    class Answer:
        status_code = 500

        def get_data(self, as_text=False):
            return "it broke"

    writer = run_schedule(lambda request: Answer())
    log = writer.wait_for(lambda f: f["type"] == "log" and f["invocationId"] == "s-1")
    assert log["message"] == "f: the scheduled function answered 500: it broke"
    assert log["level"] == "error"


# --- secrets (slice 2b) ------------------------------------------------------------------------------

from fireemu_runner.environment import EnvironmentGate  # noqa: E402


def build_with_gate(functions, specs, secrets):
    writer = Collected()
    return Dispatcher(functions, {"functions": specs}, writer, EnvironmentGate(secrets)), writer


def secret_spec(name, secrets):
    return {**spec(name=name), "platformOptions": {"secrets": secrets}} if secrets is not None else spec(name=name)


def test_an_event_function_sees_the_secrets_it_declares_and_a_plain_one_sees_none(monkeypatch):
    for name in ("API_KEY", "TOKEN"):
        monkeypatch.delenv(name, raising=False)
    seen = {}

    def declares(_):
        seen["declares"] = {n: os.environ.get(n) for n in ("API_KEY", "TOKEN")}

    def plain(_):
        seen["plain"] = {n: os.environ.get(n) for n in ("API_KEY", "TOKEN")}

    dispatcher, writer = build_with_gate(
        {"declares": declares, "plain": plain},
        [secret_spec("declares", ["API_KEY"]), secret_spec("plain", None)],
        {"API_KEY": "k", "TOKEN": "t"},
    )
    for invocation, function in (("a", "declares"), ("b", "plain")):
        dispatcher.reserve()
        dispatcher.start({"type": "invoke", "invocationId": invocation, "function": function, "trigger": "firestore", "event": event()})
        assert writer.result(invocation)["ok"] is True
    assert seen == {"declares": {"API_KEY": "k", "TOKEN": None}, "plain": {"API_KEY": None, "TOKEN": None}}
    assert "API_KEY" not in os.environ and "TOKEN" not in os.environ


def test_a_failing_function_with_a_secret_frees_the_gate_for_the_next_invocation(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    order = []

    def breaks(_):
        order.append("breaks")
        raise RuntimeError("no")

    def after(_):
        order.append("after")

    dispatcher, writer = build_with_gate(
        {"breaks": breaks, "after": after}, [secret_spec("breaks", ["API_KEY"]), secret_spec("after", ["API_KEY"])], {"API_KEY": "k"}
    )
    for invocation, function in (("a", "breaks"), ("b", "after")):
        dispatcher.reserve()
        dispatcher.start({"type": "invoke", "invocationId": invocation, "function": function, "trigger": "firestore", "event": event()})
        writer.result(invocation)
    assert order == ["breaks", "after"] and writer.result("a")["ok"] is False and writer.result("b")["ok"] is True


def test_a_scheduled_function_with_a_secret_is_gated_too(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    seen = {}

    def function(request):
        seen["key"] = os.environ.get("API_KEY")

        class Answer:
            status_code = 200

        return Answer()

    dispatcher, writer = build_with_gate({"f": function}, [{**spec(trigger="schedule"), "platformOptions": {"secrets": ["API_KEY"]}}], {"API_KEY": "k"})
    dispatcher.reserve()
    dispatcher.start(schedule_message())
    assert writer.result("s-1")["ok"] is True and seen == {"key": "k"}


def test_a_schedule_frame_whose_event_is_not_an_object_is_a_failed_result():
    message = schedule_message()
    message["event"] = "not an event"
    ran = []
    writer = run_schedule(ran.append, message)
    assert writer.result("s-1") == {"type": "result", "invocationId": "s-1", "ok": False, "error": "the scheduled run names no job name"}
    assert ran == []
