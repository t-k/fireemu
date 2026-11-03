"""What happens to the secret gate and to the diagnostics when user code fails (Codex r1 on slice 2b, M1 and M2).

The gate is process-wide, so two things must hold whatever user code does: the environment is released when the
response is over even if closing it raises, and no code that user code can influence (an exception's `__str__`, a
generator's cleanup) runs after the invocation left the gate, where another invocation's secret may be present.
"""

import os
import threading
import time

import pytest

from fireemu_runner import dispatch
from fireemu_runner.diagnostics import describe
from fireemu_runner.dispatch import Dispatcher
from fireemu_runner.environment import EnvironmentGate
from fireemu_runner.manifest import build_manifest
from fireemu_runner.serve import RunnerRouter

from test_dispatch import Collected, event, spec

SECRETS = {"API_KEY": "key-value", "TOKEN": "token-value"}
SECRET = "s3cret"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for name in SECRETS:
        monkeypatch.delenv(name, raising=False)


# --- describe ----------------------------------------------------------------------------------------


class Hostile(Exception):
    def __str__(self):
        raise RuntimeError("no string for you")


def test_describe_gives_the_traceback_and_the_text():
    try:
        raise ValueError("it broke")
    except ValueError as error:
        diagnostic, text = describe(error)
    assert diagnostic.startswith("Traceback") and "ValueError: it broke" in diagnostic and text == "it broke"


def test_an_error_without_a_message_is_named_by_its_class():
    assert describe(KeyError())[1] == "KeyError"


def test_describe_never_raises_even_when_the_error_cannot_be_turned_into_text():
    diagnostic, text = describe(Hostile())
    assert "Hostile" in diagnostic and text == "Hostile"


# --- M2: diagnostics are made inside the invocation's own environment --------------------------------------


class LeakyError(Exception):
    """Reads the environment when it is turned into text, and waits for a secret invocation to start first."""

    def __init__(self, started):
        super().__init__("leaky")
        self.started = started
        self.seen = None

    def __str__(self):
        self.started.wait(1.0)  # without the fix, the secret invocation starts as soon as this one leaves the gate
        self.seen = os.environ.get("API_KEY")
        return f"saw {self.seen}"


def test_an_exceptions_text_is_made_before_the_next_invocation_can_enter_the_gate():
    gate = EnvironmentGate(SECRETS)
    writer = Collected()
    secret_started = threading.Event()
    plain_running = threading.Event()
    release_plain = threading.Event()
    error = LeakyError(secret_started)

    def plain(_):
        plain_running.set()
        release_plain.wait(5)
        raise error

    release_secret = threading.Event()

    def secret(_):
        secret_started.set()
        release_secret.wait(5)  # stays in the environment until the test has looked at the plain invocation's text

    functions = {"plain": plain, "secret": secret}
    specs = [spec(name="plain"), {**spec(name="secret"), "platformOptions": {"secrets": ["API_KEY"]}}]
    dispatcher = Dispatcher(functions, {"functions": specs}, writer, gate)
    for invocation, function in (("p", "plain"), ("s", "secret")):
        dispatcher.reserve()
        dispatcher.start({"type": "invoke", "invocationId": invocation, "function": function, "trigger": "firestore", "event": event()})
        if invocation == "p":
            assert plain_running.wait(5)
            time.sleep(0.1)  # the secret invocation queues behind it
    release_plain.set()
    result = writer.result("p")
    release_secret.set()
    writer.result("s")
    assert result["ok"] is False
    assert error.seen is None, "the exception was formatted while another invocation's secret was in the environment"
    assert "key-value" not in result["error"]
    logs = [frame for frame in writer.frames if frame["type"] == "log" and frame["invocationId"] == "p"]
    assert logs and all("key-value" not in log["message"] for log in logs)


def test_an_error_that_cannot_be_formatted_still_answers_the_daemon():
    writer = Collected()

    def broken(_):
        raise Hostile()

    dispatcher = Dispatcher({"f": broken}, {"functions": [spec()]}, writer, EnvironmentGate(SECRETS))
    dispatcher.reserve()
    dispatcher.start({"type": "invoke", "invocationId": "h", "function": "f", "trigger": "firestore", "event": event()})
    assert writer.result("h") == {"type": "result", "invocationId": "h", "ok": False, "error": "Hostile"}
    assert any(frame["type"] == "log" and frame["invocationId"] == "h" for frame in writer.frames)


def test_the_gate_is_free_after_an_error_that_cannot_be_formatted():
    gate = EnvironmentGate(SECRETS)
    writer = Collected()

    def broken(_):
        raise Hostile()

    dispatcher = Dispatcher({"f": broken}, {"functions": [{**spec(), "platformOptions": {"secrets": ["API_KEY"]}}]}, writer, gate)
    dispatcher.reserve()
    dispatcher.start({"type": "invoke", "invocationId": "h", "function": "f", "trigger": "firestore", "event": event()})
    writer.result("h")
    with gate.hold(["API_KEY"]):
        assert os.environ["API_KEY"] == "key-value"


# --- M1: the gate is released when the response cannot be closed cleanly ------------------------------------


def free(gate):
    """Whether a secret invocation can enter the gate now."""
    entered = threading.Event()

    def enter():
        with gate.hold(["API_KEY"]):
            entered.set()

    thread = threading.Thread(target=enter, daemon=True)
    thread.start()
    return entered.wait(2)


def post(router, name):
    """One request the way a WSGI server serves it: call, read the body, close. Failures along the way are the
    server's to log; what the tests look at is the gate."""
    from werkzeug.test import EnvironBuilder

    environ = EnvironBuilder(f"/demo-proj/us-central1/{name}", headers={"x-fireemu-runner-secret": SECRET}).get_environ()
    outcome = []
    body = router(environ, lambda *args: None)
    try:
        outcome.append(b"".join(body))
    except Exception as error:
        outcome.append(error)
    finally:
        try:
            body.close()
        except Exception as error:
            outcome.append(error)
    return outcome


def test_a_response_whose_close_callback_raises_still_releases_the_gate(discovered):
    gate = EnvironmentGate(SECRETS)
    router = RunnerRouter(discovered, build_manifest(discovered), "demo-proj", SECRET, gate)
    outcome = post(router, "closes_badly")
    assert not [item for item in outcome if isinstance(item, BaseException)], "the close failure must stay inside the runner"
    assert free(gate), "the gate stayed locked"
    assert "API_KEY" not in os.environ, "the secret stayed in the environment"


def test_a_body_whose_cleanup_raises_still_releases_the_gate():
    gate = EnvironmentGate(SECRETS)

    def generator():
        try:
            yield b"x"
        finally:
            raise RuntimeError("cleanup failed")

    def view(request):
        import flask

        return flask.Response(generator())

    manifest = {"functions": [{"name": "g", "entryPoint": "g", "region": "us-central1", "trigger": {"type": "http"}, "platformOptions": {"secrets": ["API_KEY"]}}]}
    router = RunnerRouter({"g": view}, manifest, "demo-proj", SECRET, gate)
    post(router, "g")
    assert free(gate) and "API_KEY" not in os.environ


def test_a_body_that_raises_while_it_is_read_is_reported_without_running_its_text_outside_the_gate(capsys):
    gate = EnvironmentGate(SECRETS)
    started = threading.Event()

    class Leaky(Exception):
        seen = "unset"

        def __str__(self):
            Leaky.seen = os.environ.get("TOKEN")
            return "leaky"

    def generator():
        yield b"first"
        raise Leaky()

    def view(request):
        import flask

        return flask.Response(generator())

    manifest = {"functions": [{"name": "g", "entryPoint": "g", "region": "us-central1", "trigger": {"type": "http"}, "platformOptions": {"secrets": ["API_KEY"]}}]}
    router = RunnerRouter({"g": view}, manifest, "demo-proj", SECRET, gate)
    outcome = post(router, "g")
    assert [type(item).__name__ for item in outcome if isinstance(item, BaseException)] == ["ResponseBodyFailed"]
    assert Leaky.seen == None or Leaky.seen != "token-value"  # noqa: E711
    assert Leaky.seen is None, "the exception text was made inside the function's environment (TOKEN is not declared)"
    assert free(gate)
    assert "token-value" not in capsys.readouterr().err
