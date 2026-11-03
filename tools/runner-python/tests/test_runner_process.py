"""The real runner as a process: hello, invoke dispatch, output hygiene, shutdown and failures."""

import json
import subprocess
import sys

import pytest

from conftest import FIXTURE
from harness import SCRIPT, SECRET, Runner

FS = "google.cloud.firestore.document.v1."


@pytest.fixture(scope="module")
def runner():
    process = Runner()
    process.hello()
    yield process
    process.kill()


def test_hello_announces_the_python_runner_its_http_port_and_the_manifest(runner):
    hello = runner.hello()
    assert hello["runner"] == "python"
    assert hello["codebase"] == "default"
    assert isinstance(hello["httpPort"], int) and hello["httpPort"] > 0
    assert hello["version"].startswith("3.")
    # No virtual clock, no App Check instrumentation: the daemon must see the keys absent.
    for key in ("clock", "appCheck", "adminAppCheck", "inspectorPort"):
        assert key not in hello
    manifest = hello["manifest"]
    served = {entry["name"] for entry in manifest["functions"]}
    assert {"hello", "add", "fs_created", "fs_literal", "fs_options"} <= served
    assert manifest["ignored"] == []


@pytest.mark.parametrize(
    "overrides, fragment",
    [
        ({"function": "nope"}, "unknown function"),
        ({"function": "fs_created", "entry_point": "other"}, "entry point does not match"),
        ({"function": "fs_created", "trigger": "pubsub"}, "trigger does not match"),
        # An HTTP function is never invoked by a frame.
        ({"function": "hello", "trigger": "firestore"}, "trigger does not match"),
        ({"function": "hello", "trigger": "http"}, "trigger does not match"),
    ],
)
def test_an_invoke_that_does_not_match_the_manifest_is_refused_and_nothing_runs(runner, overrides, fragment):
    before = runner.seen()
    arguments = {"function": "fs_created", "trigger": "firestore", "entry_point": None, **overrides}
    result = runner.invoke(f"refused-{fragment[:6]}-{overrides['function']}", arguments["function"], arguments["trigger"], {"type": FS + "created"}, entry_point=arguments["entry_point"])
    assert result["ok"] is False
    assert fragment in result["error"]
    assert runner.seen() == before


def test_user_output_in_every_form_never_reaches_the_protocol_channel(runner):
    status, _, body = runner.request("/demo-proj/us-central1/noisy")
    assert (status, body) == (200, b"ok")
    # Collecting every frame shows the channel is clean: a stray byte becomes a "corrupt" frame.
    assert [frame for frame in runner.frames if frame["type"] == "corrupt"] == []
    for text in ("python print", "raw fd write", "child process", "sys.stdout write", "sdk logger line"):
        assert text in runner.stderr


def test_a_shutdown_frame_ends_the_runner_cleanly():
    process = Runner()
    process.hello()
    process.send({"type": "shutdown"})
    assert process.process.wait(10) == 0
    process.close()


def test_the_end_of_stdin_ends_the_runner_cleanly():
    process = Runner()
    process.hello()
    assert process.close() == 0


@pytest.mark.parametrize("garbage", [b"x\n", b"05\n{}", b"3\n[1]", b"9\nshort"])
def test_a_corrupt_frame_stops_the_runner_with_status_2_and_a_fixed_reason(garbage):
    process = Runner()
    process.hello()
    process.send_raw(garbage)
    assert process.close() == 2
    assert "invalid runner frame" in process.stderr


def test_user_code_that_fails_to_load_exits_before_any_hello(tmp_path):
    (tmp_path / "main.py").write_text("raise RuntimeError('does not load')\n")
    process = Runner(source=tmp_path)
    assert process.close() == 1
    assert [frame for frame in process.frames if frame["type"] == "hello"] == []
    assert "RuntimeError: does not load" in process.stderr


def test_a_missing_main_py_says_so(tmp_path):
    process = Runner(source=tmp_path)
    assert process.close() == 1
    assert "main.py" in process.stderr


def test_event_families_not_served_yet_are_reported_as_planned_never_dropped(tmp_path):
    (tmp_path / "main.py").write_text(
        "from firebase_admin import initialize_app\n"
        "from firebase_functions import pubsub_fn, scheduler_fn, firestore_fn\n"
        "initialize_app()\n"
        "@pubsub_fn.on_message_published(topic='jobs')\n"
        "def later_pubsub(event):\n    pass\n"
        "@scheduler_fn.on_schedule(schedule='every 5 minutes')\n"
        "def later_schedule(request):\n    pass\n"
        "@firestore_fn.on_document_created(document='a/{id}')\n"
        "def served(event):\n    pass\n"
    )
    process = Runner(source=tmp_path)
    manifest = process.hello()["manifest"]
    assert [entry["name"] for entry in manifest["functions"]] == ["served"]
    ignored = {entry["name"]: entry for entry in manifest["ignored"]}
    assert set(ignored) == {"later_pubsub", "later_schedule"}
    assert (ignored["later_pubsub"]["triggerType"], ignored["later_schedule"]["triggerType"]) == ("pubsub", "schedule")
    for entry in ignored.values():
        assert entry["scope"] == "planned" and entry["region"] == "us-central1" and "Python" in entry["reason"]
    assert process.close() == 0


def test_a_codebase_without_http_functions_announces_no_port(tmp_path):
    (tmp_path / "main.py").write_text(
        "from firebase_admin import initialize_app\n"
        "from firebase_functions import firestore_fn\n"
        "initialize_app()\n"
        "@firestore_fn.on_document_created(document='a/{id}')\n"
        "def only(event):\n    pass\n"
    )
    process = Runner(source=tmp_path)
    hello = process.hello()
    assert hello["httpPort"] is None
    assert [entry["name"] for entry in hello["manifest"]["functions"]] == ["only"]
    assert process.close() == 0


def test_the_secret_is_not_left_in_the_environment_user_code_sees(tmp_path):
    (tmp_path / "main.py").write_text(
        "import os\n"
        "from firebase_functions import https_fn\n"
        "@https_fn.on_request()\n"
        "def env(request):\n"
        "    return {'secret': os.environ.get('FIREEMU_RUNNER_SECRET'), 'local': os.environ.get('FIREEMU_LOCAL_SECRETS_JSON')}\n"
    )
    process = Runner(source=tmp_path, extra_env={"FIREEMU_LOCAL_SECRETS_JSON": "{\"A\":\"b\"}"})
    status, _, body = process.request("/demo-proj/us-central1/env")
    assert status == 200
    assert json.loads(body) == {"secret": None, "local": None}
    process.close()
