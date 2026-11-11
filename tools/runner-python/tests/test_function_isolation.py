"""`--function <name>`: a runner dedicated to one function (`functions.isolation = "function"`).

The daemon puts FUNCTION_TARGET, FUNCTION_SIGNATURE_TYPE, K_SERVICE and the function's own secrets into the environment at
spawn, as a production instance has them from its start. The runner must serve that function only and must not rewrite them
per call. The shared runner is run beside it to show what the dedicated one removes.
"""

import json

from harness import Runner

FIXED = {"K_SERVICE": "fixed-at-spawn", "FUNCTION_TARGET": "hello", "FUNCTION_SIGNATURE_TYPE": "http"}


def hello_environment(runner):
    status, _, body = runner.request("/demo-proj/us-central1/hello")
    assert status == 200, body
    return json.loads(body)


def test_the_shared_runner_names_the_call_that_started_last():
    runner = Runner()
    try:
        runner.hello()
        answer = hello_environment(runner)
        assert (answer["k_service"], answer["function_target"], answer["function_signature_type"]) == ("hello", "hello", "http")
    finally:
        runner.kill()


def test_a_dedicated_runner_does_not_rewrite_the_identity_it_was_started_with():
    runner = Runner(extra_env=FIXED, function="hello")
    try:
        runner.hello()
        answer = hello_environment(runner)
        assert answer["k_service"] == "fixed-at-spawn"
        assert answer["function_target"] == "hello"
        assert answer["function_signature_type"] == "http"
    finally:
        runner.kill()


def test_a_dedicated_runner_announces_and_serves_only_its_function():
    runner = Runner(extra_env=FIXED, function="hello")
    try:
        assert [spec["name"] for spec in runner.hello()["manifest"]["functions"]] == ["hello"]
        status, _, _ = runner.request("/demo-proj/us-central1/seen")
        assert status == 404
        frame = runner.invoke("x1", "fs_written", "firestore", {"id": "e", "type": "x", "source": "s", "data": {}})
        assert frame["ok"] is False
    finally:
        runner.kill()


def test_a_dedicated_runner_for_a_function_the_codebase_does_not_export_exits_before_hello():
    runner = Runner(extra_env=FIXED, function="absent")
    try:
        assert runner.process.wait(30) == 1
        assert not any(frame["type"] == "hello" for frame in runner.frames)
        assert "absent" in runner.stderr
    finally:
        runner.kill()


# --- in process: the dispatcher of a dedicated runner -----------------------------------------------


def test_a_dedicated_dispatcher_leaves_the_identity_variables_as_the_daemon_set_them(monkeypatch):
    import os

    from fireemu_runner.dispatch import Dispatcher
    from test_dispatch import Collected, event, invoke, spec

    for key, value in {"FUNCTION_TARGET": "from-spawn", "FUNCTION_SIGNATURE_TYPE": "http", "K_SERVICE": "svc-from-spawn"}.items():
        monkeypatch.setenv(key, value)
    seen = {}

    def handler(_):
        seen.update({key: os.environ.get(key) for key in ("FUNCTION_TARGET", "FUNCTION_SIGNATURE_TYPE", "K_SERVICE")})

    writer = Collected()
    dispatcher = Dispatcher({"entry": handler}, {"functions": [spec(name="named", entry_point="entry")]}, writer, fixed_identity=True)
    invoke(dispatcher, function="named")
    assert writer.result("i-1")["ok"]
    assert seen == {"FUNCTION_TARGET": "from-spawn", "FUNCTION_SIGNATURE_TYPE": "http", "K_SERVICE": "svc-from-spawn"}


def test_the_shared_dispatcher_rewrites_them_per_call(monkeypatch):
    import os

    from fireemu_runner.dispatch import Dispatcher
    from test_dispatch import Collected, invoke, spec

    monkeypatch.setenv("K_SERVICE", "left-over")
    seen = {}
    writer = Collected()
    dispatcher = Dispatcher({"entry": lambda _: seen.update(service=os.environ.get("K_SERVICE"))}, {"functions": [spec(name="named", entry_point="entry")]}, writer)
    invoke(dispatcher, function="named")
    assert writer.result("i-1")["ok"]
    assert seen == {"service": "named"}


def test_a_dedicated_runner_announces_the_one_function_and_a_missing_one_stops_it(monkeypatch, capsys):
    import io

    from fireemu_runner.main import serve

    class Writer:
        def __init__(self):
            self.frames = []

        def write(self, message):
            self.frames.append(message)

    functions = {}
    writer = Writer()
    assert serve(functions, "default", "secret", io.BytesIO(b""), writer, function="absent") == 1
    assert writer.frames == []
    assert "absent" in capsys.readouterr().err


def test_serve_tells_the_dispatcher_and_the_router_whether_the_runner_is_dedicated(monkeypatch):
    import io

    from fireemu_runner import main

    manifest = {"functions": [{"name": "one", "entryPoint": "one", "trigger": {"type": "http"}}, {"name": "two", "entryPoint": "two", "trigger": {"type": "firestore"}}], "ignored": []}
    monkeypatch.setattr(main, "build_manifest", lambda functions, verified=False: manifest)
    seen = {}

    class Spy:
        def __init__(self, functions, served, writer, gate=None, fixed_identity=False):
            seen["dispatcher"] = (served, fixed_identity)

        def reserve(self):
            return True

    class Writer:
        def write(self, message):
            seen["hello"] = message

    def start(functions, served, secret, gate=None, fixed_identity=False):
        seen["router"] = (served, fixed_identity)
        return type("Server", (), {"shutdown": lambda self: None})(), 1

    monkeypatch.setattr(main, "Dispatcher", Spy)
    monkeypatch.setattr(main, "start_server", start)
    assert main.serve({}, "default", "s", io.BytesIO(b""), Writer(), function="one") == 0
    assert [spec["name"] for spec in seen["hello"]["manifest"]["functions"]] == ["one"]
    assert seen["dispatcher"][1] is True and seen["router"][1] is True
    assert [spec["name"] for spec in seen["dispatcher"][0]["functions"]] == ["one"]
    seen.clear()
    assert main.serve({}, "default", "s", io.BytesIO(b""), Writer()) == 0
    assert [spec["name"] for spec in seen["hello"]["manifest"]["functions"]] == ["one", "two"]
    assert seen["dispatcher"][1] is False and seen["router"][1] is False
