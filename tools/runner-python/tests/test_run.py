"""`run` in process: the descriptor juggling is replaced by recorded calls, everything else is real."""

import gc
import io
import os
import sys
import threading

import pytest

from fireemu_runner import main
from fireemu_runner.framing import encode_frame

CODEBASE = (
    "from firebase_functions import https_fn\n"
    "@https_fn.on_request()\n"
    "def only(request):\n"
    "    return 'x'\n"
)


class Wiring:
    """What `run` did to the descriptors, and the pipe it was given as the protocol channel."""

    def __init__(self, monkeypatch, stdin_bytes=b""):
        self.calls = []
        self.read_fd, self.write_fd = os.pipe()
        monkeypatch.setattr(os, "dup", lambda fd: (self.calls.append(("dup", fd)), self.write_fd)[1])
        monkeypatch.setattr(os, "dup2", lambda source, target: self.calls.append(("dup2", source, target)))

        class FakeStdin:
            buffer = io.BytesIO(stdin_bytes)

        monkeypatch.setattr(sys, "stdin", FakeStdin)

    def frames(self):
        from harness import read_runner_frame

        # `run` made the write end a file object; once it returns that object is collected and the pipe ends.
        gc.collect()
        out = []
        stream = os.fdopen(self.read_fd, "rb")
        while (frame := read_runner_frame(stream)) is not None:
            out.append(frame)
        return out


@pytest.fixture
def codebase(tmp_path):
    (tmp_path / "main.py").write_text(CODEBASE)
    previous = os.getcwd()
    yield tmp_path
    os.chdir(previous)


def run_with(monkeypatch, codebase, stdin_bytes, env=None):
    wiring = Wiring(monkeypatch, stdin_bytes)
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    code = main.run(["--source", str(codebase), "--codebase", "cb"])
    return code, wiring


def test_the_protocol_takes_the_original_stdout_and_stdout_becomes_stderr(monkeypatch, codebase):
    code, wiring = run_with(monkeypatch, codebase, encode_frame({"type": "shutdown"}))
    assert code == 0
    # Duplicate descriptor 1 first (it becomes the protocol channel), then point 1 at descriptor 2.
    assert wiring.calls == [("dup", 1), ("dup2", 2, 1)]
    frames = wiring.frames()
    assert [frame["type"] for frame in frames] == ["hello"]
    assert frames[0]["codebase"] == "cb" and frames[0]["runner"] == "python"
    assert [entry["name"] for entry in frames[0]["manifest"]["functions"]] == ["only"]


def test_the_runner_secret_gates_the_port_and_neither_secret_stays_in_the_environment(monkeypatch, codebase):
    import urllib.error
    import urllib.request

    pipe_in = os.pipe()
    wiring = Wiring(monkeypatch)

    class LiveStdin:
        buffer = os.fdopen(pipe_in[0], "rb")

    monkeypatch.setattr(sys, "stdin", LiveStdin)
    monkeypatch.setenv("FIREEMU_RUNNER_SECRET", "the-secret")
    monkeypatch.setenv("FIREEMU_LOCAL_SECRETS_JSON", '{"A":"b"}')
    monkeypatch.setenv("GCLOUD_PROJECT", "demo-proj")
    result = {}
    thread = threading.Thread(target=lambda: result.update(code=main.run(["--source", str(codebase)])))
    thread.start()
    from harness import read_runner_frame

    stream = os.fdopen(wiring.read_fd, "rb")
    hello = read_runner_frame(stream)
    assert hello["codebase"] == "default"
    port = hello["httpPort"]
    assert "FIREEMU_RUNNER_SECRET" not in os.environ and "FIREEMU_LOCAL_SECRETS_JSON" not in os.environ

    def status(secret):
        request = urllib.request.Request(f"http://127.0.0.1:{port}/demo-proj/us-central1/only", headers={"x-fireemu-runner-secret": secret})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    assert status("the-secret") == 200
    assert status("wrong") == 403
    os.write(pipe_in[1], encode_frame({"type": "shutdown"}))
    thread.join(10)
    assert result["code"] == 0
    os.close(pipe_in[1])


def test_a_codebase_that_fails_to_load_is_status_1_with_the_traceback_on_stderr(monkeypatch, tmp_path, capsys):
    (tmp_path / "main.py").write_text("raise RuntimeError('does not load')\n")
    previous = os.getcwd()
    try:
        code, wiring = run_with(monkeypatch, tmp_path, b"")
    finally:
        os.chdir(previous)
    assert code == 1
    err = capsys.readouterr().err
    assert "Traceback" in err and "RuntimeError: does not load" in err
    assert wiring.frames() == []


def test_the_codebase_name_defaults_to_default(monkeypatch, codebase):
    wiring = Wiring(monkeypatch, encode_frame({"type": "shutdown"}))
    assert main.run(["--source", str(codebase)]) == 0
    assert wiring.frames()[0]["codebase"] == "default"


def test_too_many_active_invocations_is_status_2_with_this_exact_line(monkeypatch, capsys):
    from fireemu_runner import dispatch

    monkeypatch.setattr(dispatch, "MAX_ACTIVE_INVOCATIONS", 0)
    stdin = io.BytesIO(encode_frame({"type": "invoke", "invocationId": "i", "function": "f", "trigger": "firestore", "event": {}}))
    from fireemu_runner.framing import FrameWriter

    assert main.serve({}, "cb", "s", stdin, FrameWriter(io.BytesIO())) == 2
    assert capsys.readouterr().err == "[functions] too many active invocations\n"


def test_a_corrupt_frame_is_one_exact_line_on_stderr(monkeypatch, capsys):
    from fireemu_runner.framing import FrameWriter

    assert main.serve({}, "cb", "s", io.BytesIO(b"x\n"), FrameWriter(io.BytesIO())) == 2
    assert capsys.readouterr().err == "[functions] invalid runner frame (decimal length)\n"


def test_without_a_runner_secret_in_the_environment_no_presented_secret_is_accepted(monkeypatch, codebase):
    import urllib.error
    import urllib.request

    pipe_in = os.pipe()
    wiring = Wiring(monkeypatch)

    class LiveStdin:
        buffer = os.fdopen(pipe_in[0], "rb")

    monkeypatch.setattr(sys, "stdin", LiveStdin)
    monkeypatch.delenv("FIREEMU_RUNNER_SECRET", raising=False)
    monkeypatch.setenv("GCLOUD_PROJECT", "demo-proj")
    thread = threading.Thread(target=lambda: main.run(["--source", str(codebase)]))
    thread.start()
    from harness import read_runner_frame

    hello = read_runner_frame(os.fdopen(wiring.read_fd, "rb"))
    for presented in (None, "", "XXXX", "wrong"):
        headers = {} if presented is None else {"x-fireemu-runner-secret": presented}
        request = urllib.request.Request(f"http://127.0.0.1:{hello['httpPort']}/demo-proj/us-central1/only", headers=headers)
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=10)
        # The Node runner answers 500 "FIREEMU_RUNNER_SECRET is required" to every request in this configuration.
        assert error.value.code == 500
    os.write(pipe_in[1], encode_frame({"type": "shutdown"}))
    thread.join(10)
    os.close(pipe_in[1])


def test_the_usage_line_names_the_script(capsys):
    with pytest.raises(SystemExit):
        main._parse(["--help"])
    assert capsys.readouterr().out.startswith("usage: runner.py ")


def test_local_secrets_that_are_not_json_stop_the_run_with_one_exact_line(monkeypatch, codebase, capsys):
    code, wiring = run_with(monkeypatch, codebase, b"", env={"FIREEMU_LOCAL_SECRETS_JSON": "{"})
    assert code == 1
    assert capsys.readouterr().err == "[functions] the local secrets are not valid JSON\n"
    assert "FIREEMU_LOCAL_SECRETS_JSON" not in os.environ


def test_the_local_secrets_of_the_daemon_reach_the_gate_the_run_serves_with(monkeypatch, codebase):
    seen = {}
    monkeypatch.setattr(main, "serve", lambda functions, name, secret, stdin, writer, gate, verified: seen.update(gate=gate) or 0)
    monkeypatch.delenv("API_KEY", raising=False)
    code, _ = run_with(monkeypatch, codebase, b"", env={"FIREEMU_LOCAL_SECRETS_JSON": '{"API_KEY": "from the daemon"}'})
    assert code == 0
    with seen["gate"].hold(["API_KEY"]):
        assert os.environ["API_KEY"] == "from the daemon"


def test_the_app_check_hook_is_installed_before_the_codebase_loads_and_its_result_reaches_serve(monkeypatch, codebase):
    order = []
    monkeypatch.setattr(main.appcheck, "install_from_environment", lambda environ: order.append("hook") or True)
    monkeypatch.setattr(main, "load_codebase", lambda source: order.append("load") or {})
    monkeypatch.setattr(main, "serve", lambda functions, name, secret, stdin, writer, gate, verified: order.append(("serve", verified)) or 0)
    code, _ = run_with(monkeypatch, codebase, b"")
    assert code == 0 and order == ["hook", "load", ("serve", True)]


def test_without_an_emulator_jwks_the_run_announces_nothing(monkeypatch, codebase):
    seen = {}
    monkeypatch.delenv("FIREEMU_APP_CHECK_JWKS_URL", raising=False)
    monkeypatch.setattr(main, "serve", lambda functions, name, secret, stdin, writer, gate, verified: seen.update(verified=verified) or 0)
    code, _ = run_with(monkeypatch, codebase, b"")
    assert code == 0 and seen == {"verified": False}
