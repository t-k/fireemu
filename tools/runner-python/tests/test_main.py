"""The serve loop in process: hello, frames from a pipe, and the exit codes."""

import io
import json
import os
import threading

import pytest

from fireemu_runner import dispatch, main
from fireemu_runner.framing import FrameWriter, encode_frame, read_frame

from test_dispatch import Collected, event, spec


class Pipe:
    """A stdin the test feeds frames to."""

    def __init__(self):
        read_fd, self._write_fd = os.pipe()
        self.stream = os.fdopen(read_fd, "rb")

    def send(self, message):
        os.write(self._write_fd, encode_frame(message))

    def send_raw(self, data):
        os.write(self._write_fd, data)

    def close(self):
        os.close(self._write_fd)


def serve_in_thread(functions, stdin, writer, secret="s"):
    result = {}

    def target():
        result["code"] = main.serve(functions, "cb", secret, stdin.stream, writer)

    thread = threading.Thread(target=target)
    thread.start()
    return thread, result


def test_hello_names_the_runner_the_codebase_and_an_http_port_only_when_there_is_an_http_function(discovered):
    stdin = Pipe()
    writer = Collected()
    thread, result = serve_in_thread(discovered, stdin, writer)
    hello = writer.wait_for(lambda f: f["type"] == "hello")
    assert (hello["runner"], hello["codebase"]) == ("python", "cb")
    assert isinstance(hello["httpPort"], int) and hello["httpPort"] > 0
    assert hello["version"].count(".") == 2
    assert {entry["name"] for entry in hello["manifest"]["functions"]} >= {"hello", "fs_created"}
    stdin.send({"type": "shutdown"})
    thread.join(10)
    assert result["code"] == 0
    stdin.close()


def test_a_codebase_with_no_http_function_starts_no_server():
    stdin = Pipe()
    writer = Collected()
    functions = {"f": _firestore_function()}
    thread, result = serve_in_thread(functions, stdin, writer)
    assert writer.wait_for(lambda f: f["type"] == "hello")["httpPort"] is None
    stdin.close()
    thread.join(10)
    assert result["code"] == 0


def _firestore_function():
    from firebase_functions.private import manifest as sdk_manifest

    def handler(_):
        pass

    handler.__firebase_endpoint__ = sdk_manifest.ManifestEndpoint(
        entryPoint="f",
        eventTrigger={
            "eventType": "google.cloud.firestore.document.v1.created",
            "retry": False,
            "eventFilters": {"database": "(default)"},
            "eventFilterPathPatterns": {"document": "a/{id}"},
        },
    )
    return handler


def test_an_invoke_is_answered_and_the_end_of_input_ends_the_loop_cleanly():
    stdin = Pipe()
    writer = Collected()
    thread, result = serve_in_thread({"f": _firestore_function()}, stdin, writer)
    writer.wait_for(lambda f: f["type"] == "hello")
    stdin.send({"type": "invoke", "invocationId": "i-9", "function": "f", "trigger": "firestore", "event": event()})
    assert writer.result("i-9")["ok"] is True
    stdin.close()
    thread.join(10)
    assert result["code"] == 0


@pytest.mark.parametrize("garbage", [b"x\n", b"05\n{}", b"9\nshort"])
def test_a_corrupt_frame_ends_the_loop_with_status_2_and_the_fixed_reason(garbage, capsys):
    stdin = Pipe()
    writer = Collected()
    thread, result = serve_in_thread({"f": _firestore_function()}, stdin, writer)
    writer.wait_for(lambda f: f["type"] == "hello")
    stdin.send_raw(garbage)
    stdin.close()
    thread.join(10)
    assert result["code"] == 2
    assert "[functions] invalid runner frame" in capsys.readouterr().err


def test_more_active_invocations_than_the_bound_ends_the_loop_with_status_2(monkeypatch, capsys):
    monkeypatch.setattr(dispatch, "MAX_ACTIVE_INVOCATIONS", 0)
    stdin = Pipe()
    writer = Collected()
    thread, result = serve_in_thread({"f": _firestore_function()}, stdin, writer)
    writer.wait_for(lambda f: f["type"] == "hello")
    stdin.send({"type": "invoke", "invocationId": "i-1", "function": "f", "trigger": "firestore", "event": event()})
    thread.join(10)
    assert result["code"] == 2
    assert "too many active invocations" in capsys.readouterr().err
    stdin.close()


def test_load_codebase_changes_into_the_source_and_returns_its_functions(tmp_path):
    (tmp_path / "main.py").write_text(
        "from firebase_functions import https_fn\n@https_fn.on_request()\ndef only(request):\n    return 'x'\n"
    )
    previous = os.getcwd()
    try:
        functions = main.load_codebase(str(tmp_path))
        assert os.path.realpath(os.getcwd()) == os.path.realpath(tmp_path)
        assert list(functions) == ["only"]
    finally:
        os.chdir(previous)


def test_a_missing_or_failing_main_py_raises_from_load_codebase(tmp_path):
    previous = os.getcwd()
    try:
        with pytest.raises(FileNotFoundError):
            main.load_codebase(str(tmp_path))
        (tmp_path / "main.py").write_text("raise RuntimeError('no')\n")
        with pytest.raises(RuntimeError, match="no"):
            main.load_codebase(str(tmp_path))
    finally:
        os.chdir(previous)


def test_the_arguments_need_a_source_and_default_the_codebase_name():
    parsed = main._parse(["--source", "/code"])
    assert (parsed.source, parsed.codebase) == ("/code", "default")
    assert main._parse(["--source", "/code", "--codebase", "api"]).codebase == "api"
    with pytest.raises(SystemExit):
        main._parse([])


def test_the_writer_and_reader_agree_through_the_pipe_used_here():
    out = io.BytesIO()
    FrameWriter(out).write({"type": "shutdown"})
    out.seek(0)
    assert read_frame(out) == {"type": "shutdown"}
    assert json.loads(out.getvalue().split(b"\n", 1)[1]) == {"type": "shutdown"}
