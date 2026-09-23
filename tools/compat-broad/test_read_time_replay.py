import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


def test_saved_read_time_record_is_pinned_and_current_program_matches():
    import broad
    from broad import digest
    from read_time_replay import PROGRAM_DIGEST, load_saved_program

    saved = load_saved_program(
        Path("spec/compatibility/broad-runs/a12183a0-second-current.json")
    )
    program = next(
        p for p in broad.programs("firestore")[0] if p["id"] == "reads/read-time"
    )
    assert saved["status"] == "completed"
    assert digest(program) == PROGRAM_DIGEST


def test_saved_read_time_record_rejects_byte_mutation(tmp_path):
    from read_time_replay import load_saved_program

    source = Path("spec/compatibility/broad-runs/a12183a0-second-current.json")
    mutated = tmp_path / "saved.json"
    mutated.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_saved_program(mutated)


def _poststate_server(status, body):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.command, self.path))
            encoded = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, requests


def _expected_document():
    import broad

    return f"projects/{broad.PROJECT}/databases/(default)/documents/rt/a"


def _write_instance(output, origin, nonce="n-1"):
    (output / "instance.json").write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "parentPid": os.getppid(),
                "nonce": nonce,
                "firestoreOrigin": origin,
            }
        )
    )


def test_child_readback_sets_validation_only_for_exact_document_and_integer_two(
    tmp_path,
):
    from read_time_replay import run_child

    server, thread, requests = _poststate_server(
        200,
        {
            "name": _expected_document(),
            "fields": {"v": {"integerValue": "2"}},
        },
    )
    output = tmp_path / "output"
    output.mkdir()
    origin = f"http://127.0.0.1:{server.server_port}"

    def delegate(child_output, nonce, program):
        assert (child_output, nonce, program) == (output, "n-1", "reads/read-time")
        _write_instance(output, origin, nonce)
        (output / "cases.json").write_text(
            json.dumps(
                {
                    "cases": [
                        {"id": "read-time", "status": "observed", "family": "reads"}
                    ],
                    "recordingComplete": True,
                }
            )
        )

    try:
        assert run_child(output, "n-1", "reads/read-time", delegate=delegate) == 0
        report = json.loads((output / "cases.json").read_text())
        assert report["stateValidation"] is True
        assert report["postStateReadback"] == {
            "status": 200,
            "documentNameMatches": True,
            "integerValueIsTwo": True,
        }
        assert requests == [("GET", f"/v1/{_expected_document()}")]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (404, {"name": _expected_document(), "fields": {"v": {"integerValue": "2"}}}),
        (
            200,
            {
                "name": "projects/wrong/databases/(default)/documents/rt/a",
                "fields": {"v": {"integerValue": "2"}},
            },
        ),
        (200, {"name": _expected_document(), "fields": {"v": {"integerValue": 2}}}),
        (200, {"name": _expected_document(), "fields": {"v": {"integerValue": "3"}}}),
        (200, {"name": _expected_document(), "fields": []}),
        (200, b"{"),
    ],
)
def test_child_readback_fails_closed_for_unexpected_response(tmp_path, status, body):
    from read_time_replay import run_child

    server, thread, requests = _poststate_server(status, body)
    output = tmp_path / "output"
    output.mkdir()
    _write_instance(output, f"http://127.0.0.1:{server.server_port}")
    (output / "cases.json").write_text(
        json.dumps(
            {
                "cases": [{"id": "read-time", "status": "observed", "family": "reads"}],
                "recordingComplete": True,
            }
        )
    )
    try:
        assert (
            run_child(output, "n-1", "reads/read-time", delegate=lambda *_: None) == 2
        )
        report = json.loads((output / "cases.json").read_text())
        assert report["stateValidation"] is False
        assert report["postStateReadback"]["status"] == status
        assert requests == [("GET", f"/v1/{_expected_document()}")]
        assert not {"fields", "integerValue", "value"} & set(
            report["postStateReadback"]
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_child_readback_transport_failure_fails_closed(tmp_path):
    from read_time_replay import run_child

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    output = tmp_path / "output"
    output.mkdir()
    _write_instance(output, origin)
    (output / "cases.json").write_text(
        json.dumps(
            {
                "cases": [{"id": "read-time", "status": "observed", "family": "reads"}],
                "recordingComplete": True,
            }
        )
    )

    assert run_child(output, "n-1", "reads/read-time", delegate=lambda *_: None) == 2
    report = json.loads((output / "cases.json").read_text())
    assert report["stateValidation"] is False
    assert report["postStateReadback"] == {
        "status": None,
        "documentNameMatches": False,
        "integerValueIsTwo": False,
    }


def test_replay_passes_dedicated_child_and_keeps_bounded_program(tmp_path, monkeypatch):
    import read_time_replay
    from read_time_replay import PROGRAM_DIGEST, replay

    saved = Path("spec/compatibility/broad-runs/a12183a0-second-current.json")
    output = tmp_path / "output"
    output.mkdir()
    calls = []

    def run(_output, **kwargs):
        calls.append(kwargs)
        return {"status": "incomplete"}

    monkeypatch.setattr(read_time_replay, "run", run)
    replay(saved, output)

    assert calls == [
        {
            "child_script": Path(read_time_replay.__file__).resolve(),
            "firestore_program": "reads/read-time",
        }
    ]
    metadata = json.loads((output / "replay.json").read_text())
    assert metadata["savedProgramDigest"] == PROGRAM_DIGEST
    assert metadata["savedRecordSha256"]


def test_child_cli_preserves_supervisor_arguments(tmp_path):
    from read_time_replay import main

    output = tmp_path / "child"
    calls = []

    def child_runner(child_output, nonce, program):
        calls.append((child_output, nonce, program))
        return 0

    assert (
        main(
            [
                "--child",
                str(output),
                "--nonce",
                "n-2",
                "--firestore-program",
                "reads/read-time",
            ],
            child_runner=child_runner,
        )
        == 0
    )
    assert calls == [(output, "n-2", "reads/read-time")]


def test_child_wrapper_imports_under_supervisor_isolated_python():
    script = Path("tools/compat-broad/read_time_replay.py").resolve()
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(script), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--firestore-program" in result.stdout
