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


def _poststate_server(status, body, *, redirect_to=None, declared_length=None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(
                (self.command, self.path, self.headers.get("Authorization"))
            )
            if redirect_to is not None:
                self.send_response(status)
                self.send_header("Location", redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            encoded = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Content-Length",
                str(declared_length if declared_length is not None else len(encoded)),
            )
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


def _read_time_cases():
    import broad

    program = broad.bounded_firestore_program("reads/read-time")[0]
    return [
        {
            "id": f"firestore:reads/read-time#{step['id']}",
            "status": "match",
            "family": "reads",
            "actual": {"status": 200, "code": "OK"},
        }
        for step in program["steps"]
    ]


def _isolated_read_poststate(origin, proxy_origin):
    script = Path("tools/compat-broad/read_time_replay.py").resolve()
    import_statement = (
        f"import sys; sys.path.insert(0, {str(script.parent)!r}); "
        "from read_time_replay import read_poststate; import json; "
        "print(json.dumps(read_poststate(sys.argv[1])))"
    )
    environment = os.environ.copy()
    for key in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        environment.pop(key, None)
    environment["HTTP_PROXY"] = proxy_origin
    environment["http_proxy"] = proxy_origin
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", import_statement, origin],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )


def test_poststate_readback_bypasses_proxy_environment():
    from read_time_replay import POSTSTATE_DOCUMENT

    body = {"name": POSTSTATE_DOCUMENT, "fields": {"v": {"integerValue": "2"}}}
    target, target_thread, target_requests = _poststate_server(200, body)
    proxy, proxy_thread, proxy_requests = _poststate_server(200, body)
    try:
        result = _isolated_read_poststate(
            f"http://127.0.0.1:{target.server_port}",
            f"http://127.0.0.1:{proxy.server_port}",
        )

        assert result.returncode == 0
        assert json.loads(result.stdout) == {
            "status": 200,
            "documentNameMatches": True,
            "integerValueIsTwo": True,
        }
        assert target_requests == [("GET", f"/v1/{POSTSTATE_DOCUMENT}", "Bearer owner")]
        assert proxy_requests == []
    finally:
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=2)
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join(timeout=2)


def test_poststate_readback_does_not_follow_redirect_or_forward_owner_header():
    from read_time_replay import POSTSTATE_DOCUMENT, read_poststate

    destination, destination_thread, destination_requests = _poststate_server(
        200, {"name": POSTSTATE_DOCUMENT, "fields": {"v": {"integerValue": "2"}}}
    )
    redirect, redirect_thread, redirect_requests = _poststate_server(
        302,
        b"",
        redirect_to=f"http://127.0.0.1:{destination.server_port}/capture",
    )
    try:
        result = read_poststate(f"http://127.0.0.1:{redirect.server_port}")

        assert result == {
            "status": 302,
            "documentNameMatches": False,
            "integerValueIsTwo": False,
        }
        assert redirect_requests == [
            ("GET", f"/v1/{POSTSTATE_DOCUMENT}", "Bearer owner")
        ]
        assert destination_requests == []
    finally:
        redirect.shutdown()
        redirect.server_close()
        redirect_thread.join(timeout=2)
        destination.shutdown()
        destination.server_close()
        destination_thread.join(timeout=2)


def test_poststate_readback_rejects_oversized_body(tmp_path):
    from read_time_replay import POSTSTATE_DOCUMENT, read_poststate

    encoded = json.dumps(
        {"name": POSTSTATE_DOCUMENT, "fields": {"v": {"integerValue": "2"}}}
    ).encode()
    body = encoded + b" " * (64 * 1024 + 1)
    server, thread, requests = _poststate_server(200, body)
    try:
        result = read_poststate(f"http://127.0.0.1:{server.server_port}")

        assert result == {
            "status": 200,
            "documentNameMatches": False,
            "integerValueIsTwo": False,
        }
        assert requests == [("GET", f"/v1/{POSTSTATE_DOCUMENT}", "Bearer owner")]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_poststate_readback_rejects_truncated_body():
    from read_time_replay import POSTSTATE_DOCUMENT, read_poststate

    body = json.dumps(
        {"name": POSTSTATE_DOCUMENT, "fields": {"v": {"integerValue": "2"}}}
    ).encode()
    server, thread, requests = _poststate_server(
        200, body, declared_length=len(body) + 10
    )
    try:
        result = read_poststate(f"http://127.0.0.1:{server.server_port}")

        assert result == {
            "status": 200,
            "documentNameMatches": False,
            "integerValueIsTwo": False,
        }
        assert requests == [("GET", f"/v1/{POSTSTATE_DOCUMENT}", "Bearer owner")]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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
                    "cases": _read_time_cases(),
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
        assert requests == [("GET", f"/v1/{_expected_document()}", "Bearer owner")]
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
        assert requests == [("GET", f"/v1/{_expected_document()}", "Bearer owner")]
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


@pytest.mark.parametrize("code", ["no-response", "probe-error"])
def test_child_marks_selected_unreceived_observation_incomplete(tmp_path, code):
    from read_time_replay import run_child

    server, thread, _requests = _poststate_server(
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
        _write_instance(output, origin, nonce)
        cases = _read_time_cases()
        selected = next(
            row
            for row in cases
            if row["id"] == "firestore:reads/read-time#read-current"
        )
        selected.update(status="indeterminate", actual={"status": 0, "code": code})
        cases.append(
            {
                "id": "firestore:other-program#unrelated",
                "status": "indeterminate",
                "family": "reads",
                "actual": {"status": 0, "code": code},
            }
        )
        (output / "cases.json").write_text(
            json.dumps(
                {
                    "cases": cases,
                }
            )
        )

    try:
        assert run_child(output, "n-1", "reads/read-time", delegate=delegate) == 2
        report = json.loads((output / "cases.json").read_text())
        assert report["stateValidation"] is True
        assert report["recordingComplete"] is False
        assert report["cases"][0]["status"] == "indeterminate"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    "variant", ["missing-one", "all-omitted", "duplicate", "upstream-false"]
)
def test_child_requires_exactly_once_complete_selected_observations(tmp_path, variant):
    from read_time_replay import run_child

    server, thread, _requests = _poststate_server(
        200,
        {
            "name": _expected_document(),
            "fields": {"v": {"integerValue": "2"}},
        },
    )
    output = tmp_path / "output"
    output.mkdir()
    origin = f"http://127.0.0.1:{server.server_port}"
    cases = _read_time_cases()
    recording_complete = True
    if variant == "missing-one":
        cases.pop()
    elif variant == "all-omitted":
        cases.clear()
    elif variant == "duplicate":
        cases.append(dict(cases[0]))
    else:
        recording_complete = False

    def delegate(child_output, nonce, program):
        _write_instance(output, origin, nonce)
        (output / "cases.json").write_text(
            json.dumps(
                {
                    "cases": cases,
                    "recordingComplete": recording_complete,
                }
            )
        )

    try:
        assert run_child(output, "n-1", "reads/read-time", delegate=delegate) == 2
        report = json.loads((output / "cases.json").read_text())
        assert report["stateValidation"] is True
        assert report["recordingComplete"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_child_keeps_received_http_error_recording_complete(tmp_path):
    from read_time_replay import run_child

    server, thread, _requests = _poststate_server(
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
        _write_instance(output, origin, nonce)
        cases = _read_time_cases()
        selected = next(
            row
            for row in cases
            if row["id"] == "firestore:reads/read-time#read-current"
        )
        selected.update(
            status="mismatch",
            actual={
                "status": 400,
                "code": "INVALID_ARGUMENT",
                "body": {"error": "semantic mismatch"},
            },
        )
        (output / "cases.json").write_text(json.dumps({"cases": cases}))

    try:
        assert run_child(output, "n-1", "reads/read-time", delegate=delegate) == 0
        report = json.loads((output / "cases.json").read_text())
        assert report["stateValidation"] is True
        assert report["recordingComplete"] is True
        assert report["cases"][0]["status"] == "mismatch"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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
