"""Owned loopback HTTP fixtures exercise actual current-wire failure capture."""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from second_admission import auth_recipe
from second_mapped import LocalAdapter


@pytest.fixture(scope="module")
def wire_server():
    class Handler(BaseHTTPRequestHandler):
        mode = "json"

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            payload = (
                b'{"ok":true}'
                if self.mode in ("json", "denied")
                else (b"" if self.mode == "empty" else b"partial")
            )
            self.send_response(
                403 if self.mode == "denied" else (200 if self.mode == "json" else 404)
            )
            self.send_header(
                "Content-Type",
                "application/json" if self.mode in ("json", "denied") else "text/plain",
            )
            self.send_header(
                "Content-Length",
                str(len(payload) + (20 if self.mode == "partial" else 0)),
            )
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()
            self.close_connection = True

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(
        ("127.0.0.1", int(os.environ.get("PORT", "0"))), Handler
    )
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize("mode", ["json", "non-json", "empty", "partial"])
def test_current_wire_distinguishes_received_body_and_interruption(
    tmp_path, wire_server, mode
):
    origin, handler = wire_server
    handler.mode = mode
    adapter = LocalAdapter(
        {"auth": origin, "firestore": origin}, "a" * 32, tmp_path / mode
    )
    adapter.phase, adapter.case_index = "diagnostic", 0
    adapter.users = {
        r: {"uid": r, "token": r + "-token", "email": r + "@example.invalid"}
        for r in ("a", "b")
    }
    if mode == "json":
        assert adapter.send(auth_recipe(0, adapter.users)) == (200, {"ok": True})
    else:
        with pytest.raises(ValueError):
            adapter.send(auth_recipe(0, adapter.users))
    received = adapter.trace[-1]["observation"]["http"]
    assert adapter.budget.counts["total"] == 1
    assert received["complete"] is (mode != "partial")
    assert received["failure"] == ("body-interrupted" if mode == "partial" else None)
    assert received["bodyKind"] == ("unavailable" if mode == "partial" else mode)
    assert (adapter.output / "wire/0/body-1.bin").is_file()
    assert (adapter.output / "transport-trace.json").is_file()


def test_rejected_owner_is_latched_before_recovery_transport(tmp_path, wire_server):
    origin, handler = wire_server
    handler.mode = "denied"
    adapter = LocalAdapter(
        {"auth": origin, "firestore": origin}, "a" * 32, tmp_path / "owner"
    )
    adapter.phase, adapter.case_index = "diagnostic", 26
    adapter.users = {
        r: {"uid": r, "token": r + "-token", "email": r + "@example.invalid"}
        for r in ("a", "b")
    }
    with pytest.raises(ValueError, match="credential rejected"):
        adapter.send(auth_recipe(26, adapter.users))
    adapter.budget.recovery = True
    with pytest.raises(ValueError, match="previously rejected"):
        adapter.send(auth_recipe(26, adapter.users))
    assert adapter.owner_rejected
    assert adapter.budget.counts["total"] == 1
    assert len(adapter.trace) == 1


def test_incomplete_direct_execution_does_not_start_mapped(tmp_path, wire_server):
    from second_mapped import run_pair

    origin, handler = wire_server
    # A received JSON object without the required signup identity fails setup.
    handler.mode = "json"
    result = run_pair(
        {"auth": origin, "firestore": origin},
        tmp_path / "pair",
        {
            "artifactSha256": "a" * 64,
            "executionCommit": "b" * 40,
            "configurationDigest": "c" * 64,
        },
    )
    assert result["mapping"] == "invalid"
    assert not result["recordingComplete"]
    assert result["safety"] is None
    assert not (tmp_path / "pair/mapped").exists()
    assert (tmp_path / "pair/direct/result.json").is_file()
