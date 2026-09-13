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
                if self.mode == "json"
                else (b"" if self.mode == "empty" else b"partial")
            )
            self.send_response(200 if self.mode == "json" else 404)
            self.send_header(
                "Content-Type",
                "application/json" if self.mode == "json" else "text/plain",
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
