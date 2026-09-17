from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

sys.path.insert(0, "tools/compat-broad/fs-write-limits")
sys.path.insert(0, "tools/compat-broad")
from transport import execute_request


class Handler(BaseHTTPRequestHandler):
    do_POST = lambda self: self.do_GET()

    def do_GET(self):
        body = {"error": {"status": "INVALID_ARGUMENT"}} if self.path.startswith("/v1/error") else {"ok": True}
        if self.path.startswith("/v1/redirect"):
            self.send_response(302); self.send_header("Location", "/v1/ok"); self.end_headers(); return
        payload = json.dumps(body).encode()
        self.send_response(400 if self.path.startswith("/v1/error") else 200)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def log_message(self, *_args):
        pass


@pytest.fixture()
def origin():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever); thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown(); thread.join(); server.server_close()


def test_request_cap_exact_and_plus_one_rejected_before_io(origin):
    request = {"method": "POST", "path": "/v1/ok", "body": {"x": "a"}}
    size = len(json.dumps(request["body"], separators=(",", ":")).encode())
    assert execute_request(origin, request, request_cap=size, response_cap=100)["kind"] == "json"
    assert execute_request(origin, request, request_cap=size - 1, response_cap=100)["kind"] == "request-too-large"


def test_response_cap_exact_and_plus_one(origin):
    request = {"method": "GET", "path": "/v1/ok"}
    body_size = len(json.dumps({"ok": True}).encode())
    assert execute_request(origin, request, request_cap=100, response_cap=body_size)["kind"] == "json"
    assert execute_request(origin, request, request_cap=100, response_cap=body_size - 1)["kind"] == "truncated"


def test_complete_api_error_and_redirect_are_distinct(origin):
    error = execute_request(origin, {"method": "GET", "path": "/v1/error"}, request_cap=100, response_cap=1000)
    assert error["kind"] == "api-error" and error["complete"] and error["status"] == 400
    redirect = execute_request(origin, {"method": "GET", "path": "/v1/redirect"}, request_cap=100, response_cap=1000)
    assert redirect["kind"] == "redirect" and not redirect["complete"]


@pytest.mark.parametrize("origin", ["https://example.com:443", "http://localhost:1234", "http://127.0.0.1:80"])
def test_remote_and_unowned_origins_rejected(origin):
    with pytest.raises(ValueError):
        execute_request(origin, {"method": "GET", "path": "/v1/ok"}, request_cap=100, response_cap=100)


def test_caps_and_deadline_are_strict(origin):
    with pytest.raises(ValueError):
        execute_request(origin, {"method": "GET", "path": "/v1/ok"}, request_cap=2 * 1024 * 1024 + 1, response_cap=100)
    with pytest.raises(ValueError):
        execute_request(origin, {"method": "GET", "path": "/v1/ok"}, request_cap=100, response_cap=100, deadline_seconds=13)
