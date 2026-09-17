from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

sys.path.insert(0, "tools/compat-broad/fs-write-limits")
sys.path.insert(0, "tools/compat-broad")
from transport import request


class Handler(BaseHTTPRequestHandler):
    do_POST = lambda self: self.do_GET()

    def do_GET(self):
        if self.path.startswith("/v1/slow"):
            self.send_response(200)
            self.send_header("Content-Length", "20")
            self.end_headers()
            for _ in range(20):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.1)
            return
        if self.path.startswith("/v1/partial"):
            self.send_response(200)
            self.send_header("Content-Length", "20")
            self.end_headers()
            self.wfile.write(b"short")
            return
        if self.path.startswith("/v1/nonjson"):
            payload = b"not-json"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        body = (
            {"error": {"status": "INVALID_ARGUMENT"}}
            if self.path.startswith("/v1/error")
            else {"ok": True}
        )
        if self.path.startswith("/v1/redirect"):
            self.send_response(302)
            self.send_header("Location", "/v1/ok")
            self.end_headers()
            return
        payload = json.dumps(body).encode()
        self.send_response(400 if self.path.startswith("/v1/error") else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


@pytest.fixture()
def origin():
    server = ThreadingHTTPServer(
        ("127.0.0.1", int(os.environ.get("PORT", "0"))), Handler
    )
    thread = Thread(target=server.serve_forever)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_request_cap_exact_and_plus_one_rejected_before_io(origin):
    operation = {"method": "POST", "path": "/v1/ok", "body": {"x": "a"}}
    size = len(json.dumps(operation["body"], separators=(",", ":")).encode())
    assert (
        request(origin, operation, request_byte_limit=size, response_byte_limit=100)[
            "kind"
        ]
        == "json"
    )
    with pytest.raises(ValueError):
        request(origin, operation, request_byte_limit=size - 1, response_byte_limit=100)


def test_response_cap_exact_and_plus_one(origin):
    operation = {"method": "GET", "path": "/v1/ok"}
    body_size = len(json.dumps({"ok": True}).encode())
    assert (
        request(
            origin, operation, request_byte_limit=100, response_byte_limit=body_size
        )["kind"]
        == "json"
    )
    assert (
        request(
            origin, operation, request_byte_limit=100, response_byte_limit=body_size - 1
        )["kind"]
        == "truncated"
    )


def test_large_request_roundtrips_and_privileged_header_is_fixed(origin):
    operation = {"method": "POST", "path": "/v1/ok", "body": {"blob": "x" * 70_000}}
    result = request(
        origin, operation, request_byte_limit=100_000, response_byte_limit=100
    )
    assert result["kind"] == "json"
    privileged = {"method": "POST", "path": "/v1/ok", "body": {}, "privileged": True}
    assert (
        request(origin, privileged, request_byte_limit=100, response_byte_limit=100)[
            "kind"
        ]
        == "json"
    )


def test_complete_api_error_and_redirect_are_distinct(origin):
    error = request(
        origin,
        {"method": "GET", "path": "/v1/error"},
        request_byte_limit=100,
        response_byte_limit=1000,
    )
    assert error["kind"] == "api-error" and error["complete"] and error["status"] == 400
    redirect = request(
        origin,
        {"method": "GET", "path": "/v1/redirect"},
        request_byte_limit=100,
        response_byte_limit=1000,
    )
    assert redirect["kind"] == "redirect" and not redirect["complete"]


def test_partial_non_json_and_hard_deadline_are_distinct(origin):
    partial = request(
        origin,
        {"method": "GET", "path": "/v1/partial"},
        request_byte_limit=100,
        response_byte_limit=100,
    )
    assert partial["kind"] == "partial" and not partial["complete"]
    non_json = request(
        origin,
        {"method": "GET", "path": "/v1/nonjson"},
        request_byte_limit=100,
        response_byte_limit=100,
    )
    assert non_json["kind"] == "non-json"
    slow = request(
        origin,
        {"method": "GET", "path": "/v1/slow"},
        request_byte_limit=100,
        response_byte_limit=100,
        timeout=0.2,
    )
    assert slow["kind"] == "deadline-exceeded" and not slow["complete"]


@pytest.mark.parametrize(
    "origin",
    ["https://example.com:443", "http://localhost:1234", "http://127.0.0.1:80"],
)
def test_remote_and_unowned_origins_rejected(origin):
    with pytest.raises(ValueError):
        request(
            origin,
            {"method": "GET", "path": "/v1/ok"},
            request_byte_limit=100,
            response_byte_limit=100,
        )


def test_caps_and_deadline_are_strict(origin):
    with pytest.raises(ValueError):
        request(
            origin,
            {"method": "GET", "path": "/v1/ok"},
            request_byte_limit=2 * 1024 * 1024 + 1,
            response_byte_limit=100,
        )
    with pytest.raises(ValueError):
        request(
            origin,
            {"method": "GET", "path": "/v1/ok"},
            request_byte_limit=100,
            response_byte_limit=100,
            timeout=13,
        )
