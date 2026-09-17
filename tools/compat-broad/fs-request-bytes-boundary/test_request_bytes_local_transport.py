import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
sys.path.insert(0, "tools/compat-broad")

from request_bytes_compiler import compile_request_bytes_plan
from request_bytes_local_transport import MAX_REQUEST_BYTES, RESPONSE_BYTES, request


class Handler(BaseHTTPRequestHandler):
    received: list[bytes] = []

    def do_POST(self):  # noqa: N802
        size = int(self.headers.get("Content-Length", "0"))
        self.received.append(self.rfile.read(size))
        body = json.dumps({"writeResults": [{"updateTime": "2026-01-01T00:00:00.000000Z"}] * 17}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture()
def origin():
    Handler.received.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_three_compiled_sizes_round_trip_over_loopback(origin):
    plan = compile_request_bytes_plan("local-project", "(default)", "0123456789abcdef0123456789abcdef")
    operation = plan["observation"][17]
    for probe in plan["probes"]:
        operation = next(row for row in plan["observation"] if row.get("probe") == probe["label"] and row["kind"] == "conditional-create-commit")
        result = request(origin, operation)
        assert result["complete"] is True
        assert result["requestBytes"] == probe["bodyBytes"]
        assert result["rawHttpMetricStatus"] == "observation hypothesis"
        assert Handler.received[-1] == json.dumps(operation["body"], separators=(",", ":"), ensure_ascii=False).encode()


def test_cap_above_approved_range_and_non_loopback_are_rejected(origin):
    plan = compile_request_bytes_plan("local-project", "(default)", "0123456789abcdef0123456789abcdef")
    operation = plan["observation"][17]
    with pytest.raises(ValueError):
        request(origin, operation, request_byte_limit=MAX_REQUEST_BYTES + 1)
    with pytest.raises(ValueError):
        request("https://example.com", operation)
    assert RESPONSE_BYTES == 2 * 1024 * 1024
