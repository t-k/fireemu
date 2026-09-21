from __future__ import annotations

import http.server
import threading
import time

import o5_user_token_https_worker as worker
import pytest


class _SlowHandler(http.server.BaseHTTPRequestHandler):
    mode = "header"

    def do_GET(self) -> None:
        if self.mode == "header":
            time.sleep(0.15)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")
            return
        if self.mode == "error-body":
            self.send_response(500)
            self.send_header("Content-Length", "2")
            self.end_headers()
            time.sleep(0.15)
            self.wfile.write(b"{}")
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        time.sleep(0.15)
        self.wfile.write(b"{}")

    def log_message(self, *_args: object) -> None:
        return


def _exchange(mode: str, seconds: float) -> None:
    _SlowHandler.mode = mode
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        envelope = {
            "service": "firestore",
            "route": "observation-get",
            "method": "GET",
            "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/owned-a",
            "headers": {"x-goog-user-project": "fireemu-35fe6"},
            "body": None,
            "seconds": seconds,
        }
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        with pytest.raises(ValueError, match="deadline|walltime"):
            worker.exchange(envelope, fixture_origin=origin)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_slow_headers_are_fail_closed_before_eight_second_bound() -> None:
    _exchange("header", 0.03)


def test_slow_body_is_fail_closed_before_eight_second_bound() -> None:
    _exchange("body", 0.03)


def test_slow_http_error_body_is_fail_closed_before_deadline() -> None:
    _exchange("error-body", 0.03)


def test_worker_rejects_deadline_above_closed_eight_second_bound() -> None:
    envelope = {
        "service": "firestore",
        "route": "observation-get",
        "method": "GET",
        "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/owned-a",
        "headers": {"x-goog-user-project": "fireemu-35fe6"},
        "body": None,
        "seconds": worker.MAX_SECONDS + 0.01,
    }
    with pytest.raises(ValueError, match="bounded worker deadline"):
        worker.exchange(envelope, fixture_origin="http://127.0.0.1:1")


@pytest.mark.parametrize(
    ("route", "method", "path", "body"),
    [
        ("ruleset-create", "POST", "/v1/projects/fireemu-35fe6/rulesets", {"source": {"files": []}}),
        ("ruleset-get", "GET", "/v1/projects/fireemu-35fe6/rulesets/ruleset-a", None),
        ("ruleset-delete", "DELETE", "/v1/projects/fireemu-35fe6/rulesets/ruleset-a", None),
        ("release-get", "GET", "/v1/projects/fireemu-35fe6/releases/cloud.firestore", None),
        ("release-patch", "PATCH", "/v1/projects/fireemu-35fe6/releases/cloud.firestore", {"release": {}, "updateMask": "rulesetName"}),
        ("release-get-executable", "GET", "/v1/projects/fireemu-35fe6/releases/cloud.firestore:getExecutable", None),
    ],
)
def test_rules_lifecycle_routes_are_allowlisted(route, method, path, body):
    worker._route("rules", route, method, path)
