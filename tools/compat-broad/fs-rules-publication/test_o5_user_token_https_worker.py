from __future__ import annotations

import http.server
import json
import threading
import time

import o5_user_token_https_worker as worker
import pytest


class _SetupHandler(http.server.BaseHTTPRequestHandler):
    def do_PATCH(self) -> None:
        payload = {"name": self.path.removeprefix("/v1/").split("?", 1)[0], "fields": {}, "updateTime": "2026-09-22T00:00:00Z"}
        self._reply(payload)

    def do_POST(self) -> None:
        if self.path.endswith("accounts:update"):
            payload = {"localId": "uid-owner-a", "displayName": "optional"}
        else:
            payload = {"localId": "uid-owner-a", "idToken": "transient", "expiresIn": "3600"}
        self._reply(payload)

    def _reply(self, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture
def setup_origin():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SetupHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _setup_envelope(route: str, method: str, path: str, body: dict[str, object]) -> dict[str, object]:
    headers = {"x-goog-user-project": "fireemu-35fe6"}
    if not path.startswith("/v1/accounts:"):
        headers["Authorization"] = "Bearer transient"
    return {
        "service": "firestore" if route == "document-create" else "identity",
        "route": route,
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
        "seconds": 2.0,
    }


def test_setup_routes_use_actual_loopback_official_responses(setup_origin):
    document_path = "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc?currentDocument.exists=false"
    result = worker.exchange(
        _setup_envelope("document-create", "PATCH", document_path, {"name": document_path.split("?", 1)[0].removeprefix("/v1/"), "fields": {}}),
        fixture_origin=setup_origin,
    )
    assert result["status"] == 200
    assert result["body"]["name"].endswith("/cases/setup-doc")
    for route, path, body in (
        ("accounts:signUp", "/v1/accounts:signUp?key=fixture-key", {"email": "owner@example.test", "password": "transient", "returnSecureToken": True}),
        ("accounts:update", "/v1/projects/fireemu-35fe6/accounts:update", {"localId": "uid-owner-a", "customAttributes": "{\"owner\":\"yes\"}"}),
        ("accounts:signInWithPassword", "/v1/accounts:signInWithPassword?key=fixture-key", {"email": "owner@example.test", "password": "transient", "returnSecureToken": True}),
    ):
        result = worker.exchange(_setup_envelope(route, "POST", path, body), fixture_origin=setup_origin)
        assert result["status"] == 200
        assert result["body"]["localId"] == "uid-owner-a"


@pytest.mark.parametrize(
    "envelope",
    [
        _setup_envelope("document-create", "PATCH", "/v1/projects/other/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc?currentDocument.exists=false", {"name": "projects/other/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc", "fields": {}}),
        _setup_envelope("document-create", "POST", "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc?currentDocument.exists=false", {"name": "projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc", "fields": {}}),
        _setup_envelope("document-create", "PATCH", "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc?currentDocument.exists=false", {"name": "projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/other-doc", "fields": {}}),
        _setup_envelope("document-create", "PATCH", "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc?currentDocument.exists=true", {"name": "projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc", "fields": {}}),
        _setup_envelope("accounts:update", "POST", "/v1/projects/fireemu-35fe6/accounts:update", {"localId": "uid-other", "customAttributes": "{}", "password": "secret"}),
        _setup_envelope("accounts:signInWithPassword", "POST", "/v1/projects/fireemu-35fe6/accounts:signInWithPassword", {"email": "owner@example.test", "password": "secret"}),
    ],
)
def test_setup_routes_reject_unbound_shapes(envelope):
    with pytest.raises(ValueError):
        worker.exchange(envelope, fixture_origin="http://127.0.0.1:1")


def test_client_setup_rejects_administrator_bearer():
    envelope = _setup_envelope(
        "accounts:signInWithPassword",
        "POST",
        "/v1/accounts:signInWithPassword?key=fixture-key",
        {"email": "owner@example.test", "password": "secret", "returnSecureToken": True},
    )
    envelope["headers"]["Authorization"] = "Bearer administrator"
    with pytest.raises(ValueError, match="must not use authorization"):
        worker.exchange(envelope, fixture_origin="http://127.0.0.1:1")


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
        ("ruleset-create", "POST", "/v1/projects/fireemu-35fe6/rulesets", {"source": {"files": [{"name": "firestore.rules", "content": "rules"}]}}),
        ("ruleset-get", "GET", "/v1/projects/fireemu-35fe6/rulesets/ruleset-a", None),
        ("ruleset-delete", "DELETE", "/v1/projects/fireemu-35fe6/rulesets/ruleset-a", None),
        ("release-get", "GET", "/v1/projects/fireemu-35fe6/releases/cloud.firestore", None),
        ("release-patch", "PATCH", "/v1/projects/fireemu-35fe6/releases/cloud.firestore", {"release": {"name": "projects/fireemu-35fe6/releases/cloud.firestore", "rulesetName": "projects/fireemu-35fe6/rulesets/ruleset-a"}, "updateMask": "rulesetName"}),
        ("release-get-executable", "GET", "/v1/projects/fireemu-35fe6/releases/cloud.firestore:getExecutable", None),
    ],
)
def test_rules_lifecycle_routes_are_allowlisted(route, method, path, body):
    worker._route("rules", route, method, path)
