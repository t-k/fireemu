"""Actual local HTTP boundaries and child-result classification, never a native run."""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import o5_user_token_local_run as module
import pytest
from test_o5_user_token_collector import case


@contextlib.contextmanager
def server():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            calls.append((self.path, self.headers.get("Authorization")))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/target")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status, raw, size = 200, b'{"ok":true}', None
            if self.path == "/short":
                status, raw, size = 404, b'{"error":{"status":"NOT_FOUND"}}', 900
            if self.path == "/oversize":
                raw = b'{"body":"' + b"x" * 65536 + b'"}'
            if self.path == "/broken":
                status, raw = 404, b"not-json"
            if self.path == "/array":
                raw = b"[]"
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(size or len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def log_message(self, *_):
            pass

    host = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=host.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{host.server_port}", calls
    finally:
        host.shutdown()
        host.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize("route", ["short", "oversize", "broken", "array"])
def test_malformed_http_cannot_become_a_complete_normalized_receipt(route):
    with server() as (origin, calls):
        with pytest.raises(module.Refused):
            module._request("GET", origin + "/" + route, credential="owner")
        assert len(calls) == 1


def test_redirect_is_not_followed_and_credential_is_not_replayed():
    with server() as (origin, calls):
        with pytest.raises(module.Refused):
            module._request("GET", origin + "/redirect", credential="owner")
        assert calls == [("/redirect", "Bearer owner")]


def test_real_loopback_success_is_preserved():
    with server() as (origin, calls):
        assert module._request("GET", origin + "/target") == (200, {"ok": True})
        assert calls == [("/target", None)]


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:9000/path",
        "http://example.invalid:9000/path",
        "http://user@127.0.0.1:9000/path",
        "http://127.0.0.1:9000/path#fragment",
        "http://127.0.0.1/path",
        "http://127.0.0.1:0/path",
    ],
)
def test_nonlocal_or_ambiguous_url_refused_before_a_network_primitive(monkeypatch, url):
    def forbidden(*_a, **_k):
        raise AssertionError("network primitive reached")

    monkeypatch.setattr(module.urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(module.urllib.request, "build_opener", forbidden)
    with pytest.raises(module.Refused):
        module._request("GET", url, credential="owner")


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"users": None},
        {"users": [], "error": {"message": "INTERNAL"}},
        {"users": [{"localId": "wrong"}]},
        {"users": [{"localId": "uid"}, {"localId": "uid"}]},
    ],
)
def test_local_account_lookup_keeps_malformed_or_wrong_identity_unknown(
    monkeypatch, body
):
    shadow = module.LocalShadow(
        "http://127.0.0.1:9000", "http://127.0.0.1:9001", "p", "a" * 32
    )
    shadow.plan = case()
    entry = shadow.plan["ownedAccounts"][0]
    shadow.uids[entry["ref"]] = "uid"
    monkeypatch.setattr(module, "_request", lambda *_a, **_k: (200, body))
    result = shadow._recover_account("account-readback", {"accountRef": entry["ref"]})
    assert result["complete"] is False


def test_lost_uid_is_not_proof_that_no_account_was_created():
    shadow = module.LocalShadow(
        "http://127.0.0.1:9000", "http://127.0.0.1:9001", "p", "a" * 32
    )
    shadow.plan = case()
    entry = shadow.plan["ownedAccounts"][0]
    result = shadow._recover_account("account-readback", {"accountRef": entry["ref"]})
    assert result["complete"] is False
    assert result.get("accountPresent") is not False


@pytest.mark.parametrize(
    "fault", ["recording", "cleanup", "deviation", "tenant", "setup"]
)
def test_child_never_exits_zero_for_failed_collection_state_or_recovery(
    tmp_path, monkeypatch, fault
):
    class Shadow:
        tenant = None
        uids = {}
        wire_requests = 0
        deleted = 0

        def __init__(self, *_):
            pass

        def create_tenant(self):
            self.tenant = "tenant-local"
            return self.tenant

        def publish(self, *_):
            pass

        def setup(self):
            if fault == "setup":
                raise module.Refused("fixture:failed")

        def execute(self, _):
            raise AssertionError("injected collector must not dispatch")

        def delete_tenant(self):
            Shadow.deleted += 1
            return fault != "tenant"

    monkeypatch.setattr(module, "LocalShadow", Shadow)
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:9000")
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9001")
    monkeypatch.setattr(
        module,
        "collect",
        lambda *_a, **_k: {
            "journal": "test-journal.jsonl",
            "recordingComplete": fault != "recording",
            "cleanup": {"cleanupComplete": fault != "cleanup"},
            "rows": [],
        },
    )
    monkeypatch.setattr(
        module,
        "local_deviations",
        lambda *_: [{"mismatch": True}] if fault == "deviation" else [],
    )
    assert module.run_child(tmp_path, "b" * 32) != 0
    assert Shadow.deleted >= 1
    assert (
        json.loads((tmp_path / "local-shadow.json").read_text())["completed"] is False
    )


@pytest.mark.parametrize("fault", [None, "wrong-kind", "page"])
def test_local_account_absence_requires_a_consistent_complete_shape(monkeypatch, fault):
    shadow = module.LocalShadow(
        "http://127.0.0.1:9000", "http://127.0.0.1:9001", "p", "a" * 32
    )
    shadow.plan = case()
    entry = shadow.plan["ownedAccounts"][0]
    shadow.uids[entry["ref"]] = "uid"
    body = {"users": []}
    if fault == "wrong-kind":
        body["kind"] = "unrelated"
    if fault == "page":
        body["nextPageToken"] = "continuation"
    monkeypatch.setattr(module, "_request", lambda *_a, **_k: (200, body))
    result = shadow._recover_account("account-absence", {"accountRef": entry["ref"]})
    assert result["complete"] is (fault is None)


@pytest.mark.parametrize(
    "status,body",
    [
        (404, {}),
        (404, {"error": {"status": "NOT_FOUND"}}),
        (404, {"error": {"status": "PERMISSION_DENIED", "code": 404}}),
        (404, {"error": {"status": "NOT_FOUND", "code": "404"}}),
        (404, {"error": {"status": "NOT_FOUND", "code": 404}, "name": "foreign"}),
        (403, {"error": {"status": "PERMISSION_DENIED", "code": 403}}),
        (500, {"error": {"status": "INTERNAL", "code": 500}}),
        (200, {"name": "wrong", "updateTime": "2026-09-19T00:00:00Z"}),
        (200, {"name": "resource", "updateTime": "2026-13-19T00:00:00Z"}),
        (200, {"name": "resource", "updateTime": "opaque"}),
        (200, {"name": "resource", "updateTime": "2026-09-19T00:00:00Z", "error": {}}),
    ],
)
def test_document_lookup_never_fabricates_absence_or_ownership(
    monkeypatch, status, body
):
    shadow = module.LocalShadow(
        "http://127.0.0.1:9000", "http://127.0.0.1:9001", "p", "a" * 32
    )
    monkeypatch.setattr(module, "_request", lambda *_a, **_k: (status, body))
    result = shadow._recover({"kind": "readback", "resource": "resource"})
    assert result["complete"] is False
    assert "documentPresent" not in result


@pytest.mark.parametrize("present", [True, False])
def test_document_readback_and_typed_absence_are_preserved(monkeypatch, present):
    body = (
        {"name": "resource", "updateTime": "2026-09-19T00:00:00.123456789Z"}
        if present
        else {"error": {"status": "NOT_FOUND", "code": 404, "message": "missing"}}
    )
    shadow = module.LocalShadow(
        "http://127.0.0.1:9000", "http://127.0.0.1:9001", "p", "a" * 32
    )
    monkeypatch.setattr(
        module, "_request", lambda *_a, **_k: (200 if present else 404, body)
    )
    result = shadow._recover({"kind": "readback", "resource": "resource"})
    assert result["complete"] is True
    assert result["documentPresent"] is present


def test_child_can_succeed_with_complete_independent_collection_and_cleanup(
    tmp_path, monkeypatch
):
    class Shadow:
        tenant = None
        uids = {}
        wire_requests = 0
        deleted = 0

        def __init__(self, *_):
            pass

        def create_tenant(self):
            self.tenant = "tenant-local"
            return self.tenant

        def publish(self, *_):
            pass

        def setup(self):
            pass

        def execute(self, _):
            raise AssertionError("injected collector must not dispatch")

        def delete_tenant(self):
            Shadow.deleted += 1
            return True

    monkeypatch.setattr(module, "LocalShadow", Shadow)
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:9000")
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9001")
    monkeypatch.setattr(
        module,
        "collect",
        lambda *_a, **_k: {
            "journal": "test-journal.jsonl",
            "recordingComplete": True,
            "cleanup": {"cleanupComplete": True},
            "rows": [],
        },
    )
    monkeypatch.setattr(module, "local_deviations", lambda *_: [])
    assert module.run_child(tmp_path, "b" * 32) == 0
    assert Shadow.deleted == 1
    result = json.loads((tmp_path / "local-shadow.json").read_text())
    assert result["resourceCleanupComplete"] is True
    assert result["completed"] is True
    assert result["productionExecuted"] is False
