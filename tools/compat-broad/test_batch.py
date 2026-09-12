"""Production preparation admission tests; never call an oracle."""

import importlib.util
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("batch_contract.py")
    assert path.exists(), "batch admission contract required before remote transport"
    spec = importlib.util.spec_from_file_location("batch_contract", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_candidate_keeps_all_new_checks_and_bounds_owned_scans():
    c = contract()
    m = c.candidate()
    assert m["diagnosticRows"] == {"auth": 19, "firestore": 27}
    assert m["resources"]["documents"] == 8
    assert m["resources"]["accounts"] == 3
    assert m["cost"]["scanDocumentsPerQuery"] == 1
    assert m["cost"]["upperEstimateUsd"] < 1
    assert m["productionApproval"] is None
    mapped = c.compile_firestore(m, "a" * 32)
    assert len(mapped) == 2
    query = next(s for s in mapped[0]["steps"] if s["id"] == "zero-limit")
    assert query["body"]["structuredQuery"]["from"] == [{"collectionId": "broad"}]
    assert query["path"].endswith("/broad_runs/" + "a" * 32 + "-0:runQuery")
    assert all("/broad_runs/" in name for p in mapped for name in p["targets"])


def test_changed_source_or_namespace_cannot_be_compiled():
    c = contract()
    m = c.candidate()
    m["firestorePrograms"][0]["steps"][0]["path"] += "/foreign"
    with pytest.raises(ValueError):
        c.compile_firestore(m, "a" * 32)
    for nonce in ["", "../outside", "a" * 31, "A" * 32]:
        with pytest.raises(ValueError):
            c.compile_firestore(c.candidate(), nonce)


def test_budget_reserves_recovery_and_counts_auth_commands():
    c = contract()
    b = c.Budget(start=0)
    b.reserve("metadata", 0, duration=80)
    assert b.counts["metadata"] == 1
    with pytest.raises(ValueError):
        b.reserve("metadata", 830, duration=80)
    b.recovery = True
    with pytest.raises(ValueError):
        b.reserve("metadata", 1190, duration=20)
    for _ in range(299):
        b.reserve("auth", 900, duration=1)
    b.reserve("auth", 900, duration=1)
    with pytest.raises(ValueError):
        b.reserve("auth", 900, duration=1)


def test_approval_is_manifest_observer_nonce_and_time_bound():
    c = contract()
    m = c.candidate()
    with pytest.raises(ValueError):
        c.approve(m, {}, "a" * 32, "b" * 64, 1000)


def test_expiry_failure_latches_and_privileged_use_requires_full_deadline():
    c = contract()
    assert hasattr(c, "Credential"), "verified expiry state required"
    token = c.Credential()
    token.accept("opaque", {"expires_in": "30"}, 100)
    assert token.usable(116, 12)
    assert not token.usable(118, 12)
    token.fail()
    assert not token.usable(100, 1)
    with pytest.raises(ValueError):
        token.accept("replacement", {"expires_in": "3600"}, 100)


def test_real_transport_bounds_redirect_body_and_total_deadline():
    import http.server
    import threading
    import time

    path = Path(__file__).with_name("batch_adapter.py")
    assert path.exists(), "bounded adapter required"
    import batch_adapter as adapter

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/sink")
                self.end_headers()
            elif self.path == "/large":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"x" * 65537)
            elif self.path == "/slow":
                time.sleep(1)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        assert adapter.wire(origin + "/ok", "GET", None, {}, local=True)[1] == {
            "ok": True
        }
        for suffix in ("/redirect", "/large", "/slow"):
            with pytest.raises(ValueError):
                adapter.wire(origin + suffix, "GET", None, {}, local=True, timeout=0.4)
        with pytest.raises(ValueError):
            adapter.wire("https://example.com/", "GET", None, {}, local=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_unjournaled_resources_and_foreign_auth_selectors_fail_before_transport(
    tmp_path,
):
    import batch_adapter as a

    c = contract()
    run = a.Adapter(
        c.candidate(),
        "a" * 32,
        tmp_path / "run",
        local_origins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
    )
    with pytest.raises(ValueError, match="journaled"):
        run.doc("projects/foreign/databases/(default)/documents/a/b", method="DELETE")
    for path, body, admin in [
        (
            "/identitytoolkit.googleapis.com/v1/accounts:update?key=fake",
            {"idToken": "foreign"},
            False,
        ),
        ("/identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=fake", {}, False),
        (
            "/identitytoolkit.googleapis.com/v1/projects/demo-firestore-probe/accounts:delete",
            {"localId": "foreign"},
            True,
        ),
    ]:
        with pytest.raises(ValueError):
            run.auth_call(path, body, admin)
    assert run.budget.counts["total"] == 0
    assert not run.journal.exists()


def test_remote_adapter_cannot_be_constructed_without_permission(tmp_path):
    import batch_adapter as a

    with pytest.raises(ValueError, match="approval"):
        a.Adapter(contract().candidate(), "a" * 32, tmp_path / "remote")
