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


@pytest.mark.parametrize("status", [401, 403])
def test_privileged_http_refusal_stops_transport_and_preserves_unconfirmed_cleanup(
    tmp_path, status
):
    import http.server
    import json
    import threading
    import time

    import batch_adapter as a

    calls = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            calls.append(self.path)
            self.send_response(status)
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": {"status": "PERMISSION_DENIED"}}).encode()
            )

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    run = a.Adapter(
        contract().candidate(),
        "a" * 32,
        tmp_path / "run",
        local_origins={"auth": origin, "firestore": origin},
    )
    run.credential.accept("verified", {"expires_in": 3600}, time.monotonic())
    name = run.compiled[0]["targets"][0]
    run.documents.add(name)
    run.record({"kind": "document-attempt", "name": name})
    try:
        with pytest.raises(ValueError, match="credential rejected"):
            run.request("firestore", "/v1/" + name, method="GET", privileged=True)
        assert run.credential.failed
        result = run.execute()
        assert not result["completed"]
        assert result["unrecovered"] == [{"kind": "document", "name": name}]
        assert len(calls) == 1
        assert run.credential.attempts == 0
        # Intentional caller refusals do not invalidate administrator credentials.
        other = a.Adapter(
            contract().candidate(),
            "b" * 32,
            tmp_path / "other",
            local_origins={"auth": origin, "firestore": origin},
        )
        assert other.request("auth", "unprivileged", method="GET")[0] == status
        assert not other.credential.failed
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_mapping_comparator_preserves_identity_types_and_array_order():
    import importlib.util

    assert importlib.util.find_spec("batch_comparison"), (
        "mapped response comparison required"
    )
    from batch_comparison import normalize

    parent = "projects/fireemu-35fe6/databases/(default)/documents/broad_runs/owned"
    body = {
        "name": parent + "/tf/doc",
        "fields": {"ordered": [True, 1, None]},
        "createTime": "2026-09-12T00:00:00Z",
    }
    got = normalize(body, parent)
    assert (
        got["name"]
        == "projects/demo-firestore-probe/databases/(default)/documents/tf/doc"
    )
    assert got["fields"]["ordered"] == [True, 1, None]
    assert type(got["fields"]["ordered"][0]) is bool
    assert got["createTime"] == "<now>"
    assert (
        normalize({"name": "projects/foreign/doc"}, parent)["name"]
        == "projects/foreign/doc"
    )


def test_finite_phase_and_intersecting_budget_boundaries():
    import itertools

    c = contract()
    checked = 0
    for recovery, elapsed, total, service_count in itertools.product(
        [False, True], [880, 900, 1190], [2099, 2100, 2399, 2400], [399, 400]
    ):
        b = c.Budget(0)
        b.recovery = recovery
        b.counts.update(total=total, auth=service_count)
        allowed = (
            elapsed + 12 <= (1200 if recovery else 900)
            and total < (2400 if recovery else 2100)
            and service_count < 400
        )
        if allowed:
            b.reserve("auth", elapsed)
            assert b.counts["auth"] == service_count + 1
            assert b.counts["total"] == total + 1
        else:
            with pytest.raises(ValueError):
                b.reserve("auth", elapsed)
            assert b.counts["total"] == total
        checked += 1
    assert checked == 48


def test_valid_permission_and_each_binding_rejection():
    c = contract()
    m = c.candidate()
    permission = {
        "kind": "owner-execution-permission",
        "manifestSha256": c.digest(m),
        "observerSha256": "b" * 64,
        "nonce": "a" * 32,
        "project": c.PROJECT,
        "projectNumber": c.NUMBER,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "issuedAt": 900,
        "expiresAt": 9000,
        "ownerIdentity": "unit-test-only-not-real-permission",
        "permissionReference": "offline-fixture",
        "authConfigDigest": "c" * 64,
        "databaseDigest": "d" * 64,
        "pricingLocation": "us-central1",
        "pricingCheckedAt": "2026-09-12",
    }
    c.approve(m, permission, "a" * 32, "b" * 64, 1000)
    for key, value in [
        ("manifestSha256", "x"),
        ("observerSha256", "x"),
        ("nonce", "x"),
        ("projectNumber", "0"),
        ("tariffsConfirmedBelowPlanningCeilings", 1),
        ("expiresAt", 1100),
        ("issuedAt", 1100),
        ("permissionReference", ""),
    ]:
        with pytest.raises(ValueError):
            c.approve(m, {**permission, key: value}, "a" * 32, "b" * 64, 1000)
