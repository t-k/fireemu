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


def test_adopted_artifact_requires_bound_receipt_and_complete_runtime_map(tmp_path):
    import hashlib
    import json

    import batch_local

    binary = tmp_path / "fireemu"
    binary.write_bytes(b"adopted-native-artifact")
    artifact_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    inputs = {f"input-{index}": f"sha-{index}" for index in range(429)}
    build = {
        "command": ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"],
        "exitCode": 0,
        "artifactSha256": artifact_sha,
        "inputs": inputs,
    }
    receipt = {
        "build": build,
        "runtimeSource": {"commit": "5" * 40, "files": inputs},
    }
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt))

    adopted = batch_local.adopted_artifact(binary, receipt_path, "5" * 40)
    assert adopted["artifactSha256"] == artifact_sha
    assert adopted["sourceCommit"] == "5" * 40
    assert adopted["runtimeInputCount"] == 429

    changed = json.loads(receipt_path.read_text())
    changed["build"]["inputs"]["input-0"] = "substituted"
    receipt_path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="runtime input map"):
        batch_local.adopted_artifact(binary, receipt_path, "5" * 40)


def test_retained_648_profile_is_exact_and_refuses_provenance_drift(
    tmp_path, monkeypatch
):
    import hashlib
    import json

    import batch_local

    source_commit = "648aabe56cf6147128ffadf565d93ca7a92013c1"
    binary = tmp_path / "fireemu"
    binary.write_bytes(b"synthetic-retained-artifact")
    artifact_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    inputs = {f"input-{index}": f"sha-{index}" for index in range(430)}
    input_map_sha = hashlib.sha256(
        json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    monkeypatch.setattr(batch_local, "RETAINED_648_ARTIFACT_SHA256", artifact_sha)
    monkeypatch.setattr(batch_local, "RETAINED_648_INPUT_MAP_SHA256", input_map_sha)

    build = {
        "command": [
            "cargo",
            "build",
            "--locked",
            "-p",
            "fireemu",
            "--message-format=json",
        ],
        "exitCode": 0,
        "artifactSha256": artifact_sha,
        "inputs": inputs,
    }
    receipt = {
        "build": build,
        "runtimeSource": {"commit": source_commit, "files": inputs},
    }
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt))

    adopted = batch_local.adopted_artifact(binary, receipt_path, source_commit)
    assert adopted["artifactSha256"] == artifact_sha
    assert adopted["sourceCommit"] == source_commit
    assert adopted["runtimeInputCount"] == 430

    with pytest.raises(ValueError, match="source commit"):
        batch_local.adopted_artifact(binary, receipt_path, "5" * 40)

    binary.write_bytes(b"substituted-artifact")
    with pytest.raises(ValueError, match="artifact hash"):
        batch_local.adopted_artifact(binary, receipt_path, source_commit)
    binary.write_bytes(b"synthetic-retained-artifact")

    changed = json.loads(receipt_path.read_text())
    changed["runtimeSource"]["files"]["input-0"] = "substituted"
    changed["build"]["inputs"]["input-0"] = "substituted"
    receipt_path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="runtime input map"):
        batch_local.adopted_artifact(binary, receipt_path, source_commit)

    changed["build"]["inputs"]["input-0"] = "sha-0"
    receipt_path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="runtime input map"):
        batch_local.adopted_artifact(binary, receipt_path, source_commit)


def test_retained_648_profile_pins_the_recorded_artifact_and_input_map():
    import batch_local

    assert batch_local.RETAINED_648_SOURCE_COMMIT == (
        "648aabe56cf6147128ffadf565d93ca7a92013c1"
    )
    assert batch_local.RETAINED_648_ARTIFACT_SHA256 == (
        "7737f6c389aff0a0f280757591af3b81f11edfbc8438cb69268da0f4c2237026"
    )
    assert batch_local.RETAINED_648_INPUT_MAP_SHA256 == (
        "7e2b0bc7037e0caf9f979f052c69a3820a398c8df72de8dbd19f1aac2f524331"
    )


def test_changed_source_or_namespace_cannot_be_compiled():
    c = contract()
    m = c.candidate()
    m["firestorePrograms"][0]["steps"][0]["path"] += "/foreign"
    with pytest.raises(ValueError):
        c.compile_firestore(m, "a" * 32)
    changed = c.candidate()
    changed["firestorePrograms"][0]["seed"][0]["fields"]["n"]["integerValue"] = "999"
    with pytest.raises(ValueError, match="unrecognized candidate"):
        c.compile_firestore(changed, "a" * 32)
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
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        assert adapter.wire(origin + "/ok", "GET", None, {}, local=True)[1] == {
            "ok": True
        }
        for suffix in ("/redirect", "/large", "/slow"):
            started = time.monotonic()
            with pytest.raises(ValueError):
                adapter.wire(origin + suffix, "GET", None, {}, local=True, timeout=0.4)
            assert time.monotonic() - started < 0.8
        with pytest.raises(ValueError):
            adapter.wire("https://example.com/", "GET", None, {}, local=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_optional_process_receipt_reports_real_reaped_worker_without_changing_default():
    import http.server
    import threading

    import batch_adapter as adapter

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        default = adapter.wire(origin + "/ok", "GET", None, {}, local=True)
        assert default == [200, {"ok": True}, "application/json"]
        observed = adapter.wire(
            origin + "/ok",
            "GET",
            None,
            {},
            local=True,
            process_receipt=True,
        )
        assert observed["status"] == 200
        assert observed["complete"] is True
        assert observed["bodyKind"] == "json"
        assert observed["body"] == {"ok": True}
        assert observed["workerReaped"] is True
        process = observed["process"]
        assert process["pid"] > 0
        assert isinstance(process["returncode"], int)
        assert process["termination"] == "exited"
        assert process["deadlineExceeded"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    ("worker_source", "returncode", "termination"),
    [
        ("import sys; sys.exit(7)", 7, "exited"),
        ("import os; os.close(0); raise SystemExit(7)", 7, "exited"),
        ("print('not-json')", 0, "exited"),
    ],
)
def test_process_receipt_failures_report_actual_terminal_state(
    tmp_path, monkeypatch, worker_source, returncode, termination
):
    import batch_adapter as adapter

    worker_dir = tmp_path / "worker"
    worker_dir.mkdir()
    (worker_dir / "batch_wire.py").write_text(worker_source + "\n", encoding="utf-8")
    monkeypatch.setattr(adapter, "HERE", worker_dir)
    with pytest.raises(adapter.WorkerProcessError) as raised:
        adapter.wire(
            "http://127.0.0.1:18081/never",
            "GET",
            {"secret": "must-not-appear"},
            {},
            local=True,
            process_receipt=True,
        )
    error = raised.value
    assert "must-not-appear" not in str(error)
    assert error.process_receipt["returncode"] == returncode
    assert error.process_receipt["workerReaped"] is True
    assert error.process_receipt["termination"] == termination


def test_process_receipt_rejects_unbounded_worker_output_after_reaping(
    tmp_path, monkeypatch
):
    import batch_adapter as adapter

    worker_dir = tmp_path / "worker"
    worker_dir.mkdir()
    (worker_dir / "batch_wire.py").write_text(
        "import sys; sys.stdout.write('x' * 200000)\n", encoding="utf-8"
    )
    monkeypatch.setattr(adapter, "HERE", worker_dir)
    with pytest.raises(adapter.WorkerProcessError, match="output exceeded") as raised:
        adapter.wire(
            "http://127.0.0.1:18081/never",
            "GET",
            None,
            {},
            local=True,
            process_receipt=True,
        )
    assert raised.value.process_receipt["workerReaped"] is True


def test_process_receipt_bounds_simultaneous_stdout_and_stderr_flood(
    tmp_path, monkeypatch
):
    import batch_adapter as adapter

    worker_dir = tmp_path / "worker"
    worker_dir.mkdir()
    (worker_dir / "batch_wire.py").write_text(
        "import sys; sys.stdout.write('x' * 200000); "
        "sys.stderr.write('e' * 20000)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(adapter, "HERE", worker_dir)
    with pytest.raises(adapter.WorkerProcessError, match="output exceeded") as raised:
        adapter.wire(
            "http://127.0.0.1:18081/never",
            "GET",
            None,
            {},
            local=True,
            process_receipt=True,
        )
    receipt = raised.value.process_receipt
    assert receipt["workerReaped"] is True
    assert receipt["returncode"] is not None


@pytest.mark.parametrize(
    "case",
    [
        lambda origin: (origin + "/" + "u" * 70000, {}, None),
        lambda origin: (origin + "/ok", {"X-Large": "h" * 70000}, None),
        lambda origin: (origin + "/ok", {}, {"nested": {"value": "n" * 200000}}),
    ],
)
def test_oversized_input_is_rejected_before_worker_start(tmp_path, monkeypatch, case):
    import batch_adapter as adapter

    worker_dir = tmp_path / "worker"
    worker_dir.mkdir()
    marker = tmp_path / "started"
    (worker_dir / "batch_wire.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('started')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(adapter, "HERE", worker_dir)
    url, headers, body = case("http://127.0.0.1:18081")
    with pytest.raises(ValueError, match="bound exceeded"):
        adapter.wire(
            url,
            "GET",
            body,
            headers,
            local=True,
            process_receipt=True,
        )
    assert not marker.exists()


def test_json_prevalidation_rejects_cycle_depth_nonfinite_unicode_and_bad_url(
    tmp_path, monkeypatch
):
    import batch_adapter as adapter

    worker_dir = tmp_path / "worker"
    worker_dir.mkdir()
    marker = tmp_path / "started"
    (worker_dir / "batch_wire.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('started')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(adapter, "HERE", worker_dir)
    cyclic = []
    cyclic.append(cyclic)
    deep = value = []
    for _ in range(70):
        value.append([])
        value = value[0]
    cases = [
        ("http://127.0.0.1:18081/ok", {"value": float("nan")}),
        ("http://127.0.0.1:18081/ok", cyclic),
        ("http://127.0.0.1:18081/ok", deep),
        ("http://127.0.0.1:18081/ok", "🦀" * 5000),
    ]
    for url, body in cases:
        with pytest.raises(ValueError):
            adapter.wire(url, "POST", body, {}, local=True, process_receipt=True)
    with pytest.raises(ValueError, match="URL"):
        adapter.wire(123, "GET", None, {}, local=True, process_receipt=True)
    assert not marker.exists()


def test_json_prevalidation_uses_one_aggregate_budget_before_serialization(
    tmp_path, monkeypatch
):
    import batch_adapter as adapter

    worker_dir = tmp_path / "worker"
    worker_dir.mkdir()
    marker = tmp_path / "started"
    (worker_dir / "batch_wire.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('started')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(adapter, "HERE", worker_dir)
    body = {"items": ["escape-🦀" * 700 for _ in range(20)]}
    with pytest.raises(ValueError, match="body bound"):
        adapter.wire(
            "http://127.0.0.1:18081/ok",
            "POST",
            body,
            {},
            local=True,
            process_receipt=True,
        )
    assert not marker.exists()


def test_process_receipt_start_failure_does_not_claim_a_worker_was_reaped(
    tmp_path, monkeypatch
):
    import batch_adapter as adapter

    monkeypatch.setattr(adapter, "HERE", tmp_path / "missing-worker")
    monkeypatch.setattr(adapter.sys, "executable", str(tmp_path / "missing-python"))
    with pytest.raises(adapter.WorkerProcessError) as raised:
        adapter.wire(
            "http://127.0.0.1:18081/never",
            "GET",
            None,
            {},
            local=True,
            process_receipt=True,
        )
    receipt = raised.value.process_receipt
    assert receipt["started"] is False
    assert receipt["pid"] is None
    assert receipt["workerReaped"] is False
    assert receipt["termination"] == "start-failed"


def test_process_receipt_timeout_kills_and_reaps_owned_worker():
    import http.server
    import threading
    import time

    import batch_adapter as adapter

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            time.sleep(0.8)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(adapter.WorkerProcessError) as raised:
            adapter.wire(
                f"http://127.0.0.1:{server.server_port}/slow",
                "GET",
                None,
                {},
                local=True,
                timeout=0.2,
                process_receipt=True,
            )
        receipt = raised.value.process_receipt
        assert receipt["deadlineExceeded"] is True
        assert receipt["termination"] == "deadline"
        assert receipt["workerReaped"] is True
        assert receipt["returncode"] is not None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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


def test_cleanup_never_deletes_a_document_replaced_after_conditional_seed(
    tmp_path, monkeypatch
):
    import batch_adapter as a

    c = contract()
    name = "projects/demo-firestore-probe/databases/(default)/documents/broad_runs/owned/tf/doc"
    fields = {"_sharedOwner": {"referenceValue": name}, "marker": {"stringValue": "owned"}}
    created = {"name": name, "fields": fields, "updateTime": "2026-09-16T00:00:00Z"}
    foreign = {"name": name, "fields": {"marker": {"stringValue": "foreign"}}, "updateTime": "2026-09-16T00:00:01Z"}
    calls = []

    def fake_wire(url, method, body, headers, *, local=False, timeout=12, receipt=False):
        calls.append((method, url, body))
        if method == "GET" and len(calls) == 1:
            return 404, {"error": {"status": "NOT_FOUND"}}, "application/json"
        if method == "PATCH":
            return 200, created, "application/json"
        if method == "GET":
            return 200, foreign, "application/json"
        pytest.fail("foreign replacement must never receive DELETE")

    run = a.Adapter(
        c.candidate(),
        "a" * 32,
        tmp_path / "run",
        local_origins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
    )
    run.compiled = [{
        "parent": name.rsplit("/tf/doc", 1)[0],
        "targets": [name],
        "seed": [{"path": "/v1/" + name, "fields": fields}],
        "steps": [],
    }]
    monkeypatch.setattr(a, "wire", fake_wire)

    run.firestore()
    run.cleanup()

    assert calls[-1][0] == "GET"
    assert run.unrecovered == [{"kind": "document", "name": name}]


def test_conditional_seed_race_keeps_existing_document_unowned(tmp_path, monkeypatch):
    import batch_adapter as a

    c = contract()
    name = "projects/demo-firestore-probe/databases/(default)/documents/broad_runs/owned/tf/doc"
    fields = {"marker": {"stringValue": "owned"}}
    foreign = {
        "name": name,
        "fields": {"marker": {"stringValue": "foreign"}},
        "updateTime": "2026-09-16T00:00:01Z",
    }
    calls = []

    def fake_wire(url, method, body, headers, *, local=False, timeout=12, receipt=False):
        calls.append((method, url, body))
        if method == "GET" and len(calls) == 1:
            return 404, {"error": {"status": "NOT_FOUND"}}, "application/json"
        if method == "PATCH":
            return 400, {"error": {"status": "ALREADY_EXISTS"}}, "application/json"
        if method == "GET":
            return 200, foreign, "application/json"
        pytest.fail("preflight race must never receive DELETE")

    run = a.Adapter(
        c.candidate(),
        "a" * 32,
        tmp_path / "run",
        local_origins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
    )
    run.compiled = [{
        "parent": name.rsplit("/tf/doc", 1)[0],
        "targets": [name],
        "seed": [{"path": "/v1/" + name, "fields": fields}],
        "steps": [],
    }]
    monkeypatch.setattr(a, "wire", fake_wire)

    with pytest.raises(ValueError, match="conditional creation"):
        run.firestore()
    run.cleanup()

    assert run.unrecovered == [{"kind": "document", "name": name}]
    assert all(method != "DELETE" for method, _url, _body in calls)


def test_cleanup_never_deletes_same_version_document_with_changed_fields(
    tmp_path, monkeypatch
):
    import batch_adapter as a

    c = contract()
    name = "projects/demo-firestore-probe/databases/(default)/documents/broad_runs/owned/tf/doc"
    fields = {"marker": {"stringValue": "owned"}}
    foreign = {"marker": {"stringValue": "foreign"}}
    calls = []

    def fake_wire(url, method, body, headers, *, local=False, timeout=12, receipt=False):
        calls.append((method, url, body))
        if method == "GET" and len(calls) == 1:
            return 404, {"error": {"status": "NOT_FOUND"}}, "application/json"
        if method == "PATCH":
            return 200, {
                "name": name,
                "fields": fields,
                "updateTime": "2026-09-16T00:00:00Z",
            }, "application/json"
        if method == "GET":
            return 200, {
                "name": name,
                "fields": foreign,
                "updateTime": "2026-09-16T00:00:00Z",
            }, "application/json"
        pytest.fail("same-version field replacement must never receive DELETE")

    run = a.Adapter(
        c.candidate(),
        "a" * 32,
        tmp_path / "run",
        local_origins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
    )
    run.compiled = [{
        "parent": name.rsplit("/tf/doc", 1)[0],
        "targets": [name],
        "seed": [{"path": "/v1/" + name, "fields": fields}],
        "steps": [],
    }]
    monkeypatch.setattr(a, "wire", fake_wire)

    run.firestore()
    run.cleanup()

    assert calls[-1][0] == "GET"
    assert run.unrecovered == [{"kind": "document", "name": name}]


def test_cleanup_readback_completes_transform_proof_before_conditional_delete(
    tmp_path, monkeypatch
):
    import batch_adapter as a

    c = contract()
    name = "projects/demo-firestore-probe/databases/(default)/documents/broad_runs/owned/tf/transform"
    fields = {"count": {"doubleValue": "NaN"}}
    created = {"name": name, "fields": fields, "updateTime": "2026-09-16T00:00:01Z"}
    seeded = {
        "name": name,
        "fields": {"marker": {"stringValue": "seed"}},
        "updateTime": "2026-09-16T00:00:00Z",
    }
    calls = []

    def fake_wire(url, method, body, headers, *, local=False, timeout=12, receipt=False):
        calls.append((method, url, body))
        if method == "GET" and len(calls) == 1:
            return 404, {"error": {"status": "NOT_FOUND"}}, "application/json"
        if method == "PATCH":
            return 200, seeded, "application/json"
        if method == "GET":
            if len(calls) == 3:
                return 200, created, "application/json"
            return 404, {"error": {"status": "NOT_FOUND"}}, "application/json"
        if method == "DELETE":
            return 200, {}, "application/json"
        pytest.fail(f"unexpected request: {method} {url}")

    run = a.Adapter(
        c.candidate(),
        "a" * 32,
        tmp_path / "run",
        local_origins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
    )
    run.compiled = [{
        "parent": name.rsplit("/tf/transform", 1)[0],
        "targets": [name],
        "seed": [{"path": "/v1/" + name, "fields": {"marker": {"stringValue": "seed"}}}],
        "steps": [],
    }]
    monkeypatch.setattr(a, "wire", fake_wire)

    run.firestore()
    run.creation_proofs[name]["updateTime"] = created["updateTime"]
    run.creation_proofs[name]["fieldsDigest"] = None
    run.cleanup()

    assert [method for method, _url, _body in calls] == [
        "GET", "PATCH", "GET", "DELETE", "GET"
    ]
    assert run.unrecovered == []


def test_firestore_proves_and_cleans_up_every_successful_commit_document(
    tmp_path, monkeypatch
):
    from urllib.parse import quote

    import batch_adapter as a

    c = contract()
    base = "projects/demo-firestore-probe/databases/(default)/documents/broad_runs/owned/tf"
    names = [base + "/" + label for label in ("doc", "extrema", "created", "sat", "nan")]
    seed_fields = {"marker": {"stringValue": "seed"}}
    writes = [
        {"update": {"name": names[0], "fields": {"marker": {"stringValue": "mutated"}}}},
        {"update": {"name": names[1], "fields": {"marker": {"stringValue": "extrema"}}}},
        {"transform": {"document": names[2], "fieldTransforms": [{"fieldPath": "count", "increment": {"integerValue": "1"}}]}},
        {"update": {"name": names[3], "fields": {"marker": {"stringValue": "sat"}}}},
        {"update": {"name": names[4], "fields": {"marker": {"stringValue": "nan"}}}},
    ]
    versions = {name: f"2026-09-16T00:00:{index + 1:02d}Z" for index, name in enumerate(names)}
    created_documents = {
        names[0]: {"marker": {"stringValue": "mutated"}},
        names[1]: {"marker": {"stringValue": "extrema"}},
        names[2]: {"count": {"integerValue": "1"}},
        names[3]: {"marker": {"stringValue": "sat"}},
        names[4]: {"marker": {"stringValue": "nan"}},
    }
    current = {}
    calls = []

    def fake_wire(url, method, body, headers, *, local=False, timeout=12, receipt=False):
        calls.append((method, url, body))
        path = url.split("/v1/", 1)[-1]
        if method == "GET" and path in names and path not in current:
            return 404, {"error": {"status": "NOT_FOUND"}}, "application/json"
        if method == "GET" and path in names:
            return 200, {
                "name": path,
                "fields": current[path],
                "updateTime": versions[path],
            }, "application/json"
        if method == "PATCH":
            current[names[0]] = seed_fields
            versions[names[0]] = "2026-09-16T00:00:00Z"
            return 200, {
                "name": names[0],
                "fields": seed_fields,
                "updateTime": versions[names[0]],
            }, "application/json"
        if method == "POST" and path.endswith(":commit"):
            current.update(created_documents)
            return 200, {
                "writeResults": [{"updateTime": versions[name]} for name in names],
                "commitTime": "2026-09-16T00:01:00Z",
            }, "application/json"
        if method == "DELETE":
            name = path.split("?", 1)[0]
            assert name in names
            assert "currentDocument.updateTime=" + quote(versions[name], safe="") in path
            current.pop(name, None)
            return 200, {}, "application/json"
        pytest.fail(f"unexpected request: {method} {url}")

    run = a.Adapter(
        c.candidate(),
        "a" * 32,
        tmp_path / "run",
        local_origins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
    )
    run.compiled = [{
        "id": "owned-documents",
        "parent": base,
        "targets": names,
        "seed": [{"path": "/v1/" + names[0], "fields": seed_fields}],
        "steps": [
            {
                "id": "create-and-mutate",
                "method": "POST",
                "path": "/v1/" + base + ":commit",
                "body": {"writes": writes},
            },
            *[
                {"id": "read-" + name.rsplit("/", 1)[-1], "method": "GET", "path": "/v1/" + name}
                for name in names
            ],
        ],
    }]
    monkeypatch.setattr(a, "wire", fake_wire)

    run.firestore()
    assert set(run.creation_proofs) == set(names)
    assert all(proof["fieldsDigest"] for proof in run.creation_proofs.values())
    run.cleanup()

    assert run.unrecovered == []
    assert not current


@pytest.mark.parametrize("partial", [False, True])
def test_failed_commit_keeps_creation_uncertain_without_unsafe_cleanup(
    tmp_path, monkeypatch, partial
):
    import batch_adapter as a

    c = contract()
    base = "projects/demo-firestore-probe/databases/(default)/documents/broad_runs/owned/tf"
    seed = base + "/seed"
    candidate = base + "/candidate"
    fields = {"marker": {"stringValue": "owned"}}
    foreign = {"marker": {"stringValue": "unknown"}}
    current = {}
    calls = []

    def fake_wire(url, method, body, headers, *, local=False, timeout=12, receipt=False):
        calls.append((method, url, body))
        path = url.split("/v1/", 1)[-1]
        if method == "GET" and path.split("?", 1)[0] in (seed, candidate):
            name = path.split("?", 1)[0]
            if name not in current:
                return 404, {"error": {"status": "NOT_FOUND"}}, "application/json"
            return 200, {
                "name": name,
                "fields": current[name],
                "updateTime": "2026-09-16T00:00:00Z",
            }, "application/json"
        if method == "PATCH":
            current[seed] = fields
            return 200, {
                "name": seed,
                "fields": fields,
                "updateTime": "2026-09-16T00:00:00Z",
            }, "application/json"
        if method == "POST" and path.endswith(":commit"):
            if partial:
                current[candidate] = foreign
            return 400, {"error": {"status": "FAILED_PRECONDITION"}}, "application/json"
        if method == "DELETE":
            name = path.split("?", 1)[0]
            assert name == seed
            current.pop(name, None)
            return 200, {}, "application/json"
        pytest.fail(f"unexpected request: {method} {url}")

    run = a.Adapter(
        c.candidate(),
        "a" * 32,
        tmp_path / "run",
        local_origins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
    )
    run.compiled = [{
        "id": "failed-commit",
        "parent": base,
        "targets": [seed, candidate],
        "seed": [{"path": "/v1/" + seed, "fields": fields}],
        "steps": [{
            "id": "failed-create",
            "method": "POST",
            "path": "/v1/" + base + ":commit",
            "body": {"writes": [{"update": {"name": candidate, "fields": foreign}}]},
        }],
    }]
    monkeypatch.setattr(a, "wire", fake_wire)

    run.firestore()

    assert candidate not in run.creation_proofs
    run.cleanup()
    if partial:
        assert {entry["name"] for entry in run.unrecovered} == {candidate}
        assert all(
            method != "DELETE" or seed in url
            for method, url, _body in calls
        )
    else:
        assert run.unrecovered == []


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
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        # Every statement that can raise stays inside the block that stops the
        # server; a stranded loopback server used to survive the whole session.
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
        with pytest.raises(ValueError, match="credential rejected"):
            run.request("firestore", "/v1/" + name, method="GET", privileged=True)
        assert run.credential.failed
        captured = json.loads(
            (run.output / "responses.jsonl").read_text().splitlines()[0]
        )
        assert captured["response"]["httpStatus"] == status
        assert captured["response"]["body"]["error"]["status"] == "PERMISSION_DENIED"
        assert (run.output / "responses.jsonl").stat().st_mode & 0o777 == 0o600
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
        thread.join(timeout=5)


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
        "comparisonContractDigest": c.digest(__import__("batch_pair").binding(m)),
        "manifestSha256": c.digest(m),
        "observerSha256": "b" * 64,
        "nonce": "a" * 32,
        "project": c.PROJECT,
        "projectNumber": c.NUMBER,
        "quotaProject": c.PROJECT,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "issuedAt": 900,
        "expiresAt": 9000,
        "ownerIdentity": "unit-test-only-not-real-permission",
        "permissionReference": "offline-fixture",
        "authConfigDigest": "c" * 64,
        "databaseProjection": {
            "name": "projects/fireemu-35fe6/databases/(default)",
            "uid": "fixture",
            "type": "FIRESTORE_NATIVE",
            "databaseEdition": "STANDARD",
            "locationId": "us-central1",
        },
        "databaseProjectionContractDigest": c.digest(c.DATABASE_PROJECTION),
        "pricingLocation": "us-central1",
        "pricingCheckedAt": "2026-09-12",
    }
    permission["databaseProjectionDigest"] = c.digest(permission["databaseProjection"])
    c.approve(m, permission, "a" * 32, "b" * 64, 1000)
    for key, value in [
        ("manifestSha256", "x"),
        ("observerSha256", "x"),
        ("nonce", "x"),
        ("projectNumber", "0"),
        ("quotaProject", "foreign-project"),
        ("quotaProject", None),
        ("tariffsConfirmedBelowPlanningCeilings", 1),
        ("expiresAt", 1100),
        ("issuedAt", 1100),
        ("permissionReference", ""),
    ]:
        with pytest.raises(ValueError):
            c.approve(m, {**permission, key: value}, "a" * 32, "b" * 64, 1000)


def test_request_headers_bind_only_remote_privileged_quota():
    from batch_adapter import request_headers

    for local in (False, True):
        for token in (None, "offline-token"):
            for form in (False, True):
                headers = request_headers(token, local=local, form=form)
                assert headers.get("x-goog-user-project") == (
                    "fireemu-35fe6" if token and not local else None
                )
                assert headers.get("Authorization") == (
                    "Bearer offline-token" if token else None
                )
                assert headers["Content-Type"] == (
                "application/x-www-form-urlencoded" if form else "application/json"
                )


def test_empty_commit_acknowledgement_is_valid_but_nonempty_requires_results():
    import batch_adapter as a

    run = object.__new__(a.Adapter)
    run._record_document_writes(
        {
            "method": "POST",
            "path": "/v1/projects/demo/databases/(default)/documents:commit",
            "body": {"writes": []},
        },
        200,
        {},
    )

    with pytest.raises(ValueError, match="document commit acknowledgement incomplete"):
        run._record_document_writes(
            {
                "method": "POST",
                "path": "/v1/projects/demo/databases/(default)/documents:commit",
                "body": {
                    "writes": [
                        {"delete": "projects/demo/databases/(default)/documents/x"}
                    ]
                },
            },
            200,
            {},
        )
