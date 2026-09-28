"""Offline boundaries of the broad local runner; no oracle calls."""

import pytest
from broad_contract import catalog, compare_program, local_origin
from broad import (
    HISTORICAL_INDEX_SHA256,
    INDEX_NX_LOCAL_SHA256,
    index_bytes_for_profile,
)


def program():
    return {
        "id": "a",
        "steps": [{"id": "create", "body": {"value": 1}}, {"id": "read"}],
    }


def test_comparison_preserves_types_missing_fields_and_order():
    p = program()
    historical = {
        "create": {
            "production": {
                "status": 200,
                "code": "OK",
                "body": {"x": 1, "list": [1, 2]},
            }
        },
        "read": {"production": {"status": 400, "code": "DENIED"}},
    }
    actual: dict = {
        "steps": {
            "create": {
                "status": 200,
                "code": "OK",
                "body": {"x": True, "list": [2, 1]},
            },
            "read": {"status": 400, "code": "DENIED"},
        }
    }
    result = compare_program(p, p, actual, historical)
    assert [r["status"] for r in result] == ["mismatch", "match"]
    assert result[0]["firstDifference"] == "$.body.list[0]"
    changed = {
        "steps": {
            "create": {
                "status": 200,
                "code": "OK",
                "body": {"x": 1, "list": [1, 2], "extra": None},
            }
        }
    }
    assert compare_program(p, p, changed, historical)[0]["status"] == "mismatch"


def test_same_id_changed_operation_is_not_compared():
    p = program()
    old = {**p, "steps": [{"id": "create", "body": {"value": 2}}, {"id": "read"}]}
    assert all(
        r["status"] == "indeterminate"
        for r in compare_program(p, old, {"steps": {}}, {})
    )


def test_missing_timeout_and_unobserved_rows_never_pass():
    p = program()
    rows = compare_program(
        p, p, {"steps": {"create": {"status": 0, "code": "probe-error"}}}, {}
    )
    assert all(r["status"] in {"not-run", "indeterminate"} for r in rows)


@pytest.mark.parametrize(
    "value",
    [
        "https://firestore.googleapis.com",
        "http://example.com",
        "http://127.0.0.1@evil.test",
        "http://127.0.0.1:1/path",
        "http://127.0.0.1:1?x=1",
        "http://localhost:80",
    ],
)
def test_remote_or_ambiguous_origins_are_refused(value):
    with pytest.raises(ValueError):
        local_origin(value)


def test_os_assigned_loopback_origin_is_accepted():
    assert local_origin("http://127.0.0.1:12345") == "http://127.0.0.1:12345"


def test_historical_index_profile_is_unchanged():
    value, sha256, source_commit = index_bytes_for_profile("historical")
    assert sha256 == HISTORICAL_INDEX_SHA256
    assert source_commit == "2526c61eda5fc53ac91250307786127ae3c601be"
    assert value.endswith(b"\n")


def test_nx_local_index_profile_is_closed_and_exact():
    value, sha256, source_commit = index_bytes_for_profile("nx-local")
    assert sha256 == INDEX_NX_LOCAL_SHA256
    assert source_commit is None
    assert value.count(b'"collectionGroup": "nx"') == 1
    with pytest.raises(ValueError, match="unknown local index profile"):
        index_bytes_for_profile("arbitrary")


def test_inventory_retains_unexecuted_editions_and_protocols():
    value = catalog()
    assert len(value["surfaces"]) >= 169
    ids = {f["id"] for f in value["families"]}
    assert {
        "auth-tenants",
        "auth-mfa",
        "fs-listen",
        "fs-enterprise",
        "fs-sdk",
        "fs-rules",
    } <= ids
    assert all(f["currentStatus"] == "not-run" for f in value["families"])
    assert all(s["currentStatus"] == "not-run" for s in value["surfaces"])


def test_boolean_request_change_is_not_equal_to_number():
    old = {"id": "p", "steps": [{"id": "write", "body": {"value": 1}}]}
    current = {"id": "p", "steps": [{"id": "write", "body": {"value": True}}]}
    row = {"status": 200, "code": "OK", "body": {}}
    result = compare_program(
        current, old, {"steps": {"write": row}}, {"write": {"production": row}}
    )
    assert result[0]["status"] == "indeterminate"


def test_seeded_read_must_return_the_same_document():
    from broad_cases import check_generated, generated_programs

    p = generated_programs()[0]
    got = {
        "steps": {
            "read-normal": {
                "status": 200,
                "code": "OK",
                "body": {
                    "name": "projects/other/databases/(default)/documents/foreign/doc",
                    "fields": p["seed"][0]["fields"],
                },
            }
        }
    }
    assert check_generated(p, got)[0]["status"] == "fail"


def test_registration_failure_cannot_skip_parent_termination(tmp_path):
    import subprocess

    import broad

    (tmp_path / "auth-process.json").write_text("invalid-json")
    parent = subprocess.Popen(["sleep", "60"])
    try:
        report = {"status": "completed"}
        broad.cleanup_run(parent, tmp_path, "nonce", report)
        assert parent.poll() is not None
        assert report["status"] == "incomplete"
        assert (tmp_path / "manifest.json").exists()
    finally:
        if parent.poll() is None:
            parent.terminate()
            parent.wait(timeout=5)


def test_one_bad_registration_does_not_skip_other_owned_children(tmp_path):
    import json
    import subprocess

    import broad

    (tmp_path / "a-process.json").write_text("invalid-json")
    child = subprocess.Popen(["sleep", "60"])
    (tmp_path / "b-process.json").write_text(
        json.dumps({"pid": child.pid, "argv": ["sleep", "60"]})
    )
    try:
        with pytest.raises(ValueError):
            broad.stop_registered(tmp_path, 100, "nonce")
        child.wait(timeout=3)
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)


def test_node_guard_finite_host_and_budget_boundaries(tmp_path):
    import os
    import subprocess
    from pathlib import Path

    guard = (Path(__file__).parent / "local-guard.mjs").resolve().as_uri()
    code = """
import { authorizeRequest } from "GUARD";
let tested = 0;
for (const host of ["127.0.0.1:12345", "127.0.0.1:12346", "example.com:12345"])
for (const scheme of ["http", "https"])
for (const user of ["", "owner:password@"])
for (const requests of [1500, 1501])
for (const elapsed of [115000, 115001]) {
  const expected = host === "127.0.0.1:12345" && scheme === "http" && user === "" && requests === 1500 && elapsed === 115000;
  let accepted = true;
  try { authorizeRequest(`${scheme}://${user}${host}/v1/test`, "http://127.0.0.1:12345", requests, elapsed); }
  catch { accepted = false; }
  if (accepted !== expected) throw new Error("guard mismatch");
  tested++;
}
if (tested !== 48) throw new Error("model size mismatch");
""".replace("GUARD", guard)
    environment = {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ}
    environment.update(
        BROAD_ORIGIN="http://127.0.0.1:12345", BROAD_STATS=str(tmp_path / "stats.json")
    )
    subprocess.run(
        ["node", "--input-type=module"],
        input=code,
        text=True,
        env=environment,
        check=True,
        timeout=10,
        capture_output=True,
    )


def test_missing_entire_program_remains_not_run():
    p = program()
    rows = compare_program(p, p, {}, {})
    assert all(row["status"] == "not-run" for row in rows)


def test_registration_write_failure_stops_the_real_node_child(tmp_path):
    import os
    import signal
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    import broad

    release = threading.Event()

    class PendingResponse(BaseHTTPRequestHandler):
        def do_POST(self):
            release.wait(5)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), PendingResponse)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    (tmp_path / "auth-process.json").mkdir()
    command_suffix = str(broad.ROOT / "conformance/src/auth-probe/session.mjs")

    def children():
        listing = subprocess.check_output(["ps", "-axo", "pid=,ppid=,args="], text=True)
        found = []
        for line in listing.splitlines():
            fields = line.strip().split(maxsplit=2)
            if (
                len(fields) == 3
                and fields[1] == str(os.getpid())
                and fields[2].endswith(command_suffix)
            ):
                found.append(int(fields[0]))
        return found

    try:
        with pytest.raises(IsADirectoryError):
            broad.session(
                "auth",
                [
                    {
                        "id": "hold",
                        "steps": [
                            {"id": "hold", "path": "v1/accounts:lookup", "body": {}}
                        ],
                    }
                ],
                f"http://127.0.0.1:{server.server_port}",
                tmp_path,
            )
        assert children() == []
    finally:
        for pid in children():
            try:
                os.kill(pid, signal.SIGTERM)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
        release.set()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


def test_real_redirect_and_failed_reset_are_blocked(tmp_path):
    import os
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path

    hits = {"source": 0, "sink": 0}

    class Sink(BaseHTTPRequestHandler):
        def do_GET(self):
            hits["sink"] += 1
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)

    class Source(BaseHTTPRequestHandler):
        def do_GET(self):
            hits["source"] += 1
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/sink")
            self.end_headers()

        def do_DELETE(self):
            hits["source"] += 1
            self.send_response(500)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), Source)
    threads = [
        threading.Thread(target=s.serve_forever, daemon=True) for s in (source, sink)
    ]
    for thread in threads:
        thread.start()
    try:
        origin = f"http://127.0.0.1:{source.server_port}"
        environment = {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ}
        environment.update(
            BROAD_ORIGIN=origin, BROAD_STATS=str(tmp_path / "stats.json")
        )
        code = """
for (const [path, method] of [["/redirect", "GET"], ["/emulator/reset", "DELETE"]]) {
  let failed = false;
  try { await fetch(process.env.BROAD_ORIGIN + path, {method}); } catch { failed = true; }
  if (!failed) process.exit(2);
}
"""
        subprocess.run(
            [
                "node",
                "--import",
                str((Path(__file__).parent / "local-guard.mjs").resolve()),
                "--input-type=module",
            ],
            input=code,
            text=True,
            env=environment,
            check=True,
            timeout=10,
            capture_output=True,
        )
        assert hits == {"source": 2, "sink": 0}
    finally:
        for server in (source, sink):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_expanded_selection_keeps_legacy_and_current_transforms_separate():
    import broad_contract as contract

    assert hasattr(contract, "replay_selection"), (
        "explicit historical replay selection required"
    )
    current, legacy = contract.replay_selection()
    by_id = {p["id"]: p for p in current}
    assert {
        "values/type-order",
        "values/numeric-ties",
        "queries/filters",
        "queries/aggregations",
    } <= by_id.keys()
    old, _, _ = contract.historical("firestore")
    original = next(p for p in old if p["id"] == "writes/transforms")
    assert legacy == [original]
    assert contract.digest(by_id[original["id"]]) != contract.digest(original)
    assert len(original["steps"]) == 18
    assert contract.family_for("firestore", "queries/aggregations") == "fs-aggregations"


def test_recorded_update_scope_does_not_claim_current_or_enterprise_execution():
    families = {f["id"]: f for f in catalog()["families"]}
    scope = families["auth-accounts"]["recordedCoverage"]
    assert scope["original"] != scope["repaired"]
    assert scope["remaining"]
    assert families["auth-accounts"]["currentStatus"] == "not-run"
    enterprise = families["fs-enterprise"]["implementationUnits"]
    assert any(
        u["unit"] == "read-only Pipeline execution" and u["status"] == "not-implemented"
        for u in enterprise
    )


def test_bounded_firestore_selection_accepts_only_read_time():
    import broad as runner

    selected = runner.bounded_firestore_program("reads/read-time")
    assert [program["id"] for program in selected] == ["reads/read-time"]


@pytest.mark.parametrize("program_id", ["queries/filters", "writes/transforms", ""])
def test_bounded_firestore_selection_rejects_other_programs(program_id):
    import broad as runner

    with pytest.raises(ValueError, match="reads/read-time"):
        runner.bounded_firestore_program(program_id)


def test_retained_artifact_preserves_exact_bytes_and_refuses_replacement(tmp_path):
    import hashlib

    from broad import retain_artifact

    source, destination = tmp_path / "source", tmp_path / "retained"
    source.write_bytes(b"first-build")
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    retain_artifact(source, destination, expected)
    source.write_bytes(b"relinked-build")
    assert destination.read_bytes() == b"first-build"
    with pytest.raises(FileExistsError):
        retain_artifact(source, destination, expected)
    with pytest.raises(ValueError):
        retain_artifact(source, tmp_path / "wrong", expected)
    assert destination.read_bytes() == b"first-build"


def temporary_checkout(path):
    """Build a committed git repository so checkout state is the only variable."""
    import os
    import subprocess

    # Isolate from the developer's git configuration: this repository is only a
    # fixture, and inherited identity, hooks or signing settings would make the
    # test depend on the machine rather than on the checkout state.
    environment = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_NAME": "broad",
        "GIT_AUTHOR_EMAIL": "broad@example.invalid",
        "GIT_COMMITTER_NAME": "broad",
        "GIT_COMMITTER_EMAIL": "broad@example.invalid",
    }

    def git(*arguments):
        subprocess.run(
            ["git", *arguments],
            cwd=path,
            env=environment,
            check=True,
            capture_output=True,
        )

    path.mkdir(parents=True, exist_ok=True)
    git("init", "--quiet")
    (path / "tracked.txt").write_text("committed\n")
    git("add", "tracked.txt")
    git("commit", "--quiet", "-m", "initial")
    return path


def test_frozen_checkout_accepts_a_committed_tree(tmp_path, monkeypatch):
    import broad as runner

    monkeypatch.setattr(runner, "ROOT", temporary_checkout(tmp_path / "clean"))
    assert runner.require_frozen_checkout() is None


def test_dirty_checkout_names_its_cause_and_offending_paths(tmp_path, monkeypatch):
    import broad as runner

    checkout = temporary_checkout(tmp_path / "dirty")
    (checkout / "tracked.txt").write_text("edited\n")
    (checkout / "untracked.txt").write_text("new\n")
    monkeypatch.setattr(runner, "ROOT", checkout)
    with pytest.raises(runner.DirtyCheckoutError) as raised:
        runner.require_frozen_checkout()
    message = str(raised.value)
    assert "working tree is dirty" in message
    assert "commit or discard changes before running artifact-backed tests" in message
    assert "2 uncommitted path(s)" in message
    # The modified path is listed first and its status columns are stripped
    # without eating the path itself.
    assert message.endswith("(2 uncommitted path(s): tracked.txt, untracked.txt)")
    assert "more" not in message


def test_dirty_checkout_lists_at_most_ten_paths(tmp_path, monkeypatch):
    import broad as runner

    checkout = temporary_checkout(tmp_path / "many")
    for index in range(14):
        (checkout / f"extra-{index:02d}.txt").write_text("new\n")
    monkeypatch.setattr(runner, "ROOT", checkout)
    with pytest.raises(runner.DirtyCheckoutError) as raised:
        runner.require_frozen_checkout()
    message = str(raised.value)
    assert "14 uncommitted path(s)" in message
    assert message.count("extra-") == runner.DIRTY_CHECKOUT_PATH_LIMIT
    assert "and 4 more" in message


def test_artifact_run_refuses_a_dirty_checkout_before_building(tmp_path, monkeypatch):
    import broad as runner

    checkout = temporary_checkout(tmp_path / "run")
    (checkout / "untracked.txt").write_text("new\n")
    monkeypatch.setattr(runner, "ROOT", checkout)

    def unexpected_build():
        raise AssertionError("a dirty checkout must be refused before the build")

    monkeypatch.setattr(runner, "build_artifact", unexpected_build)
    with pytest.raises(runner.DirtyCheckoutError):
        runner.run(tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_dirty_checkout_error_remains_a_value_error(tmp_path, monkeypatch):
    """Existing callers catch ValueError; the dedicated type stays compatible."""
    import broad as runner

    checkout = temporary_checkout(tmp_path / "compat")
    (checkout / "untracked.txt").write_text("new\n")
    monkeypatch.setattr(runner, "ROOT", checkout)
    with pytest.raises(ValueError):
        runner.require_frozen_checkout()
