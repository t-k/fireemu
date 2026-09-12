"""Offline boundaries of the broad local runner; no oracle calls."""

import pytest
from broad_contract import catalog, compare_program, local_origin


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
