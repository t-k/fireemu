"""Pure receipt fixtures: no simulated production observations or network calls."""

from __future__ import annotations

import copy

import pytest
from compiler import compile_limits_plan
from shadow import evaluate_rows, resolve_recovery, save, validate_local_receipt


@pytest.fixture(scope="module")
def plan():
    return compile_limits_plan("demo-firestore-probe", "(default)", "a" * 32)


def fixture_rows(plan):
    documents = {d["resource"]: d for d in plan["documents"].values()}
    rows = []
    for index, request in enumerate(plan["requests"][:16]):
        resource = request["path"].split("?", 1)[0].removeprefix("/v1/")
        positive = resource.endswith(("/exact", "/nested-exact"))
        if request["kind"] == "preflight-typed-absence" or (
            not positive and request["method"] == "GET"
        ):
            status, body = 404, {"error": {"status": "NOT_FOUND", "code": 404}}
        elif not positive:
            status, body = 400, {"error": {"status": "INVALID_ARGUMENT", "code": 400}}
        else:
            status, body = (
                200,
                {
                    "name": resource,
                    "fields": documents[resource]["fields"],
                    "updateTime": "2026-09-17T00:00:00Z",
                },
            )
        rows.append(
            {
                "index": index,
                "request": plan["localGatePlan"]["jobs"]["limits"]["observation"][
                    index
                ],
                "status": status,
                "body": body,
                "complete": True,
                "failure": None,
            }
        )
    return rows


def test_exact_receipts_validate_typed_values_and_versions(plan):
    assert evaluate_rows(fixture_rows(plan), plan) == []


@pytest.mark.parametrize(
    "index,mutation",
    [
        (0, "untyped"),
        (4, "fields"),
        (5, "version"),
        (8, "accepted"),
        (9, "untyped"),
        (10, "fields"),
        (11, "version"),
    ],
)
def test_state_corruption_is_rejected(plan, index, mutation):
    rows = copy.deepcopy(fixture_rows(plan))
    row = rows[index]
    if mutation == "untyped":
        row["body"] = {"message": "missing"}
    elif mutation == "fields":
        row["body"]["fields"] = {}
    elif mutation == "version":
        row["body"]["updateTime"] = "2026-09-18T00:00:00Z"
    else:
        row["status"], row["body"] = 200, {}
    assert evaluate_rows(rows, plan)


def test_incomplete_wire_receipt_is_not_a_semantic_observation(plan):
    rows = fixture_rows(plan)
    rows[8].update(complete=False, failure="response-byte-limit", status=None)
    assert evaluate_rows(rows, plan) == []


def test_recovery_version_is_resolved_from_exact_capture(plan):
    operation = plan["localGatePlan"]["jobs"]["limits"]["recovery"][1]
    version = "2026-09-17T00:00:00Z"
    resolved = resolve_recovery(
        operation, [{"status": 200, "body": {"updateTime": version}}]
    )
    assert resolved["path"].endswith(
        "?currentDocument.updateTime=2026-09-17T00%3A00%3A00Z"
    )
    assert "versionFrom" not in resolved
    assert resolve_recovery(operation, [{"status": 404}])["path"] == operation["path"]


def test_output_history_cannot_be_replaced(tmp_path):
    output = tmp_path / "receipt.json"
    save(output, {"first": True})
    with pytest.raises(FileExistsError):
        save(output, {"second": True})
    assert '"first"' in output.read_text()


def fixture_receipt(plan):
    from broad_contract import digest

    receipt = {
        "productionExecuted": False,
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "completed": True,
        "rows": fixture_rows(plan),
        "resourceAbsence": {d["resource"]: True for d in plan["documents"].values()},
    }
    cleanup = []
    proofs = {}
    for row in receipt["rows"]:
        if row["request"]["method"] == "PATCH" and row["status"] == 200:
            body = row["body"]
            proofs[body["name"]] = {
                "name": body["name"],
                "updateTime": body["updateTime"],
                "fieldsDigest": digest(body["fields"]),
                "requestDigest": digest(row["request"]),
                "responseDigest": digest(body),
            }
    gate_plan = plan["localGatePlan"]
    recovery = gate_plan["jobs"]["limits"]["recovery"]
    for index, declared in enumerate(recovery):
        operation = resolve_recovery(declared, cleanup)
        resource = declared["path"].removeprefix("/v1/")
        row = {"index": index, "request": operation, "complete": True, "failure": None}
        if index % 3 == 0 and resource in proofs:
            doc = next(
                d for d in plan["documents"].values() if d["resource"] == resource
            )
            row.update(
                status=200,
                body={
                    "name": resource,
                    "fields": doc["fields"],
                    "updateTime": proofs[resource]["updateTime"],
                },
            )
        elif index % 3 == 1:
            if resource in proofs:
                row.update(status=200, body={})
            else:
                row.update(
                    status=None,
                    body={"skipped": "absent-or-unavailable-cleanup-read"},
                    skipped=True,
                )
        else:
            row.update(status=404, body={"error": {"code": 404, "status": "NOT_FOUND"}})
        cleanup.append(row)
    resources = gate_plan["jobs"]["limits"]["resources"]
    receipt["cleanup"] = cleanup
    receipt["gate"] = {
        "plan": gate_plan,
        "planDigest": digest(gate_plan),
        "jobs": {
            "limits": {
                "complete": True,
                "inflight": False,
                "observation": 16,
                "recovery": 12,
                "resources": resources,
                "absent": list(resources),
                "creationProofs": proofs,
            }
        },
    }
    return receipt


def test_complete_count_cannot_substitute_for_state_validation(plan):
    receipt = fixture_receipt(plan)
    assert validate_local_receipt(receipt, plan)
    receipt["rows"][10]["body"] = {}
    assert not validate_local_receipt(receipt, plan)


def test_child_cli_does_not_require_output(tmp_path):
    import subprocess
    import sys

    import shadow

    result = subprocess.run(
        [sys.executable, str(shadow.HERE / "shadow.py"), "--child", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "--nonce is required with --child" in result.stderr
    assert "--output is required" not in result.stderr


def test_source_binding_contains_actual_checkout_inputs():
    import shadow

    inputs = shadow.source_inputs()
    assert "tools/compat-broad/fs-write-limits/shadow.py" in inputs
    assert "tools/compat-broad/fs-write-limits/compiler.py" in inputs
    assert "tools/compat-broad/fs-write-limits/test_shadow.py" in inputs
    assert all(len(value) == 64 for value in inputs.values())


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "short",
        "reorder",
        "path",
        "skip",
        "absence",
        "read-version",
        "gate-complete",
        "gate-absence",
        "gate-proof",
        "gate-plan",
    ],
)
def test_incomplete_or_altered_cleanup_is_rejected(plan, mutation):
    receipt = copy.deepcopy(fixture_receipt(plan))
    if mutation == "missing":
        del receipt["cleanup"]
    elif mutation == "short":
        receipt["cleanup"].pop()
    elif mutation == "reorder":
        receipt["cleanup"][0], receipt["cleanup"][2] = (
            receipt["cleanup"][2],
            receipt["cleanup"][0],
        )
    elif mutation == "path":
        receipt["cleanup"][1]["request"]["path"] = receipt["cleanup"][0]["request"][
            "path"
        ]
    elif mutation == "skip":
        receipt["cleanup"][4].update(status=200, body={}, skipped=False)
    elif mutation == "absence":
        receipt["cleanup"][2]["body"] = {}
    elif mutation == "read-version":
        receipt["cleanup"][0]["body"]["updateTime"] = "2026-09-18T00:00:00Z"
    elif mutation == "gate-complete":
        receipt["gate"]["jobs"]["limits"]["complete"] = False
    elif mutation == "gate-absence":
        receipt["gate"]["jobs"]["limits"]["absent"].pop()
    elif mutation == "gate-proof":
        receipt["gate"]["jobs"]["limits"]["creationProofs"] = {}
    else:
        receipt["gate"]["planDigest"] = "0" * 64
    assert not validate_local_receipt(receipt, plan)


def test_catalog_bytes_are_bound_across_temporary_checkout(tmp_path):
    import json
    import shutil
    import subprocess
    import sys

    import shadow

    catalog = "spec/limits/firestore-standard-2026-08-25.json"
    for relative in [
        "tools/compat-broad/fs-write-limits/shadow.py",
        "tools/compat-broad/fs-write-limits/compiler.py",
        "tools/compat-broad/broad_contract.py",
        catalog,
    ]:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(shadow.ROOT / relative, destination)
    command = [
        sys.executable,
        "-c",
        "import json, shadow; print(json.dumps(shadow.source_inputs()))",
    ]
    directory = tmp_path / "tools/compat-broad/fs-write-limits"
    before = json.loads(subprocess.check_output(command, cwd=directory))
    (tmp_path / catalog).write_bytes((tmp_path / catalog).read_bytes() + b" ")
    after = json.loads(subprocess.check_output(command, cwd=directory))
    assert catalog in before
    assert before[catalog] != after[catalog]
    assert all(before[key] == after[key] for key in before if key != catalog)
    assert not before == after == before  # Parent/child/post-run binding rejects drift.
