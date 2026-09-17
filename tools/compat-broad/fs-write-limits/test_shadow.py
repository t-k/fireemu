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


def test_complete_count_cannot_substitute_for_state_validation(plan):
    receipt = {
        "productionExecuted": False,
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "completed": True,
        "rows": fixture_rows(plan),
        "resourceAbsence": {d["resource"]: True for d in plan["documents"].values()},
    }
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
