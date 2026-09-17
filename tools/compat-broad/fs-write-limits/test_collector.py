"""Deterministic collector safety decisions, separate from real artifact evidence."""

from collector import writes_safe
from compiler import compile_limits_plan


def test_empty_and_unproven_preflight_cannot_authorize_writes():
    plan = compile_limits_plan("demo-test", "(default)", "a" * 32)
    assert writes_safe([], plan) is False
    rows = [
        {
            "index": i,
            "status": 404,
            "complete": True,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
            "request": plan["localGatePlan"]["jobs"]["limits"]["observation"][i],
        }
        for i in range(4)
    ]
    assert writes_safe(rows, plan) is True
    rows[2]["body"]["error"]["status"] = "INVALID_ARGUMENT"
    assert writes_safe(rows, plan) is False


def test_unexpected_negative_success_does_not_mean_collection_failure():
    plan = compile_limits_plan("demo-test", "(default)", "b" * 32)
    rows = []
    for index, operation in enumerate(
        plan["localGatePlan"]["jobs"]["limits"]["observation"]
    ):
        resource = operation["path"].split("?")[0].removeprefix("/v1/")
        doc = next(d for d in plan["documents"].values() if d["resource"] == resource)
        body = (
            {"error": {"code": 404, "status": "NOT_FOUND"}}
            if index < 4
            else {
                "name": resource,
                "fields": doc["fields"],
                "updateTime": "2026-09-17T00:00:00Z",
            }
        )
        rows.append(
            {
                "index": index,
                "request": operation,
                "complete": True,
                "status": 404 if index < 4 else 200,
                "body": body,
            }
        )
    assert writes_safe(rows, plan) is True
    rows[10]["body"] = {**rows[10]["body"], "updateTime": "2026-09-17T00:00:01Z"}
    assert writes_safe(rows, plan) is False


def test_failed_recovery_admission_sends_nothing_and_retains_incomplete_journal(
    tmp_path,
):
    from collector import collect
    from shared_gate import Gate, create

    plan = compile_limits_plan("demo-test", "(default)", "c" * 32)
    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    attempts = []

    def interrupted_wire(operation, recovery, index, request_index):
        attempts.append((recovery, index))
        raise TimeoutError("injected transport interruption before a response")

    def denied_recovery():
        raise ValueError("injected recovery admission failure")

    output = tmp_path / "collection"
    result = collect(
        gate, plan, output, interrupted_wire, before_recovery=denied_recovery
    )
    assert attempts == [(False, 0)]
    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is False
    assert result["collectionComplete"] is False
    assert result["cleanup"] == []
    assert {failure["phase"] for failure in result["infrastructureFailures"]} >= {
        "observation",
        "recovery-admission",
        "finish",
    }
    assert gate.snapshot()["jobs"]["limits"]["complete"] is False
    original = (output / "collection.json").read_bytes()
    import pytest

    with pytest.raises(FileExistsError):
        collect(gate, plan, output, interrupted_wire)
    assert (output / "collection.json").read_bytes() == original
    assert attempts == [(False, 0)]
