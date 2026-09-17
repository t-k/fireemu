from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from query_in_collector import collect_local
from query_in_compiler import compile_plan


def _ok(body: Any, status: int = 200) -> dict[str, Any]:
    return {"complete": True, "failure": None, "status": status, "body": body}


def _not_found() -> dict[str, Any]:
    return _ok({"error": {"code": 404, "status": "NOT_FOUND"}}, 404)


def _owned(plan: dict[str, Any], update_time: str = "2026-09-17T00:00:00.000000Z") -> dict[str, Any]:
    return _ok({
        "name": plan["document"],
        "fields": copy.deepcopy(plan["fixtureFields"]),
        "updateTime": update_time,
    })


def _transport(plan: dict[str, Any], *, mutate: bool = False):
    state = {"present": False, "updateTime": "2026-09-17T00:00:00.000000Z"}

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if mutate:
            operation["executorOnly"] = True
        kind = operation["kind"]
        if kind in {"preflight-typed-absence", "cleanup-verify-absence"}:
            return _not_found() if not state["present"] else _owned(plan, state["updateTime"])
        if kind == "create-only-patch":
            state["present"] = True
            return _owned(plan, state["updateTime"])
        if kind == "cleanup-ownership-read":
            return _owned(plan, state["updateTime"]) if state["present"] else _not_found()
        if kind == "cleanup-conditional-delete":
            assert "currentDocument.updateTime=" in operation["path"]
            state["present"] = False
            return _ok({})
        if kind in {"positive-query", "diagnostic-query"}:
            return _ok({"documents": [plan["expectedPositiveDocument"]]})
        return _owned(plan, state["updateTime"])

    return execute


def _plan() -> dict[str, Any]:
    return compile_plan("fireemu-test", "(default)", "0123456789abcdef0123456789abcdef")


def test_collects_six_observations_three_recovery_and_exclusive_rows(tmp_path: Path) -> None:
    plan = _plan()
    before = copy.deepcopy(plan)
    result = collect_local(plan, _transport(plan, mutate=True), tmp_path / "receipt")

    assert result["completed"] is True
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["productionExecuted"] is False
    assert len(result["rows"]) == 6
    assert len(result["cleanup"]) == 3
    assert "executorOnly" not in result["rows"][0]["request"]
    assert plan == before
    assert sorted(p.name for p in (tmp_path / "receipt").iterdir()) == [
        "collection.json",
        "observation-00.json",
        "observation-01.json",
        "observation-02.json",
        "observation-03.json",
        "observation-04.json",
        "observation-05.json",
        "recovery-00.json",
        "recovery-01.json",
        "recovery-02.json",
    ]
    assert json.loads((tmp_path / "receipt" / "observation-04.json").read_text())["index"] == 4


def test_complete_namespace_mismatch_stops_before_create_and_preserves_receipt(tmp_path: Path) -> None:
    plan = _plan()

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "preflight-typed-absence":
            return _ok({"error": {"code": 404, "status": "NOT_FOUND", "name": "other"}}, 404)
        raise AssertionError("unsafe operation dispatched")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert len(result["rows"]) == 1
    assert result["rows"][0]["complete"] is True
    assert result["cleanup"][1]["skipped"] == "unsafe-delete"
    assert result["completed"] is False
    assert result["semanticMismatches"][0]["reason"] == "preflight-typed-absence"


def test_non_json_404_is_semantic_mismatch_and_never_proves_absence(tmp_path: Path) -> None:
    plan = _plan()

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "preflight-typed-absence":
            return _ok("not-json", 404)
        raise AssertionError("unsafe operation dispatched")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["rows"][0]["body"] == "not-json"
    assert result["resourceAbsence"][plan["document"]] is False
    assert result["cleanup"][1]["skipped"] == "unsafe-delete"


def test_cleanup_uses_latest_update_time_and_refuses_foreign_namespace(tmp_path: Path) -> None:
    plan = _plan()
    seen: list[dict[str, Any]] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        seen.append(copy.deepcopy(operation))
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return _owned(plan, "2026-09-17T01:02:03.000000Z")
        if operation["kind"] == "cleanup-ownership-read":
            return _owned(plan, "2026-09-17T04:05:06.000000Z")
        if operation["kind"] == "cleanup-conditional-delete":
            assert "2026-09-17T04%3A05%3A06.000000Z" in operation["path"]
            return _ok({})
        if operation["kind"] == "cleanup-verify-absence":
            return _not_found()
        return _ok({"documents": []})

    result = collect_local(plan, execute, tmp_path / "receipt")
    delete = next(item for item in seen if item["kind"] == "cleanup-conditional-delete")
    assert "currentDocument.updateTime=" in delete["path"]
    assert result["cleanupComplete"] is True


def test_persistence_failure_after_create_keeps_recovery_responsibility(tmp_path: Path) -> None:
    plan = _plan()
    output = tmp_path / "receipt"
    output.mkdir()
    (output / "observation-01.json").write_text("occupied")

    result = collect_local(plan, _transport(plan), output)

    assert result["persistenceComplete"] is False
    assert result["attemptedResources"] == [plan["document"]]
    assert result["cleanup"][1]["request"]["kind"] == "cleanup-conditional-delete"
    assert result["cleanup"][1]["status"] == 200
    assert result["resourceAbsence"][plan["document"]] is True
    assert result["completed"] is False


def test_incomplete_executor_receipt_stops_observation_but_runs_safe_recovery(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[str] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        calls.append(operation["kind"])
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return {"complete": False, "failure": "transport-timeout"}
        if operation["kind"] == "cleanup-ownership-read":
            return _not_found()
        if operation["kind"] == "cleanup-verify-absence":
            return _not_found()
        raise AssertionError("delete must not be dispatched without owned read")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert calls[:2] == ["preflight-typed-absence", "create-only-patch"]
    assert result["rows"][1]["complete"] is False
    assert result["cleanup"][1]["skipped"] == "already-absent"
    assert result["infrastructureFailures"]
    assert result["completed"] is False


def test_oversized_receipt_is_bounded_but_owned_recovery_still_deletes(tmp_path: Path) -> None:
    plan = _plan()

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return _ok({"largeDiagnostic": "x" * 200_000})
        if operation["kind"] == "cleanup-ownership-read":
            return _owned(plan)
        if operation["kind"] == "cleanup-conditional-delete":
            return _ok({})
        if operation["kind"] == "cleanup-verify-absence":
            return _not_found()
        raise AssertionError("observation must stop after oversized mutation response")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["rows"][1]["failure"] == "receipt-too-large"
    assert len(json.dumps(result["rows"][1])) < 2_000
    assert result["cleanup"][1]["status"] == 200
    assert result["resourceAbsence"][plan["document"]] is True
    assert result["completed"] is False


def test_publication_failure_before_create_releases_no_unowned_delete(tmp_path: Path) -> None:
    plan = _plan()
    output = tmp_path / "receipt"
    output.mkdir()
    (output / "observation-00.json").write_text("occupied")
    calls: list[str] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        calls.append(operation["kind"])
        if operation["kind"] in {"preflight-typed-absence", "cleanup-ownership-read", "cleanup-verify-absence"}:
            return _not_found()
        raise AssertionError("create and delete require ownership evidence")

    result = collect_local(plan, execute, output)

    assert calls == [
        "preflight-typed-absence",
        "cleanup-ownership-read",
        "cleanup-verify-absence",
    ]
    assert result["cleanup"][1]["skipped"] == "already-absent"
    assert result["attemptedResources"] == []
    assert result["resourceAbsence"][plan["document"]] is True
    assert result["completed"] is False
    assert not list(output.glob(".receipt-*"))
