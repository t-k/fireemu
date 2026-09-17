from __future__ import annotations

import copy

from local_collector import LocalTransformStore, collect_local
from transform_compiler import compile_plan


def test_local_collector_preserves_500_success_and_501_refusal_then_cleans_mutated_document():
    plan = compile_plan("demo", "(default)", "a" * 32)
    store = LocalTransformStore()
    result = collect_local(plan, store.execute)

    assert result["productionExecuted"] is False
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["completed"] is True
    commits = [row for row in result["rows"] if row["request"]["kind"] == "commit-transform"]
    assert [row["status"] for row in commits] == [200, 400]
    assert commits[1]["body"]["error"]["status"] == "INVALID_ARGUMENT"
    assert result["rows"][7]["body"]["fields"]["t499"] == {"integerValue": "1"}
    assert result["rows"][9]["body"]["fields"] == plan["documents"]["over-501"]["fields"]
    assert all(item["absent"] for item in result["cleanup"] if item["request"]["kind"] == "cleanup-verify-absence")
    exact_cleanup = result["cleanup"][:3]
    assert exact_cleanup[1]["request"]["path"].endswith(
        "?currentDocument.updateTime=" + exact_cleanup[0]["body"]["updateTime"].replace(":", "%3A")
    )
    assert store.documents == {}


def test_incomplete_commit_stops_observation_but_recovers_only_owned_created_documents():
    plan = compile_plan("demo", "(default)", "b" * 32)
    store = LocalTransformStore(fail_kind="commit-transform")
    result = collect_local(plan, store.execute)

    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is True
    assert result["completed"] is False
    assert len(result["rows"]) == 7
    assert [item["request"]["kind"] for item in result["cleanup"]] == [
        "cleanup-ownership-read", "cleanup-conditional-delete", "cleanup-verify-absence",
        "cleanup-ownership-read", "cleanup-conditional-delete", "cleanup-verify-absence",
    ]
    assert store.documents == {}


def test_cleanup_refuses_marker_mismatch_without_deleting_foreign_document():
    plan = compile_plan("demo", "(default)", "c" * 32)
    store = LocalTransformStore()
    resource = plan["documents"]["exact-500"]["resource"]
    store.documents[resource] = {
        "name": resource,
        "fields": {"_sharedOwner": {"referenceValue": "foreign"}},
        "updateTime": "2026-01-01T00:00:00Z",
    }
    result = collect_local(plan, store.execute)

    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is True
    assert store.documents[resource]["fields"]["_sharedOwner"]["referenceValue"] == "foreign"


def test_cleanup_keeps_mutated_foreign_marker_and_never_sends_conditional_delete():
    plan = compile_plan("demo", "(default)", "e" * 32)
    store = LocalTransformStore()
    calls = []
    mutated = False

    def execute(operation):
        nonlocal mutated
        calls.append((operation["kind"], operation.get("resource")))
        if operation["kind"] == "cleanup-ownership-read" and not mutated:
            resource = plan["documents"]["exact-500"]["resource"]
            store.documents[resource]["fields"]["_sharedOwner"] = {"referenceValue": "foreign"}
            mutated = True
        return store.execute(operation)

    result = collect_local(plan, execute)
    assert result["completed"] is False
    resource = plan["documents"]["exact-500"]["resource"]
    assert not any(kind == "cleanup-conditional-delete" and item_resource == resource for kind, item_resource in calls)
    assert resource in store.documents


def test_cleanup_requires_completed_typed_not_found_receipt():
    plan = compile_plan("demo", "(default)", "f" * 32)
    store = LocalTransformStore()

    def execute(operation):
        receipt = store.execute(operation)
        if operation["kind"] == "cleanup-verify-absence":
            receipt["body"] = {"error": {"code": 404, "status": "UNKNOWN"}}
        return receipt

    result = collect_local(plan, execute)
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is False
    assert result["completed"] is False
    assert all(item["absent"] is False for item in result["cleanup"] if item["request"]["kind"] == "cleanup-verify-absence")


def test_executor_exception_becomes_bounded_failure_and_still_cleans_up():
    plan = compile_plan("demo", "(default)", "7" * 32)
    store = LocalTransformStore()

    def execute(operation):
        if operation["kind"] == "commit-transform":
            raise RuntimeError("unbounded implementation detail")
        return store.execute(operation)

    result = collect_local(plan, execute)
    failed = result["rows"][-1]
    assert failed["complete"] is False
    assert failed["failure"] == "local-executor:RuntimeError"
    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is True
    assert store.documents == {}
