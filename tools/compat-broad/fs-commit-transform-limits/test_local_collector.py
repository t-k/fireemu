from __future__ import annotations

from local_collector import collect_local
from local_store_fixture import LocalTransformStore
from transform_compiler import compile_plan


def test_local_collector_preserves_500_success_and_501_refusal_then_cleans_mutated_document():
    plan = compile_plan("demo", "(default)", "a" * 32)
    store = LocalTransformStore()
    result = collect_local(plan, store.execute)

    assert result["productionExecuted"] is False
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["completed"] is True
    commits = [
        row for row in result["rows"] if row["request"]["kind"] == "commit-transform"
    ]
    assert [row["status"] for row in commits] == [200, 400]
    assert commits[1]["body"]["error"]["status"] == "INVALID_ARGUMENT"
    assert result["rows"][7]["body"]["fields"]["t499"] == {"integerValue": "1"}
    assert (
        result["rows"][9]["body"]["fields"] == plan["documents"]["over-501"]["fields"]
    )
    assert all(
        item["absent"]
        for item in result["cleanup"]
        if item["request"]["kind"] == "cleanup-verify-absence"
    )
    exact_cleanup = result["cleanup"][:3]
    assert exact_cleanup[1]["request"]["path"].endswith(
        "?currentDocument.updateTime="
        + exact_cleanup[0]["body"]["updateTime"].replace(":", "%3A")
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
        "cleanup-ownership-read",
        "cleanup-conditional-delete",
        "cleanup-verify-absence",
        "cleanup-ownership-read",
        "cleanup-conditional-delete",
        "cleanup-verify-absence",
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
    assert result["cleanupComplete"] is False
    assert result["resourceAbsence"][resource] is False
    assert (
        store.documents[resource]["fields"]["_sharedOwner"]["referenceValue"]
        == "foreign"
    )


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
            store.documents[resource]["fields"]["_sharedOwner"] = {
                "referenceValue": "foreign"
            }
            mutated = True
        return store.execute(operation)

    result = collect_local(plan, execute)
    assert result["completed"] is False
    resource = plan["documents"]["exact-500"]["resource"]
    assert not any(
        kind == "cleanup-conditional-delete" and item_resource == resource
        for kind, item_resource in calls
    )
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
    assert all(
        item["absent"] is False
        for item in result["cleanup"]
        if item["request"]["kind"] == "cleanup-verify-absence"
    )


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


def test_ambiguous_create_keeps_cleanup_responsibility():
    plan = compile_plan("demo", "(default)", "8" * 32)
    store = LocalTransformStore()

    def execute(operation):
        receipt = store.execute(operation)
        if operation["kind"] == "create-only-patch":
            return {"complete": False, "failure": "lost-response"}
        return receipt

    result = collect_local(plan, execute)
    assert result["recordingComplete"] is False
    assert store.documents == {}
    assert result["cleanupComplete"] is True
    assert all(result["resourceAbsence"].values())


def test_float_absence_cannot_authorize_mutations_or_cleanup_success():
    plan = compile_plan("demo", "(default)", "9" * 32)
    calls = []

    def execute(operation):
        calls.append(operation)
        return {
            "complete": True,
            "failure": None,
            "status": 404.0,
            "body": {"error": {"code": 404.0, "status": "NOT_FOUND"}},
        }

    result = collect_local(plan, execute)
    assert not any(operation["method"] != "GET" for operation in calls)
    assert result["cleanupComplete"] is False
    assert not any(result["resourceAbsence"].values())


def test_cleanup_failure_is_not_erased_by_later_absence():
    plan = compile_plan("demo", "(default)", "1" * 32)
    store = LocalTransformStore()

    def execute(operation):
        receipt = store.execute(operation)
        if operation["kind"] == "cleanup-conditional-delete":
            receipt["failure"] = "response-integrity-failure"
        return receipt

    result = collect_local(plan, execute)
    assert all(result["resourceAbsence"].values())
    assert result["cleanupComplete"] is False
    assert result["completed"] is False


def test_complete_unexpected_commit_statuses_remain_full_observations():
    plan = compile_plan("demo", "(default)", "2" * 32)
    store = LocalTransformStore()

    def execute(operation):
        if (
            operation["kind"] == "commit-transform"
            and operation["transformCount"] == 500
        ):
            return {
                "complete": True,
                "failure": None,
                "status": 400,
                "body": {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
            }
        return store.execute(operation)

    result = collect_local(plan, execute)
    assert len(result["rows"]) == 11
    assert result["recordingComplete"] is True
    assert result["rows"][6]["status"] == 400
    assert result["cleanupComplete"] is True
    assert store.documents == {}


def test_receipt_cannot_replace_compiled_request_or_index():
    plan = compile_plan("demo", "(default)", "3" * 32)
    store = LocalTransformStore()

    def execute(operation):
        return {**store.execute(operation), "request": {"path": "foreign"}, "index": 99}

    result = collect_local(plan, execute)
    assert result["rows"][0]["request"] == plan["observation"][0]
    assert result["rows"][0]["index"] == 0
    assert result["recordingComplete"] is False


def test_malformed_create_acknowledgement_is_recovered_and_preserved():
    plan = compile_plan("demo", "(default)", "4" * 32)
    store = LocalTransformStore()

    def execute(operation):
        receipt = store.execute(operation)
        if operation["kind"] == "create-only-patch":
            receipt["body"] = {"unexpected": True}
        return receipt

    result = collect_local(plan, execute)
    assert result["rows"][2]["body"] == {"unexpected": True}
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert store.documents == {}


def test_non_object_executor_receipt_still_reaches_bounded_recovery():
    plan = compile_plan("demo", "(default)", "5" * 32)
    store = LocalTransformStore()

    def execute(operation):
        receipt = store.execute(operation)
        if operation["kind"] == "create-only-patch":
            return None
        return receipt

    result = collect_local(plan, execute)
    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is True
    assert store.documents == {}


def test_non_calendar_cleanup_timestamp_does_not_authorize_delete():
    plan = compile_plan("demo", "(default)", "6" * 32)
    store = LocalTransformStore()
    deletes = []

    def execute(operation):
        if operation["kind"] == "cleanup-conditional-delete":
            deletes.append(operation)
        receipt = store.execute(operation)
        if operation["kind"] == "cleanup-ownership-read":
            receipt["body"]["updateTime"] = "2026-99-99T99:99:99Z"
        return receipt

    result = collect_local(plan, execute)
    assert result["cleanupComplete"] is False
    assert deletes == []
    assert len(store.documents) == 2


def test_error_code_float_is_not_typed_absence_with_integer_http_status():
    plan = compile_plan("demo", "(default)", "7" * 32)
    calls = []

    def execute(operation):
        calls.append(operation)
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404.0, "status": "NOT_FOUND"}},
        }

    result = collect_local(plan, execute)
    assert not any(operation["method"] != "GET" for operation in calls)
    assert result["cleanupComplete"] is False
    assert not any(result["resourceAbsence"].values())
