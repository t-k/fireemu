import copy

from query_in_comparator import compare_evidence
from query_in_compiler import compile_plan


def _bundle(project: str = "demo", nonce: str = "a" * 32) -> dict:
    plan = compile_plan(project, "(default)", nonce)
    rows = []
    for index, operation in enumerate(plan["observation"]):
        if operation["kind"] in {"preflight-typed-absence"}:
            status, body = 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        elif operation["kind"] in {"create-only-patch", "before-readback", "after-readback"}:
            status, body = 200, {"name": plan["document"], "fields": plan["fixtureFields"], "updateTime": "2026-09-18T00:00:00Z"}
        elif operation["kind"] == "positive-query":
            status, body = 200, {"documents": [plan["expectedPositiveDocument"]]}
        else:
            status, body = 400, {"error": {"status": "INVALID_ARGUMENT"}}
        rows.append(
            {
                "index": index,
                "request": copy.deepcopy(operation),
                "complete": True,
                "failure": None,
                "status": status,
                "body": body,
                "rawSha256": f"{index:064x}",
            }
        )
    cleanup = []
    for index, operation in enumerate(plan["recovery"]):
        cleanup.append(
            {
                "index": index,
                "request": copy.deepcopy(operation),
                "complete": True,
                "failure": None,
                "status": 404 if index != 1 else None,
                "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
                "rawSha256": f"{index + 6:064x}",
                **({"skipped": "already-absent"} if index == 1 else {}),
            }
        )
    return {
        "plan": plan,
        "rows": rows,
        "cleanup": cleanup,
        "ownership": {"created": False, "cleanupComplete": True},
        "raw": {str(index): {"projectionVersion": 1, "sourceRawSha256": f"{index:064x}"} for index in range(9)},
    }


def test_identical_complete_journals_match_without_acquisition_authority():
    left = _bundle()
    right = copy.deepcopy(left)
    result = compare_evidence(left, right)
    assert result["classification"] == "MATCH"
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False


def test_plan_or_operation_drift_is_indeterminate():
    left = _bundle()
    right = _bundle("other")
    right["rows"][2]["request"]["body"]["structuredQuery"]["limit"] = 2
    result = compare_evidence(left, right)
    assert result["classification"] == "INDETERMINATE"
    assert result["errors"]


def test_complete_typed_response_difference_is_semantic_mismatch():
    left = _bundle()
    right = copy.deepcopy(left)
    left["rows"][2]["status"] = 200
    left["rows"][2]["body"] = {"documents": [{"name": left["plan"]["document"], "fields": left["plan"]["fixtureFields"]}]}
    right["rows"][2]["status"] = 200
    right["rows"][2]["body"] = {"documents": []}
    result = compare_evidence(left, right)
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_incomplete_receipt_and_unsafe_cleanup_are_indeterminate():
    left = _bundle()
    right = copy.deepcopy(left)
    right["rows"][0]["complete"] = False
    right["cleanup"][0]["ownership"] = False
    result = compare_evidence(left, right)
    assert result["classification"] == "INDETERMINATE"
