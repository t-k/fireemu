import copy

from query_in_comparator import compare_evidence
from query_in_compiler import compile_plan


def _bundle(project: str = "demo", nonce: str = "a" * 32) -> dict:
    plan = compile_plan(project, "(default)", nonce)
    rows = []
    for index, operation in enumerate(plan["observation"]):
        rows.append(
            {
                "index": index,
                "request": copy.deepcopy(operation),
                "complete": True,
                "failure": None,
                "status": operation["expect"]["status"],
                "body": {},
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
                **({"skipped": "already-absent"} if index == 1 else {}),
            }
        )
    return {
        "plan": plan,
        "rows": rows,
        "cleanup": cleanup,
        "ownership": {"created": False, "cleanupComplete": True},
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
