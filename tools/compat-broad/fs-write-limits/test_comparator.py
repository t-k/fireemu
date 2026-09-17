"""Synthetic semantic controls, not production observations."""

import copy

import pytest
from comparator import compare_rows
from compiler import compile_limits_plan


def journal(nonce="a", project="demo-test"):
    plan = compile_limits_plan(project, "(default)", nonce * 32)
    rows = []
    for index, request in enumerate(
        plan["localGatePlan"]["jobs"]["limits"]["observation"]
    ):
        rows.append(
            {
                "index": index,
                "request": copy.deepcopy(request),
                "complete": True,
                "status": 400,
                "body": {"error": {"status": "INVALID_ARGUMENT"}},
            }
        )
    return plan, rows


def test_complete_errors_are_observations_not_collection_failure():
    p, rows = journal()
    other = copy.deepcopy(rows)
    other[4]["status"] = 200
    assert compare_rows(p, rows, p, rows)["classification"] == "MATCH"
    assert compare_rows(p, rows, p, other)["classification"] == "SEMANTIC_MISMATCH"


@pytest.mark.parametrize("mutation", ["complete", "body", "request", "count", "index"])
def test_incomplete_or_unbound_journal_is_indeterminate(mutation):
    p, rows = journal()
    other = copy.deepcopy(rows)
    if mutation == "complete":
        other[0]["complete"] = False
    elif mutation == "body":
        del other[0]["body"]
    elif mutation == "request":
        other[4]["request"]["body"]["fields"]["blob"] = {"stringValue": "different"}
    elif mutation == "count":
        other.pop()
    else:
        other[0]["index"] = False
    result = compare_rows(p, rows, p, other)
    assert result["classification"] == "INDETERMINATE"
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False


def test_only_document_metadata_is_normalized_and_version_changes_survive():
    p, rows = journal()
    q, other = journal("b", "demo-other")
    for plan, journal_rows, timestamp in [
        (p, rows, "2026-01-01T00:00:00Z"),
        (q, other, "2026-02-01T00:00:00Z"),
    ]:
        document = plan["documents"]["exact-document-boundary"]
        for index in (4, 5, 10, 14):
            journal_rows[index].update(
                status=200,
                body={
                    "name": document["resource"],
                    "fields": copy.deepcopy(document["fields"]),
                    "createTime": timestamp,
                    "updateTime": timestamp,
                },
            )
    assert (
        compare_rows(p, rows, q, other)["classification"] == "EXPECTED_NONDETERMINISM"
    )
    other[10]["body"]["updateTime"] = "2026-02-02T00:00:00Z"
    assert compare_rows(p, rows, q, other)["classification"] == "SEMANTIC_MISMATCH"
    other[10]["body"]["updateTime"] = "2026-02-01T00:00:00Z"
    rows[4]["body"]["fields"]["user"] = {
        "stringValue": p["documents"]["exact-document-boundary"]["resource"]
    }
    other[4]["body"]["fields"]["user"] = {
        "stringValue": q["documents"]["exact-document-boundary"]["resource"]
    }
    assert compare_rows(p, rows, q, other)["classification"] == "SEMANTIC_MISMATCH"


@pytest.mark.parametrize("a,b", [(True, 1), (1, 1.0)])
def test_json_types_are_not_erased(a, b):
    p, rows = journal()
    other = copy.deepcopy(rows)
    rows[0]["body"] = {"error": {"code": a}}
    other[0]["body"] = {"error": {"code": b}}
    assert compare_rows(p, rows, p, other)["classification"] == "SEMANTIC_MISMATCH"


def test_late_incomplete_overrides_earlier_mismatch():
    p, rows = journal()
    other = copy.deepcopy(rows)
    other[0]["status"] = 200
    other[-1]["complete"] = False
    assert compare_rows(p, rows, p, other)["classification"] == "INDETERMINATE"


def test_timestamp_equality_and_order_are_preserved():
    p, rows = journal()
    resource = p["documents"]["exact-document-boundary"]["resource"]
    rows[4].update(
        status=200,
        body={
            "name": resource,
            "createTime": "2026-01-01T00:00:00Z",
            "updateTime": "2026-01-02T00:00:00Z",
        },
    )
    other = copy.deepcopy(rows)
    other[4]["body"]["createTime"] = "2026-02-02T00:00:00Z"
    other[4]["body"]["updateTime"] = "2026-02-01T00:00:00Z"
    assert compare_rows(p, rows, p, other)["classification"] == "SEMANTIC_MISMATCH"
    other[4]["body"]["createTime"] = other[4]["body"]["updateTime"]
    assert compare_rows(p, rows, p, other)["classification"] == "SEMANTIC_MISMATCH"
