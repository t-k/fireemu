from __future__ import annotations

import copy

import pytest
from comparator import compare_rows
from compiler import compile_plan


def _rows(plan: dict) -> list[dict]:
    rows = []
    for index, request in enumerate(plan["observation"]):
        if request["kind"] == "commit-transform":
            body = {"commitTime": "2026-09-17T00:00:00Z", "writeResults": []}
            status = 200 if request["expect"]["outcome"] == "accepted" else 400
        elif request["kind"] == "preflight-typed-absence":
            body, status = {"error": {"code": 404, "status": "NOT_FOUND"}}, 404
        elif request["kind"] == "create-only-patch":
            body, status = (
                {
                    "name": request["body"]["name"],
                    "fields": request["body"]["fields"],
                    "updateTime": "2026-09-17T00:00:00Z",
                },
                200,
            )
        else:
            document = next(
                value
                for value in plan["documents"].values()
                if value["resource"]
                == request["path"].split("?", 1)[0].removeprefix("/v1/")
            )
            fields = copy.deepcopy(
                document["expectedFields"]
                if request["expect"].get("postState") == "transformed"
                else document["fields"]
            )
            body, status = (
                {
                    "name": document["resource"],
                    "fields": fields,
                    "updateTime": "2026-09-17T00:00:00Z",
                },
                200,
            )
        rows.append(
            {
                "index": index,
                "request": copy.deepcopy(request),
                "complete": True,
                "failure": None,
                "status": status,
                "body": body,
            }
        )
    return rows


def _recovery_rows(plan: dict) -> list[dict]:
    rows = []
    for index, request in enumerate(plan["recovery"]):
        resource = request["resource"]
        document = next(
            value
            for value in plan["documents"].values()
            if value["resource"] == resource
        )
        if request["kind"] == "cleanup-ownership-read":
            body, status = (
                {"name": resource, "fields": copy.deepcopy(document["expectedFields"])},
                200,
            )
        elif request["kind"] == "cleanup-conditional-delete":
            body, status = {}, 200
        else:
            body, status = {"error": {"code": 404, "status": "NOT_FOUND"}}, 404
        rows.append(
            {
                "index": index,
                "request": copy.deepcopy(request),
                "complete": True,
                "failure": None,
                "status": status,
                "body": body,
            }
        )
    return rows


def test_accepted_and_refused_commit_outcomes_compare_with_exact_poststate() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    rows = _rows(plan)
    other = copy.deepcopy(rows)
    result = compare_rows(plan, rows, plan, other)
    assert result["classification"] == "MATCH"
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False


def test_timestamp_metadata_is_ignored_but_transformed_poststate_is_strict() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    rows = _rows(plan)
    other = copy.deepcopy(rows)
    other[6]["body"]["commitTime"] = "2026-09-18T00:00:00Z"
    assert compare_rows(plan, rows, plan, other)["classification"] == "MATCH"
    other[7]["body"]["fields"]["t0"] = {"integerValue": "999"}
    assert (
        compare_rows(plan, rows, plan, other)["classification"] == "SEMANTIC_MISMATCH"
    )


@pytest.mark.parametrize(
    "mutation", ["request", "index", "complete", "missing-body", "unexpected-status"]
)
def test_unbound_or_incomplete_rows_are_indeterminate(mutation: str) -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    rows = _rows(plan)
    if mutation == "request":
        rows[6]["request"]["body"]["writes"][0]["transform"]["document"] = "foreign"
    elif mutation == "index":
        rows[0]["index"] = False
    elif mutation == "complete":
        rows[0]["complete"] = False
    elif mutation == "missing-body":
        del rows[0]["body"]
    else:
        rows[8]["status"] = 200
    result = compare_rows(plan, _rows(plan), plan, rows)
    assert result["classification"] == "INDETERMINATE"
    assert result["promotionReady"] is False


def test_refused_commit_requires_unchanged_negative_document() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    rows = _rows(plan)
    rows[9]["body"]["fields"]["unexpected"] = {"stringValue": "mutation"}
    result = compare_rows(plan, rows, plan, _rows(plan))
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_cleanup_rows_are_part_of_the_strict_contract() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left = _recovery_rows(plan)
    right = copy.deepcopy(left)
    assert (
        compare_rows(
            plan,
            _rows(plan),
            plan,
            _rows(plan),
            left_recovery=left,
            right_recovery=right,
        )["classification"]
        == "MATCH"
    )
    right[0]["body"]["fields"]["_sharedOwner"] = {"referenceValue": "foreign"}
    result = compare_rows(
        plan, _rows(plan), plan, _rows(plan), left_recovery=left, right_recovery=right
    )
    assert result["classification"] == "INDETERMINATE"
