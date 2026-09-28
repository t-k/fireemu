from __future__ import annotations

import copy
from urllib.parse import quote

import pytest
from transform_comparator import compare_rows
from transform_compiler import compile_plan


def _rows(plan: dict) -> list[dict]:
    rows = []
    for index, request in enumerate(plan["observation"]):
        if request["kind"] == "commit-transform":
            if request["expect"]["outcome"] == "accepted":
                body = {
                    "commitTime": "2026-09-18T00:00:00Z",
                    "writeResults": [
                        {"updateTime": "2026-09-18T00:00:00Z"},
                        {"updateTime": "2026-09-18T00:00:00Z"},
                    ],
                }
                status = 200
            else:
                body = {
                    "error": {
                        "code": 400,
                        "status": "INVALID_ARGUMENT",
                        "details": [{"reason": "field transform limit"}],
                    }
                }
                status = 400
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
                    "updateTime": "2026-09-18T00:00:00Z"
                    if request["expect"].get("postState") == "transformed"
                    else "2026-09-17T00:00:00Z",
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
                {
                    "name": resource,
                    "fields": copy.deepcopy(document["expectedFields"]),
                    "updateTime": "2026-09-18T00:00:00Z"
                    if document["transformCount"] == 500
                    else "2026-09-17T00:00:00Z",
                },
                200,
            )
        elif request["kind"] == "cleanup-conditional-delete":
            prior = rows[-1]["body"]
            request = copy.deepcopy(request)
            request["path"] += "?currentDocument.updateTime=" + quote(
                prior["updateTime"], safe=""
            )
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
    other[6]["body"]["commitTime"] = "2026-09-19T00:00:00Z"
    for result in other[6]["body"]["writeResults"]:
        result["updateTime"] = "2026-09-19T00:00:00Z"
    for index in (7, 10):
        other[index]["body"]["updateTime"] = "2026-09-19T00:00:00Z"
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
    assert result["classification"] == (
        "SEMANTIC_MISMATCH" if mutation == "unexpected-status" else "INDETERMINATE"
    )
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
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_complete_unexpected_commit_status_is_a_semantic_mismatch() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    rows = _rows(plan)
    rows[6]["status"] = 400
    result = compare_rows(plan, _rows(plan), plan, rows)
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_typed_commit_error_details_are_compared_without_timestamp_erasure() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    rows = _rows(plan)
    other = copy.deepcopy(rows)
    other[8]["body"]["error"]["details"][0]["reason"] = "different"
    result = compare_rows(plan, rows, plan, other)
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_only_supported_top_level_timestamps_are_normalized() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    rows = _rows(plan)
    other = copy.deepcopy(rows)
    other[7]["body"]["fields"]["userUpdateTime"] = {"stringValue": "one"}
    rows[7]["body"]["fields"]["userUpdateTime"] = {"stringValue": "two"}
    assert (
        compare_rows(plan, rows, plan, other)["classification"] == "SEMANTIC_MISMATCH"
    )


def test_distinct_project_and_nonce_are_structural_identity_changes_only() -> None:
    left_plan = compile_plan("demo-left", "(default)", "a" * 32)
    right_plan = compile_plan("demo-right", "(default)", "b" * 32)
    assert (
        compare_rows(left_plan, _rows(left_plan), right_plan, _rows(right_plan))[
            "classification"
        ]
        == "MATCH"
    )


def test_resolved_cleanup_delete_must_bind_to_ownership_read_version() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left = _recovery_rows(plan)
    right = copy.deepcopy(left)
    right[1]["request"]["path"] = right[1]["request"]["path"].replace(
        "2026-09-18T00%3A00%3A00Z", "2026-09-18T00%3A00%3A01Z"
    )
    result = compare_rows(
        plan, _rows(plan), plan, _rows(plan), left_recovery=left, right_recovery=right
    )
    assert result["classification"] == "INDETERMINATE"


def test_both_journals_are_structurally_validated_before_poststate_semantics() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left = _rows(plan)
    right = _rows(plan)
    left[7]["body"]["fields"]["t0"] = {"integerValue": "999"}
    right[0]["complete"] = False
    result = compare_rows(plan, left, plan, right)
    assert result["classification"] == "INDETERMINATE"


@pytest.mark.parametrize(
    "mutation,classification",
    [
        ("rejected-version", "SEMANTIC_MISMATCH"),
        ("impossible-timestamp", "SEMANTIC_MISMATCH"),
        ("placeholder-path", "INDETERMINATE"),
        ("integer-privilege", "INDETERMINATE"),
        ("foreign-delete", "INDETERMINATE"),
        ("extra-delete-query", "INDETERMINATE"),
        ("literal-timestamp", "SEMANTIC_MISMATCH"),
        ("duplicate-delete-query", "INDETERMINATE"),
        ("delete-fragment", "INDETERMINATE"),
    ],
)
def test_review_counterexamples(mutation: str, classification: str) -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left, right = _rows(plan), _rows(plan)
    recovery = _recovery_rows(plan)
    changed = copy.deepcopy(recovery)
    if mutation == "rejected-version":
        right[9]["body"]["updateTime"] = "2026-09-18T00:00:00Z"
    elif mutation == "impossible-timestamp":
        right[9]["body"]["updateTime"] = "2026-99-99T99:99:99Z"
    elif mutation == "placeholder-path":
        right[4]["request"]["path"] = "/v1/<exact-500>"
    elif mutation == "integer-privilege":
        right[0]["request"]["privileged"] = 1
    elif mutation == "foreign-delete":
        changed[1]["request"]["path"] = (
            "https://foreign.example" + changed[1]["request"]["path"]
        )
    elif mutation == "extra-delete-query":
        changed[1]["request"]["path"] += "&currentDocument.exists=false"
    elif mutation == "duplicate-delete-query":
        changed[1]["request"]["path"] += (
            "&" + changed[1]["request"]["path"].split("?", 1)[1]
        )
    elif mutation == "delete-fragment":
        changed[1]["request"]["path"] += "#ignored"
    else:
        left[4]["body"]["createTime"] = "2026-09-17T00:00:00Z"
        right[4]["body"]["createTime"] = "<createTime>"
    assert (
        compare_rows(
            plan, left, plan, right, left_recovery=recovery, right_recovery=changed
        )["classification"]
        == classification
    )


@pytest.mark.parametrize("side", ["left", "right"])
def test_incomplete_recovery_precedes_other_journal_semantics(side: str) -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left, right = _rows(plan), _rows(plan)
    left[6]["status"] = 500
    recoveries = {"left": _recovery_rows(plan), "right": _recovery_rows(plan)}
    recoveries[side].pop()
    assert (
        compare_rows(
            plan,
            left,
            plan,
            right,
            left_recovery=recoveries["left"],
            right_recovery=recoveries["right"],
        )["classification"]
        == "INDETERMINATE"
    )


def test_independent_scopes_and_clock_values_match_with_complete_recovery() -> None:
    left_plan = compile_plan("left-project", "left-db", "1" * 32)
    right_plan = compile_plan("right-project", "right-db", "2" * 32)
    left, right = _rows(left_plan), _rows(right_plan)
    left_recovery, right_recovery = (
        _recovery_rows(left_plan),
        _recovery_rows(right_plan),
    )
    # Advance only declared metadata; leave user strings and request bodies exact.
    for row in right + right_recovery:
        body = row["body"]
        for key in ("createTime", "updateTime", "commitTime"):
            if key in body:
                body[key] = body[key].replace("2026-09", "2026-10")
        for result in body.get("writeResults", []):
            result["updateTime"] = result["updateTime"].replace("2026-09", "2026-10")
        if row["request"]["kind"] == "cleanup-conditional-delete":
            row["request"]["path"] = row["request"]["path"].replace(
                "2026-09", "2026-10"
            )
    result = compare_rows(
        left_plan,
        left,
        right_plan,
        right,
        left_recovery=left_recovery,
        right_recovery=right_recovery,
    )
    assert result["classification"] == "MATCH"
    assert result["promotionReady"] is result["acquisitionValidated"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "baseline",
        "accepted",
        "control",
        "write-result",
        "missing-results",
        "cleanup-version",
        "error-detail",
        "non-leap-date",
    ],
)
def test_version_relations_and_literal_error_details_are_not_erased(
    mutation: str,
) -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left, right = _rows(plan), _rows(plan)
    recovery, changed = _recovery_rows(plan), _recovery_rows(plan)
    indices = {"baseline": 4, "accepted": 7, "control": 10}
    if mutation in indices:
        right[indices[mutation]]["body"]["updateTime"] = "2026-09-19T00:00:00Z"
    elif mutation == "write-result":
        right[6]["body"]["writeResults"][0]["updateTime"] = "2026-09-19T00:00:00Z"
    elif mutation == "missing-results":
        right[6]["body"]["writeResults"] = []
    elif mutation == "cleanup-version":
        changed[0]["body"]["updateTime"] = "2026-09-19T00:00:00Z"
        changed[1]["request"]["path"] = changed[1]["request"]["path"].replace(
            "2026-09-18", "2026-09-19"
        )
    elif mutation == "error-detail":
        left[8]["body"]["error"]["details"] = [{"updateTime": "2026-09-17T00:00:00Z"}]
        right[8]["body"]["error"]["details"] = [{"updateTime": "2026-09-18T00:00:00Z"}]
    else:
        right[9]["body"]["updateTime"] = "2026-02-29T00:00:00Z"
    assert (
        compare_rows(
            plan, left, plan, right, left_recovery=recovery, right_recovery=changed
        )["classification"]
        == "SEMANTIC_MISMATCH"
    )


def test_identical_valid_commit_time_later_than_final_write_version_matches() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    rows = _rows(plan)
    rows[6]["body"]["commitTime"] = "2026-09-19T00:00:00Z"
    assert (
        compare_rows(plan, rows, plan, copy.deepcopy(rows))["classification"] == "MATCH"
    )


def test_creation_and_initial_update_equality_is_not_erased() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left, right = _rows(plan), _rows(plan)
    for index in (2, 4, 7, 10):
        left[index]["body"]["createTime"] = "2026-09-17T00:00:00Z"
        right[index]["body"]["createTime"] = "2026-09-16T00:00:00Z"
    assert (
        compare_rows(plan, left, plan, right)["classification"] == "SEMANTIC_MISMATCH"
    )


def test_commit_and_final_update_equality_is_compared_as_a_relation() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left, right = _rows(plan), _rows(plan)
    right[6]["body"]["commitTime"] = "2026-09-19T00:00:00Z"
    assert (
        compare_rows(plan, left, plan, right)["classification"] == "SEMANTIC_MISMATCH"
    )


def test_independent_clock_shifts_preserve_later_commit_and_creation_relations() -> (
    None
):
    left_plan = compile_plan("left", "db-left", "a" * 32)
    right_plan = compile_plan("right", "db-right", "b" * 32)
    left, right = _rows(left_plan), _rows(right_plan)
    for rows, month in ((left, "09"), (right, "10")):
        for row in rows:
            body = row["body"]
            for key in ("updateTime", "commitTime"):
                if key in body:
                    body[key] = body[key].replace("-09-", f"-{month}-")
            for result in body.get("writeResults", []):
                result["updateTime"] = result["updateTime"].replace(
                    "-09-", f"-{month}-"
                )
            if "name" in body:
                body["createTime"] = f"2026-{month}-16T00:00:00Z"
        rows[6]["body"]["commitTime"] = f"2026-{month}-19T00:00:00Z"
        rows[6]["body"]["writeResults"][0]["updateTime"] = f"2026-{month}-17T12:00:00Z"
    assert compare_rows(left_plan, left, right_plan, right)["classification"] == "MATCH"


_ABSENCE_KINDS = ("preflight-typed-absence", "cleanup-verify-absence")


def _with_absence_messages(
    rows: list[dict], *, template: str = 'Document "{resource}" not found.'
) -> list[dict]:
    """Add the resource-bearing NOT_FOUND message production actually returns."""
    rows = copy.deepcopy(rows)
    for row in rows:
        if row["request"]["kind"] in _ABSENCE_KINDS:
            resource = row["request"].get("resource") or row["request"]["path"].split(
                "?", 1
            )[0].removeprefix("/v1/")
            row["body"]["error"]["message"] = template.format(resource=resource)
    return rows


def test_not_found_message_resource_name_is_normalized_like_the_name_slot() -> None:
    left_plan = compile_plan("fireemu-oracle", "(default)", "a" * 32)
    right_plan = compile_plan("demo-firestore-probe", "(default)", "b" * 32)
    left = _with_absence_messages(_rows(left_plan))
    right = _with_absence_messages(_rows(right_plan))
    left_recovery = _with_absence_messages(_recovery_rows(left_plan))
    right_recovery = _with_absence_messages(_recovery_rows(right_plan))
    result = compare_rows(
        left_plan,
        left,
        right_plan,
        right,
        left_recovery=left_recovery,
        right_recovery=right_recovery,
    )
    absent = [
        index
        for index, row in enumerate(left + left_recovery)
        if row["request"]["kind"] in _ABSENCE_KINDS
    ]
    assert absent == [0, 1, 13, 16]
    assert [result["rows"][index]["classification"] for index in absent] == [
        "MATCH"
    ] * 4
    assert result["classification"] == "MATCH"
    assert len(result["rows"]) == 17


def test_a_genuinely_different_not_found_message_remains_a_semantic_mismatch() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    left = _with_absence_messages(_rows(plan))
    right = _with_absence_messages(
        _rows(plan), template='Document "{resource}" was deleted.'
    )
    result = compare_rows(plan, left, plan, right)
    assert result["rows"][0]["classification"] == "SEMANTIC_MISMATCH"
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_a_not_found_message_naming_a_foreign_resource_is_not_normalized() -> None:
    left_plan = compile_plan("demo-left", "(default)", "a" * 32)
    right_plan = compile_plan("demo-right", "(default)", "b" * 32)
    left = _with_absence_messages(_rows(left_plan))
    right = _with_absence_messages(_rows(right_plan))
    right[0]["body"]["error"]["message"] = (
        'Document "projects/other/databases/(default)/documents/x/y" not found.'
    )
    result = compare_rows(left_plan, left, right_plan, right)
    assert result["rows"][0]["classification"] == "SEMANTIC_MISMATCH"
