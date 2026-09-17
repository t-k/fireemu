"""Offline semantic comparison for the finite compiled IN query campaign."""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from query_in_compiler import validate_plan

_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")
_PHASES = (("rows", "observation", 6), ("cleanup", "recovery", 3))


def _exact(left: Any, right: Any) -> bool:
    try:
        return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
            right, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError):
        return False


def _canonical(value: Any, plan: dict[str, Any], timestamp_ranks: dict[str, int]) -> Any:
    if isinstance(value, str):
        if value == plan["document"]:
            return "$owned-document"
        if value == plan["parent"]:
            return "$owned-parent"
        if _TIMESTAMP.fullmatch(value):
            if value not in timestamp_ranks:
                timestamp_ranks[value] = len(timestamp_ranks)
            return {"$timestampRank": timestamp_ranks[value]}
        return value
    if isinstance(value, list):
        return [_canonical(item, plan, timestamp_ranks) for item in value]
    if isinstance(value, dict):
        return {
            key: _canonical(item, plan, timestamp_ranks)
            for key, item in sorted(value.items())
        }
    return value


def _receipt_valid(receipt: Any, *, allow_skip: bool) -> bool:
    if not isinstance(receipt, dict) or receipt.get("complete") is not True:
        return False
    if receipt.get("failure") is not None:
        return False
    if "skipped" in receipt:
        return allow_skip and receipt["skipped"] in {
            "already-absent",
            "create-not-proven",
            "create-version-mismatch",
            "unsafe-delete",
        }
    return (
        type(receipt.get("status")) is int
        and 100 <= receipt["status"] <= 599
        and "body" in receipt
    )


def _recovery_request_matches(
    row: dict[str, Any], operation: dict[str, Any], prior: dict[str, Any]
) -> bool:
    request = row.get("request")
    if _exact(request, operation):
        return True
    if operation.get("kind") != "cleanup-conditional-delete":
        return False
    if not isinstance(request, dict) or not isinstance(request.get("path"), str):
        return False
    body = prior.get("body") if isinstance(prior, dict) else None
    update_time = body.get("updateTime") if isinstance(body, dict) else None
    suffix = "?currentDocument.updateTime=" + str(update_time)
    expected = copy.deepcopy(operation)
    expected["path"] += suffix
    return isinstance(update_time, str) and _exact(request, expected)


def _typed_absence(row: dict[str, Any]) -> bool:
    body = row.get("body")
    error = body.get("error") if isinstance(body, dict) else None
    return (
        row.get("status") == 404
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error["code"] == 404
        and error.get("status") == "NOT_FOUND"
    )


def _owned_read(row: dict[str, Any], plan: dict[str, Any]) -> bool:
    body = row.get("body")
    return (
        row.get("status") == 200
        and isinstance(body, dict)
        and body.get("name") == plan["document"]
        and body.get("fields") == plan["fixtureFields"]
        and isinstance(body.get("updateTime"), str)
        and _TIMESTAMP.fullmatch(body["updateTime"]) is not None
    )


def _validate_side(bundle: Any) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(bundle, dict):
        raise TypeError("evidence bundle must be an object")
    plan = bundle.get("plan")
    validate_plan(plan)
    if bundle.get("planDigest") is not None and bundle["planDigest"] != plan.get("planDigest"):
        raise ValueError("plan digest binding differs")
    if bundle.get("acquisitionValidated") is True or bundle.get("promotionReady") is True:
        raise ValueError("comparator cannot accept acquisition authority")
    rows = bundle.get("rows")
    cleanup = bundle.get("cleanup")
    if not isinstance(rows, list) or not isinstance(cleanup, list):
        raise TypeError("missing operation journals")
    if len(rows) != 6 or len(cleanup) != 3:
        raise ValueError("incomplete operation journals")
    for index, (row, operation) in enumerate(zip(rows, plan["observation"], strict=True)):
        if (
            not isinstance(row, dict)
            or type(row.get("index")) is not int
            or row["index"] != index
            or not _exact(row.get("request"), operation)
            or not _receipt_valid(row, allow_skip=False)
        ):
            raise ValueError(f"invalid observation journal row {index}")
    for index, (row, operation) in enumerate(zip(cleanup, plan["recovery"], strict=True)):
        if (
            not isinstance(row, dict)
            or type(row.get("index")) is not int
            or row["index"] != index
            or not _recovery_request_matches(row, operation, cleanup[0])
            or not _receipt_valid(row, allow_skip=True)
        ):
            raise ValueError(f"invalid recovery journal row {index}")
    if not (_typed_absence(cleanup[0]) or _owned_read(cleanup[0], plan)):
        raise ValueError("cleanup ownership read is not typed")
    if "skipped" not in cleanup[1] and not (
        cleanup[1].get("status") == 200 and isinstance(cleanup[1].get("body"), dict)
    ):
        raise ValueError("cleanup delete receipt is not typed")
    if not _typed_absence(cleanup[2]):
        raise ValueError("cleanup absence is not typed")
    ownership = bundle.get("ownership", {})
    if not isinstance(ownership, dict) or ownership.get("cleanupComplete") is not True:
        raise ValueError("ownership and cleanup evidence is incomplete")
    raw = bundle.get("raw")
    if raw is not None and not isinstance(raw, dict):
        raise ValueError("typed raw receipt evidence is malformed")
    if isinstance(raw, dict):
        for slot, view in raw.items():
            if not isinstance(slot, str) or not slot.isdigit() or not isinstance(view, dict):
                raise ValueError("typed raw receipt evidence is malformed")
            digest = view.get("sourceRawSha256")
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("typed raw receipt evidence is unbound")
    return plan, rows, cleanup


def _canonical_journal(
    plan: dict[str, Any], rows: list[dict[str, Any]], cleanup: list[dict[str, Any]]
) -> list[Any]:
    ranks: dict[str, int] = {}
    result: list[Any] = []
    for row in [*rows, *cleanup]:
        result.append(
            {
                "index": row["index"],
                "request": _canonical(row["request"], plan, ranks),
                "complete": row["complete"],
                "failure": row.get("failure"),
                "status": row.get("status"),
                "body": _canonical(row.get("body"), plan, ranks),
                "skipped": row.get("skipped"),
            }
        )
    return result


def compare_evidence(production: dict[str, Any], local: dict[str, Any]) -> dict[str, Any]:
    """Compare two retained bundles without asserting production acquisition."""
    result: dict[str, Any] = {
        "kind": "fs-query-in-boundary-semantic-kernel-v1",
        "semanticOnly": True,
        "classification": "INDETERMINATE",
        "acquisitionValidated": False,
        "promotionReady": False,
        "rows": [],
        "errors": [],
    }
    try:
        production_plan, production_rows, production_cleanup = _validate_side(production)
        local_plan, local_rows, local_cleanup = _validate_side(local)
    except (ValueError, TypeError, KeyError, IndexError) as error:
        result["errors"].append(str(error))
        return result
    left = _canonical_journal(production_plan, production_rows, production_cleanup)
    right = _canonical_journal(local_plan, local_rows, local_cleanup)
    for index, (a, b) in enumerate(zip(left, right, strict=True)):
        raw_a = {key: production_rows[index][key] for key in ("status", "body")} if index < 6 else production_cleanup[index - 6]
        raw_b = {key: local_rows[index][key] for key in ("status", "body")} if index < 6 else local_cleanup[index - 6]
        classification = "SEMANTIC_MISMATCH" if not _exact(a, b) else (
            "MATCH" if _exact(raw_a, raw_b) else "EXPECTED_NONDETERMINISM"
        )
        result["rows"].append({"index": index, "classification": classification})
    classes = {row["classification"] for row in result["rows"]}
    result["classification"] = next(
        value for value in ("SEMANTIC_MISMATCH", "EXPECTED_NONDETERMINISM", "MATCH") if value in classes
    )
    left_raw = production.get("raw")
    right_raw = local.get("raw")
    if left_raw is not None or right_raw is not None:
        if not isinstance(left_raw, dict) or not isinstance(right_raw, dict):
            result["classification"] = "INDETERMINATE"
            result["errors"].append("raw receipt pair is incomplete")
            return result
        raw_left = {
            key: {name: value for name, value in view.items() if name != "sourceRawSha256"}
            for key, view in left_raw.items()
        }
        raw_right = {
            key: {name: value for name, value in view.items() if name != "sourceRawSha256"}
            for key, view in right_raw.items()
        }
        if not _exact(raw_left, raw_right):
            result["classification"] = "SEMANTIC_MISMATCH"
        elif result["classification"] == "MATCH" and left_raw != right_raw:
            result["classification"] = "EXPECTED_NONDETERMINISM"
    return result


def compare_rows(
    production_plan: dict[str, Any],
    production_rows: list[dict[str, Any]],
    local_plan: dict[str, Any],
    local_rows: list[dict[str, Any]],
    *,
    production_cleanup: list[dict[str, Any]] | None = None,
    local_cleanup: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compatibility entry point for callers holding journals separately."""
    return compare_evidence(
        {"plan": production_plan, "rows": production_rows, "cleanup": production_cleanup or [], "ownership": {"cleanupComplete": True}},
        {"plan": local_plan, "rows": local_rows, "cleanup": local_cleanup or [], "ownership": {"cleanupComplete": True}},
    )


compare_collections = compare_evidence
