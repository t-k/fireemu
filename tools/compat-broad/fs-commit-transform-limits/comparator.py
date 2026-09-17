"""Strict, credential-free comparison contract for the O3 compiler."""

from __future__ import annotations

import json
from typing import Any

from compiler import compile_plan

_TIMESTAMP_KEYS = {"createTime", "updateTime", "commitTime"}


class _PostStateMismatch(ValueError):
    """A complete, bound response violated the declared state contract."""


def _exact(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            name: "<timestamp>"
            if name in _TIMESTAMP_KEYS and isinstance(item, str)
            else _canonical(item)
            for name, item in value.items()
        }
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def _resource_for(row: dict[str, Any]) -> str | None:
    resource = row["request"].get("resource")
    if isinstance(resource, str):
        return resource
    path = row["request"].get("path")
    if isinstance(path, str):
        return path.split("?", 1)[0].removeprefix("/v1/")
    return None


def _validate_plan(plan: dict[str, Any]) -> None:
    expected = compile_plan(plan["project"], plan["database"], plan["nonce"])
    digest = plan.get("planDigest")
    unsigned = {key: value for key, value in plan.items() if key != "planDigest"}
    import hashlib

    calculated = hashlib.sha256(
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()
    if not _exact(plan, expected) or digest != calculated:
        raise ValueError("compiler plan drift")


def _typed_absence(body: Any) -> bool:
    return isinstance(body, dict) and body.get("error", {}).get("status") == "NOT_FOUND"


def _validate_row(
    plan: dict[str, Any], row: dict[str, Any], request: dict[str, Any], index: int
) -> None:
    if (
        not isinstance(row, dict)
        or type(row.get("index")) is not int
        or row.get("index") != index
        or not _exact(row.get("request"), request)
        or row.get("complete") is not True
        or row.get("failure") is not None
        or type(row.get("status")) is not int
        or "body" not in row
    ):
        raise ValueError("incomplete or unbound observation")
    status, body = row["status"], row["body"]
    kind = request["kind"]
    if kind == "preflight-typed-absence" and not (
        status == 404 and _typed_absence(body)
    ):
        raise ValueError("preflight outcome differs")
    if kind == "create-only-patch":
        if (
            status != 200
            or not isinstance(body, dict)
            or body.get("name") != request["body"]["name"]
        ):
            raise ValueError("creation acknowledgement differs")
        if not _exact(body.get("fields"), request["body"]["fields"]):
            raise ValueError("creation marker or fields differ")
    if kind == "commit-transform":
        outcome = request["expect"]["outcome"]
        if outcome == "accepted" and status != 200:
            raise ValueError("accepted Commit was not successful")
        if outcome == "refused" and not 400 <= status < 500:
            raise ValueError("refused Commit is not a typed 4xx outcome")
    if kind in {
        "baseline-readback",
        "poststate-readback",
        "poststate-control-readback",
    }:
        resource = _resource_for(row)
        document = next(
            item for item in plan["documents"].values() if item["resource"] == resource
        )
        if status != request["expect"]["status"] or not isinstance(body, dict):
            raise ValueError("post-state status differs")
        expected = (
            document["expectedFields"]
            if request["expect"].get("postState") == "transformed"
            else document["fields"]
        )
        if body.get("name") != resource or not _exact(body.get("fields"), expected):
            raise _PostStateMismatch("post-state differs")
    if kind == "cleanup-ownership-read":
        if status == 404:
            if not _typed_absence(body):
                raise ValueError("cleanup absence is not typed")
        elif status == 200:
            resource = _resource_for(row)
            document = next(
                item
                for item in plan["documents"].values()
                if item["resource"] == resource
            )
            if not isinstance(body, dict) or body.get("name") != resource:
                raise ValueError("cleanup ownership identity differs")
            fields = body.get("fields")
            if not isinstance(fields, dict) or not _exact(
                fields.get("_sharedOwner"), {"referenceValue": resource}
            ):
                raise ValueError("cleanup ownership marker differs")
            expected = (
                document["expectedFields"]
                if document["transformCount"] == 500
                else document["fields"]
            )
            if not _exact(fields, expected):
                raise _PostStateMismatch("cleanup fields differ")
        else:
            raise ValueError("cleanup ownership status differs")
    if kind == "cleanup-conditional-delete" and status != 200:
        raise ValueError("conditional cleanup delete differs")
    if kind == "cleanup-verify-absence" and not (
        status == 404 and _typed_absence(body)
    ):
        raise ValueError("cleanup absence differs")


def _validate_rows(
    plan: dict[str, Any], rows: list[dict[str, Any]], requests: list[dict[str, Any]]
) -> None:
    if not isinstance(rows, list) or len(rows) != len(requests):
        raise ValueError("incomplete observation journal")
    for index, (row, request) in enumerate(zip(rows, requests, strict=True)):
        _validate_row(plan, row, request, index)


def compare_rows(
    left_plan: dict[str, Any],
    left_rows: list[dict[str, Any]],
    right_plan: dict[str, Any],
    right_rows: list[dict[str, Any]],
    *,
    left_recovery: list[dict[str, Any]] | None = None,
    right_recovery: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare two complete journals without granting acquisition or promotion."""
    result = {
        "kind": "fs-commit-transform-semantic-kernel-v1",
        "classification": "INDETERMINATE",
        "promotionReady": False,
        "acquisitionValidated": False,
        "rows": [],
        "errors": [],
    }
    try:
        _validate_plan(left_plan)
        _validate_plan(right_plan)
        if left_plan["campaignId"] != right_plan["campaignId"]:
            raise ValueError("campaign identity differs")
        _validate_rows(left_plan, left_rows, left_plan["observation"])
        _validate_rows(right_plan, right_rows, right_plan["observation"])
        if (left_recovery is None) != (right_recovery is None):
            raise ValueError("recovery journal pair incomplete")
        if left_recovery is not None:
            _validate_rows(left_plan, left_recovery, left_plan["recovery"])
            _validate_rows(right_plan, right_recovery or [], right_plan["recovery"])
    except _PostStateMismatch:
        result["classification"] = "SEMANTIC_MISMATCH"
        result["errors"].append("post-state-contract")
        return result
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        result["errors"].append("invalid-binding-or-journal")
        return result
    for index, (left, right) in enumerate(zip(left_rows, right_rows, strict=True)):
        left_value = {"status": left["status"], "body": _canonical(left["body"])}
        right_value = {"status": right["status"], "body": _canonical(right["body"])}
        classification = (
            "MATCH" if _exact(left_value, right_value) else "SEMANTIC_MISMATCH"
        )
        result["rows"].append({"index": index, "classification": classification})
    result["classification"] = (
        "SEMANTIC_MISMATCH"
        if any(row["classification"] == "SEMANTIC_MISMATCH" for row in result["rows"])
        else "MATCH"
    )
    return result
