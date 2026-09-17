"""Strict, credential-free comparison contract for the O3 compiler."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from compiler import compile_plan

_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")


def _exact(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _timestamp(value: Any) -> bool:
    return isinstance(value, str) and _TIMESTAMP.fullmatch(value) is not None


def _resource_labels(plan: dict[str, Any]) -> dict[str, str]:
    return {
        document["resource"]: label for label, document in plan["documents"].items()
    }


def _canonical_request(request: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """Normalize compiler-declared identity slots, never arbitrary strings."""
    value = copy.deepcopy(request)
    labels = _resource_labels(plan)
    resource = value.get("resource")
    if resource in labels:
        value["resource"] = {"document": labels[resource]}
    if isinstance(value.get("resources"), list):
        value["resources"] = [{"document": labels[item]} for item in value["resources"]]
    path = value.get("path")
    if isinstance(path, str):
        for resource_name, label in labels.items():
            path = path.replace("/v1/" + resource_name, "/v1/<" + label + ">")
        if value.get("kind") == "cleanup-conditional-delete":
            parsed = urlsplit(path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            if "currentDocument.updateTime" in query:
                path = parsed.path + "?currentDocument.updateTime=<version>"
        value["path"] = path
    body = value.get("body")
    if isinstance(body, dict):
        body = copy.deepcopy(body)
        if body.get("name") in labels:
            body["name"] = {"document": labels[body["name"]]}
        writes = body.get("writes")
        if isinstance(writes, list):
            for write in writes:
                transform = write.get("transform") if isinstance(write, dict) else None
                if isinstance(transform, dict) and transform.get("document") in labels:
                    transform["document"] = {"document": labels[transform["document"]]}
        fields = body.get("fields")
        if isinstance(fields, dict):
            owner = fields.get("_sharedOwner")
            if isinstance(owner, dict) and owner.get("referenceValue") in labels:
                owner["referenceValue"] = {"document": labels[owner["referenceValue"]]}
        value["body"] = body
    return value


def _canonical_body(body: Any, plan: dict[str, Any], *, kind: str) -> Any:
    """Normalize only protocol-defined top-level metadata."""
    value = copy.deepcopy(body)
    if not isinstance(value, dict):
        return value
    labels = _resource_labels(plan)
    if kind == "commit-transform":
        if isinstance(value.get("commitTime"), str) and _timestamp(value["commitTime"]):
            value["commitTime"] = "<commitTime>"
        return value
    if kind not in {
        "create-only-patch",
        "baseline-readback",
        "poststate-readback",
        "poststate-control-readback",
        "cleanup-ownership-read",
    }:
        return value
    if value.get("name") in labels:
        value["name"] = {"document": labels[value["name"]]}
    for key in ("createTime", "updateTime"):
        if isinstance(value.get(key), str) and _timestamp(value[key]):
            value[key] = "<" + key + ">"
    fields = value.get("fields")
    if isinstance(fields, dict):
        owner = fields.get("_sharedOwner")
        if isinstance(owner, dict) and owner.get("referenceValue") in labels:
            owner["referenceValue"] = {"document": labels[owner["referenceValue"]]}
    return value


def _validate_plan(plan: dict[str, Any]) -> None:
    expected = compile_plan(plan["project"], plan["database"], plan["nonce"])
    if not _exact(plan, expected):
        raise ValueError("compiler plan drift")
    unsigned = {key: value for key, value in plan.items() if key != "planDigest"}
    if plan.get("planDigest") != _digest(unsigned):
        raise ValueError("compiler plan digest differs")


def _typed_absence(body: Any) -> bool:
    return (
        isinstance(body, dict)
        and isinstance(body.get("error"), dict)
        and body["error"].get("status") == "NOT_FOUND"
        and type(body["error"].get("code")) is int
        and body["error"]["code"] == 404
    )


def _resource_for(request: dict[str, Any]) -> str | None:
    resource = request.get("resource")
    if isinstance(resource, str):
        return resource
    path = request.get("path")
    return path.split("?", 1)[0].removeprefix("/v1/") if isinstance(path, str) else None


def _resolved_delete_matches(
    request: dict[str, Any], expected: dict[str, Any], prior: dict[str, Any]
) -> bool:
    actual = urlsplit(request.get("path", ""))
    if actual.path != expected["path"]:
        return False
    versions = parse_qs(actual.query, keep_blank_values=True).get(
        "currentDocument.updateTime"
    )
    body = prior.get("body") if isinstance(prior, dict) else None
    version = body.get("updateTime") if isinstance(body, dict) else None
    return (
        prior.get("status") == 200
        and isinstance(body, dict)
        and _timestamp(version)
        and versions == [version]
    )


def _validate_row_shape(
    plan: dict[str, Any],
    row: dict[str, Any],
    expected: dict[str, Any],
    index: int,
    prior: dict[str, Any] | None,
) -> None:
    if (
        not isinstance(row, dict)
        or type(row.get("index")) is not int
        or row["index"] != index
        or row.get("complete") is not True
        or row.get("failure") is not None
        or type(row.get("status")) is not int
        or "body" not in row
        or not isinstance(row.get("request"), dict)
    ):
        raise ValueError("incomplete journal row")
    request = row["request"]
    if expected["kind"] == "cleanup-conditional-delete":
        if not _resolved_delete_matches(request, expected, prior or {}):
            raise ValueError("cleanup delete version is not bound to ownership read")
        expected_copy = copy.deepcopy(expected)
        expected_copy["path"] = request["path"]
        if _canonical_request(request, plan) != _canonical_request(expected_copy, plan):
            raise ValueError("cleanup delete request differs")
    elif _canonical_request(request, plan) != _canonical_request(expected, plan):
        raise ValueError("request binding differs")
    json.dumps(row["body"], allow_nan=False)


def _validate_shapes(
    plan: dict[str, Any], rows: list[dict[str, Any]], requests: list[dict[str, Any]]
) -> None:
    if not isinstance(rows, list) or len(rows) != len(requests):
        raise ValueError("incomplete journal")
    for index, (row, expected) in enumerate(zip(rows, requests, strict=True)):
        prior = (
            rows[index - 1]
            if expected["kind"] == "cleanup-conditional-delete"
            else None
        )
        _validate_row_shape(plan, row, expected, index, prior)


def _semantic_issues(
    plan: dict[str, Any], rows: list[dict[str, Any]], requests: list[dict[str, Any]]
) -> list[str]:
    issues: list[str] = []
    for index, (row, request) in enumerate(zip(rows, requests, strict=True)):
        status, body, kind = row["status"], row["body"], request["kind"]
        if kind == "preflight-typed-absence" and not (
            status == 404 and _typed_absence(body)
        ):
            issues.append(f"{index}:preflight")
        elif kind == "create-only-patch":
            if (
                status != 200
                or not isinstance(body, dict)
                or body.get("name") != request["body"]["name"]
                or not _exact(body.get("fields"), request["body"]["fields"])
            ):
                issues.append(f"{index}:create")
        elif kind == "commit-transform":
            expectation = request["expect"]
            if expectation["outcome"] == "accepted" and (
                status != 200
                or not isinstance(body, dict)
                or not _timestamp(body.get("commitTime"))
                or not isinstance(body.get("writeResults"), list)
            ):
                issues.append(f"{index}:accepted-commit")
            if expectation["outcome"] == "refused" and (
                not 400 <= status < 500
                or not isinstance(body, dict)
                or not isinstance(body.get("error"), dict)
                or type(body["error"].get("code")) is not int
                or not isinstance(body["error"].get("status"), str)
            ):
                issues.append(f"{index}:refused-commit")
        elif kind in {
            "baseline-readback",
            "poststate-readback",
            "poststate-control-readback",
        }:
            resource = _resource_for(request)
            document = next(
                item
                for item in plan["documents"].values()
                if item["resource"] == resource
            )
            expected_fields = (
                document["expectedFields"]
                if request["expect"].get("postState") == "transformed"
                else document["fields"]
            )
            if (
                status != request["expect"]["status"]
                or not isinstance(body, dict)
                or not _timestamp(body.get("updateTime"))
                or body.get("name") != resource
                or not _exact(body.get("fields"), expected_fields)
            ):
                issues.append(f"{index}:poststate")
        elif kind == "cleanup-ownership-read":
            resource = _resource_for(request)
            document = next(
                item
                for item in plan["documents"].values()
                if item["resource"] == resource
            )
            expected_fields = (
                document["expectedFields"]
                if document["transformCount"] == 500
                else document["fields"]
            )
            if status == 404:
                if not _typed_absence(body):
                    issues.append(f"{index}:cleanup-absence")
            elif (
                status != 200
                or not isinstance(body, dict)
                or body.get("name") != resource
                or not _timestamp(body.get("updateTime"))
                or not _exact(body.get("fields"), expected_fields)
            ):
                issues.append(f"{index}:cleanup-owner")
        elif kind == "cleanup-conditional-delete" and status != 200:
            issues.append(f"{index}:cleanup-delete")
        elif kind == "cleanup-verify-absence" and not (
            status == 404 and _typed_absence(body)
        ):
            issues.append(f"{index}:cleanup-verify")
    return issues


def compare_rows(
    left_plan: dict[str, Any],
    left_rows: list[dict[str, Any]],
    right_plan: dict[str, Any],
    right_rows: list[dict[str, Any]],
    *,
    left_recovery: list[dict[str, Any]] | None = None,
    right_recovery: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate both complete journals before classifying typed differences."""
    result = {
        "kind": "fs-commit-transform-semantic-kernel-v2",
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
        _validate_shapes(left_plan, left_rows, left_plan["observation"])
        _validate_shapes(right_plan, right_rows, right_plan["observation"])
        if (left_recovery is None) != (right_recovery is None):
            raise ValueError("recovery pair incomplete")
        if left_recovery is not None:
            _validate_shapes(left_plan, left_recovery, left_plan["recovery"])
            _validate_shapes(right_plan, right_recovery or [], right_plan["recovery"])
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        result["errors"].append("invalid-binding-or-journal")
        return result

    left_issues = _semantic_issues(left_plan, left_rows, left_plan["observation"])
    right_issues = _semantic_issues(right_plan, right_rows, right_plan["observation"])
    if left_recovery is not None:
        left_issues.extend(
            _semantic_issues(left_plan, left_recovery, left_plan["recovery"])
        )
        right_issues.extend(
            _semantic_issues(right_plan, right_recovery or [], right_plan["recovery"])
        )
    if left_issues or right_issues:
        result["classification"] = "SEMANTIC_MISMATCH"
        result["errors"].extend(left_issues + right_issues)
        return result

    pairs = list(zip(left_rows, right_rows, strict=True))
    if left_recovery is not None:
        pairs.extend(zip(left_recovery, right_recovery or [], strict=True))
    for index, (left, right) in enumerate(pairs):
        left_value = {
            "status": left["status"],
            "body": _canonical_body(
                left["body"], left_plan, kind=left["request"]["kind"]
            ),
        }
        right_value = {
            "status": right["status"],
            "body": _canonical_body(
                right["body"], right_plan, kind=right["request"]["kind"]
            ),
        }
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
