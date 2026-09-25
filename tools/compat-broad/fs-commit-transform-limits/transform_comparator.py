"""Strict, credential-free comparison contract for the O3 compiler."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from typing import Any
from urllib.parse import quote

from transform_compiler import compile_plan

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
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value[:19] + "+0000", "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return False
    return True


def _instant(value: str) -> tuple[str, str]:
    return value[:19], value[19:-1].removeprefix(".").ljust(9, "0")


def _canonical_body(body: Any, plan: dict[str, Any], *, kind: str) -> Any:
    """Tag every literal before replacing explicitly declared protocol slots.

    Internal metadata tokens cannot collide with any JSON literal, including a
    user-supplied object that resembles the token's serialized representation.

    A typed absence response embeds the requested resource name inside its
    message. Only that one substring is replaced by the same identity label the
    `name` slot uses; the rest of the message is still compared literally, and a
    message naming no declared resource is not normalized at all.
    """
    absence_kinds = {
        "preflight-typed-absence",
        "cleanup-verify-absence",
    }
    document_kinds = {
        "create-only-patch",
        "baseline-readback",
        "poststate-readback",
        "poststate-control-readback",
        "cleanup-ownership-read",
    }
    labels = {item["resource"]: label for label, item in plan["documents"].items()}

    def project(value: Any, path: tuple[Any, ...]) -> Any:
        identity = kind in document_kinds and path in {
            ("name",),
            ("fields", "_sharedOwner", "referenceValue"),
        }
        timestamp = (
            kind in document_kinds and path in {("createTime",), ("updateTime",)}
        ) or (
            kind == "commit-transform"
            and (
                path == ("commitTime",)
                or len(path) == 3
                and path[0] == "writeResults"
                and path[2] == "updateTime"
            )
        )
        message = kind in absence_kinds and path == ("error", "message")
        if identity and isinstance(value, str) and value in labels:
            return ("identity", labels[value])
        if message and isinstance(value, str):
            for resource, label in sorted(
                labels.items(), key=lambda item: len(item[0]), reverse=True
            ):
                if resource in value:
                    head, _, tail = value.partition(resource)
                    return ("message", head, ("identity", label), tail)
        if timestamp and _timestamp(value):
            return ("metadata", path[-1])
        if isinstance(value, dict):
            return (
                "object",
                tuple(
                    (key, project(item, (*path, key)))
                    for key, item in sorted(value.items())
                ),
            )
        if isinstance(value, list):
            return (
                "array",
                tuple(
                    project(item, (*path, index)) for index, item in enumerate(value)
                ),
            )
        return ("literal", type(value).__name__, value)

    return project(body, ())


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
    body = prior.get("body") if isinstance(prior, dict) else None
    version = body.get("updateTime") if isinstance(body, dict) else None
    # Require the exact relative target emitted by the resolver, not URL parser
    # equivalence (which can erase hosts, fragments and additional predicates).
    return (
        prior.get("status") == 200
        and _timestamp(version)
        and request.get("path")
        == expected["path"] + "?currentDocument.updateTime=" + quote(version, safe="")
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
        if not _exact(request, expected_copy):
            raise ValueError("cleanup delete request differs")
    elif not _exact(request, expected):
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
    versions: dict[str, str] = {}
    created: dict[str, str] = {}
    for index, (row, request) in enumerate(zip(rows, requests, strict=True)):
        status, body, kind = row["status"], row["body"], request["kind"]
        if (
            isinstance(body, dict)
            and kind
            in {
                "create-only-patch",
                "baseline-readback",
                "poststate-readback",
                "poststate-control-readback",
                "cleanup-ownership-read",
            }
            and status == 200
        ):
            resource = _resource_for(request)
            for key in ("createTime", "updateTime"):
                if (key == "updateTime" or key in body) and not _timestamp(
                    body.get(key)
                ):
                    issues.append(f"{index}:invalid-{key}")
            version = body.get("updateTime")
            if _timestamp(version):
                if resource in versions and _instant(version) != _instant(
                    versions[resource]
                ):
                    issues.append(f"{index}:version-relation")
                versions[resource] = version
            creation = body.get("createTime")
            if _timestamp(creation):
                if resource in created and _instant(creation) != _instant(
                    created[resource]
                ):
                    issues.append(f"{index}:creation-relation")
                if _timestamp(version) and _instant(creation) > _instant(version):
                    issues.append(f"{index}:creation-after-update")
                created[resource] = creation
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
            if expectation["outcome"] == "accepted" and isinstance(body, dict):
                commit = body.get("commitTime")
                results = body.get("writeResults")
                if not isinstance(results, list) or len(results) != len(
                    request["body"]["writes"]
                ):
                    issues.append(f"{index}:write-results")
                elif _timestamp(commit):
                    for write_result in results:
                        update = (
                            write_result.get("updateTime")
                            if isinstance(write_result, dict)
                            else None
                        )
                        if not _timestamp(update) or _instant(update) > _instant(
                            commit
                        ):
                            issues.append(f"{index}:commit-version")
                    resource = request["resources"][0]
                    final_result = results[-1]
                    final_update = (
                        final_result.get("updateTime")
                        if isinstance(final_result, dict)
                        else None
                    )
                    if _timestamp(final_update):
                        if resource in versions and _instant(final_update) <= _instant(
                            versions[resource]
                        ):
                            issues.append(f"{index}:final-write-not-newer")
                        versions[resource] = final_update
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


def _timestamp_relations(plan: dict[str, Any], rows: list[dict[str, Any]]) -> Any:
    """Preserve equality and order of declared timestamps within each resource.

    Ranks describe relations only: independent projects can have independent
    clocks, while an equality becoming an inequality remains observable.
    """
    labels = {item["resource"]: label for label, item in plan["documents"].items()}
    slots: dict[str, list[tuple[Any, tuple[str, str]]]] = {
        label: [] for label in labels.values()
    }
    for index, row in enumerate(rows):
        request, body = row["request"], row["body"]
        if not isinstance(body, dict):
            continue
        kind = request["kind"]
        if kind == "commit-transform":
            resource = request["resources"][0]
            values = [(("commitTime",), body.get("commitTime"))]
            results = body.get("writeResults")
            for number, result in enumerate(
                results if isinstance(results, list) else []
            ):
                if isinstance(result, dict):
                    values.append(
                        (
                            ("writeResults", number, "updateTime"),
                            result.get("updateTime"),
                        )
                    )
        elif kind in {
            "create-only-patch",
            "baseline-readback",
            "poststate-readback",
            "poststate-control-readback",
            "cleanup-ownership-read",
        }:
            resource = _resource_for(request)
            values = [((key,), body.get(key)) for key in ("createTime", "updateTime")]
        else:
            continue
        for path, value in values:
            if _timestamp(value):
                slots[labels[resource]].append(((index, path), _instant(value)))
    projection = {}
    for label, entries in slots.items():
        ranks = {
            instant: rank
            for rank, instant in enumerate(sorted({instant for _, instant in entries}))
        }
        projection[label] = [(slot, ranks[instant]) for slot, instant in entries]
    return projection


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

    left_issues = _semantic_issues(
        left_plan,
        left_rows + (left_recovery or []),
        left_plan["observation"]
        + (left_plan["recovery"] if left_recovery is not None else []),
    )
    right_issues = _semantic_issues(
        right_plan,
        right_rows + (right_recovery or []),
        right_plan["observation"]
        + (right_plan["recovery"] if right_recovery is not None else []),
    )
    if left_issues or right_issues:
        result["classification"] = "SEMANTIC_MISMATCH"
        result["errors"].extend(left_issues + right_issues)
        return result

    if not _exact(
        _timestamp_relations(left_plan, left_rows + (left_recovery or [])),
        _timestamp_relations(right_plan, right_rows + (right_recovery or [])),
    ):
        result["classification"] = "SEMANTIC_MISMATCH"
        result["errors"].append("timestamp-relations-differ")
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
