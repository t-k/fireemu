"""Offline semantic kernel only; acquisition and cleanup require separate validation."""

from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime

from compiler import compile_limits_plan

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")


def _exact(a, b):
    return json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(
        b, sort_keys=True, allow_nan=False
    )


def _validated(plan, rows):
    resource = plan["documents"]["exact-document-boundary"]["resource"]
    parts = resource.split("/")
    expected = compile_limits_plan(parts[1], parts[3], plan["nonce"])
    if not _exact(plan, expected):
        raise ValueError("compiler plan drift")
    operations = plan["localGatePlan"]["jobs"]["limits"]["observation"]
    if len(rows) != len(operations):
        raise ValueError("incomplete observation journal")
    for index, (row, operation) in enumerate(zip(rows, operations, strict=True)):
        if (
            type(row.get("index")) is not int
            or row["index"] != index
            or not _exact(row.get("request"), operation)
            or row.get("complete") is not True
            or row.get("failure") is not None
            or type(row.get("status")) is not int
            or not 100 <= row["status"] <= 599
            or "body" not in row
        ):
            raise ValueError("incomplete or unbound observation")
        json.dumps(row["body"], allow_nan=False)


def _time(value):
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    base, _, fraction = value[:-1].partition(".")
    try:
        return (
            datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC),
            fraction.ljust(9, "0"),
        )
    except ValueError:
        return None


def _normalized(plan, rows):
    resources = {doc["resource"]: case for case, doc in plan["documents"].items()}
    times = {}
    for row in rows:
        body = row["body"]
        resource = row["request"]["path"].split("?", 1)[0].removeprefix("/v1/")
        if (
            row["status"] == 200
            and isinstance(body, dict)
            and body.get("name") == resource
        ):
            for key in ("createTime", "updateTime"):
                value = _time(body.get(key))
                if value is not None:
                    times.setdefault(resource, set()).add(value)
    ranks = {
        resource: {value: i for i, value in enumerate(sorted(values))}
        for resource, values in times.items()
    }
    result = []
    for row in rows:
        body = copy.deepcopy(row["body"])
        resource = row["request"]["path"].split("?", 1)[0].removeprefix("/v1/")
        metadata = {}
        # Normalized values live outside the raw body to prevent literal collisions.
        if (
            row["status"] == 200
            and isinstance(body, dict)
            and body.get("name") == resource
        ):
            metadata["name"] = resources[resource]
            del body["name"]
            fields = body.get("fields")
            if isinstance(fields, dict) and _exact(
                fields.get("_sharedOwner"), {"referenceValue": resource}
            ):
                metadata["owner"] = resources[resource]
                del fields["_sharedOwner"]
            for key in ("createTime", "updateTime"):
                value = _time(body.get(key))
                if value is not None:
                    metadata[key] = ranks[resource][value]
                    del body[key]
        result.append({"status": row["status"], "body": body, "metadata": metadata})
    return result


def compare_rows(production_plan, production_rows, local_plan, local_rows):
    """No input is asserted to be production evidence merely by calling this function."""
    result = {
        "kind": "fs-write-limits-semantic-kernel-v1",
        "semanticOnly": True,
        "promotionReady": False,
        "acquisitionValidated": False,
        "classification": "INDETERMINATE",
        "rows": [],
        "errors": [],
    }
    try:
        _validated(production_plan, production_rows)
        _validated(local_plan, local_rows)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
        result["errors"].append(type(error).__name__)
        return result
    left = _normalized(production_plan, production_rows)
    right = _normalized(local_plan, local_rows)
    for index, (a, b) in enumerate(zip(left, right, strict=True)):
        raw_a = {k: production_rows[index][k] for k in ("status", "body")}
        raw_b = {k: local_rows[index][k] for k in ("status", "body")}
        classification = (
            "SEMANTIC_MISMATCH"
            if not _exact(a, b)
            else "MATCH"
            if _exact(raw_a, raw_b)
            else "EXPECTED_NONDETERMINISM"
        )
        result["rows"].append({"index": index, "classification": classification})
    classes = {row["classification"] for row in result["rows"]}
    result["classification"] = next(
        c
        for c in ("SEMANTIC_MISMATCH", "EXPECTED_NONDETERMINISM", "MATCH")
        if c in classes
    )
    return result
