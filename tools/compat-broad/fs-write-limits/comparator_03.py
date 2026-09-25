"""Offline semantic kernel for FS-WRITE-LIMITS-03.

The contract is the one O7 reviewed for limits-02: both plans are regenerated
from the compiler, every ordered request including its typed body is checked,
and a complete response journal is required. Normalized document identity and
server timestamps may differ as `EXPECTED_NONDETERMINISM`; everything else,
message text included, is significant.

One field is added, and it is additive only. `structural` reports, per row, the
status and post-state shape with message text removed. It never changes
`classification`. It exists because this campaign's whole point is whether
production continues past a bad BatchWrite item, and a known diagnostic wording
difference would otherwise hide that answer inside a `SEMANTIC_MISMATCH`.

Calling this function asserts nothing about where either journal came from.
"""

from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime

from compiler_03 import compile_limits_plan, dispatched_operations

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")


def _exact(a, b):
    return json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(
        b, sort_keys=True, allow_nan=False
    )


def _validated(plan, rows):
    if (
        not isinstance(plan, dict)
        or not isinstance(plan.get("documents"), dict)
        or not plan["documents"]
        or not isinstance(rows, list)
    ):
        raise ValueError("non-empty document plan and observation list required")
    resource = next(iter(plan["documents"].values()))["resource"]
    parts = resource.split("/")
    expected = compile_limits_plan(parts[1], parts[3], plan["nonce"], plan["part"])
    if not _exact(plan, expected):
        raise ValueError("compiler plan drift")
    operations = dispatched_operations(plan)
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


def _batch_writes(plan, row):
    request = plan["requests"][row["index"]]
    if request["kind"] != "batch-write":
        return None
    return request["body"]["writes"]


def _ranks(plan, rows):
    """Rank every observed server timestamp within its own resource."""
    times = {}

    def note(resource, value):
        parsed = _time(value)
        if parsed is not None:
            times.setdefault(resource, set()).add(parsed)

    for row in rows:
        body = row["body"]
        writes = _batch_writes(plan, row)
        if writes is not None:
            results = body.get("writeResults") if isinstance(body, dict) else None
            if isinstance(results, list) and len(results) == len(writes):
                for write, result in zip(writes, results, strict=True):
                    update = write.get("update") if isinstance(write, dict) else None
                    if isinstance(update, dict) and isinstance(result, dict):
                        note(update["name"], result.get("updateTime"))
            continue
        resource = row["request"]["path"].split("?", 1)[0].removeprefix("/v1/")
        if (
            row["status"] == 200
            and isinstance(body, dict)
            and body.get("name") == resource
        ):
            for key in ("createTime", "updateTime"):
                note(resource, body.get(key))
    return {
        resource: {value: index for index, value in enumerate(sorted(values))}
        for resource, values in times.items()
    }


def _normalized(plan, rows):
    resources = {doc["resource"]: case for case, doc in plan["documents"].items()}
    ranks = _ranks(plan, rows)
    result = []
    for row in rows:
        body = copy.deepcopy(row["body"])
        metadata = {}
        writes = _batch_writes(plan, row)
        if writes is not None:
            metadata["case"] = plan["requests"][row["index"]]["case"]
            results = body.get("writeResults") if isinstance(body, dict) else None
            if isinstance(results, list) and len(results) == len(writes):
                versions = []
                for write, entry in zip(writes, results, strict=True):
                    update = write.get("update") if isinstance(write, dict) else None
                    value = (
                        _time(entry.get("updateTime"))
                        if isinstance(entry, dict)
                        else None
                    )
                    if isinstance(update, dict) and value is not None:
                        versions.append(ranks[update["name"]][value])
                        del entry["updateTime"]
                    else:
                        versions.append(None)
                metadata["writeResultVersions"] = versions
            result.append({"status": row["status"], "body": body, "metadata": metadata})
            continue
        resource = row["request"]["path"].split("?", 1)[0].removeprefix("/v1/")
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


def _structural(plan, rows):
    """Status and post-state shape with diagnostic wording removed."""
    view = []
    for row in rows:
        body = row["body"]
        error = body.get("error") if isinstance(body, dict) else None
        entry = {
            "status": row["status"],
            "errorCode": error.get("code") if isinstance(error, dict) else None,
            "errorStatus": error.get("status") if isinstance(error, dict) else None,
        }
        writes = _batch_writes(plan, row)
        if writes is not None:
            statuses = body.get("status") if isinstance(body, dict) else None
            results = body.get("writeResults") if isinstance(body, dict) else None
            entry["itemCodes"] = (
                [
                    item.get("code", 0) if isinstance(item, dict) else None
                    for item in statuses
                ]
                if isinstance(statuses, list)
                else None
            )
            entry["writeResultCount"] = (
                len(results) if isinstance(results, list) else None
            )
        else:
            resource = row["request"]["path"].split("?", 1)[0].removeprefix("/v1/")
            entry["documentPresent"] = (
                row["status"] == 200
                and isinstance(body, dict)
                and body.get("name") == resource
            )
        view.append(entry)
    return view


def _compare_rows(production_plan, production_rows, local_plan, local_rows):
    result = {
        "kind": "fs-write-limits-03-semantic-kernel-v1",
        "campaignId": "FS-WRITE-LIMITS-03",
        "semanticOnly": True,
        "promotionReady": False,
        "acquisitionValidated": False,
        "classification": "INDETERMINATE",
        "structuralClassification": "INDETERMINATE",
        "rows": [],
        "errors": [],
    }
    try:
        _validated(production_plan, production_rows)
        _validated(local_plan, local_rows)
        # Distinct compiler parts describe different semantic scenarios.
        # Reject a pair before normalization or producing row comparisons.
        if production_plan["part"] != local_plan["part"]:
            raise ValueError("campaign parts differ")
        if len(production_rows) != len(local_rows):
            raise ValueError("observation counts differ")
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
        result["errors"].append(type(error).__name__)
        return result
    left = _normalized(production_plan, production_rows)
    right = _normalized(local_plan, local_rows)
    left_shape = _structural(production_plan, production_rows)
    right_shape = _structural(local_plan, local_rows)
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
        result["rows"].append(
            {
                "index": index,
                "kind": production_plan["requests"][index]["kind"],
                "classification": classification,
                "structural": "MATCH"
                if _exact(left_shape[index], right_shape[index])
                else "SEMANTIC_MISMATCH",
            }
        )
    for key, field in (
        ("classification", "classification"),
        ("structuralClassification", "structural"),
    ):
        classes = {row[field] for row in result["rows"]}
        result[key] = next(
            c
            for c in ("SEMANTIC_MISMATCH", "EXPECTED_NONDETERMINISM", "MATCH")
            if c in classes
        )
    return result


def compare_rows(production_plan, production_rows, local_plan, local_rows):
    """Compare validated observations without asserting production evidence."""
    try:
        return _compare_rows(production_plan, production_rows, local_plan, local_rows)
    except RecursionError:
        return {
            "kind": "fs-write-limits-03-semantic-kernel-v1",
            "campaignId": "FS-WRITE-LIMITS-03",
            "semanticOnly": True,
            "promotionReady": False,
            "acquisitionValidated": False,
            "classification": "INDETERMINATE",
            "structuralClassification": "INDETERMINATE",
            "rows": [],
            "errors": ["RecursionError"],
        }
