"""Comparator for FS-CONFIG-LIFECYCLE collection records.

A record is `{executionKind, collection}` where `collection` is a result written by
`lifecycle_collector.collect`. The comparator lines the two records up case by case
on the rows the collector marked `role: case`, and compares HTTP status, typed error
code and the type shape of the body: field presence, JSON types and enum spelling.
Values are never compared; the shape already collapsed them.

It can classify a comparison as MATCH only when one side executed on the fixed
production wire. Every other pairing is PREPARATION_ONLY, so a local rehearsal
compared against a fake or against another local run can never read as production
evidence. Promotion is never decided here.
"""

from __future__ import annotations

import json
from typing import Any

from .cases import compile_cases
from .manifest import SCHEMA as MANIFEST_SCHEMA
from .manifest import compile_manifest
from .surface_matrix import CASE_ID, digest

SCHEMA = "fs-config-lifecycle-comparison-v2"
PRODUCTION_KIND = "fixed-production-wire"
LOCAL_KIND = "injected-local-transport"
EXECUTION_KINDS = (PRODUCTION_KIND, LOCAL_KIND)

MATCH = "MATCH"
MISMATCH = "MISMATCH"
INDETERMINATE = "INDETERMINATE"
EXPECTED_LOCAL_DEVIATION = "EXPECTED_LOCAL_DEVIATION"

_VALUE_NORMALIZED = (
    "earliestVersionTime",
    "etag",
    "createTime",
    "updateTime",
    "deleteTime",
    "uid",
    "snapshotTime",
    "startTime",
    "endTime",
    "name",
)

COMPARISON_CONTRACT: dict[str, Any] = {
    "kind": "fs-config-lifecycle-comparison-contract-v2",
    "valueNormalizedFields": list(_VALUE_NORMALIZED),
    "valueNormalizedRule": (
        "Presence and JSON type are compared; the value is not. These fields either "
        "advance on their own, identify one provisioning instance or carry the run "
        "nonce, so an equal value would be accidental and an unequal value is not "
        "evidence of incompatibility."
    ),
    "significant": [
        "HTTP status",
        "typed error code and status",
        "field presence and absence",
        "JSON types",
        "array order",
        "enum spelling",
    ],
    "reportedButNotRequiredToMatch": [
        "error message prose",
        "long-running operation metadata progress counters",
        "response latency",
        "the number of operation polls",
    ],
    "indeterminate": [
        "A case one side never reached is indeterminate, never a mismatch.",
        "A transport failure, credential refusal or quota refusal is indeterminate.",
        "A run whose cleanup did not complete is indeterminate as a whole.",
    ],
    "expectedLocalDeviation": (
        "A case the classification matrix says the local runtime refuses is reported "
        "as an expected local deviation only when the local side answered exactly "
        "that typed UNIMPLEMENTED refusal and the production side served the request "
        "with a 2xx; it is neither a match nor a mismatch and never counts toward "
        "one. A refusal on both sides is compared like any other row."
    ),
    "matchRequires": (
        "One side executed on the fixed production wire, both sides completed their "
        "cleanup, and every case is MATCH or EXPECTED_LOCAL_DEVIATION."
    ),
}


def _case_rows(collection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in collection.get("rows", []):
        if row.get("role") == "case" and row.get("case") not in rows:
            rows[row["case"]] = row
    return rows


def _record_errors(record: Any, side: str) -> list[str]:
    if not isinstance(record, dict):
        return [f"{side}-record-shape"]
    errors = []
    if record.get("executionKind") not in EXECUTION_KINDS:
        errors.append(f"{side}-execution-kind")
    collection = record.get("collection")
    if not isinstance(collection, dict) or collection.get("campaignId") != CASE_ID:
        errors.append(f"{side}-collection-shape")
    return errors


def compare_rows(
    local: dict[str, Any], production: dict[str, Any], nonce: str
) -> list[dict[str, Any]]:
    expected_local = {
        case["id"]: case["expectedLocal"] for case in compile_cases(nonce)
    }
    local_rows, production_rows = _case_rows(local), _case_rows(production)
    rows = []
    for case_id, expected in expected_local.items():
        left, right = local_rows.get(case_id), production_rows.get(case_id)
        row: dict[str, Any] = {
            "case": case_id,
            "local": _summary(left),
            "production": _summary(right),
        }
        if (
            left is None
            or right is None
            or not left["complete"]
            or not right["complete"]
        ):
            row["classification"] = INDETERMINATE
        elif (
            expected["outcome"] == "not-served"
            and left["typedError"] is not None
            and (left["typedError"] or {}).get("status") == "UNIMPLEMENTED"
            and right["typedError"] is None
            and type(right["status"]) is int
            and 200 <= right["status"] < 300
        ):
            # Only when production served the request that the classification
            # matrix says the local runtime refuses. A refusal on both sides is
            # compared like any other row, so it reads MATCH or MISMATCH and never
            # hides behind the expected deviation.
            row["classification"] = EXPECTED_LOCAL_DEVIATION
            row["reason"] = expected.get("refusalReason")
        elif (
            left["status"] == right["status"]
            and left["typedError"] == right["typedError"]
            and left["shape"] == right["shape"]
        ):
            row["classification"] = MATCH
        else:
            row["classification"] = MISMATCH
            row["differs"] = [
                key
                for key in ("status", "typedError", "shape")
                if left[key] != right[key]
            ]
        rows.append(row)
    return rows


def _summary(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "status": row.get("status"),
        "typedError": row.get("typedError"),
        "shapeDigest": digest(row.get("shape")),
        "complete": row.get("complete"),
    }


def compare(
    manifest: dict[str, Any], local: Any, production: Any, nonce: str
) -> dict[str, Any]:
    """Compare a local record with a production record under a drift-checked manifest."""
    result: dict[str, Any] = {
        "kind": SCHEMA,
        "classification": "PREPARATION_ONLY",
        "promotionReady": False,
        "acquisitionValidated": False,
        "productionUnobservedConditionsReduced": 0,
        "contract": COMPARISON_CONTRACT,
        "rows": [],
        "errors": [],
    }
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        result["errors"] = ["manifest-invalid"]
        return result
    try:
        expected = compile_manifest(nonce)
    except ValueError:
        result["errors"] = ["nonce-invalid"]
        return result
    if json.loads(json.dumps(manifest)) != json.loads(json.dumps(expected)):
        result["errors"] = ["manifest-drift"]
        return result
    errors = _record_errors(local, "local") + _record_errors(production, "production")
    if errors:
        result["errors"] = sorted(set(errors))
        return result
    if local["executionKind"] != LOCAL_KIND or production["executionKind"] != (
        PRODUCTION_KIND
    ):
        result["errors"] = ["preparation-only"]
        return result
    rows = compare_rows(local["collection"], production["collection"], nonce)
    result["rows"] = rows
    result["localCleanupComplete"] = local["collection"].get("cleanupComplete") is True
    result["productionCleanupComplete"] = (
        production["collection"].get("cleanupComplete") is True
    )
    classes = {row["classification"] for row in rows}
    if not result["localCleanupComplete"] or not result["productionCleanupComplete"]:
        result["classification"] = INDETERMINATE
    elif classes <= {MATCH, EXPECTED_LOCAL_DEVIATION}:
        result["classification"] = MATCH
    elif MISMATCH in classes:
        result["classification"] = MISMATCH
    else:
        result["classification"] = INDETERMINATE
    result["acquisitionValidated"] = result["classification"] in (MATCH, MISMATCH)
    return result
