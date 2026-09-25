"""Derived offline limits comparison for exact current-resource error wording."""

from __future__ import annotations

import copy
import hashlib
import re
import sys
from pathlib import Path

SIBLING = Path(__file__).resolve().parent.parent / "fs-write-limits"
sys.path.insert(0, str(SIBLING))

import comparator as _v1

V1_COMPARATOR = SIBLING / "comparator.py"
V1_PRODUCTION = SIBLING / "production.py"
V2_SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

_NOT_FOUND = re.compile(r'^Document "([^"]+)" not found\.$')
_SIZE_LIMIT = re.compile(
    r"^Document '([^']+)'( cannot be written because its size \(.+\) exceeds .+)$"
)


def _resource(plan, row):
    return row["request"]["path"].split("?", 1)[0].removeprefix("/v1/")


def _error_segments(plan, row, message):
    """Return structured segments only for an exact current-request resource."""
    resource = _resource(plan, row)
    case = {
        document["resource"]: name for name, document in plan["documents"].items()
    }.get(resource)
    if case is None or not isinstance(message, str):
        return None
    match = _NOT_FOUND.fullmatch(message)
    if match is not None and match.group(1) == resource:
        return {
            "grammar": "not-found-double-quoted",
            "segments": [
                'Document "',
                {"slot": "current-resource", "case": case},
                " not found.",
            ],
        }
    match = _SIZE_LIMIT.fullmatch(message)
    if match is not None and match.group(1) == resource:
        return {
            "grammar": "size-limit-single-quoted",
            "segments": [
                "Document '",
                {"slot": "current-resource", "case": case},
                match.group(2),
            ],
        }
    return None


def _normalized(plan, rows):
    result = _v1._normalized(plan, rows)
    for normalized, row in zip(result, rows, strict=True):
        body = row["body"]
        error = body.get("error") if isinstance(body, dict) else None
        segments = (
            _error_segments(plan, row, error.get("message"))
            if isinstance(error, dict)
            else None
        )
        if segments is None:
            continue
        normalized_error = normalized["body"].get("error")
        if not isinstance(normalized_error, dict):
            continue
        normalized_error = copy.deepcopy(normalized_error)
        del normalized_error["message"]
        normalized["body"]["error"] = normalized_error
        normalized["metadata"]["errorMessage"] = segments
    return result


def compare_rows(production_plan, production_rows, local_plan, local_rows):
    """Compare validated rows while deriving a separate v2 semantic result."""
    result = {
        "kind": "fs-write-limits-semantic-kernel-v2",
        "semanticOnly": True,
        "promotionReady": False,
        "acquisitionValidated": False,
        "classification": "INDETERMINATE",
        "rows": [],
        "errors": [],
        "originalContract": "fs-write-limits-semantic-kernel-v1",
        "derivedAnalysis": True,
    }
    try:
        _v1._validated(production_plan, production_rows)
        _v1._validated(local_plan, local_rows)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
        result["errors"].append(type(error).__name__)
        return result
    left = _normalized(production_plan, production_rows)
    right = _normalized(local_plan, local_rows)
    for index, (a, b) in enumerate(zip(left, right, strict=True)):
        raw_a = {key: production_rows[index][key] for key in ("status", "body")}
        raw_b = {key: local_rows[index][key] for key in ("status", "body")}
        classification = (
            "SEMANTIC_MISMATCH"
            if not _v1._exact(a, b)
            else "MATCH"
            if _v1._exact(raw_a, raw_b)
            else "EXPECTED_NONDETERMINISM"
        )
        result["rows"].append({"index": index, "classification": classification})
    classes = {row["classification"] for row in result["rows"]}
    result["classification"] = next(
        classification
        for classification in (
            "SEMANTIC_MISMATCH",
            "EXPECTED_NONDETERMINISM",
            "MATCH",
        )
        if classification in classes
    )
    return result
