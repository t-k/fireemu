"""Strict interpretation of the bounded corpus, shared by capture and publication."""

import math
import re

from evidence_common import require
from probe import summarize_aggregation


def validate_aggregate_fields(fields: dict, case: dict) -> None:
    aliases = (
        set(case["expected"])
        if "expected" in case
        else {aggregation["alias"] for aggregation in case["aggregations"]}
    )
    require(set(fields) == aliases, "missing or unexpected aggregate alias")
    for alias, value in fields.items():
        require(
            isinstance(value, dict) and len(value) == 1, "invalid aggregate Value oneof"
        )
        kind, scalar = next(iter(value.items()))
        allowed = {
            "count": {"integerValue"},
            "sum": {"integerValue", "doubleValue"},
            "avg": {"doubleValue", "nullValue"},
        }[alias]
        require(kind in allowed, "invalid aggregate scalar type")
        if kind == "integerValue":
            require(
                isinstance(scalar, str)
                and re.fullmatch(r"-?(0|[1-9][0-9]*)", scalar) is not None,
                "invalid integer encoding",
            )
            require(-(2**63) <= int(scalar) < 2**63, "integer out of range")
        elif kind == "doubleValue":
            require(
                type(scalar) in [int, float] and math.isfinite(scalar),
                "invalid finite double",
            )
        else:
            require(scalar is None, "invalid null encoding")


def query_matches(case: dict, status: int, raw: object) -> bool:
    """Reject malformed responses; retain supported well-formed mismatches as false."""
    require(type(status) is int, "invalid HTTP status")
    if status == 200:
        fields = summarize_aggregation(raw)
        validate_aggregate_fields(fields, case)
        return fields == case.get("expected")

    expected = case.get("expectedError")
    if not isinstance(expected, dict) or status != 400:
        raise ValueError("unexpected query HTTP status")
    if isinstance(raw, list):
        require(len(raw) == 1, "invalid error stream")
        raw = raw[0]
    if not isinstance(raw, dict) or set(raw) != {"error"}:
        raise ValueError("invalid error envelope")
    error = raw["error"]
    require(
        isinstance(error, dict) and set(error) == {"code", "message", "status"},
        "unsupported error fields",
    )
    require(
        type(error["code"]) is int
        and error["code"] == status
        and isinstance(error["message"], str)
        and bool(error["message"].strip())
        and isinstance(error["status"], str)
        and bool(error["status"].strip()),
        "invalid error details",
    )
    return status == expected["httpStatus"] and error["status"] == expected["status"]
