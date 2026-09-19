"""Current transport receipt and explicit JSON-only bridge to immutable history."""

import re

from broad_contract import ROOT, compare_program, digest

HTTP_CONTRACT = "bounded-http-v1"
COMPARISON_CONTRACT = "current-http-legacy-json-v1"


def contract():
    paths = ["record-http.mjs", "current-session.mjs", "current_contract.py"]
    import hashlib

    return {
        "id": COMPARISON_CONTRACT,
        "http": HTTP_CONTRACT,
        "inputs": {
            p: hashlib.sha256(
                (ROOT / "tools/compat-broad" / p).read_bytes()
            ).hexdigest()
            for p in paths
        },
        "nonJsonHistoryComparable": False,
    }


def received(value):
    if not isinstance(value, dict) or not isinstance(value.get("http"), dict):
        return False
    wire = value["http"]
    return (
        wire.get("contract") == HTTP_CONTRACT
        and type(wire.get("status")) is int
        and 100 <= wire["status"] <= 599
        and value.get("status") == wire["status"]
        and wire.get("complete") is True
        and wire.get("failure") is None
        and wire.get("truncated") is False
        and wire.get("digestScope") == "full"
        and wire.get("bodyKind") in {"json", "non-json", "empty"}
        and isinstance(wire.get("contentType"), str)
        and wire.get("contentTypeTruncated") is False
        and type(wire.get("receivedBytes")) is int
        and wire["receivedBytes"] >= 0
        and type(wire.get("retainedBytes")) is int
        and wire.get("retainedBytes") == wire["receivedBytes"]
        and isinstance(wire.get("bodySha256"), str)
        and re.fullmatch("[0-9a-f]{64}", wire["bodySha256"]) is not None
    )


def compare_current(program, old, actual, expected):
    """Only fully captured JSON uses the byte-preserved legacy normalization bridge."""
    projected = {"steps": {}}
    for key, value in actual.get("steps", {}).items():
        if received(value) and value["http"]["bodyKind"] == "json":
            projected["steps"][key] = {k: v for k, v in value.items() if k != "http"}
        else:
            projected["steps"][key] = {"status": 0, "code": "probe-error"}
    rows = compare_program(program, old, projected, expected)
    for row in rows:
        key = row["id"].split("#", 1)[1]
        value = actual.get("steps", {}).get(key)
        row["comparisonContract"] = COMPARISON_CONTRACT
        row["collectionComplete"] = received(value)
        if value is not None:
            row["actual"] = value
        if (
            digest(program) == digest(old)
            and received(value)
            and value["http"]["bodyKind"] != "json"
        ):
            row.update(
                status="indeterminate",
                reason="no-compatible-historical-body-contract",
                localExecution="observed",
            )
    return rows
