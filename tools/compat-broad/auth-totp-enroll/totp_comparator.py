"""Comparator for saved, secret-free local/production-shaped receipts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

_SENSITIVE = ("secret", "otp", "token", "password")


def _normalize(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {name: _normalize(item, name) for name, item in sorted(value.items())}
    if isinstance(value, list):
        return [_normalize(item, key) for item in value]
    if any(part in key.lower() for part in _SENSITIVE) and isinstance(value, str):
        return {"redacted": True, "length": len(value)}
    return value


def compare(left: dict, right: dict) -> dict:
    if not left.get("recordingComplete", False) or not right.get("recordingComplete", False):
        classification = "INCONCLUSIVE"
    elif not left.get("cleanupComplete", False) or not right.get("cleanupComplete", False):
        classification = "INDETERMINATE"
    elif not left.get("rows") or not right.get("rows"):
        classification = "SEMANTIC_MISMATCH"
    else:
        normalized_left = _normalize(left["rows"])
        normalized_right = _normalize(right["rows"])
        same_rows = normalized_left == normalized_right
        if not same_rows:
            classification = "SEMANTIC_MISMATCH"
        elif left["rows"] != right["rows"]:
            classification = "EXPECTED_NONDETERMINISM"
        else:
            classification = "MATCH"
    return {
        "classification": classification,
        "productionExecuted": False,
        "normalizedDigest": hashlib.sha256(
            json.dumps([_normalize(left), _normalize(right)], sort_keys=True).encode()
        ).hexdigest(),
    }
