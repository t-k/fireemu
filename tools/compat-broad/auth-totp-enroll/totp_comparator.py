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
    else:
        same_rows = _normalize(left.get("rows", [])) == _normalize(right.get("rows", []))
        if not same_rows:
            classification = "DIFF"
        elif left.get("cleanupComplete") != right.get("cleanupComplete"):
            classification = "CLEANUP_DIFF"
        else:
            classification = "MATCH"
    return {
        "classification": classification,
        "productionExecuted": False,
        "normalizedDigest": hashlib.sha256(
            json.dumps([_normalize(left), _normalize(right)], sort_keys=True).encode()
        ).hexdigest(),
    }
