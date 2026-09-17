"""Stable offline comparison for preparation receipts."""

from __future__ import annotations

import re
from typing import Any

CONTRACT = "auth-settings-v1"
_DYNAMIC = re.compile(r"^(?:local|prod)-[a-z0-9-]+$")


def _stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: _stable(v)
            for k, v in sorted(value.items())
            if k not in {"timestamp", "nonce", "token", "idToken", "refreshToken"}
        }
    if isinstance(value, list):
        return sorted((_stable(v) for v in value), key=repr)
    if isinstance(value, str) and _DYNAMIC.fullmatch(value):
        return "$dynamic"
    return value


def compare(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    required = (
        "contract",
        "caseId",
        "status",
        "productionExecuted",
        "operations",
        "cleanup",
    )
    if any(key not in left or key not in right for key in required):
        return {
            "contract": CONTRACT,
            "classification": "INDETERMINATE",
            "reason": "binding-missing",
        }
    if (
        left.get("contract") != CONTRACT
        or right.get("contract") != CONTRACT
        or left.get("caseId") != right.get("caseId")
    ):
        return {
            "contract": CONTRACT,
            "classification": "INDETERMINATE",
            "reason": "contract-binding-mismatch",
        }
    if (
        left.get("productionExecuted") is not False
        or right.get("productionExecuted") is not False
    ):
        return {
            "contract": CONTRACT,
            "classification": "INDETERMINATE",
            "reason": "production-receipt-not-admissible",
        }
    if (
        left.get("cleanup", {}).get("complete") is not True
        or right.get("cleanup", {}).get("complete") is not True
    ):
        return {
            "contract": CONTRACT,
            "classification": "INDETERMINATE",
            "reason": "cleanup-incomplete",
        }
    if _stable(left) == _stable(right):
        return {
            "contract": CONTRACT,
            "classification": "MATCH",
            "productionCompared": False,
        }
    return {
        "contract": CONTRACT,
        "classification": "SEMANTIC_MISMATCH",
        "productionCompared": False,
    }
