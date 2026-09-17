"""Stable offline comparison for preparation receipts."""

from __future__ import annotations

from typing import Any

CONTRACT = "auth-settings-v1"


def _stable(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        ignored = {"timestamp", "nonce", "token", "idToken", "refreshToken"}
        return {k: _stable(v, k) for k, v in sorted(value.items()) if k not in ignored}
    if isinstance(value, list):
        return [_stable(v, key) for v in value]
    if key in {"uid", "subject", "localId"} and isinstance(value, str):
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
    if not isinstance(left, dict) or not isinstance(right, dict):
        return {
            "contract": CONTRACT,
            "classification": "INDETERMINATE",
            "reason": "receipt-not-object",
        }
    if any(key not in left or key not in right for key in required):
        return {
            "contract": CONTRACT,
            "classification": "INDETERMINATE",
            "reason": "binding-missing",
        }
    for receipt in (left, right):
        operations = receipt.get("operations")
        if not isinstance(operations, list) or any(
            not isinstance(row, dict)
            or row.get("status") in {None, "transport-error", "incomplete"}
            or row.get("failure") is not None
            for row in operations
        ):
            return {
                "contract": CONTRACT,
                "classification": "INDETERMINATE",
                "reason": "transport-or-incomplete-operation",
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
        not isinstance(left.get("cleanup"), dict)
        or not isinstance(right.get("cleanup"), dict)
        or left["cleanup"].get("complete") is not True
        or right["cleanup"].get("complete") is not True
        or left.get("after") != {}
        or right.get("after") != {}
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
