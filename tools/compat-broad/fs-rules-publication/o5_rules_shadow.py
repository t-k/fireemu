"""Offline illustration of expected observation statuses, never a receipt."""

from __future__ import annotations

from typing import Any

from o5_rules_case import digest, validate_plan


def shadow_receipt(plan: dict[str, Any]) -> dict[str, Any]:
    validate_plan(plan)
    return {
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "planDigest": digest(plan),
        "observations": [
            {"kind": operation["kind"], "expectedStatus": operation["expect"]["status"]}
            for operation in plan["observation"]
        ],
    }


def validate_shadow(case: Any, plan: Any) -> bool:
    try:
        return case == shadow_receipt(plan)
    except (TypeError, ValueError):
        return False
