"""Fail-closed placeholder until a typed production collector is reviewed."""

from __future__ import annotations

from typing import Any

from o5_rules_case import validate_plan


def compare_receipts(production: Any, local: Any, plan: Any) -> dict[str, Any]:
    """Never classify uncollected, caller-supplied data as semantic evidence."""
    result = {
        "kind": "fs-rules-publication-preparation-v1",
        "status": "PREPARATION_ONLY",
        "classification": "INDETERMINATE",
        "productionExecuted": False,
        "productionReady": False,
        "rows": [],
        "errors": ["typed-production-collector-unavailable"],
    }
    try:
        validate_plan(plan)
    except (TypeError, ValueError):
        result["errors"].append("plan-drift")
    return result
