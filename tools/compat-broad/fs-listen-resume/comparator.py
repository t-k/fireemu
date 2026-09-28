"""Comparator boundary for the offline O6 preparation contract.

This version intentionally cannot classify receipts as a production match.
"""

from __future__ import annotations

from typing import Any

from .manifest import digest, validate_plan

_OBSERVED_FIELDS = {"collector", "transport", "bounds", "cleanup", "events"}


def _errors(plan: dict[str, Any], receipt: Any) -> list[str]:
    if not isinstance(receipt, dict):
        return ["receipt-shape"]
    errors: list[str] = []
    if receipt.get("schema") != "o6-listen-resume-preparation-v2":
        errors.append("receipt-shape")
    if receipt.get("caseId") != plan.get("caseId") or receipt.get(
        "planDigest"
    ) != digest(plan):
        errors.append("plan-binding")
    if receipt.get("status") != "PREPARATION_ONLY":
        errors.append("status")
    if receipt.get("productionExecuted") is not False:
        errors.append("production-executed")
    if _OBSERVED_FIELDS & receipt.keys():
        errors.append("observed-fields")
    if receipt.get("sdk") != plan.get("sdk") or receipt.get("shadow") != plan.get(
        "shadow"
    ):
        errors.append("sdk-binding")
    if receipt.get("sourceBinding") != plan.get("sourceBinding"):
        errors.append("source-binding")
    if receipt.get("transportBinding") != plan.get("transportBinding"):
        errors.append("transport-binding")
    if receipt.get("unsupportedObligations") != plan.get("unsupportedObligations"):
        errors.append("obligations-binding")
    if not isinstance(receipt.get("expectedLogicalEvents"), list):
        errors.append("expected-events-shape")
    return errors


def compare_receipts(
    plan: dict[str, Any], left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    result = {
        "kind": "o6-listen-resume-preparation-v2",
        "semanticOnly": True,
        "promotionReady": False,
        "acquisitionValidated": False,
        "classification": "PREPARATION_ONLY",
        "errors": [],
        "rows": [],
    }
    if not validate_plan(plan):
        result["errors"] = ["plan-invalid"]
        return result
    errors = _errors(plan, left) + _errors(plan, right)
    if errors:
        result["errors"] = sorted(set(errors))
    elif left["expectedLogicalEvents"] != right["expectedLogicalEvents"]:
        result["errors"] = ["preparation-only"]
    return result
