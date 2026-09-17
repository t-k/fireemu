"""Offline semantic comparator for bound Listen receipts."""

from __future__ import annotations

from typing import Any

from manifest import digest, validate_plan

_EVENT_FIELDS = (
    "snapshotType",
    "document",
    "revision",
    "changeKind",
    "oldIndex",
    "newIndex",
    "lifecycle",
    "errorCode",
)


def _normalized(receipt: dict[str, Any], owned: set[str]) -> list[dict[str, Any]]:
    result = []
    for event in receipt["events"]:
        if event.get("document") is not None and event["document"] not in owned:
            raise ValueError("foreign-resource")
        result.append({field: event.get(field) for field in _EVENT_FIELDS})
    return result


def _valid_receipt(plan: dict[str, Any], receipt: Any) -> list[str]:
    errors = []
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != "o6-listen-resume-receipt-v1"
    ):
        return ["receipt-shape"]
    if receipt.get("caseId") != plan.get("caseId") or receipt.get(
        "planDigest"
    ) != digest(plan):
        errors.append("plan-binding")
    if type(receipt.get("productionExecuted")) is not bool:
        errors.append("production-executed")
    collector = receipt.get("collector")
    if not isinstance(collector, dict) or collector.get("complete") is not True:
        errors.append("collector-incomplete")
    transport = receipt.get("transport")
    if (
        not isinstance(transport, dict)
        or transport.get("interruptionObserved") is not True
    ):
        errors.append("transport-interruption-unobserved")
    if not isinstance(receipt.get("events"), list) or not isinstance(
        receipt.get("cleanup"), dict
    ):
        errors.append("receipt-shape")
    elif collector.get("complete") is True and collector.get("eventCount") != len(
        receipt["events"]
    ):
        errors.append("event-count")
    return errors


def compare_receipts(
    plan: dict[str, Any], left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    result = {
        "kind": "o6-listen-resume-semantic-kernel-v1",
        "semanticOnly": True,
        "promotionReady": False,
        "acquisitionValidated": False,
        "classification": "INDETERMINATE",
        "errors": [],
        "rows": [],
    }
    if not validate_plan(plan):
        result["errors"].append("plan-invalid")
        return result
    left_errors = _valid_receipt(plan, left)
    right_errors = _valid_receipt(plan, right)
    if left_errors or right_errors:
        result["errors"] = sorted(set(left_errors + right_errors))
        return result
    owned = {item["path"] for item in plan["ownedResources"]}
    try:
        left_events = _normalized(left, owned)
        right_events = _normalized(right, owned)
    except ValueError as error:
        result["errors"] = [str(error)]
        return result
    if left["cleanup"] != right["cleanup"]:
        result["errors"].append("cleanup-binding")
        return result
    result["rows"] = [
        {"index": index, "classification": "MATCH" if a == b else "SEMANTIC_MISMATCH"}
        for index, (a, b) in enumerate(zip(left_events, right_events))
    ]
    if len(left_events) != len(right_events):
        result["classification"] = "SEMANTIC_MISMATCH"
        return result
    result["classification"] = (
        "MATCH" if left_events == right_events else "SEMANTIC_MISMATCH"
    )
    return result
