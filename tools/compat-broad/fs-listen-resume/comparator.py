"""Offline semantic comparator for bound Listen receipts."""

from __future__ import annotations

from typing import Any

from .manifest import digest, validate_plan

_EVENT_FIELDS = (
    "snapshotType",
    "document",
    "revision",
    "changeKind",
    "oldIndex",
    "newIndex",
    "lifecycle",
    "errorCode",
    "tokenCase",
)
_EXPECTED_REVISIONS = {"one": {0, 1, 2}, "two": {0}}
_ERRORS = {
    "stale-token": "FAILED_PRECONDITION",
    "compacted-token": "FAILED_PRECONDITION",
    "session-reset": "ABORTED",
}


def _normalized(receipt: dict[str, Any], owned: set[str]) -> list[dict[str, Any]]:
    result = []
    for event in receipt["events"]:
        if not isinstance(event, dict):
            raise TypeError("event-shape")
        if event.get("document") is not None and event["document"] not in owned:
            raise ValueError("foreign-resource")
        if not isinstance(event, dict) or any(
            field not in event for field in _EVENT_FIELDS
        ):
            raise ValueError("event-shape")
        snapshot = event["snapshotType"]
        if snapshot not in {"initial", "delta", "reset", "error"}:
            raise ValueError("event-shape")
        if snapshot == "error":
            if (
                event["document"] is not None
                or event["revision"] is not None
                or event["tokenCase"] not in _ERRORS
            ):
                raise ValueError("event-shape")
            if event["errorCode"] != _ERRORS[event["tokenCase"]]:
                raise ValueError("negative-token-semantics")
        elif (
            not isinstance(event["document"], str)
            or type(event["revision"]) is not int
            or event["revision"] < 0
            or event["changeKind"] not in {"added", "modified", "removed"}
            or type(event["oldIndex"]) is not int
            or type(event["newIndex"]) is not int
            or event["errorCode"] is not None
            or event["tokenCase"] is not None
        ):
            raise ValueError("event-shape")
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
    if (
        not isinstance(transport, dict)
        or transport.get("reconnectObserved") is not True
    ):
        errors.append("reconnect-unobserved")
    if receipt.get("sdk") != plan.get("sdk") or receipt.get("shadow") != plan.get(
        "shadow"
    ):
        errors.append("sdk-binding")
    if receipt.get("transportBinding") != plan.get("transportBinding"):
        errors.append("transport-binding")
    if receipt.get("sourceBinding") != plan.get("sourceBinding"):
        errors.append("source-binding")
    bounds = receipt.get("bounds")
    if not isinstance(bounds, dict):
        errors.append("bounds-missing")
    else:
        if (
            type(bounds.get("runCount")) is not int
            or not 1 <= bounds["runCount"] <= plan["limits"]["maxRuns"]
        ):
            errors.append("run-budget")
        if (
            type(bounds.get("requestCount")) is not int
            or not 0 <= bounds["requestCount"] <= plan["limits"]["maxOperations"]
        ):
            errors.append("request-budget")
        if (
            type(bounds.get("durationSeconds")) not in (int, float)
            or not 0
            <= bounds["durationSeconds"]
            <= plan["limits"]["maxDurationSeconds"]
        ):
            errors.append("time-budget")
        if bounds.get("concurrency") != plan["limits"]["maxConcurrency"]:
            errors.append("concurrency-budget")
        if (
            type(bounds.get("snapshotCount")) is not int
            or not 0 <= bounds["snapshotCount"] <= plan["limits"]["maxSnapshots"]
        ):
            errors.append("snapshot-budget")
        if (
            type(bounds.get("estimatedCostUsd")) not in (int, float)
            or not 0
            <= bounds["estimatedCostUsd"]
            <= plan["limits"]["hardCostCeilingUsd"]
        ):
            errors.append("cost-budget")
    if not isinstance(receipt.get("events"), list) or not isinstance(
        receipt.get("cleanup"), dict
    ):
        errors.append("receipt-shape")
    elif (
        isinstance(collector, dict)
        and collector.get("complete") is True
        and collector.get("eventCount") != len(receipt["events"])
    ):
        errors.append("event-count")
    if not errors and isinstance(receipt.get("events"), list):
        try:
            events = _normalized(
                receipt, {item["path"] for item in plan["ownedResources"]}
            )
            if receipt["bounds"]["snapshotCount"] != sum(
                event["snapshotType"] != "error" for event in events
            ):
                errors.append("snapshot-count")
            seen = {
                (event["document"], event["revision"])
                for event in events
                if event["revision"] is not None
            }
            expected = {
                (f"{plan['owner']['collection']}/{name}", revision)
                for name, revisions in _EXPECTED_REVISIONS.items()
                for revision in revisions
            }
            if seen != expected:
                errors.append("revision-coverage")
            if events and events[0]["snapshotType"] != "initial":
                errors.append("event-order")
            ordered = [
                (event["document"], event["revision"])
                for event in events
                if event["revision"] is not None
            ]
            expected_order = [
                (f"{plan['owner']['collection']}/one", 0),
                (f"{plan['owner']['collection']}/one", 1),
                (f"{plan['owner']['collection']}/one", 2),
                (f"{plan['owner']['collection']}/two", 0),
            ]
            if ordered != expected_order:
                errors.append("event-order")
        except (ValueError, TypeError) as error:
            errors.append(str(error))
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
        if result["errors"] in (["event-order"], ["negative-token-semantics"]):
            result["classification"] = "SEMANTIC_MISMATCH"
        return result
    owned = {item["path"] for item in plan["ownedResources"]}
    try:
        left_events = _normalized(left, owned)
        right_events = _normalized(right, owned)
    except (ValueError, TypeError) as error:
        result["errors"] = [str(error)]
        return result
    expected_cleanup = {item["path"]: True for item in plan["ownedResources"]}
    if left["cleanup"] != expected_cleanup or right["cleanup"] != expected_cleanup:
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
