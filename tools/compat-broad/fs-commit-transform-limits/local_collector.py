"""Finite local collection and ownership-bound recovery, independent of outcomes."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from transform_comparator import _exact, _timestamp, _validate_plan


def complete(receipt: dict[str, Any]) -> bool:
    return (
        receipt.get("complete") is True
        and receipt.get("failure") is None
        and type(receipt.get("status")) is int
        and 100 <= receipt["status"] <= 599
        and "body" in receipt
    )


def typed_not_found(receipt: dict[str, Any]) -> bool:
    body = receipt.get("body")
    error = body.get("error") if isinstance(body, dict) else None
    return (
        complete(receipt)
        and receipt["status"] == 404
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error["code"] == 404
        and error.get("status") == "NOT_FOUND"
    )


def owned(receipt: dict[str, Any], resource: str) -> bool:
    body = receipt.get("body")
    fields = body.get("fields") if isinstance(body, dict) else None
    return (
        complete(receipt)
        and receipt["status"] == 200
        and isinstance(body, dict)
        and body.get("name") == resource
        and isinstance(fields, dict)
        and _exact(fields.get("_sharedOwner"), {"referenceValue": resource})
        and _timestamp(body.get("updateTime"))
    )


def _row(
    index: int, request: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, Any]:
    return {**copy.deepcopy(receipt), "index": index, "request": copy.deepcopy(request)}


def normalize_receipt(receipt: Any) -> dict[str, Any]:
    """Validate the executor envelope without accepting provenance overrides."""
    json.dumps(receipt, allow_nan=False)
    if not isinstance(receipt, dict) or any(
        key in receipt for key in ("index", "request", "skipped", "absent")
    ):
        raise ValueError("invalid receipt envelope")
    receipt = copy.deepcopy(receipt)
    if not complete(receipt):
        receipt.update(
            complete=False, failure=receipt.get("failure") or "invalid-receipt"
        )
    return receipt


def collect_local(
    plan: dict[str, Any], execute: Callable[[dict[str, Any]], dict[str, Any]]
) -> dict[str, Any]:
    """Run at most 11 observations and six recovery slots without retrying.

    Only transport failure or missing mutation ownership stops observation.
    Complete unexpected API responses remain semantic evidence. A create attempt
    incurs recovery responsibility before dispatch, including a lost response.
    """
    _validate_plan(plan)
    plan = copy.deepcopy(plan)

    def dispatch(operation: dict[str, Any]) -> dict[str, Any]:
        try:
            receipt = execute(copy.deepcopy(operation))
            return normalize_receipt(receipt)
        except Exception as error:  # noqa: BLE001 -- every ambiguous mutation still enters recovery.
            return {
                "complete": False,
                "failure": f"local-executor:{type(error).__name__}",
            }

    rows: list[dict[str, Any]] = []
    attempted: set[str] = set()
    proven_owned: set[str] = set()
    for index, operation in enumerate(plan["observation"]):
        kind = operation["kind"]
        if kind == "commit-transform" and operation["resources"][0] not in proven_owned:
            break
        if kind == "create-only-patch":
            attempted.add(operation["resource"])
        receipt = dispatch(operation)
        rows.append(_row(index, operation, receipt))
        if not complete(receipt):
            break
        if kind == "preflight-typed-absence" and not typed_not_found(receipt):
            break
        if kind in {"create-only-patch", "baseline-readback"}:
            resource = operation["resource"]
            if owned(receipt, resource):
                proven_owned.add(resource)
            else:
                proven_owned.discard(resource)

    cleanup: list[dict[str, Any]] = []
    for index, declared in enumerate(plan["recovery"]):
        operation = copy.deepcopy(declared)
        resource = operation["resource"]
        if operation["kind"] == "cleanup-conditional-delete":
            prior = cleanup[index - 1]
            if typed_not_found(prior):
                cleanup.append(
                    _row(
                        index,
                        operation,
                        {
                            "complete": True,
                            "failure": None,
                            "status": None,
                            "body": None,
                            "skipped": "already-absent",
                        },
                    )
                )
                continue
            if resource not in attempted or not owned(prior, resource):
                cleanup.append(
                    _row(
                        index,
                        operation,
                        {
                            "complete": False,
                            "failure": "owned-read-unavailable",
                            "status": None,
                            "body": None,
                            "skipped": "unsafe-delete",
                        },
                    )
                )
                continue
            operation["path"] += "?currentDocument.updateTime=" + quote(
                prior["body"]["updateTime"], safe=""
            )
        receipt = dispatch(operation)
        row = _row(index, operation, receipt)
        row["absent"] = operation[
            "kind"
        ] == "cleanup-verify-absence" and typed_not_found(receipt)
        cleanup.append(row)

    absence = {
        resource: any(
            row["request"]["resource"] == resource
            and row["request"]["kind"] == "cleanup-verify-absence"
            and typed_not_found(row)
            for row in cleanup
        )
        for resource in plan["ownedResources"]
    }
    recovery_valid = []
    for index in (0, 3):
        read, delete, verify = cleanup[index : index + 3]
        deletion_ok = (
            delete.get("skipped") == "already-absent"
            and typed_not_found(read)
            and delete.get("failure") is None
        ) or (complete(delete) and delete["status"] == 200)
        recovery_valid.append(
            (owned(read, read["request"]["resource"]) or typed_not_found(read))
            and deletion_ok
            and typed_not_found(verify)
        )
    recording = len(rows) == 11 and all(complete(row) for row in rows)
    cleanup_complete = all(recovery_valid) and all(absence.values())
    return {
        "productionExecuted": False,
        "acquisitionValidated": False,
        "promotionReady": False,
        "recordingComplete": recording,
        "cleanupComplete": cleanup_complete,
        "completed": recording and cleanup_complete,
        "rows": rows,
        "cleanup": cleanup,
        "resourceAbsence": absence,
        "attemptedResources": sorted(attempted),
    }
