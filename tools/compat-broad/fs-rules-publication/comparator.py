"""Compare finite Rules transition receipts without promoting local evidence."""

from __future__ import annotations

import copy
from typing import Any

from compiler import compile_plan, digest

_KINDS = (
    "user-sdk-owned-a",
    "user-sdk-owned-a-control",
    "user-sdk-owned-a-repeat",
    "user-sdk-owned-b-denied",
    "user-sdk-public-b-control",
    "user-sdk-owned-u2-denied",
)


def _canonical(row: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(row)
    body = value.get("body")
    if isinstance(body, dict):
        body.pop("requestId", None)
        body.pop("readTime", None)
        body.pop("token", None)
    value.pop("requestId", None)
    value.pop("token", None)
    value.pop("timestamp", None)
    return value


def _validate_rows(
    receipt: Any, plan: dict[str, Any], *, production: bool
) -> tuple[list[dict[str, Any]] | None, str | None]:
    if not isinstance(receipt, dict) or receipt.get("planDigest") != digest(plan):
        return None, "plan-digest"
    if receipt.get("credentialKind") != "firebase-auth-user-sdk-id-token":
        return None, "wrong-credential-kind"
    if receipt.get("productionExecuted") is not production:
        return None, "production-role"
    rows = receipt.get("rows")
    if not isinstance(rows, list) or len(rows) != 6:
        return None, "incomplete-rows"
    cleanup = receipt.get("cleanup")
    if (
        not isinstance(cleanup, dict)
        or cleanup.get("complete") is not True
        or cleanup.get("lock", {}).get("key") != plan["nonceReservation"]["lockKey"]
        or cleanup.get("lock", {}).get("acquired") is not True
        or cleanup.get("lock", {}).get("released") is not True
        or cleanup.get("rules") != {"finalDecision": "fixed-deny-all", "readback": True}
    ):
        return None, "cleanup-unproven"
    documents = cleanup.get("documents")
    users = cleanup.get("users")
    if (
        not isinstance(documents, list)
        or len(documents) != 2
        or not isinstance(users, list)
        or [item.get("resource") for item in documents if isinstance(item, dict)]
        != plan["ownedResources"]
        or [item.get("uid") for item in users if isinstance(item, dict)]
        != [user["uid"] for user in plan["authUsers"]]
        or any(
            not isinstance(item, dict)
            or item.get("nonce") != plan["nonce"]
            or item.get("absent") is not True
            or item.get("readback", {}).get("status") != "owned"
            or item.get("delete", {}).get("versionFrom")
            != item.get("readback", {}).get("version")
            for item in documents
        )
        or any(
            not isinstance(item, dict)
            or item.get("nonce") != plan["nonce"]
            or item.get("deleteStatus") != "deleted"
            or item.get("absent") is not True
            for item in users
        )
    ):
        return None, "cleanup-unproven"
    for index, (row, operation) in enumerate(zip(rows, plan["observation"], strict=True)):
        if (
            not isinstance(row, dict)
            or row.get("index") != index
            or row.get("request") != operation
        ):
            return None, "request-binding"
        if row.get("complete") is not True or row.get("failure") is not None:
            return None, "incomplete-row"
        if row.get("transport") != "official-user-sdk" or row.get(
            "credentialKind"
        ) != "firebase-auth-user-sdk-id-token":
            return None, "row-credential"
        if row.get("status") not in {"success", "permission-denied"}:
            return None, "status-classification"
        if row.get("status") != operation["expect"]["status"]:
            return None, "unexpected-status"
        if row.get("status") == "success":
            body = row.get("body")
            expected_fields = plan["fixtures"][
                "public" if operation["path"] == plan["publicDocument"] else "owned"
            ]
            if not isinstance(body, dict) or body.get("name") != operation["path"]:
                return None, "success-body"
            if body.get("fields") != expected_fields:
                return None, "success-body"
        if row.get("status") == "permission-denied" and row.get("body") not in (None, {}):
            return None, "denied-body-leak"
        transport = str(row.get("transport", "")).lower()
        if "admin" in transport or "rest" in transport:
            return None, "admin-transport"
    return rows, None


def compare_receipts(production: Any, local: Any, plan: dict[str, Any]) -> dict[str, Any]:
    """Return semantic comparison only; this function can never authorize a run."""
    result = {
        "kind": "fs-rules-publication-user-token-comparison-v1",
        "classification": "INDETERMINATE",
        "promotionReady": False,
        "acquisitionValidated": False,
        "rows": [],
        "errors": [],
    }
    expected = compile_plan(plan["project"], plan["database"], plan["nonce"])
    if plan != expected:
        result["errors"].append("plan-drift")
        return result
    left, left_error = _validate_rows(production, plan, production=True)
    right, right_error = _validate_rows(local, plan, production=False)
    if left_error or right_error:
        result["errors"] = [error for error in (left_error, right_error) if error]
        return result
    assert left is not None and right is not None
    for index, (a, b) in enumerate(zip(left, right, strict=True)):
        if _canonical(a, plan) != _canonical(b, plan):
            classification = "SEMANTIC_MISMATCH"
        elif a != b:
            classification = "EXPECTED_NONDETERMINISM"
        else:
            classification = "MATCH"
        result["rows"].append({"index": index, "classification": classification})
    classes = {row["classification"] for row in result["rows"]}
    result["classification"] = next(
        name
        for name in ("SEMANTIC_MISMATCH", "EXPECTED_NONDETERMINISM", "MATCH")
        if name in classes
    )
    return result
