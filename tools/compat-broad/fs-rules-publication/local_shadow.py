"""Credential-free local shadow for collector and comparator sanity checks."""

from __future__ import annotations

from typing import Any

from compiler import digest


def shadow_receipt(plan: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for index, operation in enumerate(plan["observation"]):
        denied = operation["kind"] in {
            "user-sdk-owned-b-denied",
            "user-sdk-owned-u2-denied",
        }
        rows.append({
            "index": index,
            "request": operation,
            "transport": "official-user-sdk",
            "credentialKind": "firebase-auth-user-sdk-id-token",
            "status": "permission-denied" if denied else "success",
            "body": {} if denied else {
                "name": operation["path"],
                "fields": plan["fixtures"][
                    "public" if operation["path"] == plan["publicDocument"] else "owned"
                ],
            },
            "complete": True,
            "failure": None,
        })
    return {
        "productionExecuted": False,
        "planDigest": digest(plan),
        "credentialKind": "firebase-auth-user-sdk-id-token",
        "rows": rows,
        "cleanup": {
            "complete": True,
            "resourcesAbsent": plan["ownedResources"],
            "usersAbsent": [user["uid"] for user in plan["authUsers"]],
        },
    }


def validate_shadow(receipt: Any, plan: dict[str, Any]) -> bool:
    if not isinstance(receipt, dict) or receipt.get("productionExecuted") is not False:
        return False
    rows = receipt.get("rows")
    if not isinstance(rows, list) or len(rows) != 6:
        return False
    expected_denied = {3, 5}
    for index, row in enumerate(rows):
        if row.get("index") != index or row.get("request") != plan["observation"][index]:
            return False
        denied = row.get("status") == "permission-denied"
        if denied != (index in expected_denied) or (denied and row.get("body") not in ({}, None)):
            return False
        if row.get("complete") is not True or row.get("failure") is not None:
            return False
    cleanup = receipt.get("cleanup")
    return (
        isinstance(cleanup, dict)
        and cleanup.get("complete") is True
        and cleanup.get("resourcesAbsent") == plan["ownedResources"]
        and cleanup.get("usersAbsent") == [user["uid"] for user in plan["authUsers"]]
    )
