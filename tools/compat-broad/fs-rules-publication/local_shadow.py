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
            "lock": {
                "key": plan["nonceReservation"]["lockKey"],
                "acquired": True,
                "released": True,
            },
            "documents": [
                {
                    "resource": resource,
                    "nonce": plan["nonce"],
                    "ownerUid": plan["authUsers"][0]["uid"],
                    "readback": {"status": "owned", "version": f"local-v{index}"},
                    "delete": {"status": "deleted", "versionFrom": f"local-v{index}"},
                    "absent": True,
                }
                for index, resource in enumerate(plan["ownedResources"])
            ],
            "users": [
                {
                    "uid": user["uid"],
                    "nonce": plan["nonce"],
                    "deleteStatus": "deleted",
                    "absent": True,
                }
                for user in plan["authUsers"]
            ],
            "rules": {"finalDecision": "fixed-deny-all", "readback": True},
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
        if not isinstance(row, dict):
            return False
        if row.get("index") != index or row.get("request") != plan["observation"][index]:
            return False
        status = row.get("status")
        if status not in {"success", "permission-denied"}:
            return False
        denied = status == "permission-denied"
        if denied != (index in expected_denied) or (denied and row.get("body") not in ({}, None)):
            return False
        if row.get("complete") is not True or row.get("failure") is not None:
            return False
    cleanup = receipt.get("cleanup")
    documents = cleanup.get("documents") if isinstance(cleanup, dict) else None
    users = cleanup.get("users") if isinstance(cleanup, dict) else None
    lock = cleanup.get("lock") if isinstance(cleanup, dict) else None
    return (
        isinstance(cleanup, dict)
        and cleanup.get("complete") is True
        and isinstance(lock, dict)
        and lock == {"key": plan["nonceReservation"]["lockKey"], "acquired": True, "released": True}
        and isinstance(documents, list)
        and len(documents) == 2
        and all(
            isinstance(item, dict)
            and item.get("resource") == resource
            and item.get("nonce") == plan["nonce"]
            and item.get("ownerUid") == plan["authUsers"][0]["uid"]
            and item.get("readback", {}).get("status") == "owned"
            and item.get("delete", {}).get("versionFrom") == item.get("readback", {}).get("version")
            and item.get("absent") is True
            for item, resource in zip(documents, plan["ownedResources"], strict=True)
        )
        and isinstance(users, list)
        and users == [
            {"uid": user["uid"], "nonce": plan["nonce"], "deleteStatus": "deleted", "absent": True}
            for user in plan["authUsers"]
        ]
        and cleanup.get("rules") == {"finalDecision": "fixed-deny-all", "readback": True}
    )
