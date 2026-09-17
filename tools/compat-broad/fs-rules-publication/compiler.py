"""Compile the finite O5 user-token Rules publication transition offline.

This module describes an eventual observation. It never obtains credentials,
publishes Rules, starts a server, or sends a Firestore request.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

CAMPAIGN = "FS-RULES-PUBLICATION-USER-TOKEN-01"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _resource(project: str, database: str, *segments: str) -> str:
    return (
        f"projects/{project}/databases/{database}/documents/"
        + "/".join(segments)
    )


def _rules_source(nonce: str, *, deny_owned: bool) -> str:
    owned = "false" if deny_owned else "request.auth.uid == resource.data.ownerUid"
    return "\n".join(
        [
            "rules_version = '2';",
            "service cloud.firestore {",
            "  match /databases/{database}/documents {",
            f"    match /o5-rules-transition/{nonce}/owned {{",
            f"      allow read: if {owned};",
            "    }",
            f"    match /o5-rules-transition/{nonce}/public {{",
            "      allow read: if true;",
            "    }",
            "  }",
            "}",
        ]
    )


def _read(kind: str, path: str, *, ruleset: str, uid: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "service": "firestore",
        "transport": "official-user-sdk",
        "method": "get",
        "path": path,
        "ruleset": ruleset,
        "authUid": uid,
        "expect": {},
    }


def _compile_plan(project: str, database: str, nonce: str) -> dict[str, Any]:
    if not isinstance(project, str) or not _NAME.fullmatch(project):
        raise ValueError("malformed project")
    if not isinstance(database, str) or (
        database != "(default)" and not _NAME.fullmatch(database)
    ):
        raise ValueError("malformed database")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")

    root = ("o5-rules-transition", nonce)
    owned = _resource(project, database, *root, "owned")
    public = _resource(project, database, *root, "public")
    uid, uid2 = f"o5-u-{nonce}", f"o5-u2-{nonce}"
    owned_fields = {"ownerUid": uid, "nonce": nonce, "kind": "owned"}
    public_fields = {"nonce": nonce, "kind": "public"}
    observations = [
        _read("user-sdk-owned-a", owned, ruleset="A", uid=uid),
        _read("user-sdk-owned-a-control", owned, ruleset="A", uid=uid),
        _read("user-sdk-owned-a-repeat", owned, ruleset="A", uid=uid),
        _read("user-sdk-owned-b-denied", owned, ruleset="B", uid=uid),
        _read("user-sdk-public-b-control", public, ruleset="B", uid=uid),
        _read("user-sdk-owned-u2-denied", owned, ruleset="B", uid=uid2),
    ]
    expectations = [
        {"status": "success", "document": "owned", "body": "present"},
        {"status": "success", "document": "owned", "body": "present"},
        {"status": "success", "document": "owned", "body": "present"},
        {"status": "permission-denied", "body": "absent"},
        {"status": "success", "document": "public", "body": "present"},
        {"status": "permission-denied", "body": "absent"},
    ]
    for operation, expect in zip(observations, expectations, strict=True):
        operation["expect"] = expect
    recovery = [
        {"kind": "cleanup-owned-document", "resource": owned, "mode": "conditional-owned-delete"},
        {"kind": "cleanup-public-document", "resource": public, "mode": "conditional-owned-delete"},
        {"kind": "cleanup-users-and-rules", "uids": [uid2, uid], "mode": "readback-then-delete"},
    ]
    plan = {
        "schemaVersion": 1,
        "campaignId": CAMPAIGN,
        "project": project,
        "database": database,
        "nonce": nonce,
        "ownedScope": _resource(project, database, *root),
        "ownedDocument": owned,
        "publicDocument": public,
        "ownedResources": [owned, public],
        "fixtures": {"owned": owned_fields, "public": public_fields},
        "authUsers": [{"label": "U", "uid": uid}, {"label": "U2", "uid": uid2}],
        "rulesets": {
            "A": {
                "source": _rules_source(nonce, deny_owned=False),
                "decision": "allow-owned-user",
                "publicDecision": "allow-public",
            },
            "B": {
                "source": _rules_source(nonce, deny_owned=True),
                "decision": "deny-owned-user",
                "publicDecision": "allow-public",
            },
            "recovery": {"decision": "fixed-deny-all"},
        },
        "observation": observations,
        "recovery": recovery,
        "negativeCredentials": ["empty-bearer", "malformed-bearer", "admin-shaped-credential"],
        "budget": {
            "authUsersMaximum": 2,
            "documentsMaximum": 2,
            "rulesPublicationsMaximum": 3,
            "userSdkReadsMaximum": 6,
            "observationRequests": 6,
            "recoveryRequests": 3,
            "requestUpperBound": 9,
        },
        "productionReady": False,
        "evidenceBoundary": (
            "local-shadow-and-admin-publication-receipts-never-prove-"
            "user-token-authorization"
        ),
    }
    return plan


def compile_plan(project: str, database: str, nonce: str) -> dict[str, Any]:
    plan = _compile_plan(project, database, nonce)
    validate_plan(plan)
    return plan


def validate_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict) or plan.get("campaignId") != CAMPAIGN:
        raise ValueError("campaign binding drift")
    try:
        expected = _compile_plan(plan["project"], plan["database"], plan["nonce"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid plan identity") from error
    if plan != expected:
        raise ValueError("compiled plan drift")
    project, database, nonce = plan.get("project"), plan.get("database"), plan.get("nonce")
    if (
        not isinstance(project, str)
        or not _NAME.fullmatch(project)
        or not isinstance(database, str)
        or not isinstance(nonce, str)
        or not _NONCE.fullmatch(nonce)
    ):
        raise ValueError("invalid plan identity")
    # Rebuild without recursion while keeping validation useful to callers.
    if plan.get("ownedResources") != [plan.get("ownedDocument"), plan.get("publicDocument")]:
        raise ValueError("owned resource drift")
    if any(nonce not in value for value in plan["ownedResources"]):
        raise ValueError("resource escaped nonce")
    if len(plan.get("observation", [])) != 6 or len(plan.get("recovery", [])) != 3:
        raise ValueError("operation budget drift")
    if plan.get("budget", {}).get("requestUpperBound") != 9:
        raise ValueError("request budget drift")
    for index, operation in enumerate(plan["observation"]):
        if operation.get("transport") != "official-user-sdk" or operation.get(
            "authUid"
        ) not in {"o5-u-" + nonce, "o5-u2-" + nonce}:
            raise ValueError("user SDK binding drift")
        expected_kinds = [
            "user-sdk-owned-a",
            "user-sdk-owned-a-control",
            "user-sdk-owned-a-repeat",
            "user-sdk-owned-b-denied",
            "user-sdk-public-b-control",
            "user-sdk-owned-u2-denied",
        ]
        if operation.get("kind") != expected_kinds[index]:
            raise ValueError("operation order drift")
    if plan.get("productionReady") is not False:
        raise ValueError("production must remain unbound")
