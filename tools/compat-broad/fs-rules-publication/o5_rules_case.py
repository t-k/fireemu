"""Compile the finite O5 user-token Rules publication transition offline.

This module describes an eventual observation. It never obtains credentials,
publishes Rules, starts a server, or sends a Firestore request.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

CAMPAIGN = "FS-RULES-PUBLICATION-USER-TOKEN-01"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_DATABASE = re.compile(r"^[a-z][a-z0-9-]{2,61}[a-z0-9]$")


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _resource(project: str, database: str, *segments: str) -> str:
    return f"projects/{project}/databases/{database}/documents/" + "/".join(segments)


def _rules_source(nonce: str, *, deny_owned: bool) -> str:
    owned = "false" if deny_owned else "request.auth.uid == resource.data.ownerUid"
    return "\n".join(
        [
            "rules_version = '2';",
            "service cloud.firestore {",
            "  match /databases/{database}/documents {",
            f"    match /o5-rules-transition/{nonce}/cases/owned {{",
            f"      allow read: if {owned};",
            "    }",
            f"    match /o5-rules-transition/{nonce}/cases/public {{",
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
    if not isinstance(project, str) or not _PROJECT.fullmatch(project):
        raise ValueError("malformed project")
    if not isinstance(database, str) or (
        database != "(default)" and not _DATABASE.fullmatch(database)
    ):
        raise ValueError("malformed database")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")

    root = ("o5-rules-transition", nonce, "cases")
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
    plan = {
        "schemaVersion": 2,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
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
        },
        "observation": observations,
        "negativeCredentials": [
            "empty-bearer",
            "malformed-bearer",
            "admin-shaped-credential",
        ],
        "unresolved": [
            "project/database binding",
            "nonce reservation and shared publication lock",
            "typed user-token collector",
            "Rules publication and readback",
            "version-bound resource cleanup and final absence",
            "conditional restoration of preexisting database Rules",
            "wire, cost, and execution-window enforcement",
        ],
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
