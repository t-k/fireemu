"""Deterministic, offline preparation contract for FS-LISTEN-SDK-002."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from types import MappingProxyType
from typing import Any

CASE_ID = "FS-LISTEN-SDK-002"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_SDK = {
    "firebase": "12.18.0",
    "firebase-admin": "14.3.0",
    "firebase-functions": "7.3.2",
    "rules-unit-testing": "5.0.2",
}
_SHADOW = {
    "firebase-tools": "15.28.2",
    "firestore-emulator": "1.22.0",
    "node": "24.14.0",
}
_LIMITS = {
    "maxRuns": 3,
    "maxDurationSeconds": 120,
    "maxConcurrency": 1,
    "maxDocuments": 2,
    "maxOperations": 32,
    "maxSnapshots": 6,
    "estimatedCostUsd": 1,
    "hardCostCeilingUsd": 10,
}
SDK = MappingProxyType(_SDK)
SHADOW = MappingProxyType(_SHADOW)
LIMITS = MappingProxyType(_LIMITS)
LOCKFILES = {
    "tools/sdk-smoke/package-lock.json": "77320cd304149c5c3e99289b7548757e307c08373bf02a811a5ae8518775704c",
    "conformance/pnpm-lock.yaml": "a1287b8bf5d8ef937b0bd82d7cec0df65abe3fe8f6669a4d2e3d927874291432",
}


def digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def compile_plan(
    nonce: str, project: str = "fireemu-35fe6", database: str = "(default)"
) -> dict[str, Any]:
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be exactly 128-bit lowercase hexadecimal")
    if project != "fireemu-35fe6" or database != "(default)":
        raise ValueError("project/database are fixed to the oracle default")
    collection = f"o6_resume_{nonce}"
    one, two = f"{collection}/one", f"{collection}/two"
    operations = [
        {"index": 0, "kind": "create", "path": one, "revision": 0},
        {"index": 1, "kind": "listen", "query": collection, "snapshotBudget": 1},
        {"index": 2, "kind": "update", "path": one, "revision": 1},
        {"index": 3, "kind": "interrupt", "owner": "collector", "count": 1},
        {"index": 4, "kind": "update", "path": one, "revision": 2},
        {"index": 5, "kind": "create", "path": two, "revision": 0},
        {"index": 6, "kind": "reconnect", "query": collection, "snapshotBudget": 3},
        {"index": 7, "kind": "unsubscribe", "query": collection},
        {"index": 8, "kind": "delete", "path": one},
        {"index": 9, "kind": "delete", "path": two},
        {"index": 10, "kind": "absence", "path": one},
        {"index": 11, "kind": "absence", "path": two},
    ]
    return {
        "schema": "o6-listen-resume-plan-v1",
        "caseId": CASE_ID,
        "seed": "o6-listen-resume-v1",
        "project": project,
        "database": database,
        "owner": {
            "namespace": f"o6/{CASE_ID}/{nonce}",
            "collection": collection,
            "nonceDigest": digest(nonce),
        },
        "ownedResources": [
            {"path": one, "revision": [0, 1, 2]},
            {"path": two, "revision": [0]},
        ],
        "sdk": deepcopy(_SDK),
        "shadow": deepcopy(_SHADOW),
        "sourceBinding": {
            "lockfiles": deepcopy(LOCKFILES),
            "entrypoint": "tools/compat-broad/fs-listen-resume",
        },
        "transportBinding": {
            "kind": "grpc-listen",
            "resumeBoundary": "sdk-managed",
            "endpointPolicy": "declared-only",
        },
        "resumeToken": {"persist": "sha256", "rawBytes": False},
        "limits": deepcopy(_LIMITS),
        "operations": operations,
        "negativeCases": ["stale-token", "compacted-token", "session-reset"],
        "cleanup": {
            "order": [
                "unsubscribe",
                "listener-close",
                "delete-owned",
                "absence-check",
                "process-close",
            ],
            "recovery": "same-nonce-only",
        },
        "productionExecuted": False,
    }


def validate_plan(plan: Any) -> bool:
    if not isinstance(plan, dict) or plan.get("schema") != "o6-listen-resume-plan-v1":
        return False
    try:
        nonce_digest = plan["owner"]["nonceDigest"]
        resources = [item["path"] for item in plan["ownedResources"]]
        if (
            len(resources) != 2
            or plan["limits"] != _LIMITS
            or plan["sdk"] != _SDK
            or plan["shadow"] != _SHADOW
        ):
            return False
        if (
            plan.get("productionExecuted") is not False
            or len(plan["operations"]) > LIMITS["maxOperations"]
        ):
            return False
        collection = plan["owner"]["collection"]
        nonce = collection.removeprefix("o6_resume_")
        if (
            not collection.startswith("o6_resume_")
            or not _NONCE.fullmatch(nonce)
            or digest(nonce) != nonce_digest
        ):
            return False
        expected = compile_plan(nonce, plan["project"], plan["database"])
        return plan == expected
    except (KeyError, TypeError, IndexError, AttributeError):
        return False
