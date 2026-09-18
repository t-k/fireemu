"""Campaign manifest for the bounded partition/cursor observation.

The manifest freezes the lane's own source inputs, the wire and resource budget,
the owner preconditions and the reasons production admission stays closed. It
contains no transport, no credential handling and no way to open admission.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

from partition_cursor_case import (
    CAMPAIGN,
    CURSOR_DOCUMENTS,
    OBSERVATION_COUNT,
    PARTITION_DOCUMENTS,
    RECOVERY_COUNT,
    compile_plan,
    validate_plan,
)

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TEMPLATE_PROJECT = "template-project"
TEMPLATE_NONCE = "0" * 32
BLOCKERS = (
    "owner-permission",
    "execution-window-and-nonce-reservation",
    "cost-and-retention-acceptance",
    "exclusive-collection-group-namespace",
    "typed-production-collector",
    "recovery-owner",
)
_OWNED_DOCUMENTS = PARTITION_DOCUMENTS + CURSOR_DOCUMENTS + 1


def source_inputs() -> dict[str, str]:
    """Bind every lane module by source bytes; test modules are excluded."""
    files = sorted(
        path
        for path in HERE.glob("*.py")
        if not path.name.startswith("test_") and path.name != "conftest.py"
    )
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }


def manifest() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "campaignId": CAMPAIGN,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "planTemplate": compile_plan(TEMPLATE_PROJECT, "(default)", TEMPLATE_NONCE),
        "sourceInputs": source_inputs(),
        "isolation": {
            # Production requires a database parent for PartitionQuery, so the
            # query is database-wide and the nonce-unique collection group is
            # what keeps it matching only this run's own documents.
            "partitionParent": "database",
            "collectionGroup": "nonce-unique",
            "ownedPrefix": "oracle/{nonce}/o4-query-partition-cursor/root",
        },
        "budget": {
            "observationRequests": OBSERVATION_COUNT,
            "recoveryRequests": RECOVERY_COUNT,
            "requestUpperBound": OBSERVATION_COUNT + RECOVERY_COUNT,
            "documentUpperBound": _OWNED_DOCUMENTS,
            "writeUpperBound": _OWNED_DOCUMENTS * 2,
            "concurrencyUpperBound": 1,
            "costCeilingUsd": 0.01,
            "costBasis": "at most 42 document writes, 21 document deletes and a few "
            "hundred document reads across 37 requests in one run",
        },
        "ownerPreconditions": {
            "indexFile": "conformance/firestore.indexes.json",
            "requiredCompositeIndexes": [],
            "indexFileChangeRequired": False,
            "deliberatelyUnindexed": ["partition-order-non-name"],
            "notes": [
                "Partition queries order by __name__ only, which needs no index.",
                (
                    "Cursor cases use single-field orders at collection scope, "
                    "which automatic single-field indexes already cover."
                ),
                (
                    "The nonce-unique collection group must have no field "
                    "override, exemption or time-to-live policy."
                ),
            ],
        },
        "unresolved": [
            "owner identity, permission reference and execution window",
            "fresh nonce reservation and exclusive collection-group namespace",
            "current pricing acceptance and retention bound for the retained bundle",
            "typed production collector and its raw sidecar retention boundary",
            "named recovery owner for an interrupted run",
        ],
        "blockers": list(BLOCKERS),
    }


def bound_manifest(project: str, database: str, nonce: str) -> dict[str, Any]:
    value = manifest()
    value["observationCase"] = compile_plan(project, database, nonce)
    value["caseDigest"] = value["observationCase"]["planDigest"]
    return value


def validate_manifest(value: Any) -> None:
    """Reject any manifest that is not the compiled preparation record."""
    if not isinstance(value, dict):
        raise TypeError("manifest must be an object")
    case = value.get("observationCase")
    if not isinstance(case, dict):
        raise ValueError("manifest must carry one compiled observation case")  # noqa: TRY004
    validate_plan(case)
    expected = bound_manifest(case["project"], case["database"], case["nonce"])
    if value != expected:
        raise ValueError("manifest preparation drift")


def admission_status(plan: dict[str, Any]) -> dict[str, Any]:
    """Report the closed admission state; the returned gate always refuses."""
    validate_plan(plan)

    def closed() -> None:
        raise PermissionError("O4 partition/cursor production admission is unavailable")

    return {
        "campaignId": CAMPAIGN,
        "productionReady": False,
        "requestCeiling": OBSERVATION_COUNT + RECOVERY_COUNT,
        "documentCeiling": _OWNED_DOCUMENTS,
        "blockers": list(BLOCKERS),
        "admit": closed,
    }


def validate_permission(permission: Any) -> None:
    """No permission can satisfy the unbound live prerequisites."""
    if not isinstance(permission, dict):
        raise TypeError("permission must be an object")
    expiry = permission.get("expiresAt")
    if type(expiry) not in (int, float) or not math.isfinite(expiry):
        raise ValueError("a finite expiry is required")
    raise ValueError(
        "O4 partition/cursor owner, window, namespace, cost and recovery "
        "bindings are unavailable"
    )
