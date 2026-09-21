"""Campaign manifest for the bounded partition/cursor observation.

The manifest freezes the lane's own source inputs, the wire and resource budget,
the owner preconditions and the reasons its own admission stays closed. It
contains no transport, no credential handling and no way to open admission:
the only production path is the O8 launcher (`partition_cursor_o8.py`), which
takes an independently frozen owner permission, an approval minted outside the
packet, a private credential handoff and a shared Ledger reservation.
"""

from __future__ import annotations

import hashlib
import json
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
# What the manifest itself cannot supply. Each is an owner input the O8 path
# takes through the frozen permission and the approval; the typed production
# collector that used to stand here exists now (`partition_cursor_production`).
BLOCKERS = (
    "owner-permission",
    "execution-window-and-nonce-reservation",
    "cost-and-retention-acceptance",
    "exclusive-collection-group-namespace",
    "recovery-owner",
    "independent-o7-review",
)
_OWNED_DOCUMENTS = PARTITION_DOCUMENTS + CURSOR_DOCUMENTS + 1


def source_inputs() -> dict[str, str]:
    """Bind every lane module by source bytes; test modules are excluded."""
    files = sorted(
        path
        for path in HERE.glob("*.py")
        if not path.name.startswith("test_") and path.name != "conftest.py"
    )
    files.append(HERE.parent / "batch_wire.py")
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
            "minimalPermissions": [
                "datastore.entities.create",
                "datastore.entities.get",
                "datastore.entities.list",
                "datastore.entities.delete",
            ],
            "permissionNotes": [
                (
                    "Every compiled operation is a data-plane read, write or "
                    "delete on the owned documents; none reads or changes "
                    "configuration, indexes, Rules or backups."
                ),
                (
                    "datastore.entities.list covers RunQuery and PartitionQuery, "
                    "which need database-wide read because PartitionQuery takes "
                    "a database parent."
                ),
                (
                    "roles/datastore.user is the smallest predefined role that "
                    "grants these; a custom role limited to the four "
                    "permissions is smaller and sufficient."
                ),
            ],
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
            "named recovery owner for an interrupted run",
            "independent O7 review of the frozen packet and its approval",
        ],
        "productionPath": {
            "launcher": "tools/compat-broad/fs-query-partition-cursor/partition_cursor_o8.py",
            "descriptor": "tools/compat-broad/o8-core/o4_partition_cursor_descriptor.py",
            "collector": "tools/compat-broad/fs-query-partition-cursor/partition_cursor_production.py",
            "gateProjection": "tools/compat-broad/fs-query-partition-cursor/partition_cursor_gate.py",
            "productionOrigin": "fixed in partition_cursor_wire.PRODUCTION_ORIGIN",
        },
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


# Versioned: v1 and v2 are historical records and stay byte-identical.
EVIDENCE = (
    ROOT / "spec/compatibility/broad-runs/fs-query-partition-cursor-preparation-v3.json"
)


def write_evidence() -> Path:
    """Publish the frozen preparation record; regenerate it after any lane edit."""
    EVIDENCE.write_text(json.dumps(manifest(), indent=1, sort_keys=True) + "\n")
    return EVIDENCE
