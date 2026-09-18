"""Campaign manifest for the FS-CONFIG-LIFECYCLE management-contract observation.

The manifest freezes inputs, budget, permission envelope, owner preconditions, abort
rules, the owned-resource ledger and a bounded, resumable long-running-operation poll.
It grants nothing: an owner permission is a separate artifact this repository does not
contain, and compiling a manifest performs no request and acquires no credential.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from .cases import (
    DEFAULT_DATABASE,
    NONCE_PATTERN,
    PROJECT,
    cases_digest,
    compile_cases,
    owned_resources,
)
from .surface_matrix import CASE_ID, build_matrix, digest

SCHEMA = "fs-config-lifecycle-campaign-manifest-v1"

REQUIRED_PERMISSIONS = (
    "datastore.databases.create",
    "datastore.databases.delete",
    "datastore.databases.get",
    "datastore.databases.getMetadata",
    "datastore.databases.list",
    "datastore.databases.update",
    "datastore.indexes.get",
    "datastore.indexes.list",
    "datastore.operations.get",
    "datastore.operations.list",
)

FORBIDDEN_PERMISSIONS = (
    "datastore.backups.delete",
    "datastore.backups.get",
    "datastore.backups.list",
    "datastore.databases.export",
    "datastore.databases.import",
    "datastore.databases.restore",
    "datastore.entities.create",
    "datastore.entities.delete",
    "datastore.entities.get",
    "datastore.entities.list",
    "datastore.entities.update",
    "iam.serviceAccountKeys.create",
    "resourcemanager.projects.delete",
    "resourcemanager.projects.setIamPolicy",
)

_BUDGET_BASIS = (
    "Firestore Admin calls are not metered per request and every case is confined to "
    "configuration. No document is read, written or deleted, so the created database "
    "holds zero bytes for its whole lifetime and the time-to-live and exemption patches "
    "build single-field index entries over an empty collection group. The estimate is "
    "therefore zero, and the ceiling exists only so an unexpected metered charge stops "
    "the run rather than continuing."
)

_OWNER_PRECONDITIONS = (
    (
        "The project must be on a pay-as-you-go billing plan, because creating a database "
        "beyond the default one is refused on the free Spark plan. The owner confirms this "
        "before the run; the collector never enables billing itself."
    ),
    (
        "Only one database beyond the default is created. The free-tier allowance covers "
        "the default database alone, so the second database has no allowance of its own. "
        "That is why it holds no data and is deleted in the same run."
    ),
    (
        "databases.list must return exactly the expected set before the run. Any unexpected "
        "database means another session owns this project, and the run does not start."
    ),
    (
        "The created database is requested with delete protection disabled, so the delete "
        "that ends the run cannot be blocked by protection state."
    ),
    (
        "The two field configurations are patched only on collection groups whose names "
        "carry this run's nonce, so no collection group another lane uses is touched."
    ),
    (
        "The default database is never created, patched, deleted, restored or cloned; only "
        "its field configurations under the nonce-owned collection groups are changed, and "
        "each is reverted in the same run."
    ),
    (
        "The run requires exclusive use of the oracle project for its duration. It "
        "enumerates databases before and after, so another lane creating or deleting a "
        "database while it runs would fail its reconciliation."
    ),
)

_ABORT_RULES = (
    (
        "Abort before any mutation if the default database's uid, edition, type or location "
        "differs from the approved baseline; identity drift is never normalized away."
    ),
    (
        "Abort if databases.list returns a database that this run did not create and did not "
        "expect, and run cleanup for anything already created."
    ),
    (
        "Abort without retry on any billing, quota or permission refusal from "
        "databases.create, and record the refusal as the observation."
    ),
    (
        "Abort if a long-running operation has not finished within the poll deadline, then "
        "run cleanup from the ledger rather than continuing to the next case."
    ),
    (
        "Never retry a mutating case automatically. A retry is a new run with a new nonce "
        "and a new owner permission."
    ),
    (
        "Abort if a field configuration read back after a revert differs from the baseline "
        "captured before the patch, and report the resource as unrecovered."
    ),
)

_ENVELOPE_NOTE = (
    "The required set reads and changes configuration only. No document permission is "
    "requested, so a collector defect cannot read or destroy data."
)

_CLEANUP_ORDER = (
    "revert-field-configurations",
    "verify-field-configuration-baseline",
    "delete-created-database",
    "delete-conditionally-created-databases",
    "verify-database-absence",
    "reconcile-database-enumeration",
    "write-final-ledger",
)

_RECONCILIATION = {
    "comparesAgainst": "OC-02",
    "method": "firestore.projects.databases.list",
    "failsClosed": True,
    "rule": (
        "After every revert and delete, enumerate the databases again and compare with "
        "the enumeration OC-02 captured before the run. Any database present now that "
        "was absent then fails the run, and any database whose id begins with the "
        "fsconfig- prefix fails the run even if a ledger entry claims it was recovered."
    ),
    "coversCasesOutsideTheLedger": (
        "A create this campaign never declared, or an identifier production normalized "
        "into a different id, is caught here rather than escaping unnoticed."
    ),
}

_CLEANUP_COMPLETION = (
    "Every ledger entry is marked recovered.",
    "Every reverted field configuration matches the baseline captured before its patch.",
    "The created database answers NOT_FOUND on a final get.",
    (
        "The post-run database enumeration matches the one captured before the run, with "
        "no database carrying the owned prefix."
    ),
    "A run with any unrecovered resource exits non-zero and is not a valid observation.",
)


def compile_manifest(nonce: str) -> dict[str, Any]:
    if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
    cases = compile_cases(nonce)
    matrix = build_matrix()
    ledger = owned_resources(cases)
    budget = {
        "estimatedCostUsd": 0.0,
        "hardCeilingUsd": 1.0,
        "basis": _BUDGET_BASIS,
        "maxRequests": 64,
        "maxWallSeconds": 900,
        "maxCreatedDatabases": 1,
        "maxPatchedFieldConfigurations": 2,
        "maxDocumentOperations": 0,
        "enforced": False,
    }
    polling = {
        "maxAttemptsPerOperation": 60,
        "deadlineSeconds": 600,
        "initialBackoffSeconds": 2,
        "maxBackoffSeconds": 15,
        "onDeadline": "abort-and-run-cleanup",
        "checkpoint": {
            "path": "<run directory>/operations.checkpoint.jsonl",
            "writtenAfterEveryPoll": True,
            "fsyncBeforeContinuing": True,
            "resumeFrom": "owned-resource-ledger",
            "contents": [
                "operation name",
                "owning case id",
                "attempt count",
                "first seen and last polled monotonic offsets",
                "terminal state when reached",
            ],
        },
    }
    return {
        "schema": SCHEMA,
        "caseId": CASE_ID,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "ownerApproval": None,
        "credentials": "none acquired; none referenced",
        "project": PROJECT,
        "database": DEFAULT_DATABASE,
        "frozenInputs": {
            "matrixDigest": digest(matrix),
            "casesDigest": cases_digest(nonce),
            "discoveryPath": matrix["discovery"]["path"],
            "discoverySha256": matrix["discovery"]["sha256"],
            "nonceDigest": digest(nonce),
        },
        "caseCount": len(cases),
        "budget": budget,
        "permissionEnvelope": {
            "required": list(REQUIRED_PERMISSIONS),
            "forbidden": list(FORBIDDEN_PERMISSIONS),
            "note": _ENVELOPE_NOTE,
        },
        "ownerPreconditions": list(_OWNER_PRECONDITIONS),
        "abortRules": list(_ABORT_RULES),
        "cleanup": {
            "ledger": ledger,
            "order": list(_CLEANUP_ORDER),
            "reconciliation": deepcopy(_RECONCILIATION),
            "completionRequires": list(_CLEANUP_COMPLETION),
            "unrecoveredResourcesFailTheRun": True,
        },
        "operationPolling": polling,
        "unresolved": [
            "A typed collector that issues these requests does not exist yet.",
            "Request, wall-clock and cost limits are declared, not enforced.",
            "No owner permission, nonce reservation or validity window is supplied here.",
            "Production error shapes for every negative case remain unknown.",
            (
                "Long-running operation metadata shapes are declared from the pinned "
                "discovery input, not from any response."
            ),
        ],
    }


def validate_manifest(manifest: Any, nonce: str) -> bool:
    if not isinstance(manifest, dict):
        return False
    try:
        expected = compile_manifest(nonce)
    except (ValueError, OSError, KeyError):
        return False
    if manifest.get("schema") != SCHEMA:
        return False
    if manifest.get("status") != "PREPARATION_ONLY":
        return False
    if manifest.get("productionExecuted") is not False:
        return False
    if manifest.get("ownerApproval") is not None:
        return False
    budget = manifest.get("budget")
    if not isinstance(budget, dict) or budget.get("hardCeilingUsd", 0) > 1.0:
        return False
    cleanup = manifest.get("cleanup")
    if not isinstance(cleanup, dict) or not cleanup.get("ledger"):
        return False
    return json.loads(json.dumps(manifest)) == json.loads(json.dumps(expected))
