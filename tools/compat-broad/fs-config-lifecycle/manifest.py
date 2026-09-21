"""Campaign manifest for the FS-CONFIG-LIFECYCLE management-contract observation.

The manifest freezes inputs, budget, permission envelope, owner preconditions, abort
rules, the owned-resource ledger, the Ledger lock scopes and a bounded, resumable
long-running-operation poll. It grants nothing: an owner permission is a separate
artifact this repository does not contain, and compiling a manifest performs no request
and acquires no credential.

The budget is enforced, not declared: `lifecycle_gate.py` charges every request before
it is sent and refuses one that would exceed the request count, the wall clock or the
cost ceiling. The figures here are the ones that gate reads.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from .cases import (
    DEFAULT_DATABASE,
    DROPPED_CASES,
    EXECUTION_ORDER,
    NONCE_PATTERN,
    PROJECT,
    cases_digest,
    compile_cases,
    locked_steps,
    owned_resources,
)
from .surface_matrix import CASE_ID, build_matrix, digest

SCHEMA = "fs-config-lifecycle-campaign-manifest-v2"

# fields.get/list/patch are governed by the datastore.indexes.* permissions; the
# database projection and enumeration by datastore.databases.get/getMetadata/list;
# the operation poll by datastore.operations.get. Nothing creates, deletes or patches
# a database, so no datastore.databases.create/delete/update is required.
REQUIRED_PERMISSIONS = (
    "datastore.databases.get",
    "datastore.databases.getMetadata",
    "datastore.databases.list",
    "datastore.indexes.get",
    "datastore.indexes.list",
    "datastore.indexes.update",
    "datastore.operations.get",
    "datastore.operations.list",
)

FORBIDDEN_PERMISSIONS = (
    "datastore.backups.delete",
    "datastore.backups.get",
    "datastore.backups.list",
    "datastore.databases.create",
    "datastore.databases.delete",
    "datastore.databases.export",
    "datastore.databases.import",
    "datastore.databases.restore",
    "datastore.databases.update",
    "datastore.entities.create",
    "datastore.entities.delete",
    "datastore.entities.get",
    "datastore.entities.list",
    "datastore.entities.update",
    "iam.serviceAccountKeys.create",
    "resourcemanager.projects.delete",
    "resourcemanager.projects.setIamPolicy",
)

# Every figure below is an upper bound the gate enforces. The request count is derived
# from the execution order: one credential preflight, two controls, two locked steps
# of baseline, patch, readback, revert and verify (five requests each), the field
# listing, at most sixteen polls for each of the six operations a patch, a revert or
# the one recovery re-revert per step may return, one recovery revert and verify per
# step, and the five closing reconciliation reads (two filters per owned group plus
# the enumeration). 1 + 2 + 10 + 1 + 96 + 4 + 5 = 119, rounded up to a power of two.
MAX_REQUESTS = 128
MAX_WALL_SECONDS = 900
RECOVERY_RESERVE_SECONDS = 360
REQUEST_SLOT_SECONDS = 6.0
POLL_ATTEMPTS = 16
POLL_DEADLINE_SECONDS = 120
POLL_BACKOFF_SECONDS = (2, 15)
# Two patches, two reverts, and one recovery re-revert per step for a revert that
# was acknowledged but not verified.
MAX_OPERATIONS = 6
# One authorized principal's quota is spent; no account is created. The figure is
# the Ledger's `accounts` dimension, published here so the claim has a basis.
MAX_ACCOUNTS = 1
# Firestore Admin calls carry no tariff. One micro-USD per request is the admission
# allowance the shared Ledger charges for every call this campaign may make, so the
# reservation is never zero-cost on paper while the estimated tariff stays zero.
REQUEST_ALLOWANCE_MICROUSD = 1
HARD_CEILING_MICROUSD = 1_000_000

_BUDGET_BASIS = (
    "Firestore Admin calls are not metered per request and every case is confined to "
    "configuration. No document is read, written or deleted, and the time-to-live and "
    "exemption patches build single-field index entries over an empty collection "
    "group. The estimated tariff is therefore zero micro-USD. The shared Ledger still "
    "charges one micro-USD of admission allowance per request, so the reserved figure "
    "is the request bound, and the ceiling exists only so an unexpected metered charge "
    "stops the run rather than continuing."
)

_OWNER_PRECONDITIONS = (
    (
        "The default database's projection digest, computed under the "
        "database-settings-v2 contract from the databases.get answer, equals the digest "
        "frozen in the owner permission. The collector reads it first and never patches "
        "anything when it differs."
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
        "The run holds an EXCLUSIVE shared Ledger lock on each field configuration it "
        "patches and READ locks on the database, its index configuration and the "
        "project identity, so a data campaign that depends on the same configuration "
        "is refused for the duration of the run and cannot start while it is held."
    ),
    (
        "No named database exists beyond the ones enumerated in the frozen baseline. "
        "The closing reconciliation compares the enumeration again and fails the run "
        "when it changed, because a change means another session owns this project."
    ),
)

_ABORT_RULES = (
    (
        "Stop before any mutation if the default database's projection digest differs "
        "from the frozen baseline; identity drift is never normalized away."
    ),
    (
        "Stop when the request bound, the observation wall or the cost ceiling would be "
        "exceeded by the next request; the recovery reserve is kept free for the reverts."
    ),
    (
        "Stop on a credential refusal (401 or 403) from any request, then still attempt "
        "every revert from the ledger; each attempt is charged and its refusal recorded."
    ),
    (
        "Stop if a long-running operation has not finished within the poll deadline, "
        "then run the reverts from the ledger rather than continuing to the next case."
    ),
    (
        "Never retry a mutating case automatically. A retry is a new run with a new nonce "
        "and a new owner permission."
    ),
    (
        "A field configuration read back after a revert that differs from the baseline "
        "captured before the patch is unrecovered: the run reports it, exits non-zero and "
        "leaves the shared Ledger reservation held until the owner restores it by hand."
    ),
)

_ENVELOPE_NOTE = (
    "The required set reads configuration and patches field configuration only. No "
    "document permission and no database lifecycle permission is requested, so a "
    "collector defect cannot read or destroy data and cannot create or delete a "
    "database."
)

_CLEANUP_ORDER = (
    "revert-field-configurations",
    "verify-field-configuration-baseline",
    "reconcile-field-listings",
    "reconcile-database-enumeration",
    "write-final-ledger",
)

_RECONCILIATION = {
    "comparesAgainst": "OC-02",
    "method": "firestore.projects.databases.list",
    "fieldListings": "firestore.projects.databases.collectionGroups.fields.list",
    "fieldListingFilters": ["indexConfig.usesAncestorConfig:false", "ttlConfig:*"],
    "failsClosed": True,
    "rule": (
        "After every revert, list both nonce-owned collection groups twice: under "
        "indexConfig.usesAncestorConfig:false, which shows an overridden index "
        "configuration, and under ttlConfig:*, which shows a time-to-live policy "
        "(a field whose only override is a policy keeps usesAncestorConfig and is "
        "invisible under the first filter). Any entry fails the run even if a ledger "
        "entry claims the field was restored. Then enumerate the databases again and "
        "compare with the enumeration OC-02 captured before the run; any difference "
        "fails the run."
    ),
    "coversCasesOutsideTheLedger": (
        "A configuration the campaign never declared under an owned collection group, "
        "or a revert that production acknowledged without applying, is caught here "
        "rather than escaping unnoticed."
    ),
}

_CLEANUP_COMPLETION = (
    "Every ledger entry is marked recovered.",
    "Every reverted field configuration matches the baseline captured before its patch.",
    (
        "Both owned collection groups list no overridden index configuration and no "
        "time-to-live policy."
    ),
    "The post-run database enumeration matches the one captured before the run.",
    "A run with any unrecovered resource exits non-zero and is not a valid observation.",
)

_SCOPE_DECISION = {
    "decidedOn": "2026-09-18",
    "droppedCases": list(DROPPED_CASES),
    "reason": (
        "Creating, deleting and probing creation of a named database are "
        "managed-infrastructure surfaces the owner excluded from the compatibility "
        "program on 2026-09-18, together with any change to the project's billing "
        "contract. The twelve remaining cases observe the database projection and "
        "enumeration, the two field-configuration transitions, the field listing and "
        "the operation poll, none of which allocates a managed resource."
    ),
}


def lock_scopes(nonce: str) -> list[dict[str, str]]:
    """The shared Ledger locks one run holds: EXCLUSIVE per patched field, READ around it."""
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/{DEFAULT_DATABASE}"
    locks = [
        {"key": step["lockKey"], "mode": step["lockMode"]}
        for step in locked_steps(nonce)
    ]
    locks.extend(
        [
            {"key": f"{firestore}/database", "mode": "READ"},
            {"key": f"{firestore}/indexes", "mode": "READ"},
            {"key": f"{scope}/identity", "mode": "READ"},
        ]
    )
    return locks


def budget() -> dict[str, Any]:
    return {
        "estimatedCostUsd": 0.0,
        "estimatedCostMicrousd": 0,
        "hardCeilingUsd": HARD_CEILING_MICROUSD / 1_000_000,
        "hardCeilingMicrousd": HARD_CEILING_MICROUSD,
        "requestAllowanceMicrousd": REQUEST_ALLOWANCE_MICROUSD,
        "reservedMicrousd": MAX_REQUESTS * REQUEST_ALLOWANCE_MICROUSD,
        "basis": _BUDGET_BASIS,
        "maxRequests": MAX_REQUESTS,
        "maxWallSeconds": MAX_WALL_SECONDS,
        "recoveryReserveSeconds": RECOVERY_RESERVE_SECONDS,
        "requestSlotSeconds": REQUEST_SLOT_SECONDS,
        "maxCreatedDatabases": 0,
        "maxAccounts": MAX_ACCOUNTS,
        "maxPatchedFieldConfigurations": 2,
        "maxOperations": MAX_OPERATIONS,
        "maxDocumentOperations": 0,
        "enforced": True,
        "enforcedBy": "tools/compat-broad/fs-config-lifecycle/lifecycle_gate.py",
    }


def polling() -> dict[str, Any]:
    return {
        "maxAttemptsPerOperation": POLL_ATTEMPTS,
        "deadlineSeconds": POLL_DEADLINE_SECONDS,
        "initialBackoffSeconds": POLL_BACKOFF_SECONDS[0],
        "maxBackoffSeconds": POLL_BACKOFF_SECONDS[1],
        "maxOperations": MAX_OPERATIONS,
        "onDeadline": "abort-and-run-recovery",
        "checkpoint": {
            "path": "<run directory>/gate/state.json",
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


def compile_manifest(nonce: str) -> dict[str, Any]:
    if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
    cases = compile_cases(nonce)
    matrix = build_matrix()
    ledger = owned_resources(cases)
    return {
        "schema": SCHEMA,
        "caseId": CASE_ID,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "ownerApproval": None,
        "credentials": "none acquired; none referenced",
        "project": PROJECT,
        "database": DEFAULT_DATABASE,
        "scopeDecision": deepcopy(_SCOPE_DECISION),
        "frozenInputs": {
            "matrixDigest": digest(matrix),
            "casesDigest": cases_digest(nonce),
            "discoveryPath": matrix["discovery"]["path"],
            "discoverySha256": matrix["discovery"]["sha256"],
            "nonceDigest": digest(nonce),
        },
        "caseCount": len(cases),
        "executionOrder": list(EXECUTION_ORDER),
        "lockedSteps": locked_steps(nonce),
        "lockScopes": lock_scopes(nonce),
        "budget": budget(),
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
        "operationPolling": polling(),
        "unresolved": [
            (
                "The shared Ledger cannot release a configuration-only reservation: "
                "shared_gate.create refuses a plan that owns no document and every "
                "terminal Ledger transition re-reads that Gate. A clean run therefore "
                "ends held with a typed release-blocked record until the shared core "
                "admits a configuration contract."
            ),
            "No owner permission, nonce reservation or validity window is supplied here.",
            "Production error shapes for a refused patch or revert remain unknown.",
            (
                "Long-running operation metadata shapes are declared from the method "
                "and schema names in the pinned Discovery input, not from any response. "
                "That input carries locators only, with no types, descriptions or "
                "output-only markers, so it can supply an enumeration of names but "
                "never a message shape."
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
    budget_ = manifest.get("budget")
    if not isinstance(budget_, dict) or budget_.get("hardCeilingUsd", 0) > 1.0:
        return False
    cleanup = manifest.get("cleanup")
    if not isinstance(cleanup, dict) or not cleanup.get("ledger"):
        return False
    return json.loads(json.dumps(manifest)) == json.loads(json.dumps(expected))
