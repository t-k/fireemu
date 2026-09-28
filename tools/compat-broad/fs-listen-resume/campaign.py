"""Frozen campaign manifest for a bounded FS-LISTEN-SDK production observation.

The manifest is offline and deterministic. Compiling it performs no network
call, reads no credential and grants no permission: a compiled campaign always
carries `status = BLOCKED_OWNER` until an owner supplies a campaign-specific
permission identifier, and even then it only becomes `PREPARED`. Execution is a
separate, unimplemented step.
"""

from __future__ import annotations

import re
from copy import deepcopy
from types import MappingProxyType
from typing import Any

from . import cases
from .manifest import digest

SCHEMA = "o6-listen-sdk-campaign-v1"
CASE_ID = "FS-LISTEN-SDK"
PROJECT = "fireemu-35fe6"
DATABASE = "(default)"

_NONCE = re.compile(r"^[0-9a-f]{32}$")
_PERMISSION = re.compile(r"^o6-listen-sdk-[0-9a-f]{16}$")

STATUS_BLOCKED = "BLOCKED_OWNER"
STATUS_PREPARED = "PREPARED"

# Resolved npm identities taken from the pinned lockfile. These are the frozen
# SDK inputs: a campaign that resolves a different tarball is a different
# campaign.
SDK_PIN = MappingProxyType(
    {
        "firebase": "12.18.0",
        "@firebase/firestore": "4.17.1",
        "@firebase/auth": "1.13.5",
        "@firebase/webchannel-wrapper": "1.0.7",
    }
)
SDK_INTEGRITY = MappingProxyType(
    {
        "firebase": "sha512-XaL6tlE5Xd20ZDhckqOMIw+JJTET+wTdeZPxQ7ihc42oxRb7kWUyn/j1LO5V9dH1xq8Rv5R71Pv1fBCdIkt9Rw==",
        "@firebase/firestore": "sha512-8lqPNf2w10CtYG+tayVjZO1pSyQpnhztQRudeD109VtXDzNbASTaYdO43sj5PMsDcWq0aOYY3RmJOUlXu9++jw==",
        "@firebase/auth": "sha512-1AXoBJqBVD8WL8FZYo3S2GmJF9YUoom6Y6ngMxOSkzzhW5sT83pLchb6TGFgxes91dfXx8s/VYc5VrLDNqpLog==",
        "@firebase/webchannel-wrapper": "sha512-phBFwieDLvkZGYN9CE9ZFNEIoBVksprzsnCzQejCmCHtgwCXReeuRpoEGN9C4EbhONztv8NRV1tau6Rb9pONwQ==",
    }
)
SOURCE_LOCKFILE = "tools/sdk-smoke/package-lock.json"
SOURCE_LOCKFILE_DIGEST = (
    "77320cd304149c5c3e99289b7548757e307c08373bf02a811a5ae8518775704c"
)

# Node SDK transport. The Node build of the JS SDK selects gRPC; WebChannel is
# reachable only from a browser, which this lane cannot drive.
TRANSPORT = MappingProxyType(
    {
        "kind": "grpc-listen",
        "selectedBy": "firebase/firestore node entrypoint",
        "resumeBoundary": "sdk-managed",
        "rawResumeTokenVisible": False,
    }
)

# Published Firestore list prices used only to bound the planning estimate.
# They are a ceiling for a plan, never an observed bill.
_PRICE_PER_100K = MappingProxyType({"read": 0.06, "write": 0.18, "delete": 0.02})

BUDGET = MappingProxyType(
    {
        "maxRuns": 1,
        "maxDurationSeconds": 600,
        "maxConcurrency": 1,
        "maxConcurrentListeners": 3,
        "maxListenerRegistrations": 40,
        "maxClients": 3,
        "maxAccounts": 2,
        "maxDocuments": 6,
        "maxWrites": 60,
        "maxDeletes": 80,
        "maxReads": 600,
        # Cleanup runs on its own reserve so an exhausted observation budget or
        # an expired observation deadline can never leave an owned document
        # behind. The reserve is charged separately and reported separately.
        "cleanupReserveSeconds": 180,
        "cleanupReserveReads": 300,
        "cleanupReserveDeletes": 150,
        "maxSnapshots": 120,
        "estimatedCostUsd": 0.01,
        "hardCostCeilingUsd": 0.5,
    }
)

# Owner work that must exist before a run. None of it is performed here.
OWNER_PRECONDITIONS = (
    MappingProxyType(
        {
            "id": "rules-fragment",
            "requirement": "Merge the additive Rules fragment into the oracle project and "
            "publish it. The fragment grants nothing to unauthenticated callers.",
            "verifiable": "requiredRulesDigest matches the deployed fragment",
        }
    ),
    MappingProxyType(
        {
            "id": "throwaway-account",
            "requirement": "Create two throwaway email/password accounts owned by the campaign "
            "operator in the oracle project: the principal every case signs in "
            "as, and the second principal of the cross-identity and revocation "
            "cases. Each password is supplied to the collector through its own "
            "private file descriptor, never through argv or the environment.",
            "verifiable": "exactly two account identifiers appear in the receipt",
        }
    ),
    MappingProxyType(
        {
            "id": "single-field-index",
            "requirement": "No composite index is needed: the query filters and orders on the "
            "same field, which the automatic single-field index serves.",
            "verifiable": "no FAILED_PRECONDITION index error in the receipt",
        }
    ),
    MappingProxyType(
        {
            "id": "clean-prefix",
            "requirement": "The nonce-scoped run document and the private document must not "
            "exist before the run.",
            "verifiable": "preflight absence rows for every owned path",
        }
    ),
)

# Permissions granted to other campaigns never authorize this one.
PERMISSION_ENVELOPE = MappingProxyType(
    {
        "scope": "fs-listen-sdk-campaign",
        "inheritsFrom": None,
        "allows": (
            "one run of the declared case catalog against the oracle project",
            "sign-in, sign-out and session revocation of at most two throwaway accounts",
            "creation and conditional deletion of the declared owned documents",
        ),
        "forbids": (
            "reuse of any earlier compat-broad permission",
            "any write outside the nonce-scoped run document and the two private documents",
            "any retry after the deadline or the hard cost ceiling",
            "recording an identity token, refresh token or password in any output",
        ),
    }
)


def owned_paths(nonce: str, uid_placeholder: str = "{uid}") -> dict[str, str]:
    """Return the first principal's owned document paths for a run nonce.

    This mirrors `ownedPaths` in `listen_collector.mjs`; the second principal's
    single document comes from `secondary_paths`.
    """
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be exactly 128-bit lowercase hexadecimal")
    run = f"{cases.RUN_COLLECTION}/{uid_placeholder}/runs/{nonce}"
    docs = f"{run}/{cases.DOCS_SUBCOLLECTION}"
    return {
        "run": run,
        "alpha": f"{docs}/alpha",
        "beta": f"{docs}/beta",
        "gamma": f"{docs}/gamma",
        "absent": f"{docs}/absent",
        "private": f"{cases.PRIVATE_COLLECTION}/{uid_placeholder}",
    }


def secondary_paths(nonce: str, uid_placeholder: str = "{uidB}") -> dict[str, str]:
    """Return the second principal's owned document path (`secondaryPaths` in Node)."""
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be exactly 128-bit lowercase hexadecimal")
    return {"privateB": f"{cases.PRIVATE_COLLECTION}/{uid_placeholder}"}


def campaign_paths(nonce: str) -> dict[str, str]:
    """Every document a run may create, both principals together."""
    return {**owned_paths(nonce), **secondary_paths(nonce)}


def count_operations() -> dict[str, int]:
    """Count the operations the declared catalog requires.

    Reads are counted pessimistically: every document named by an expected
    event is charged once per event, plus one cleanup read per owned document.
    """
    writes = deletes = reads = snapshots = listeners = 0
    for case in cases.CASES:
        for step in case["steps"]:
            if step["kind"] in {"seed", "write"}:
                writes += 1
            elif step["kind"] == "delete":
                deletes += 1
            elif step["kind"] == "listen":
                listeners += 1
        for event in case["expectedLocal"]:
            snapshots += 1
            reads += max(len(event["docs"]), 1)
    # Each case is isolated by a conditional cleanup pass over every owned path:
    # one read to prove ownership, one delete, one read to prove absence. Those
    # operations are charged to the cleanup reserve, not to the observation
    # budget, so they are counted separately.
    owned = len(campaign_paths("0" * 32)) - 1  # the run document itself is not seeded
    passes = len(cases.CASES) + 1  # once per case, plus one final pass
    return {
        "writes": writes,
        "deletes": deletes,
        "reads": reads,
        "snapshots": snapshots,
        "listenerRegistrations": listeners,
        # Listeners subscribe with metadata changes, so the transport delivers
        # more raw snapshots than the compared projection keeps: a cached
        # delivery, a server delivery and, for a local write, a pending and an
        # acknowledged delivery. The budget bounds raw deliveries, so it
        # reserves four per compared event.
        "rawSnapshotAllowance": snapshots * 4,
        "cleanupReads": owned * passes * 2,
        "cleanupDeletes": owned * passes,
    }


def estimate_cost_usd(counts: dict[str, int] | None = None) -> float:
    counts = counts or count_operations()
    total = (
        (counts["reads"] + counts["cleanupReads"]) * _PRICE_PER_100K["read"]
        + counts["writes"] * _PRICE_PER_100K["write"]
        + (counts["deletes"] + counts["cleanupDeletes"]) * _PRICE_PER_100K["delete"]
    ) / 100_000
    return round(total, 6)


def compile_campaign(
    nonce: str,
    *,
    permission: str | None = None,
    project: str = PROJECT,
    database: str = DATABASE,
) -> dict[str, Any]:
    """Compile the frozen campaign manifest for one run nonce."""
    paths = campaign_paths(nonce)
    if project != PROJECT or database != DATABASE:
        raise ValueError("project/database are fixed to the oracle default")
    if permission is not None and not _PERMISSION.fullmatch(permission):
        raise ValueError(
            "permission must be a campaign-scoped o6-listen-sdk identifier"
        )
    counts = count_operations()
    if (
        counts["writes"] > BUDGET["maxWrites"]
        or counts["deletes"] > BUDGET["maxDeletes"]
        or counts["reads"] > BUDGET["maxReads"]
        or counts["rawSnapshotAllowance"] > BUDGET["maxSnapshots"]
        or counts["listenerRegistrations"] > BUDGET["maxListenerRegistrations"]
        or counts["cleanupReads"] > BUDGET["cleanupReserveReads"]
        or counts["cleanupDeletes"] > BUDGET["cleanupReserveDeletes"]
    ):
        raise ValueError("declared catalog exceeds the frozen budget")
    return {
        "schema": SCHEMA,
        "caseId": CASE_ID,
        "status": STATUS_BLOCKED if permission is None else STATUS_PREPARED,
        "permission": permission,
        "permissionEnvelope": _plain(PERMISSION_ENVELOPE),
        "project": project,
        "database": database,
        "owner": {
            "namespace": f"o6/{CASE_ID}/{nonce}",
            "nonceDigest": digest(nonce),
            "paths": paths,
        },
        "sdk": dict(SDK_PIN),
        "sdkIntegrity": dict(SDK_INTEGRITY),
        "sourceBinding": {
            "kind": "resolved-lockfile-pin",
            "lockfile": SOURCE_LOCKFILE,
            "lockfileDigest": SOURCE_LOCKFILE_DIGEST,
            "catalogDigest": cases.catalog_digest(),
            "evidence": "declaration-only",
        },
        "transport": dict(TRANSPORT),
        "caseIds": list(cases.case_ids()),
        "requiredRulesFragment": cases.REQUIRED_RULES_FRAGMENT,
        "requiredRulesDigest": digest(cases.REQUIRED_RULES_FRAGMENT),
        "ownerPreconditions": [dict(item) for item in OWNER_PRECONDITIONS],
        "budget": dict(BUDGET),
        "plannedCounts": counts,
        "estimatedCostUsd": estimate_cost_usd(counts),
        "unobservedPaths": [dict(entry) for entry in cases.UNOBSERVED_PATHS],
        "productionExecuted": False,
    }


def _plain(value: Any) -> Any:
    if isinstance(value, (MappingProxyType, dict)):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def validate_campaign(campaign: Any) -> bool:
    """Recompile the manifest from its own nonce and require byte equality."""
    if not isinstance(campaign, dict) or campaign.get("schema") != SCHEMA:
        return False
    try:
        run = campaign["owner"]["paths"]["run"]
        segments = run.split("/")
        if (
            len(segments) != 4
            or segments[0] != cases.RUN_COLLECTION
            or segments[2] != "runs"
        ):
            return False
        nonce = segments[3]
        if (
            not _NONCE.fullmatch(nonce)
            or digest(nonce) != campaign["owner"]["nonceDigest"]
        ):
            return False
        if campaign.get("productionExecuted") is not False:
            return False
        if campaign.get("status") not in {STATUS_BLOCKED, STATUS_PREPARED}:
            return False
        if (campaign.get("permission") is None) != (
            campaign["status"] == STATUS_BLOCKED
        ):
            return False
        if campaign.get("estimatedCostUsd", 1e9) > BUDGET["hardCostCeilingUsd"]:
            return False
        expected = compile_campaign(
            nonce,
            permission=campaign.get("permission"),
            project=campaign.get("project", PROJECT),
            database=campaign.get("database", DATABASE),
        )
        return campaign == expected
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def campaign_digest(campaign: dict[str, Any]) -> str:
    return digest(deepcopy(campaign))
