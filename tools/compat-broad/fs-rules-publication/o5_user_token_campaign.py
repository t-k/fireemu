"""Campaign manifest for the FS-RULES user-token observation matrix.

The manifest freezes the inputs an execution would have to reproduce, states a
budget estimate and a permission envelope, and lists the owner preconditions
that this repository cannot satisfy. It grants no authority: ``admit`` always
raises, and the status never leaves ``PREPARATION_ONLY``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from o5_user_token_case import CAMPAIGN, compile_case, digest

CAMPAIGN_CONTRACT = "fs-rules-user-token-campaign-v1"

_SOURCE_FILES = (
    "o5_user_token_case.py",
    "o5_user_token_collector.py",
    "o5_user_token_campaign.py",
    "o5_user_token_comparator.py",
    "o5_user_token_comparator_v2.py",
    "o5_user_token_semantics.py",
    "o5_user_token_shadow.py",
    "o5_user_token_local_run.py",
    "o5_user_token_descriptor.py",
)

# Unit prices are the public Firestore Standard edition list prices used only to
# show that the campaign is small. They are an estimate, not a quoted tariff,
# and the owner accepts the real bill.
_PRICE_PER_DOCUMENT_READ_USD = 0.06 / 100_000
_PRICE_PER_DOCUMENT_WRITE_USD = 0.18 / 100_000

RULES_MANAGEMENT_OBSERVATION = (
    "baseline-release-get", "baseline-ruleset-get", "baseline-executable-get",
    "create-a", "create-a-get", "patch-a", "patch-a-get", "patch-a-executable",
    "create-b", "create-b-get", "patch-b", "patch-b-get", "patch-b-executable",
)
RULES_MANAGEMENT_RECOVERY = (
    "restore-patch", "restore-get", "restore-executable",
    "delete-a-get", "delete-a", "delete-a-absence",
    "delete-b-get", "delete-b", "delete-b-absence",
)


def rules_management_plan() -> dict[str, Any]:
    """Compiler-owned fixed Gate slots for response-derived Rules operations."""
    return {
        "dispatchKind": "closed-v1",
        "observation": [{"id": value, "timeout": 8.0} for value in RULES_MANAGEMENT_OBSERVATION],
        "recovery": [{"id": value, "timeout": 8.0} for value in RULES_MANAGEMENT_RECOVERY],
        "totalRequests": len(RULES_MANAGEMENT_OBSERVATION) + len(RULES_MANAGEMENT_RECOVERY),
        "requestCostMicrousd": 1,
        "wallClockDeadlineSeconds": 600.0,
        "recoveryDeadlineSeconds": 900.0,
    }

OWNER_PRECONDITIONS = (
    "project and database identity confirmed by the owner",
    "a fresh nonce reserved for this campaign only",
    "an execution window with a named owner present for the whole window",
    "an administrator credential for fixture setup, custom-claim minting and cleanup",
    "Identity Platform multi-tenancy enabled with the named tenant already created",
    (
        "the two Rulesets already released by the owner, or an owner-held "
        "publication lock plus the captured bytes and version of the "
        "preexisting release"
    ),
    "a recovery owner who restores the preexisting release if the window ends early",
    "accepted cost ceiling and data-retention decision for the run directory",
)

PERMISSION_ENVELOPE = {
    "services": ["identitytoolkit.googleapis.com", "firestore.googleapis.com"],
    "firestoreScope": "the campaign nonce subtree only",
    "authScope": (
        "seven throwaway accounts created by this campaign only, three of "
        "which are revoked, disabled or deleted by the administrator credential "
        "after sign-in"
    ),
    "rulesScope": "read the active release; publish only the two campaign Rulesets",
    "forbidden": [
        "any document outside the nonce subtree",
        "any preexisting Auth account",
        "database, index, TTL or backup configuration changes",
        "concurrent execution with any other campaign in the same database",
    ],
    "concurrency": 1,
    "networkEgress": "the two listed Google APIs only",
}


def source_digests() -> dict[str, str]:
    """SHA-256 of every lane module, read from disk now.

    The collector records these as its observer identity and the acquisition
    comparator recomputes them, so a bundle produced by other bytes than the
    ones under review is named as drift rather than accepted.
    """
    here = Path(__file__).resolve().parent
    digests = {}
    for name in _SOURCE_FILES:
        path = here / name
        digests[name] = (
            hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""
        )
    return digests


def budget(plan: dict[str, Any]) -> dict[str, Any]:
    observation = len(plan["observation"])
    resources = len(plan["ownedResources"])
    fixtures = len(plan["fixtures"])
    accounts = plan["ownedAccounts"]
    # Per account: sign-up, plus a claim write and a re-sign-in when it carries
    # a custom claim, plus one administrator action and one lookup readback
    # when the account is revoked, disabled or deleted between two rows. Plus
    # one tenant create and one tenant delete.
    auth_requests = (
        sum(3 if entry["claims"] else 1 for entry in accounts)
        + sum(2 for entry in accounts if entry.get("postSignIn"))
        + 2
    )
    # Rules management includes baseline reads, response-derived create/read,
    # activation/readback, exact restore, and guarded delete/absence proof.
    rules_requests = len(RULES_MANAGEMENT_OBSERVATION) + len(RULES_MANAGEMENT_RECOVERY)
    # Recovery: read back, delete and verify absence for every document and
    # every account.
    recovery_requests = 3 * (resources + len(accounts))
    total = observation + fixtures + auth_requests + rules_requests + recovery_requests
    reads = observation + resources + len(accounts)
    writes = fixtures + resources + 4
    cost = reads * _PRICE_PER_DOCUMENT_READ_USD + writes * _PRICE_PER_DOCUMENT_WRITE_USD
    return {
        "observationRequests": observation,
        "fixtureRequests": fixtures,
        "authRequests": auth_requests,
        "rulesRequests": rules_requests,
        "recoveryRequests": recovery_requests,
        "requestUpperBound": total,
        "concurrencyUpperBound": 1,
        "perRequestTimeoutSeconds": 12.0,
        "wallClockDeadlineSeconds": 600.0,
        "recoveryDeadlineSeconds": 900.0,
        "billedDocumentReads": reads,
        "billedDocumentWrites": writes,
        "estimatedCostUsd": round(cost, 6),
        "costCeilingUsd": 1.0,
        "estimateBasis": "public Firestore Standard list prices; not a quoted tariff",
    }


def manifest(
    project: str, database: str, nonce: str, tenant: str = "o5-user-token-tenant"
) -> dict[str, Any]:
    plan = compile_case(project, database, nonce, tenant)
    value = {
        "contract": CAMPAIGN_CONTRACT,
        "schemaVersion": 1,
        "campaignId": CAMPAIGN,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "frozenInputs": {
            "caseDigest": plan["planDigest"],
            "sources": source_digests(),
            "rulesetDigests": {
                label: digest(body["source"])
                for label, body in plan["rulesets"].items()
            },
        },
        "budget": budget(plan),
        "permissionEnvelope": PERMISSION_ENVELOPE,
        "ownerPreconditions": list(OWNER_PRECONDITIONS),
        "blockers": [
            "owner-permission",
            "nonce-reservation",
            "ruleset-release-authority",
            "tenant-provisioning",
            "cost-and-retention",
        ],
        "observationCase": plan,
    }
    value["manifestDigest"] = digest(
        {key: value[key] for key in value if key != "manifestDigest"}
    )
    return value


def admitted_manifest_digest(project: str, database: str, nonce: str) -> str:
    """The digest of the manifest a run of this nonce is admitted under.

    The tenant identifier is assigned by Identity Platform (or by the local
    Auth emulator) only once the run has started, so the admitted manifest is
    the one compiled with the placeholder tenant. Both sides of a comparison
    bind this digest; the tenant-specific plan digests are bound separately.
    """
    return manifest(project, database, nonce)["manifestDigest"]


def validate_manifest(value: Any) -> None:
    if not isinstance(value, dict) or value.get("contract") != CAMPAIGN_CONTRACT:
        raise ValueError("manifest contract drift")
    if value.get("status") != "PREPARATION_ONLY":
        raise ValueError("manifest status drift")
    if (
        value.get("productionExecuted") is not False
        or value.get("productionReady") is not False
    ):
        raise ValueError("manifest cannot claim production authority")
    case = value.get("observationCase")
    if not isinstance(case, dict):
        raise TypeError("invalid observation case")
    identity = [case.get(key) for key in ("project", "database", "nonce", "tenant")]
    if not all(isinstance(part, str) for part in identity):
        raise ValueError("invalid case identity")
    expected = manifest(*identity)
    if value != expected:
        raise ValueError("manifest preparation drift")


def admission(value: dict[str, Any]) -> dict[str, Any]:
    """Describe why execution is closed, without offering a way to open it."""
    validate_manifest(value)

    def admit() -> None:
        raise PermissionError(
            "no owner permission exists for "
            + CAMPAIGN
            + "; this repository cannot grant one"
        )

    return {
        "campaignId": CAMPAIGN,
        "productionReady": False,
        "blockers": list(value["blockers"]),
        "ownerPreconditions": list(value["ownerPreconditions"]),
        "admit": admit,
    }
