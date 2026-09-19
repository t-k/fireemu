"""Campaign manifest for the AUTH-CREDENTIAL token and session-cookie observation.

The manifest is inert. It freezes what a future bounded production run would do, states
what an owner must supply first, and records that nothing has been observed. Building it
grants no permission: a nonce checked here is syntax only, and the source binding stays
unbound until a separate executable run fills it from a clean frozen checkout.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from credential_cases import CAMPAIGN_ID, observation_cases
from credential_collector import BOUND_MODULES, module_digests
from credential_comparator import CONTRACT

STATUS = "PREPARATION"

#: Modules whose bytes a run must bind. The collector owns this list, because it is the
#: collector binding that makes a receipt pair comparable.
FROZEN_MODULES = BOUND_MODULES

#: `recoveryRequests` is held back from `maxRequests`, not added to it: sixty requests is
#: the bound the campaign is approved against, and twelve of them are reserved so cleanup
#: is reachable from any stopping point. Cleanup needs three calls per owned account and
#: the run creates at most four.
#:
#: Time is declared differently, because a clock cannot be held back the way a counter
#: can. The observation phase gets `maxWallSeconds` less `recoveryWallSeconds`, and the
#: cleanup tail gets `recoveryWallSeconds` from the moment it starts, granted absolutely.
#: An undisturbed run therefore fits inside `maxWallSeconds`, and a run that overran its
#: observation still gets its full cleanup window rather than none: what the owner
#: approves is a bounded observation plus a bounded tail. `worstCaseWallSeconds` is what
#: that costs when the observation phase is stopped by its own deadline.
BUDGET = {
    "maxRequests": 60,
    "maxWallSeconds": 600,
    "maxCostUsd": 0.05,
    "recoveryRequests": 12,
    "recoveryWallSeconds": 60,
    "observationWallSeconds": 540,
    "recoveryGrantedAbsolutely": True,
    "worstCaseWallSeconds": 600,
    "enforced": True,
}

#: What the estimate rests on. Identity Platform bills per monthly active user, not per
#: request, and the run creates at most four throwaway accounts that exist for minutes.
#: Sixty requests against one project is well inside the free allowance, so the ceiling
#: above is a guard against a runaway loop rather than a forecast.
COST_BASIS = (
    "At most four throwaway accounts and sixty requests against one project.",
    "Identity Platform bills monthly active users, not requests; these accounts are deleted within the run.",
    "The US$0.05 ceiling is a runaway guard, not a forecast; the expected charge is zero.",
)

OWNER_PRECONDITIONS = (
    "A service account in the oracle project able to mint RS256 custom tokens for it, either through a key file or `iam.serviceAccounts.signBlob` on itself. Local custom tokens are unsigned, so the custom-token and claim-precedence groups cannot run without this.",
    "An OAuth access token scoped for Identity Toolkit, for the privileged `accounts:update` (validSince), `accounts:lookup` and `:createSessionCookie` calls.",
    "A Web API key for the same project, for end-user sign-in and the secure-token exchange.",
    "Confirmation that the oracle project's Identity Platform tier makes the budgeted requests non-billable, or an accepted charge.",
    "Confirmation that the throwaway address domain is accepted by production sign-up; the local runtime accepting it proves nothing about production.",
    "A fresh unused 32-character hexadecimal nonce and a validity window for the run.",
)

#: Every field an owner permission must carry. The prepared package is not permission.
PERMISSION_ENVELOPE = {
    "kind": "owner-execution-permission",
    "requiredFields": (
        "campaignId",
        "frozenCommit",
        "manifestSha256",
        "comparisonContract",
        "projectId",
        "nonce",
        "validityWindow",
        "budget",
        "recoveryTerms",
    ),
    "grantedHere": False,
}

CLEANUP_CONTRACT = (
    "Every account the run creates is registered before it is used, so a crash leaves a record of what to remove.",
    "The campaign is approved as 540 seconds of observation plus up to 60 seconds of cleanup. The cleanup window is granted absolutely, from the moment cleanup starts, however the observation phase ended; a run stopped by its observation deadline still gets the whole window, so the accounts it created are still deleted.",
    "Cleanup is bounded in turn: it may spend 12 requests and its 60 seconds and no more, so the tail cannot become an unbounded run of its own.",
    "Cleanup deletes each owned account and reads back both its UID and its address as absent; a delete without a readback is not cleanup.",
    "A cleanup failure is recorded and fails the run; it can never be downgraded to a warning or skipped by a later step.",
    "The run changes no project or tenant configuration, so there is nothing to restore.",
)

FAILURE_REHEARSAL = (
    "budget-exhausted: the enforced request or wall-clock bound trips mid-run; the run stops, records the partial rows and still runs cleanup.",
    "privileged-call-refused: an admin call returns 401 or 403; no further privileged work is attempted and unconfirmed accounts stay in the journal.",
    "cleanup-refused: a delete or its readback fails; the receipt records remaining accounts and `recordingComplete` stays false.",
    "process-killed: the collector is terminated between sign-in and cleanup; the owned-account journal is the recovery input and is written before each account is used.",
    "boundary-unpinned: the same-second boundary cannot be pinned from server-reported values; the row is classified EXPECTED_NONDETERMINISM rather than dropped.",
    "deadline-exceeded: the run passes its absolute observation deadline, during a request or while waiting between two of them; it opens no further observation, hands what it has to recovery, and the receipt records the phase, the elapsed time and the limit.",
    "boundary-control-unrelated: a control is refused for a reason other than the documented expiry; the refusal is recorded and compared, and the boundary row that depends on it is INDETERMINATE.",
)

UNRESOLVED = (
    "No production request has been made and no production receipt exists.",
    "The source and artifact binding is unbound; a run must fill it from a clean frozen checkout.",
    "Production-unobserved conditions reduced by this package: 0.",
)


def cases_digest() -> str:
    """Digest the frozen case list, so a changed case cannot reuse an old receipt."""
    canonical = json.dumps(observation_cases(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def campaign_manifest(nonce: str) -> dict[str, Any]:
    """Return the inert manifest. Nonce validation proves syntax, not freshness."""
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("a 32-character hexadecimal nonce is required")
    return {
        "campaignId": CAMPAIGN_ID,
        "status": STATUS,
        "productionExecuted": False,
        "productionAllowed": False,
        "comparisonContract": CONTRACT,
        "nonce": nonce,
        "nonceStatus": "syntax-only; freshness and ownership unverified",
        "sourceBinding": {"commit": None, "artifactSha256": None},
        "frozenInputs": {"casesSha256": cases_digest(), "modules": module_digests()},
        "caseCount": len(observation_cases()),
        "budget": dict(BUDGET),
        "costBasis": list(COST_BASIS),
        "ownerPreconditions": list(OWNER_PRECONDITIONS),
        "permissionEnvelope": {
            **PERMISSION_ENVELOPE,
            "requiredFields": list(PERMISSION_ENVELOPE["requiredFields"]),
        },
        "cleanupContract": list(CLEANUP_CONTRACT),
        "failureRehearsal": list(FAILURE_REHEARSAL),
        "unresolved": list(UNRESOLVED),
    }


def validate_permission(permission: Any, manifest: dict[str, Any]) -> list[str]:
    """Return why a supplied permission is not acceptable; empty means well-formed.

    A well-formed permission is still not permission granted by this repository. This
    function checks shape only, so a caller cannot mistake a prepared package for one.
    """
    problems = []
    if not isinstance(permission, dict):
        return ["permission must be an object"]
    if permission.get("kind") != PERMISSION_ENVELOPE["kind"]:
        problems.append("kind must be owner-execution-permission")
    for field in PERMISSION_ENVELOPE["requiredFields"]:
        if permission.get(field) in (None, "", [], {}):
            problems.append(f"missing {field}")
    if permission.get("campaignId") not in (None, CAMPAIGN_ID):
        problems.append("campaignId does not name this campaign")
    if (
        permission.get("nonce") == manifest.get("nonce")
        and permission.get("nonce") is not None
    ):
        # The manifest's own nonce is a syntax example, never an approved one.
        problems.append("permission may not reuse the manifest nonce")
    return problems


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Print the inert campaign manifest.")
    parser.add_argument("--nonce", required=True)
    print(
        json.dumps(
            campaign_manifest(parser.parse_args().nonce), indent=2, sort_keys=True
        )
    )
