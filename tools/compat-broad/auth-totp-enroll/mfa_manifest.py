"""The frozen campaign manifest for AUTH-MFA-AGE-TOTP-01.

This manifest is the input a future authorized production run would be executed from.
Compiling it performs no network access and confers no permission: the permission
envelope below describes what an owner would have to grant, not what has been granted.
"""

from __future__ import annotations

import re
from copy import deepcopy
from types import MappingProxyType
from typing import Any

from mfa_cases import (
    AGED_PENDING_SAMPLES,
    CAMPAIGN_ID,
    REFUSAL_DIRECTION_CONTROL_AGE_SECONDS,
    SAMPLED_AGES_SECONDS,
    SOURCES,
    TOTP_STEP_ROLLOVER_SECONDS,
    critical_path_seconds,
    observation_cases,
    owned_accounts,
    serial_aging_seconds,
)
from mfa_provenance import compute_provenance, repository_root

SCHEMA = "o2-mfa-campaign-v1"
PROJECT = "fireemu-35fe6"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
SELECTOR_NAME = "pending-age-300-v1"
SELECTED_REQUEST_CONTINGENCY = {
    "resumeTokeninfoRequests": 3,
    "abandonTokeninfoRequests": 1,
    "restoreFallbackRequests": 4,
}
SELECTED_CASE_IDS = (
    "age-300s-start",
    "age-300s-finalize",
    "age-300s-same-account-fresh-control",
)
SELECTED_ACCOUNT_ROLES = ("pending-age-300",)

# Time the run spends on work that is not waiting: account creation and verification, the
# phone and TOTP enrollments, the eleven TOTP lifecycle rows, the five interaction rows,
# deletion and absence checks.
PROVISIONING_SECONDS = 420

_LIMITS = {
    # Counted from the transport rather than per case: the collector charges the real
    # number of calls each step made, so this bound is the whole run's HTTP traffic,
    # including acquisition before the first row and deletion after the last. The local
    # shadow charges about 135; the headroom covers production's preflight, configuration
    # read and restore, and credential refreshes.
    "maxRequests": 400,
    # The aging is concurrent, so the critical path is the largest due offset plus one TOTP
    # step rollover, not the sum of the offsets. The serial cost is recorded beside it so
    # the difference the acquisition schedule buys is visible rather than implied.
    "maxWallSeconds": 2700,
    "criticalPathSeconds": critical_path_seconds(),
    "serialAgingSeconds": serial_aging_seconds(),
    "provisioningSeconds": PROVISIONING_SECONDS,
    "recoveryReserveSeconds": 300,
    "maxOwnedAccounts": 14,
    "maxConcurrency": 1,
    "estimatedCostUsd": 0.1,
    "hardCostCeilingUsd": 0.5,
    "enforced": True,
}
LIMITS = MappingProxyType(_LIMITS)

_PERMISSION_ENVELOPE = {
    "project": PROJECT,
    "database": None,
    "allowedEndpoints": [
        "accounts:signUp",
        "accounts:signInWithPassword",
        "accounts:signInWithCustomToken",
        "accounts:lookup",
        "accounts:update",
        "accounts:delete",
        "accounts/mfaEnrollment:start",
        "accounts/mfaEnrollment:finalize",
        "accounts/mfaEnrollment:withdraw",
        "accounts/mfaSignIn:start",
        "accounts/mfaSignIn:finalize",
        "projects:getConfig",
        "projects:updateConfig",
    ],
    "forbidden": [
        "any Firestore, Storage, Functions or Pub/Sub operation",
        "any account the run did not create",
        "any tenant operation",
        "any blocking function deployment",
        (
            "recording a shared secret, a one-time code, an ID or refresh token, a pending "
            "credential or a session identifier in any published artifact"
        ),
    ],
    "configurationMutation": {
        "allowed": ["multi-factor state and enabled providers", "test phone numbers"],
        "restoreRequired": True,
        "restoreProof": "readback plus whole-configuration digest equality with the pre-run baseline",
    },
}

_OWNER_PRECONDITIONS = (
    (
        "Identity Platform (not legacy Firebase Authentication) is enabled on the project, "
        "because multi-factor configuration lives there."
    ),
    (
        "Multi-factor authentication is set to ENABLED with TOTP among the enabled providers; "
        "the pre-run configuration is captured and its digest recorded first."
    ),
    (
        "Phone multi-factor is enabled with one test phone number and a fixed code, so the "
        "pending-age rows send no SMS and incur no per-message charge."
    ),
    "The SMS region policy allows the test number's region for the duration of the run.",
    "No tenant, blocking function or identity-provider change happens during the run.",
    (
        "The executing principal may create, read, update and delete accounts it created, "
        "and may read and restore the project configuration."
    ),
    (
        "A named owner approves one run, bound to this manifest digest and a fresh nonce, "
        "and acknowledges that the run creates up to fourteen accounts it will delete."
    ),
)

_UNSUPPORTED_OBLIGATIONS = (
    "expired-pending-with-independently-valid-code",
    "tenant-scoped multi-factor behaviour",
    "blocking-function interaction",
    "SDK and Rules paths",
    "exact production TTL values",
)


def selector_spec(selector: str | None) -> dict[str, Any] | None:
    """Return the sole reviewed finite selector, or refuse every other spelling."""
    if selector is None:
        return None
    if selector != SELECTOR_NAME:
        raise ValueError("unsupported MFA selector")
    catalog = {case["id"]: case for case in observation_cases()}
    if any(identifier not in catalog for identifier in SELECTED_CASE_IDS):
        raise ValueError("selected MFA case is not in the campaign catalog")
    return {
        "name": SELECTOR_NAME,
        "caseIds": list(SELECTED_CASE_IDS),
        "accountRoles": list(SELECTED_ACCOUNT_ROLES),
        "observedAgeSeconds": 301,
        "dataRequests": 11,
        "recoveryRequests": 4,
        "managementRequests": 6,
        "declaredRequests": 22,
        "requestContingency": deepcopy(SELECTED_REQUEST_CONTINGENCY),
        "maxWallSeconds": 1200,
        "criticalPathSeconds": 301,
        "slackSeconds": 119,
    }


def compile_campaign(
    nonce: str, project: str = PROJECT, selector: str | None = None
) -> dict[str, Any]:
    """Compile the deterministic campaign manifest for one fresh nonce."""
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be exactly 128-bit lowercase hexadecimal")
    if project != PROJECT:
        raise ValueError("the campaign is fixed to the oracle project")
    from mfa_collector import digest as canonical_digest

    accounts = [
        {
            "role": role,
            "email": f"o2-mfa-{role}-{nonce}@example.com",
            "ownership": "created-by-this-run",
        }
        for role in owned_accounts()
    ]
    cases = observation_cases()
    manifest = {
        "schema": SCHEMA,
        "campaignId": CAMPAIGN_ID,
        "status": "PREPARED_UNOBSERVED",
        "productionExecuted": False,
        "productionAllowed": False,
        "project": project,
        "owner": {
            "namespace": f"o2/{CAMPAIGN_ID}/{nonce}",
            "nonceDigest": canonical_digest(nonce),
            "accounts": accounts,
        },
        "sampledAgesSeconds": list(SAMPLED_AGES_SECONDS),
        "refusalDirectionControlAgeSeconds": REFUSAL_DIRECTION_CONTROL_AGE_SECONDS,
        "agingSchedule": {
            "mode": "concurrent-acquisition",
            "contract": (
                "Every aged pending credential and every aged enrollment session is "
                "acquired at one common origin before any wait begins, and each aged row "
                "is scheduled at that origin plus its own age. The ages therefore elapse "
                "concurrently and the run's critical path is the largest age rather than "
                "their sum. Acquiring a resource immediately before its own wait, which is "
                "the obvious reading, costs the serial total instead and does not fit the "
                "wall budget."
            ),
            "acquireAtOriginSeconds": 0,
            "agedPendingSamplesSeconds": list(AGED_PENDING_SAMPLES),
            "agedSessionSamplesSeconds": list(SAMPLED_AGES_SECONDS),
            "totpStepRolloverSeconds": TOTP_STEP_ROLLOVER_SECONDS,
            "dueOffsetsSeconds": [
                {"case": case["id"], "dueOffsetSeconds": case["dueOffsetSeconds"]}
                for case in observation_cases()
                if case["dueOffsetSeconds"]
            ],
        },
        "sources": dict(SOURCES),
        "limits": deepcopy(_LIMITS),
        "permissionEnvelope": deepcopy(_PERMISSION_ENVELOPE),
        "ownerPreconditions": list(_OWNER_PRECONDITIONS),
        "unsupportedObligations": list(_UNSUPPORTED_OBLIGATIONS),
        "cleanupContract": {
            "order": [
                "withdraw-enrolled-factors",
                "delete-owned-accounts",
                "verify-account-absence-by-uid-and-email",
                "restore-project-configuration",
                "verify-configuration-digest-equals-baseline",
            ],
            "onAbort": "cleanup still runs; an incomplete cleanup makes the run incomplete",
            "residueAllowed": 0,
        },
        "cases": cases,
        "caseCount": len(cases),
    }
    selected = selector_spec(selector)
    if selected is not None:
        manifest["limits"] = deepcopy(_LIMITS)
        manifest["limits"]["maxWallSeconds"] = selected["maxWallSeconds"]
        manifest["limits"]["criticalPathSeconds"] = selected["criticalPathSeconds"]
        manifest["limits"]["serialAgingSeconds"] = selected["criticalPathSeconds"]
        manifest["selector"] = selected
    return manifest


def campaign_provenance(root: Any = None) -> dict[str, Any]:
    """Recompute the bound-input provenance for the campaign in this worktree."""
    return compute_provenance(repository_root() if root is None else root)


def validate_campaign(plan: Any) -> bool:
    """Return True only when `plan` equals a freshly compiled manifest."""
    if not isinstance(plan, dict) or plan.get("schema") != SCHEMA:
        return False
    try:
        from mfa_collector import digest as canonical_digest

        nonce_digest = plan["owner"]["nonceDigest"]
        namespace = plan["owner"]["namespace"]
        nonce = namespace.rsplit("/", 1)[-1]
        if not _NONCE.fullmatch(nonce) or canonical_digest(nonce) != nonce_digest:
            return False
        if (
            plan.get("productionExecuted") is not False
            or plan.get("productionAllowed") is not False
        ):
            return False
        selector = plan.get("selector", {}).get("name") if "selector" in plan else None
        return plan == compile_campaign(nonce, plan["project"], selector)
    except (KeyError, TypeError, AttributeError, ValueError):
        return False
