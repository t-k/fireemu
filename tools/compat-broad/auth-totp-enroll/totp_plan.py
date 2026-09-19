"""Non-executable logical preparation for a future TOTP observation."""

from __future__ import annotations

import json
import re

CAMPAIGN_ID = "AUTH-MFA-TOTP-ENROLL-RETRY-01"
STAGE_IDS = (
    "verified-account-prerequisite",
    "totp-start",
    "wrong-code",
    "same-session-correct-retry",
    "successful-session-replay",
    "account-factor-readback",
    "owned-resource-cleanup",
)
_PREREQUISITES = (
    "Production-capable verified-account setup and typed TOTP request contracts",
    "Validated same-session pending-state observation and tenant selector",
    "Real owned-resource cleanup finalizer and recovery evidence",
    "Enforced request, wall-clock, and cost limits",
    "Source-bound paired local and production receipts",
)


def campaign_manifest(nonce: str) -> dict:
    """Return an inert observation outline; nonce validation proves syntax only."""
    if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce):
        raise ValueError("32-character hexadecimal nonce required")
    return {
        "campaignId": CAMPAIGN_ID,
        "status": "PREPARATION",
        "productionExecuted": False,
        "productionAllowed": False,
        "nonce": nonce,
        "nonceStatus": "syntax-only; freshness and ownership unverified",
        "sourceBinding": {"commit": None, "artifactSha256": None},
        "uniqueObligation": "same TOTP session after wrong-code retry and after successful replay, with account and factor readback",
        "existingControls": [
            "conformance/fixtures/auth/mfa-error-shapes.json",
            "conformance/fixtures/auth/mfa-enrollment-eligibility.json",
            "conformance/src/auth-probe/programs.mjs",
        ],
        "stages": [{"id": stage, "status": "unresolved"} for stage in STAGE_IDS],
        "prerequisites": list(_PREREQUISITES),
        "limits": {
            "proposedMaxRequests": 15,
            "proposedMaxWallSeconds": 600,
            "proposedMaxCostUsd": 2.0,
            "enforced": False,
        },
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    print(json.dumps(campaign_manifest(args.nonce), indent=2, sort_keys=True))
