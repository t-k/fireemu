"""Offline plan for AUTH-MFA-TOTP-ENROLL-RETRY-01.

This module only describes a future observation. It does not contain a
production transport or credentials.
"""

from __future__ import annotations

import re

CAMPAIGN_ID = "AUTH-MFA-TOTP-ENROLL-RETRY-01"
SOURCE_COMMIT = "f3be8df11f9096a44b45272681744b406c9713d5"


def _operation(stage: str, method: str, path: str, resource: str, principal: str, *, body: dict | None = None) -> dict:
    return {
        "stage": stage,
        "service": "auth",
        "method": method,
        "path": path,
        "body": body,
        "resource": resource,
        "principal": principal,
        "origin": "loopback-only",
        "productionAllowed": False,
    }


def campaign_manifest(nonce: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{32}", nonce or ""):
        raise ValueError("fresh hexadecimal nonce required")
    account = f"accounts/{nonce}"
    session = f"mfaSessions/{nonce}"
    principal = f"owned-account:{nonce}"
    operations = [
        _operation("C0-create-user", "POST", "/v1/accounts:signUp", account, principal),
        _operation("C0-verify-email", "POST", "/v1/accounts:sendOobCode", account, principal),
        _operation("C0-read-user", "POST", "/v1/accounts:lookup", account, principal),
        _operation("C1-start", "POST", "/v2/accounts/mfaEnrollment:start", session, principal, body={"idToken": "$owned:idToken", "totpEnrollmentInfo": {}}),
        _operation("C1-read-user", "POST", "/v1/accounts:lookup", account, principal),
        _operation("C1-read-session", "GET", f"/v2/{session}", session, principal),
        _operation("C2-wrong-code", "POST", "/v2/accounts/mfaEnrollment:finalize", session, principal, body={"idToken": "$owned:idToken", "totpVerificationInfo": {"sessionInfo": "$owned:sessionInfo", "verificationCode": "$classified:wrong", "displayName": "O2 TOTP"}}),
        _operation("C2-read-state", "POST", "/v1/accounts:lookup", account, principal),
        _operation("C3-correct-code", "POST", "/v2/accounts/mfaEnrollment:finalize", session, principal, body={"idToken": "$owned:idToken", "totpVerificationInfo": {"sessionInfo": "$owned:sessionInfo", "verificationCode": "$classified:correct", "displayName": "O2 TOTP"}}),
        _operation("C3-read-user", "POST", "/v1/accounts:lookup", account, principal),
        _operation("C4-replay", "POST", "/v2/accounts/mfaEnrollment:finalize", session, principal, body={"idToken": "$owned:idToken", "totpVerificationInfo": {"sessionInfo": "$owned:sessionInfo", "verificationCode": "$classified:correct", "displayName": "O2 TOTP"}}),
        _operation("C4-read-user", "POST", "/v1/accounts:lookup", account, principal),
        _operation("N0-unverified-start", "POST", "/v2/accounts/mfaEnrollment:start", f"negative/{nonce}", principal, body={"idToken": "$owned:unverifiedIdToken", "totpEnrollmentInfo": {}}),
        _operation("N1-wrong-tenant-start", "POST", "/v2/accounts/mfaEnrollment:start", f"tenant/{nonce}", principal, body={"idToken": "$owned:idToken", "totpEnrollmentInfo": {}}),
        _operation("cleanup-read", "POST", "/v1/accounts:lookup", account, principal),
    ]
    return {
        "campaignId": CAMPAIGN_ID,
        "status": "PREPARED_NOT_READY",
        "technicalStatus": "LOCAL_SHADOW_ONLY",
        "productionExecuted": False,
        "nonce": nonce,
        "sourceBinding": {"commit": SOURCE_COMMIT, "artifactSha256": None},
        "gate": {"productionAuthorization": False, "owner": None, "credential": None},
        "limits": {"maxRequests": 15, "maxWallSeconds": 600, "maxCostUsd": 2.0},
        "operations": operations,
        "cleanup": {"ownedOnly": True, "recovery": "stop and retain recovery receipt; never unconditional delete"},
        "outOfScope": ["production requests", "SMS/email delivery", "expired OTP", "clock skew", "multiple factors"],
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    print(json.dumps(campaign_manifest(args.nonce), indent=2, sort_keys=True))
