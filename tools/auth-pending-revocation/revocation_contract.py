"""Finite observations of an existing MFA pending credential across an explicit revocation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require, tokens

# Phases: baseline (fresh pending credentials for both accounts complete), revoked (the
# pending credential of A that was issued before the revocation is tried, then a fresh A
# sign-in and B's control complete). Only "revoked-a-held-*" rows are diagnostic: the
# production outcome is what is being observed, so accepted and refused are both valid.
CASES = (
    "baseline-a-fresh-finalize",
    "baseline-b-fresh-finalize",
    "revoked-a-held-start",
    "revoked-a-held-finalize",
    "revoked-a-held-lookup",
    "revoked-a-held-refresh",
    "revoked-a-fresh-finalize",
    "revoked-b-fresh-finalize",
)
DIAGNOSTIC = tuple(name for name in CASES if name.startswith("revoked-a-held-"))
CORPUS = {"slice": "auth-pending-revocation", "revision": 1, "cases": list(CASES)}
ERRORS = {
    "INVALID_MFA_PENDING_CREDENTIAL",
    "INVALID_SESSION_INFO",
    "INVALID_CODE",
    "MFA_ENROLLMENT_NOT_FOUND",
    "MISSING_RECAPTCHA_TOKEN",
    "INVALID_RECAPTCHA_TOKEN",
    "CAPTCHA_CHECK_FAILED",
    "OPERATION_NOT_ALLOWED",
    "TOKEN_EXPIRED",
    "INVALID_ID_TOKEN",
    "INVALID_REFRESH_TOKEN",
    "USER_DISABLED",
    "USER_NOT_FOUND",
}
FINALIZE_CHECKS = {
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "claimSubMatches",
    "claimEmailMatches",
    "secondFactorClaim",
    "derivedLookup",
}
TEST_PHONES = {"a": "+15555550100", "b": "+15555550101"}
TEST_CODE = "135790"


def error_code(value):
    error = value.get("error") if isinstance(value, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    message = message.split(" : ", 1)[0] if isinstance(message, str) else None
    return (
        message
        if isinstance(message, str) and message in ERRORS
        else "UNCLASSIFIED_ERROR"
    )


def validate_row(row, name):
    require(
        name in CASES
        and isinstance(row, dict)
        and set(row)
        == {
            "id",
            "httpStatus",
            "outcome",
            "observedError",
            "checks",
            "elapsedMs",
            "skipped",
        }
    )
    require(row["id"] == name and type(row["elapsedMs"]) is int)
    require(0 <= row["elapsedMs"] <= 600000 and type(row["skipped"]) is bool)
    if row["skipped"]:
        # Only a held-credential step after an earlier held-credential refusal is skipped.
        require(name in DIAGNOSTIC and row["httpStatus"] is None)
        require(row["outcome"] == "skipped" and row["observedError"] is None)
        require(row["checks"] == {})
        return
    require(type(row["httpStatus"]) is int)
    if row["outcome"] == "refused":
        require(name in DIAGNOSTIC)
        require(row["httpStatus"] == 400 and row["observedError"] in ERRORS)
        require(row["checks"] == {})
        return
    require(row["outcome"] == "accepted")
    require(row["httpStatus"] == 200 and row["observedError"] is None)
    require(isinstance(row["checks"], dict) and row["checks"] != {})
    require(all(v is True for v in row["checks"].values()))
    if name.endswith("-finalize"):
        # mfaSignIn:finalize returns tokens without localId, email or expiresIn: the
        # identity is checked through the ID token claims and a derived lookup.
        require(
            set(row["checks"])
            == FINALIZE_CHECKS
            | ({"authTimeAtOrAfterValidSince"} if name in DIAGNOSTIC else set())
        )
    elif name.endswith("-start"):
        require(set(row["checks"]) == {"sessionInfoPresent"})
    elif name.endswith("-lookup"):
        require(set(row["checks"]) == {"ownerMatches"})
    else:
        require(
            set(row["checks"])
            == set(tokens({}, "uid", "email", True)) | {"derivedLookup"}
        )


def complete(report):
    try:
        require(
            not any(
                k in report
                for k in ("failure", "cleanupFailure", "configRestoreFailure")
            )
        )
        require(
            report["status"] == "observed"
            and [r["id"] for r in report["cases"]] == list(CASES)
        )
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_row(row, name)
        require(report["setup"] == {"a": True, "b": True})
        require(
            report["revocation"]
            == {"validSinceReadback": True, "controlUnchanged": True}
        )
        require(report["heldCredentialIssuedBeforeRevocation"] is True)
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(report["configRestored"] is True)
        require(report["configDigestMatches"] is True)
        held = {r["id"]: r for r in report["cases"] if r["id"] in DIAGNOSTIC}
        start, finalize, lookup, refresh = (held[name] for name in DIAGNOSTIC)
        # The held credential is always tried; each later step runs exactly when the
        # previous one was accepted.
        require(not start["skipped"])
        require(finalize["skipped"] == (start["outcome"] != "accepted"))
        require(lookup["skipped"] == (finalize["outcome"] != "accepted"))
        require(refresh["skipped"] == (finalize["outcome"] != "accepted"))
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing is retained but not required to be identical across runs."""
    return [{k: v for k, v in row.items() if k != "elapsedMs"} for row in rows]
