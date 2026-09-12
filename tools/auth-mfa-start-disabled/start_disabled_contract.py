"""Finite observations of mfaSignIn:start on an account disabled after its pending credential.

The question (AUTH-U03): a pending credential is obtained while the account is enabled;
the account is then disabled administratively; an otherwise well-formed mfaSignIn:start is
attempted with that pending credential; then the account is re-enabled and the same
pending credential is started and finalized. What mfaSignIn:start returns while disabled,
and whether the pending credential survives to re-enablement, are the observations. Only
the fresh finalizes are controls; USER_DISABLED is not pinned as the expected answer.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require

CASES = (
    "baseline-fresh-finalize",
    "disabled-start",
    "disabled-finalize",
    "reenabled-start",
    "reenabled-finalize",
    "final-fresh-finalize",
)
# Every row about the disabled or re-enabled held credential is diagnostic: accepted and
# refused are both valid observations.
DIAGNOSTIC = (
    "disabled-start",
    "disabled-finalize",
    "reenabled-start",
    "reenabled-finalize",
)
CONTROLS = ("baseline-fresh-finalize", "final-fresh-finalize")
CORPUS = {"slice": "auth-mfa-start-disabled", "revision": 1, "cases": list(CASES)}

ERRORS = {
    "INVALID_MFA_PENDING_CREDENTIAL",
    "MISSING_MFA_PENDING_CREDENTIAL",
    "INVALID_SESSION_INFO",
    "INVALID_CODE",
    "SESSION_EXPIRED",
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
    "TOO_MANY_ATTEMPTS_TRY_LATER",
    "QUOTA_EXCEEDED",
}
CLASSIFIED_STATUSES = {400, 403}
TRANSIENT_ERRORS = {"TOO_MANY_ATTEMPTS_TRY_LATER", "QUOTA_EXCEEDED"}
COMPLETING_ERRORS = ERRORS - TRANSIENT_ERRORS

FINALIZE_CHECKS = {
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "claimSubMatches",
    "claimEmailMatches",
    "secondFactorClaim",
    "derivedLookup",
}
TEST_PHONE = "+15555550100"
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
        # A finalize is skipped only when its own start was not accepted.
        require(name in {"disabled-finalize", "reenabled-finalize"})
        require(row["httpStatus"] is None and row["outcome"] == "skipped")
        require(row["observedError"] is None and row["checks"] == {})
        return
    require(type(row["httpStatus"]) is int)
    if row["outcome"] == "refused":
        require(name in DIAGNOSTIC)
        require(400 <= row["httpStatus"] <= 599)
        require(row["observedError"] in ERRORS | {"UNCLASSIFIED_ERROR"})
        require(row["checks"] == {})
        return
    require(row["outcome"] == "accepted")
    require(row["httpStatus"] == 200 and row["observedError"] is None)
    require(isinstance(row["checks"], dict) and row["checks"] != {})
    if name.endswith("-start"):
        require(set(row["checks"]) == {"sessionInfoPresent"})
        require(type(row["checks"]["sessionInfoPresent"]) is bool)
        return
    require(name.endswith("-finalize"))
    require(set(row["checks"]) == FINALIZE_CHECKS)
    if name in CONTROLS:
        require(all(v is True for v in row["checks"].values()))
    else:
        # A diagnostic finalize records every token check as a boolean.
        require(all(type(v) is bool for v in row["checks"].values()))


def classified(row):
    """A refused row a receipt can rely on: a validation status with a completing
    (non-transient) error. A transient error never completes a run, at any status."""
    return row["outcome"] != "refused" or (
        row["httpStatus"] in CLASSIFIED_STATUSES
        and row["observedError"] in COMPLETING_ERRORS
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
            require(classified(row))
        require(report["setup"] is True)
        require(
            report["transitions"]
            == [
                {"disabled": True, "readback": True},
                {"disabled": False, "readback": True},
            ]
        )
        require(report["heldPendingBeforeDisable"] is True)
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(report["configRestored"] is True)
        require(report["configDigestMatches"] is True)
        rows = {r["id"]: r for r in report["cases"]}
        # A finalize runs exactly when its own start was accepted and returned a session.
        for start_name, finalize_name in (
            ("disabled-start", "disabled-finalize"),
            ("reenabled-start", "reenabled-finalize"),
        ):
            start = rows[start_name]
            accepted = (
                start["outcome"] == "accepted"
                and start["checks"].get("sessionInfoPresent") is True
            )
            require(rows[finalize_name]["skipped"] == (not accepted))
        if report["target"] == "production":
            require(report["committedCheckout"] is True)
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing is retained but not required to be identical across runs."""
    return [{k: v for k, v in row.items() if k != "elapsedMs"} for row in rows]
