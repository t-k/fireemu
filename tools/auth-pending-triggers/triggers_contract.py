"""Finite observations of an existing MFA pending credential across one revocation trigger.

The same skeleton is run once per trigger, each an independent slice, receipt and
approval: hold a pending credential and an SMS session, fire exactly one trigger, read
back, present the held credential to start and finalize, then a fresh control. Which of
the held rows still complete is the observation; only the fresh rows are controls, so a
held row that is refused or accepted is recorded either way and never aborts the run.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require, tokens

TRIGGERS = (
    "client-password-change",
    "admin-password-update",
    "password-reset",
    "provider-unlink",
)

CASES = (
    "baseline-fresh-finalize",
    "trigger",
    "held-start",
    "held-finalize",
    "held-lookup",
    "held-refresh",
    "final-fresh-finalize",
)
DIAGNOSTIC = ("trigger", "held-start", "held-finalize", "held-lookup", "held-refresh")
CONTROLS = ("baseline-fresh-finalize", "final-fresh-finalize")

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
    "CREDENTIAL_TOO_OLD_LOGIN_AGAIN",
    "PERMISSION_DENIED",
    "USER_DISABLED",
    "USER_NOT_FOUND",
    "INVALID_OOB_CODE",
    "TOO_MANY_ATTEMPTS_TRY_LATER",
    "QUOTA_EXCEEDED",
}
CLASSIFIED_STATUSES = {400, 403}

FINALIZE_CHECKS = {
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "claimSubMatches",
    "claimEmailMatches",
    "secondFactorClaim",
    "derivedLookup",
}
# The trigger row records the transition and a readback as booleans; an accepted trigger
# must at least have carried no error. Which keys are present depends on the trigger.
PASSWORD_TRIGGER_CHECKS = {"noError", "accountPresent", "tokensReturned"}
UNLINK_TRIGGER_CHECKS = {
    "noError",
    "providerAbsentAfter",
    "otherStateUnchanged",
    "tokensReturned",
}
TEST_PHONE = "+15555550100"
TEST_CODE = "135790"
LINK_PROVIDER = "google.com"


def trigger_checks(trigger):
    require(trigger in TRIGGERS)
    return (
        UNLINK_TRIGGER_CHECKS
        if trigger == "provider-unlink"
        else PASSWORD_TRIGGER_CHECKS
    )


def corpus(trigger):
    require(trigger in TRIGGERS)
    return {
        "slice": f"auth-pending-trigger-{trigger}",
        "revision": 1,
        "cases": list(CASES),
    }


def error_code(value):
    error = value.get("error") if isinstance(value, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    message = message.split(" : ", 1)[0] if isinstance(message, str) else None
    return (
        message
        if isinstance(message, str) and message in ERRORS
        else "UNCLASSIFIED_ERROR"
    )


def validate_row(row, name, trigger):
    require(trigger in TRIGGERS)
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
        # Only held-lookup and held-refresh are skipped, and only after the held finalize
        # was not accepted.
        require(name in {"held-lookup", "held-refresh"})
        require(row["httpStatus"] is None and row["outcome"] == "skipped")
        require(row["observedError"] is None and row["checks"] == {})
        return
    require(type(row["httpStatus"]) is int)
    if row["outcome"] == "refused":
        # Only diagnostic rows may be refused, with any error status, so that an
        # unforeseen production answer is recorded instead of aborting the run.
        require(name in DIAGNOSTIC)
        require(400 <= row["httpStatus"] <= 599)
        require(row["observedError"] in ERRORS | {"UNCLASSIFIED_ERROR"})
        require(row["checks"] == {})
        return
    require(row["outcome"] == "accepted")
    require(row["httpStatus"] == 200 and row["observedError"] is None)
    require(isinstance(row["checks"], dict) and row["checks"] != {})
    if name == "trigger":
        require(set(row["checks"]) == trigger_checks(trigger))
        require(all(type(v) is bool for v in row["checks"].values()))
        require(row["checks"]["noError"] is True)
        return
    if name in {"baseline-fresh-finalize", "final-fresh-finalize", "held-finalize"}:
        require(set(row["checks"]) == FINALIZE_CHECKS)
        if name in CONTROLS:
            require(all(v is True for v in row["checks"].values()))
        else:
            # A held finalize is diagnostic: every token check is recorded as a boolean.
            require(all(type(v) is bool for v in row["checks"].values()))
        return
    if name == "held-start":
        require(set(row["checks"]) == {"sessionInfoPresent"})
        require(type(row["checks"]["sessionInfoPresent"]) is bool)
        return
    if name == "held-lookup":
        require(set(row["checks"]) == {"ownerMatches"})
        require(type(row["checks"]["ownerMatches"]) is bool)
        return
    require(name == "held-refresh")
    require(
        set(row["checks"]) == set(tokens({}, "uid", "email", True)) | {"derivedLookup"}
    )
    require(all(type(v) is bool for v in row["checks"].values()))


def classified(row):
    """A refused row whose class and status a receipt can rely on."""
    return row["outcome"] != "refused" or (
        row["httpStatus"] in CLASSIFIED_STATUSES and row["observedError"] in ERRORS
    )


def complete(report):
    try:
        trigger = report["trigger"]
        require(trigger in TRIGGERS)
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
            validate_row(row, name, trigger)
            require(classified(row))
        require(report["setup"] is True)
        # provider-unlink needs a federated identity linked as a precondition; the other
        # triggers must not have one.
        require(report["providerLinked"] is (trigger == "provider-unlink"))
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(report["configRestored"] is True)
        require(report["configDigestMatches"] is True)
        rows = {r["id"]: r for r in report["cases"]}
        finalize = rows["held-finalize"]
        require(not finalize["skipped"])
        accepted = finalize["outcome"] == "accepted"
        require(rows["held-lookup"]["skipped"] == (not accepted))
        require(rows["held-refresh"]["skipped"] == (not accepted))
        if report["target"] == "production":
            require(report["committedCheckout"] is True)
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing is retained but not required to be identical across runs."""
    return [{k: v for k, v in row.items() if k != "elapsedMs"} for row in rows]
