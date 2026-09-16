"""Finite observations of a beforeSignIn blocking function that disables the account."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require, tokens

# Accounts: a (phone MFA, carries the disabling claim), b (phone MFA, control, no claim),
# c (no MFA, carries the disabling claim). The deployed beforeSignIn function answers
# `{disabled: true}` for the claim and `{}` otherwise. The "-first" rows and the token and
# second-sign-in rows are diagnostic: accepted and refused are both valid observations. The
# readback rows record whether the hook's disable persisted on the account, true or false.
CASES = (
    "baseline-b-fresh-finalize",
    "hook-c-first-signin",
    "hook-c-token-lookup",
    "hook-c-token-refresh",
    "hook-c-disabled-readback",
    "hook-c-second-signin",
    "hook-a-first-finalize",
    "hook-a-token-lookup",
    "hook-a-token-refresh",
    "hook-a-disabled-readback",
    "hook-a-second-signin",
    "final-b-fresh-finalize",
)
DIAGNOSTIC = tuple(
    name
    for name in CASES
    if name.endswith(
        (
            "-first-signin",
            "-first-finalize",
            "-token-lookup",
            "-token-refresh",
            "-second-signin",
        )
    )
)
CORPUS = {"slice": "auth-blocking-disable", "revision": 1, "cases": list(CASES)}
ERRORS = {
    "USER_DISABLED",
    "INVALID_MFA_PENDING_CREDENTIAL",
    "INVALID_SESSION_INFO",
    "INVALID_CODE",
    "MFA_ENROLLMENT_NOT_FOUND",
    "OPERATION_NOT_ALLOWED",
    "TOKEN_EXPIRED",
    "INVALID_ID_TOKEN",
    "INVALID_REFRESH_TOKEN",
    "USER_NOT_FOUND",
    "BLOCKING_FUNCTION_ERROR_RESPONSE",
    "INVALID_LOGIN_CREDENTIALS",
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
SIGNIN_CHECKS = set(tokens({}, "uid", "email")) | {"derivedLookup"}
# The MFA account's second sign-in, if accepted, yields a pending credential, not tokens.
PENDING_CHECKS = {
    "noError",
    "pendingCredentialPresent",
    "noIdToken",
    "noRefreshToken",
    "enrollmentMatches",
}
TEST_PHONES = {"a": "+15555550100", "b": "+15555550101"}
TEST_CODE = "135790"
DISABLING_CLAIM = "fireemuDisableOnSignIn"


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
    require(0 <= row["elapsedMs"] <= 900000 and type(row["skipped"]) is bool)
    if row["skipped"]:
        require(name.endswith(("-token-lookup", "-token-refresh")))
        require(row["httpStatus"] is None and row["outcome"] == "skipped")
        require(row["observedError"] is None and row["checks"] == {})
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
    if name.endswith("-disabled-readback"):
        # Whether the hook's disable persisted is itself the observation: the flag read
        # back through Admin is recorded as seen, true or false.
        require(set(row["checks"]) == {"disabledPersisted"})
        require(type(row["checks"]["disabledPersisted"]) is bool)
        return
    require(all(v is True for v in row["checks"].values()))
    if name.endswith("-finalize"):
        require(set(row["checks"]) == FINALIZE_CHECKS)
    elif name == "hook-a-second-signin":
        require(set(row["checks"]) == PENDING_CHECKS)
    elif name.endswith("-signin"):
        require(set(row["checks"]) == SIGNIN_CHECKS)
    elif name.endswith("-token-lookup"):
        require(set(row["checks"]) == {"ownerMatches"})
    elif name.endswith("-token-refresh"):
        require(
            set(row["checks"])
            == set(tokens({}, "uid", "email", True)) | {"derivedLookup"}
        )
    else:
        raise ValueError("Auth observation contract failed")


def complete(report):
    try:
        require(
            not any(
                k in report
                for k in (
                    "failure",
                    "cleanupFailure",
                    "functionRemovalFailure",
                    "configRestoreFailure",
                )
            )
        )
        require(
            report["status"] == "observed"
            and [r["id"] for r in report["cases"]] == list(CASES)
        )
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_row(row, name)
        require(report["setup"] == {"a": True, "b": True, "c": True})
        require(report["hook"] == {"deployed": True, "triggerReadback": True})
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(report["functionRemoved"] is True)
        require(report["configRestored"] is True)
        require(report["configDigestMatches"] is True)
        rows = {r["id"]: r for r in report["cases"]}
        for account in ("c", "a"):
            first = rows[
                f"hook-{account}-first-" + ("signin" if account == "c" else "finalize")
            ]
            require(not first["skipped"])
            issued = first["outcome"] == "accepted"
            require(rows[f"hook-{account}-token-lookup"]["skipped"] == (not issued))
            require(rows[f"hook-{account}-token-refresh"]["skipped"] == (not issued))
            require(not rows[f"hook-{account}-second-signin"]["skipped"])
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing is retained but not required to be identical across runs."""
    return [{k: v for k, v in row.items() if k != "elapsedMs"} for row in rows]
