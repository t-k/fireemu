"""Finite observations of a beforeSignIn function that disables an account on the very
request that creates it (sign-up), with an unaffected control."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require, tokens

# Target T signs up with the selector photo URL; the registered function answers
# disabled: true for it, so the creating request itself is subject to the disable.
# Control C signs up without the selector. The record readback rows are the observation
# of whether the created account exists and is disabled; they are recorded as seen.
CASES = (
    "control-c-signup",
    "control-c-signup-readback",
    "control-c-signin",
    "target-t-signup",
    "target-t-token-lookup",
    "target-t-token-refresh",
    "target-t-record-readback",
    "target-t-signin",
    "target-t-second-signup",
    "control-c-final-signin",
)
DIAGNOSTIC = (
    "target-t-signup",
    "target-t-token-lookup",
    "target-t-token-refresh",
    "target-t-signin",
    "target-t-second-signup",
)
CORPUS = {"slice": "auth-blocking-create-disable", "revision": 2, "cases": list(CASES)}
ERRORS = {
    "USER_DISABLED",
    "EMAIL_EXISTS",
    "USER_NOT_FOUND",
    "INVALID_LOGIN_CREDENTIALS",
    "INVALID_ID_TOKEN",
    "TOKEN_EXPIRED",
    "INVALID_REFRESH_TOKEN",
    "OPERATION_NOT_ALLOWED",
    "BLOCKING_FUNCTION_ERROR_RESPONSE",
}
SIGNIN_CHECKS = set(tokens({}, "uid", "email")) | {"derivedLookup"}
SIGNUP_CHECKS = set(tokens({}, "uid", "email")) | {"derivedLookup"}
READBACK_CHECKS = {"recordExists", "disabledPersisted"}
CONTROL_READBACK_CHECKS = {"recordExists", "photoUrlPersisted", "notDisabled"}
# Revision 1 selected on a sign-up photo URL; production does not persist that field
# (recorded 2026-09-12), so the hook never matched. Revision 2 selects on a fixed hex
# prefix of the sign-up email's local part, which stays within the owned-account email
# shape; the control keeps a random local part. Both sign-ups still send a photo URL so
# the control readback keeps observing whether sign-up persists it.
SELECTOR = "fireemu-basic-d15ab1e"
SELECTOR_PHOTO = "https://example.test/fireemu-disable-on-create"
CONTROL_PHOTO = "https://example.test/fireemu-control-photo"


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
    if name == "target-t-record-readback":
        require(set(row["checks"]) == READBACK_CHECKS)
        require(all(type(v) is bool for v in row["checks"].values()))
        return
    if name == "control-c-signup-readback":
        # Whether sign-up persisted the control's photo URL is itself an observation.
        require(set(row["checks"]) == CONTROL_READBACK_CHECKS)
        require(type(row["checks"]["photoUrlPersisted"]) is bool)
        require(
            row["checks"]["recordExists"] is True
            and row["checks"]["notDisabled"] is True
        )
        return
    require(all(v is True for v in row["checks"].values()))
    if name.endswith("-signup"):
        require(set(row["checks"]) == SIGNUP_CHECKS)
    elif name.endswith("-signin"):
        require(set(row["checks"]) == SIGNIN_CHECKS)
    elif name.endswith("-token-lookup"):
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
        require(report["setup"] == {"c": True})
        require(report["hook"] == {"deployed": True, "triggerReadback": True})
        # Per-account cleanup: the control is always deleted with confirmation; the
        # target is either deleted with confirmation or, only when the creating request
        # was refused and no record was read back, recorded as never created.
        rows = {r["id"]: r for r in report["cases"]}
        cleanup = report["cleanup"]
        require(set(cleanup) == {"c", "t"})
        require(cleanup["c"] == {"uidAbsent": True, "emailAbsent": True})
        never = cleanup["t"] == {"recordNeverCreated": True, "emailAbsent": True}
        if never:
            require(rows["target-t-signup"]["outcome"] == "refused")
            require(rows["target-t-record-readback"]["checks"]["recordExists"] is False)
        else:
            require(cleanup["t"] == {"uidAbsent": True, "emailAbsent": True})
        require(report["functionRemoved"] is True)
        require(report["configRestored"] is True)
        require(report["configDigestMatches"] is True)
        first = rows["target-t-signup"]
        require(not first["skipped"])
        issued = first["outcome"] == "accepted"
        require(rows["target-t-token-lookup"]["skipped"] == (not issued))
        require(rows["target-t-token-refresh"]["skipped"] == (not issued))
        require(not rows["target-t-record-readback"]["skipped"])
        require(not rows["target-t-second-signup"]["skipped"])
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing is retained but not required to be identical across runs."""
    return [{k: v for k, v in row.items() if k != "elapsedMs"} for row in rows]
