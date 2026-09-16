"""Finite observations of when a hook-applied disable becomes visible through Admin
readback: before, immediately after, five and thirty seconds after the refused sign-in of
one account, and after thirty seconds with no earlier read for a second account."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require, tokens

# X and Y carry the disabling custom claim (the function from tools/auth-blocking-disable
# answers disabled: true for it); Z is the unaffected control. Readback rows record the
# disabled flag as read through privileged lookup, true or false, with the time since the
# refused sign-in. Sign-in rows are diagnostic; the control must succeed.
CASES = (
    "control-z-signin",
    "x-readback-before",
    "x-first-signin",
    "x-readback-immediate",
    "x-readback-after-5s",
    "x-readback-after-30s",
    "x-second-signin",
    "y-first-signin",
    "y-readback-after-30s-unread",
    "y-second-signin",
    "control-z-final-signin",
)
DIAGNOSTIC = ("x-first-signin", "x-second-signin", "y-first-signin", "y-second-signin")
READBACKS = tuple(name for name in CASES if "-readback-" in name)
CORPUS = {"slice": "auth-blocking-readback", "revision": 1, "cases": list(CASES)}
ERRORS = {
    "USER_DISABLED",
    "USER_NOT_FOUND",
    "INVALID_LOGIN_CREDENTIALS",
    "OPERATION_NOT_ALLOWED",
    "BLOCKING_FUNCTION_ERROR_RESPONSE",
}
SIGNIN_CHECKS = set(tokens({}, "uid", "email")) | {"derivedLookup"}
READBACK_CHECKS = {"disabledPersisted", "secondsSinceRefusal"}
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
    require(0 <= row["elapsedMs"] <= 900000 and row["skipped"] is False)
    require(type(row["httpStatus"]) is int)
    if row["outcome"] == "refused":
        require(name in DIAGNOSTIC)
        require(row["httpStatus"] == 400 and row["observedError"] in ERRORS)
        require(row["checks"] == {})
        return
    require(row["outcome"] == "accepted")
    require(row["httpStatus"] == 200 and row["observedError"] is None)
    if name in READBACKS:
        require(set(row["checks"]) == READBACK_CHECKS)
        require(type(row["checks"]["disabledPersisted"]) is bool)
        seconds = row["checks"]["secondsSinceRefusal"]
        require(seconds is None or (type(seconds) is int and 0 <= seconds <= 600))
        require((seconds is None) == (name == "x-readback-before"))
        return
    require(set(row["checks"]) == SIGNIN_CHECKS)
    require(all(v is True for v in row["checks"].values()))


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
        require(report["setup"] == {"x": True, "y": True, "z": True})
        require(report["hook"] == {"deployed": True, "triggerReadback": True})
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(report["functionRemoved"] is True)
        require(report["configRestored"] is True)
        require(report["configDigestMatches"] is True)
        rows = {r["id"]: r for r in report["cases"]}
        # The time axis is only meaningful when the first sign-ins were refused.
        for account in ("x", "y"):
            require(rows[f"{account}-first-signin"]["outcome"] == "refused")
        require(rows["x-readback-before"]["checks"]["disabledPersisted"] is False)
        for name, minimum in (
            ("x-readback-after-5s", 5),
            ("x-readback-after-30s", 30),
            ("y-readback-after-30s-unread", 30),
        ):
            require(rows[name]["checks"]["secondsSinceRefusal"] >= minimum)
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing and the measured seconds are retained but not compared."""
    out = []
    for row in rows:
        checks = {k: v for k, v in row["checks"].items() if k != "secondsSinceRefusal"}
        out.append(
            {**{k: v for k, v in row.items() if k != "elapsedMs"}, "checks": checks}
        )
    return out
