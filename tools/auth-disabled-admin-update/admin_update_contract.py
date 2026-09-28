"""Finite observations of administrative updates to an already disabled account."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require, tokens

# Target A is disabled through privileged accounts:update; control B stays enabled. While
# A is disabled, an administrative password replacement and an administrative photo
# update are attempted, and any tokens the password update returns are used for lookup
# and refresh. A's own sign-in with the new password is tried while disabled and after
# re-enablement. Diagnostic rows accept either outcome; controls must succeed.
CASES = (
    "baseline-a-signin",
    "baseline-b-signin",
    "disabled-a-password-update",
    "disabled-a-update-token-lookup",
    "disabled-a-update-token-refresh",
    "disabled-a-photo-update",
    "disabled-a-signin",
    "disabled-b-signin",
    "reenabled-a-signin",
    "reenabled-b-signin",
)
DIAGNOSTIC = (
    "disabled-a-password-update",
    "disabled-a-update-token-lookup",
    "disabled-a-update-token-refresh",
    "disabled-a-photo-update",
    "disabled-a-signin",
    "reenabled-a-signin",
)
CORPUS = {"slice": "auth-disabled-admin-update", "revision": 1, "cases": list(CASES)}
ERRORS = {
    "USER_DISABLED",
    "USER_NOT_FOUND",
    "INVALID_ID_TOKEN",
    "TOKEN_EXPIRED",
    "INVALID_REFRESH_TOKEN",
    "INVALID_LOGIN_CREDENTIALS",
    "INVALID_PASSWORD",
    "WEAK_PASSWORD",
    "OPERATION_NOT_ALLOWED",
    "PERMISSION_DENIED",
}
SIGNIN_CHECKS = set(tokens({}, "uid", "email")) | {"derivedLookup"}
UPDATE_CHECKS = {"noError", "localIdMatches", "tokensReturned", "readbackApplied"}
PHOTO_URL = "https://example.test/disabled-admin-update.png"


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
        require(name.endswith(("-update-token-lookup", "-update-token-refresh")))
        require(row["httpStatus"] is None and row["outcome"] == "skipped")
        require(row["observedError"] is None and row["checks"] == {})
        return
    require(type(row["httpStatus"]) is int)
    if row["outcome"] == "refused":
        require(name in DIAGNOSTIC)
        require(row["httpStatus"] in {400, 403} and row["observedError"] in ERRORS)
        require(row["checks"] == {})
        return
    require(row["outcome"] == "accepted")
    require(row["httpStatus"] == 200 and row["observedError"] is None)
    require(isinstance(row["checks"], dict) and row["checks"] != {})
    if name.endswith("-update"):
        # Whether the administrative update returned tokens is the observation itself.
        require(set(row["checks"]) == UPDATE_CHECKS)
        require(type(row["checks"]["tokensReturned"]) is bool)
        require(
            all(
                row["checks"][k] is True
                for k in ("noError", "localIdMatches", "readbackApplied")
            )
        )
        return
    require(all(v is True for v in row["checks"].values()))
    if name.endswith("-signin"):
        require(set(row["checks"]) == SIGNIN_CHECKS)
    elif name.endswith("-update-token-lookup"):
        require(set(row["checks"]) == {"ownerMatches"})
    else:
        require(
            set(row["checks"])
            == set(tokens({}, "uid", "email", True)) | {"derivedLookup"}
        )


def complete(report):
    try:
        require(not any(k in report for k in ("failure", "cleanupFailure")))
        require(
            report["status"] == "observed"
            and [r["id"] for r in report["cases"]] == list(CASES)
        )
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_row(row, name)
        require(report["setup"] == {"a": True, "b": True})
        require(
            report["transitions"]
            == [
                {"disabled": True, "targetReadback": True, "controlUnchanged": True},
                {"disabled": False, "targetReadback": True, "controlUnchanged": True},
            ]
        )
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(report["configurationUnchanged"] is True)
        rows = {r["id"]: r for r in report["cases"]}
        update = rows["disabled-a-password-update"]
        require(not update["skipped"])
        issued = update["outcome"] == "accepted" and update["checks"]["tokensReturned"]
        require(rows["disabled-a-update-token-lookup"]["skipped"] == (not issued))
        require(rows["disabled-a-update-token-refresh"]["skipped"] == (not issued))
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing is retained but not required to be identical across runs."""
    return [{k: v for k, v in row.items() if k != "elapsedMs"} for row in rows]
