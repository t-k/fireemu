"""Finite deleted-account observations, distinct from SDK revocation semantics."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require, tokens

PHASES = ("baseline", "deleted")
CASES = tuple(
    f"{phase}-{account}-{route}"
    for phase in PHASES
    for account in ("a", "b")
    for route in ("signin", "id", "refresh")
)
CORPUS = {"slice": "auth-deleted", "revision": 1, "cases": list(CASES)}
ERRORS = {
    "USER_DISABLED",
    "TOKEN_EXPIRED",
    "INVALID_ID_TOKEN",
    "INVALID_REFRESH_TOKEN",
    "USER_NOT_FOUND",
    "INVALID_LOGIN_CREDENTIALS",
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
            "expirySeconds",
            "elapsedMs",
        }
    )
    require(row["id"] == name and type(row["httpStatus"]) is int)
    require(type(row["elapsedMs"]) is int and 0 <= row["elapsedMs"] <= 120000)
    phase, account, route = name.split("-")
    if row["outcome"] == "refused":
        require(account == "a" and phase == "deleted")
        require(
            row["httpStatus"] == 400
            and row["observedError"] in ERRORS
            and row["checks"] == {}
            and row["expirySeconds"] is None
        )
    else:
        require(not (account == "a" and phase == "deleted"))
        require(
            row["outcome"] == "accepted"
            and row["httpStatus"] == 200
            and row["observedError"] is None
        )
        flags = (
            {"stateMatches"}
            if route == "id"
            else set(tokens({}, "uid", "email", route == "refresh")) | {"derivedLookup"}
        )
        require(
            set(row["checks"]) == flags
            and all(v is True for v in row["checks"].values())
        )
        require(row["expirySeconds"] == (None if route == "id" else "3600"))


def complete(report):
    try:
        require(
            not any(
                k in report
                for k in ("failure", "cleanupFailure", "childCleanupFailure")
            )
        )
        require(
            report["status"] == "observed"
            and [r["id"] for r in report["cases"]] == list(CASES)
        )
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_row(row, name)
        require(report["setup"] == {"a": True, "b": True})
        require(all(v is True for v in report["setup"].values()))
        require(
            report["transitions"]
            == [
                {
                    "deleteHttpStatus": 200,
                    "uidAbsent": True,
                    "emailAbsent": True,
                    "controlUnchanged": True,
                }
            ]
        )
        transition = report["transitions"][0]
        require(type(transition["deleteHttpStatus"]) is int)
        require(
            all(
                transition[key] is True
                for key in ("uidAbsent", "emailAbsent", "controlUnchanged")
            )
        )
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(all(v is True for v in report["cleanup"].values()))
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing is retained but not required to be identical across runs."""
    return [{k: v for k, v in row.items() if k != "elapsedMs"} for row in rows]
