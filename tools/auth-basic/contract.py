"""Bounded semantic projections; never retain raw Auth response values."""

import re

CASES = (
    "signup",
    "signin",
    "lookup",
    "wrong-password",
    "unchanged-state",
    "refresh",
    "refreshed-lookup",
    "delete",
    "deleted-account-absent",
)


def require(condition):
    if not condition:
        raise ValueError("Auth observation contract failed")


def users(status, value):
    require(status == 200 and isinstance(value, dict) and "error" not in value)
    result = value.get("users", [])
    require(isinstance(result, list) and all(isinstance(user, dict) for user in result))
    return result


def owned(records, email, marker, uid=None):
    require(len(records) == 1)
    user = records[0]
    require(isinstance(user.get("localId"), str) and bool(user["localId"]))
    require(user.get("email") == email and user.get("displayName") == marker)
    require(uid is None or user["localId"] == uid)
    return user["localId"]


def error_code(value):
    error = value.get("error", {}) if isinstance(value, dict) else {}
    message = error.get("message") if isinstance(error, dict) else None
    code = message.split(" : ", 1)[0] if isinstance(message, str) else ""
    return code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", code) else "UNCLASSIFIED_ERROR"


def tokens(value, uid, email, refresh=False):
    value = value if isinstance(value, dict) else {}
    identity, renewal, expiry, user = (
        ("id_token", "refresh_token", "expires_in", "user_id")
        if refresh
        else ("idToken", "refreshToken", "expiresIn", "localId")
    )
    seconds = value.get(expiry)
    result = {
        "noError": "error" not in value,
        "idTokenPresent": isinstance(value.get(identity), str)
        and bool(value[identity]),
        "refreshTokenPresent": isinstance(value.get(renewal), str)
        and bool(value[renewal]),
        "uidMatches": value.get(user) == uid,
        "expiryValid": isinstance(seconds, str)
        and bool(re.fullmatch(r"[1-9][0-9]{0,5}", seconds)),
    }
    if refresh:
        result["bearerType"] = (
            value.get("token_type", "").lower() == "bearer"
            if isinstance(value.get("token_type"), str)
            else False
        )
    else:
        result["emailMatches"] = value.get("email") == email
    return result


def complete(report):
    if any(
        key in report for key in ("failure", "cleanupFailure", "childCleanupFailure")
    ):
        return False
    rows = report.get("cases")
    return (
        report.get("status") in {"passed", "failed"}
        and isinstance(rows, list)
        and all(
            isinstance(row, dict) and type(row.get("passed")) is bool for row in rows
        )
        and [row.get("id") for row in rows] == list(CASES)
        and report.get("cleanup") == {"uidAbsent": True, "emailAbsent": True}
    )


def cleanup_confirmed(uid, uid_absent, email_absent):
    """Empty reads cannot resolve a creation request with an unknown outcome."""
    return (
        isinstance(uid, str)
        and bool(uid)
        and uid_absent is True
        and email_absent is True
    )
