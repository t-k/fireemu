"""Bounded semantic projections; never retain raw Auth response values."""

import re

CASES = (
    "signup",
    "initial-lookup",
    "set-name",
    "set-name-lookup",
    "replace-name",
    "replace-name-lookup",
    "invalid-token-update",
    "unchanged-state",
    "delete-name",
    "deleted-name-lookup",
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
    require(user.get("email") == email)
    if uid is None:
        require(user.get("displayName") == marker)
    else:
        require(isinstance(uid, str) and bool(uid) and user["localId"] == uid)
    return user["localId"]


def error_code(value):
    error = value.get("error", {}) if isinstance(value, dict) else {}
    message = error.get("message") if isinstance(error, dict) else None
    code = message.split(" : ", 1)[0] if isinstance(message, str) else ""
    return code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", code) else "UNCLASSIFIED_ERROR"


def expiry_seconds(value, refresh=False):
    seconds = (
        value.get("expires_in" if refresh else "expiresIn")
        if isinstance(value, dict)
        else None
    )
    return (
        seconds
        if isinstance(seconds, str) and re.fullmatch(r"[1-9][0-9]{0,5}", seconds)
        else None
    )


def tokens(value, uid, email, refresh=False):
    value = value if isinstance(value, dict) else {}
    identity, renewal, user = (
        ("id_token", "refresh_token", "user_id")
        if refresh
        else ("idToken", "refreshToken", "localId")
    )
    seconds = expiry_seconds(value, refresh)
    result = {
        "noError": "error" not in value,
        "idTokenPresent": isinstance(value.get(identity), str)
        and bool(value[identity]),
        "refreshTokenPresent": isinstance(value.get(renewal), str)
        and bool(value[renewal]),
        "uidMatches": value.get(user) == uid,
        "expiryIsPositiveInteger": seconds is not None,
        "expiryMatchesOneHour": seconds == "3600",
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


FIRST = "Fireemu display first"
SECOND = "Fireemu display second"
REFUSED = "Fireemu display refused"
NAME_EXPECTED = {
    "initial-lookup": "initial",
    "set-name": "first",
    "set-name-lookup": "first",
    "replace-name": "second",
    "replace-name-lookup": "second",
    "delete-name": "absent",
    "deleted-name-lookup": "absent",
}
NAME_STATES = {
    "initial",
    "absent",
    "null",
    "empty",
    "first",
    "second",
    "other",
    "invalid-type",
}
TOKEN_CHECKS = set(tokens({}, "uid", "email")) | {"httpOk"}
CHECKS = {
    "signup": TOKEN_CHECKS,
    **{
        name: {"httpOk", "nameMatches", "selectedIdentityUnchanged"}
        for name in NAME_EXPECTED
    },
    "invalid-token-update": {"rejected", "expectedError"},
    "unchanged-state": {"httpOk", "selectedStableFieldsUnchanged"},
    "delete": {"httpOk", "noError"},
    "deleted-account-absent": {"bothSelectorsAbsent"},
}


def display_name(value, marker):
    if "displayName" not in value:
        return "absent"
    item = value["displayName"]
    if item is None:
        return "null"
    if not isinstance(item, str):
        return "invalid-type"
    return {marker: "initial", "": "empty", FIRST: "first", SECOND: "second"}.get(
        item, "other"
    )


def name_row(name, status, observed, identity_unchanged):
    checks = {
        "httpOk": status == 200,
        "nameMatches": observed == NAME_EXPECTED[name],
        "selectedIdentityUnchanged": identity_unchanged,
    }
    return {
        "id": name,
        "httpStatus": status,
        "nameState": observed,
        "checks": checks,
        "passed": all(checks.values()),
    }


def validate_case(row, name):
    require(name in CHECKS and isinstance(row, dict))
    extra = (
        {"expirySeconds"}
        if name == "signup"
        else ({"nameState"} if name in NAME_EXPECTED else set())
    )
    require(set(row) == {"id", "httpStatus", "checks", "passed"} | extra)
    require(
        row["id"] == name
        and type(row["httpStatus"]) is int
        and 100 <= row["httpStatus"] <= 599
    )
    checks = row["checks"]
    require(isinstance(checks, dict) and set(checks) == CHECKS[name])
    require(all(type(v) is bool for v in checks.values()))
    require(type(row["passed"]) is bool and row["passed"] == all(checks.values()))
    expected_status = 400 if name == "invalid-token-update" else 200
    require(not row["passed"] or row["httpStatus"] == expected_status)
    if "httpOk" in checks:
        require(checks["httpOk"] == (row["httpStatus"] == 200))
    if "rejected" in checks:
        require(checks["rejected"] == (row["httpStatus"] == 400))
    if name in NAME_EXPECTED:
        require(isinstance(row["nameState"], str) and row["nameState"] in NAME_STATES)
        require(checks["nameMatches"] == (row["nameState"] == NAME_EXPECTED[name]))
    if name == "signup":
        seconds = row["expirySeconds"]
        require(seconds is None or expiry_seconds({"expiresIn": seconds}) == seconds)
        require(checks["expiryIsPositiveInteger"] == (seconds is not None))
        require(checks["expiryMatchesOneHour"] == (seconds == "3600"))
