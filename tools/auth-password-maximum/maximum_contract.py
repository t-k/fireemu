"""Bounded semantic projections; never retain raw Auth response values."""

import json
import re

CASES = (
    "signup",
    "baseline-signin",
    "maximum-password-change",
    "maximum-token-lookup",
    "old-password-rejected",
    "maximum-password-signin",
    "maximum-password-lookup",
    "maximum-token-refresh",
    "maximum-refreshed-lookup",
    "tail-password-rejected",
    "state-after-tail",
    "prefix-password-rejected",
    "state-after-prefix",
    "oversize-password-rejected",
    "state-after-oversize",
    "preserved-maximum-signin",
    "preserved-maximum-lookup",
    "preserved-maximum-refresh",
    "preserved-refreshed-lookup",
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


ERROR_CODES = {
    "WEAK_PASSWORD",
    "INVALID_ID_TOKEN",
    "TOKEN_EXPIRED",
    "CREDENTIAL_TOO_OLD_LOGIN_AGAIN",
    "USER_DISABLED",
    "OPERATION_NOT_ALLOWED",
    "INVALID_PASSWORD",
    "INVALID_LOGIN_CREDENTIALS",
    "TOO_MANY_ATTEMPTS_TRY_LATER",
    "UNCLASSIFIED_ERROR",
}


def error_code(value):
    error = value.get("error", {}) if isinstance(value, dict) else {}
    message = error.get("message") if isinstance(error, dict) else None
    code = message.split(" : ", 1)[0] if isinstance(message, str) else ""
    return code if code in ERROR_CODES else "UNCLASSIFIED_ERROR"


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


TOKEN_CASES = {
    "signup",
    "baseline-signin",
    "maximum-password-change",
    "maximum-password-signin",
    "maximum-token-refresh",
    "preserved-maximum-signin",
    "preserved-maximum-refresh",
}
REFRESH_CASES = {"maximum-token-refresh", "preserved-maximum-refresh"}
TOKEN_CHECKS = set(tokens({}, "uid", "email")) | {"httpOk"}
REJECTION_CASES = {
    "old-password-rejected",
    "tail-password-rejected",
    "prefix-password-rejected",
    "oversize-password-rejected",
}
POLICY_ERRORS = {
    "PASSWORD_TOO_LONG",
    "PASSWORD_DOES_NOT_MEET_REQUIREMENTS",
    "INVALID_PASSWORD",
    "INVALID_PASSWORD_LENGTH",
    "WEAK_PASSWORD",
}
ERROR_CODES.update(POLICY_ERRORS)
CHECKS = {
    **{
        name: (
            set(tokens({}, "uid", "email", refresh=True)) | {"httpOk"}
            if name in REFRESH_CASES
            else TOKEN_CHECKS
        )
        for name in TOKEN_CASES
    },
    **{
        name: {"httpOk", "selectedStableFieldsUnchanged"}
        for name in [
            "maximum-token-lookup",
            "maximum-password-lookup",
            "maximum-refreshed-lookup",
            "state-after-tail",
            "state-after-prefix",
            "state-after-oversize",
            "preserved-maximum-lookup",
            "preserved-refreshed-lookup",
        ]
    },
    **{name: {"rejected", "expectedError"} for name in REJECTION_CASES},
    "delete": {"httpOk", "noError"},
    "deleted-account-absent": {"bothSelectorsAbsent"},
}


def expected_error(name, code):
    return (
        code in POLICY_ERRORS
        if name == "oversize-password-rejected"
        else code == "INVALID_LOGIN_CREDENTIALS"
    )


def rejection(name, status, value):
    require(name in REJECTION_CASES)
    code = error_code(value)
    checks = {"rejected": status == 400, "expectedError": expected_error(name, code)}
    return {
        "id": name,
        "httpStatus": status,
        "observedError": code,
        "checks": checks,
        "passed": all(checks.values()),
    }


def selected_state(value):
    """Private comparison only; retain field presence and JSON types, exclude credential metadata."""
    fields = {
        "localId",
        "email",
        "emailVerified",
        "displayName",
        "photoUrl",
        "disabled",
    }
    return json.dumps(
        {key: value[key] for key in sorted(fields) if key in value},
        sort_keys=True,
        separators=(",", ":"),
    )


def validate_case(row, name):
    require(name in CHECKS and isinstance(row, dict))
    extra = (
        {"expirySeconds"}
        if name in TOKEN_CASES
        else ({"observedError"} if name in REJECTION_CASES else set())
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
    expected_status = 400 if name in REJECTION_CASES else 200
    require(not row["passed"] or row["httpStatus"] == expected_status)
    if "httpOk" in checks:
        require(checks["httpOk"] == (row["httpStatus"] == 200))
    if "rejected" in checks:
        require(checks["rejected"] == (row["httpStatus"] == 400))
    if name in TOKEN_CASES:
        seconds = row["expirySeconds"]
        require(seconds is None or expiry_seconds({"expiresIn": seconds}) == seconds)
        require(checks["expiryIsPositiveInteger"] == (seconds is not None))
        require(checks["expiryMatchesOneHour"] == (seconds == "3600"))

    if name in REJECTION_CASES:
        code = row["observedError"]
        require(isinstance(code, str) and code in ERROR_CODES)
        require(checks["expectedError"] == expected_error(name, code))
