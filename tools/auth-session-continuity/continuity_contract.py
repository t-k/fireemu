"""Bounded diagnostic response and timing model; no universal revocation oracle."""

import base64
import json
import re

OFFSETS = (0, 10000, 30000)
DEADLINE_MS = 45000
LANES = ("a-id", "a-refresh", "b-id", "b-refresh", "reference-id", "reference-refresh")
SAMPLES = tuple(f"{lane}@{offset}" for offset in OFFSETS for lane in LANES)
BASELINES = (
    "signup",
    "signin-a",
    "signin-b",
    "a-id-baseline",
    "a-refresh-baseline-1",
    "a-refresh-baseline-2",
    "b-id-baseline",
    "b-refresh-baseline-1",
    "b-refresh-baseline-2",
    "reference-refresh",
)
CASES = (
    *BASELINES,
    *SAMPLES,
    "final-signin",
    "final-lookup",
    "malformed-refresh",
    "unknown-refresh",
    "delete",
    "deleted-account-absent",
)
CORPUS = {
    "slice": "auth-session-continuity",
    "revision": 1,
    "cases": list(CASES),
    "offsetsMs": list(OFFSETS),
    "deadlineMs": DEADLINE_MS,
    "requestBudgetMs": 5000,
    "lateAfterMs": 2000,
}
AUTH_ERRORS = {
    "TOKEN_EXPIRED",
    "INVALID_ID_TOKEN",
    "INVALID_REFRESH_TOKEN",
    "USER_NOT_FOUND",
    "USER_DISABLED",
    "INVALID_GRANT",
}
ERRORS = AUTH_ERRORS | {"OTHER"}
OUTCOMES = {
    "accepted",
    "auth-rejected",
    "unexpected",
    "transport-failure",
    "not-sampled",
}


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


def integer(value, low=0, high=32503680000):
    return type(value) is int and low <= value <= high


def token_time(token):
    """Decode bounded numeric timing claims only; deliberately not signature verification."""
    if not isinstance(token, str) or len(token) > 16384 or token.count(".") != 2:
        return None
    try:
        encoded = token.split(".")[1]
        payload = json.loads(
            base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
        )
        if not isinstance(payload, dict):
            return None
        issued, authenticated = payload.get("iat"), payload.get("auth_time")
        if integer(issued) and integer(authenticated) and authenticated <= issued:
            return {"iat": issued, "authTime": authenticated}
    except (ValueError, UnicodeError):
        pass
    return None


def kind_for(name):
    if name in {
        "signup",
        "signin-a",
        "signin-b",
        "final-signin",
    }:
        return "token"
    if "refresh" in name:
        return "refresh"
    if name == "delete":
        return "delete"
    if name == "deleted-account-absent":
        return "absence"
    return "lookup"


def checks_for(kind):
    if kind in {"token", "refresh"}:
        return set(tokens({}, "uid", "email", kind == "refresh")) | {"tokenTimeValid"}
    if kind == "lookup":
        return {"noError", "oneUser", "uidMatches", "emailMatches"}
    if kind == "absence":
        return {"uidAbsent", "emailAbsent"}
    require(kind == "delete")
    return {"noError"}


def classify(status, checks, error):
    if status == 200 and all(checks.values()):
        return "accepted"
    if status == 400 and error in AUTH_ERRORS:
        return "auth-rejected"
    return "unexpected"


def response(status, value, kind, uid, email):
    require(type(status) is int and 100 <= status <= 599)
    value = value if isinstance(value, dict) else {"error": {}}
    error = error_code(value) if "error" in value else None
    error = error if error in AUTH_ERRORS or error is None else "OTHER"
    extra = {}
    if kind in {"token", "refresh"}:
        checks = tokens(value, uid, email, kind == "refresh")
        metadata = token_time(value.get("id_token" if kind == "refresh" else "idToken"))
        checks["tokenTimeValid"] = metadata is not None
        extra = {
            "expirySeconds": expiry_seconds(value, kind == "refresh"),
            "tokenTime": metadata,
        }
    elif kind == "lookup":
        records = value.get("users")
        one = (
            isinstance(records, list)
            and len(records) == 1
            and isinstance(records[0], dict)
        )
        user = records[0] if one else {}
        checks = {
            "noError": "error" not in value,
            "oneUser": one,
            "uidMatches": user.get("localId") == uid,
            "emailMatches": user.get("email") == email,
        }
        since = user.get("validSince")
        extra["validSince"] = (
            int(since)
            if isinstance(since, str)
            and re.fullmatch(r"[0-9]{1,11}", since)
            and integer(int(since))
            else None
        )
    elif kind == "absence":
        checks = {
            "uidAbsent": value.get("uidAbsent") is True,
            "emailAbsent": value.get("emailAbsent") is True,
        }
    else:
        require(kind == "delete")
        checks = {"noError": "error" not in value}
    return {
        "httpStatus": status,
        "outcome": classify(status, checks, error),
        "error": error,
        "checks": checks,
        **extra,
    }


def unavailable(kind, outcome):
    require(outcome in {"transport-failure", "not-sampled"})
    row = response(500, {}, kind, "uid", "email")
    row.update(
        httpStatus=None,
        outcome=outcome,
        error=None,
        checks=dict.fromkeys(checks_for(kind), False),
    )
    return row


def validate_response(row, kind):
    require(isinstance(row, dict))
    extra = (
        {"expirySeconds", "tokenTime"}
        if kind in {"token", "refresh"}
        else ({"validSince"} if kind == "lookup" else set())
    )
    require(set(row) == {"httpStatus", "outcome", "error", "checks"} | extra)
    require(isinstance(row["outcome"], str) and row["outcome"] in OUTCOMES)
    require(
        row["error"] is None
        or (isinstance(row["error"], str) and row["error"] in ERRORS)
    )
    checks = row["checks"]
    require(
        isinstance(checks, dict)
        and set(checks) == checks_for(kind)
        and all(type(v) is bool for v in checks.values())
    )
    if row["outcome"] in {"transport-failure", "not-sampled"}:
        require(
            row["httpStatus"] is None
            and row["error"] is None
            and not any(checks.values())
        )
    else:
        require(integer(row["httpStatus"], 100, 599))
        require(row["outcome"] == classify(row["httpStatus"], checks, row["error"]))
    if "noError" in checks and row["httpStatus"] is not None:
        require(checks["noError"] == (row["error"] is None))
    if kind in {"token", "refresh"}:
        seconds = row["expirySeconds"]
        require(seconds is None or expiry_seconds({"expiresIn": seconds}) == seconds)
        require(checks["expiryIsPositiveInteger"] == (seconds is not None))
        require(checks["expiryMatchesOneHour"] == (seconds == "3600"))
        metadata = row["tokenTime"]
        require(
            metadata is None
            or (
                isinstance(metadata, dict)
                and set(metadata) == {"iat", "authTime"}
                and integer(metadata["iat"])
                and integer(metadata["authTime"])
                and metadata["authTime"] <= metadata["iat"]
            )
        )
        require(checks["tokenTimeValid"] == (metadata is not None))
    if kind == "lookup":
        require(row["validSince"] is None or integer(row["validSince"]))


def may_start(elapsed):
    return integer(elapsed, 0, DEADLINE_MS - 1)


def validate_client_action(action):
    require(action in {"signUp", "signInWithPassword", "lookup", "delete"})
    return action


def sample_quality(primary, followup, start, end, target, lane):
    if primary["outcome"] != "accepted":
        return "inconclusive"
    if "refresh" in lane and (followup is None or followup["outcome"] != "accepted"):
        return "inconclusive"
    if start < target or start - target > 2000 or end > DEADLINE_MS:
        return "late"
    return "observed"


def invalid_control_quality(value):
    return (
        "observed"
        if value["httpStatus"] == 400
        and value["outcome"] == "auth-rejected"
        and value["error"] == "INVALID_REFRESH_TOKEN"
        else "inconclusive"
    )


def validate_case(row, name):
    require(
        isinstance(row, dict)
        and set(row)
        == {
            "id",
            "response",
            "followup",
            "rotated",
            "startMs",
            "primaryEndMs",
            "endMs",
            "followupStartMs",
            "followupEndMs",
            "credentialUnchanged",
            "quality",
        }
    )
    require(row["id"] == name and name in CASES and row["credentialUnchanged"] is True)
    require(
        integer(row["startMs"], 0, 600000)
        and integer(row["endMs"], row["startMs"], 600000)
    )
    kind = kind_for(name)
    require(integer(row["primaryEndMs"], row["startMs"], row["endMs"]))
    validate_response(row["response"], kind)
    follow = row["followup"]
    if follow is not None:
        require(kind == "refresh" and row["response"]["outcome"] == "accepted")
        validate_response(follow, "lookup")
        require(
            integer(row["followupStartMs"], row["primaryEndMs"], row["endMs"])
            and integer(row["followupEndMs"], row["followupStartMs"], row["endMs"])
        )
        require(row["followupEndMs"] == row["endMs"])
    else:
        require(row["followupStartMs"] is None and row["followupEndMs"] is None)
        require(row["primaryEndMs"] == row["endMs"])
    if kind == "refresh" and row["response"]["outcome"] == "accepted":
        require(type(row["rotated"]) is bool)
    else:
        require(row["rotated"] is None)
    if name in SAMPLES:
        lane, target = name.split("@")
        target = int(target)
        if row["response"]["outcome"] != "not-sampled":
            require(may_start(row["startMs"]) and row["startMs"] >= target)
        if follow is not None and follow["outcome"] != "not-sampled":
            require(may_start(row["followupStartMs"]))
        expected = sample_quality(
            row["response"], follow, row["startMs"], row["endMs"], target, lane
        )
    elif name in {"malformed-refresh", "unknown-refresh"}:
        expected = invalid_control_quality(row["response"])
    else:
        expected = (
            "observed"
            if row["response"]["outcome"] == "accepted"
            and (
                kind != "refresh"
                or (follow is not None and follow["outcome"] == "accepted")
            )
            else "inconclusive"
        )
    require(row["quality"] == expected)


def cleanup_confirmed(uid, uid_absent, email_absent):
    return (
        isinstance(uid, str)
        and bool(uid)
        and uid_absent is True
        and email_absent is True
    )


def complete(report):
    if any(
        key in report for key in ("failure", "cleanupFailure", "childCleanupFailure")
    ):
        return False
    rows, cleanup = report.get("cases"), report.get("cleanup")
    if (
        not isinstance(rows, list)
        or len(rows) != len(CASES)
        or not isinstance(cleanup, dict)
        or set(cleanup) != {"uidAbsent", "emailAbsent"}
        or not all(v is True for v in cleanup.values())
    ):
        return False
    try:
        for row, name in zip(rows, CASES, strict=True):
            validate_case(row, name)
    except (ValueError, KeyError, TypeError):
        return False
    return report.get("status") == (
        "observed"
        if all(row["quality"] == "observed" for row in rows)
        else "inconclusive"
    )
