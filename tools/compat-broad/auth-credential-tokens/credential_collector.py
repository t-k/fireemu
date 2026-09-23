"""Credential-safe support library for the AUTH-CREDENTIAL collector.

This module holds the parts of a bounded observation that must be correct before any
request is ever made: redaction, owned-resource tracking, cleanup accounting, budget
enforcement and receipt assembly. It performs no request itself and imports no network
client, so importing it can never contact a service.

Two levels of disclosure exist and they must not be confused. `publishable` produces the
projection that may be committed: presence and type for anything secret, never a value
and never a digest. `secret_digest` produces a token-derived value for the private
receipt only, which stays outside the repository.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

from credential_cases import observation_cases
import credential_responsibility as responsibility

#: This module never performs a request. The shadow and any future production collector
#: own their transport separately, so a leak here cannot become a live call.
PERFORMS_REQUESTS = False

#: Any key whose name contains one of these fragments holds credential material.
SECRET_KEY_FRAGMENTS = (
    "token",
    "cookie",
    "password",
    "secret",
    "credential",
    "authorization",
    "apikey",
    "api_key",
    "assertion",
    "sessioninfo",
    "oobcode",
    "bearer",
)

#: Claim names whose values may be revealed, because the campaign asserts on them and
#: they are chosen by the campaign rather than by an account.
REVEALABLE_CLAIM_NAMES = ("role", "tier", "sign_in_provider", "iss", "aud")

#: Claim names published as absolute whole seconds; they are not secret and the
#: comparison contract needs their relations.
TIME_CLAIM_NAMES = ("auth_time", "iat", "exp")

OWNED_EMAIL_DOMAIN = "fireemu-credential.invalid"

#: A ceiling far below the lane's stated budget, so a typo cannot authorize real spend.
COST_CEILING_USD = 0.5

#: Members that contain a secret fragment as a substring but hold no credential. Without
#: this, a case's own `assertions` results would be redacted away as an SAML `assertion`.
NON_SECRET_KEY_NAMES = ("assertions",)

RECEIPT_SIDES = ("local", "production")

#: The error code a collector writes for a case it never reached.
NOT_RUN_ERROR_CODE = "NOT_RUN"

#: The status range a row must carry to record a response that actually arrived.
HTTP_STATUS_RANGE = (100, 599)

#: Modules whose bytes every receipt binds. The comparison contract requires both sides
#: to have been recorded by the same collector, so this binding is what makes a pair
#: comparable at all.
BOUND_MODULES = (
    "credential_cases.py",
    "credential_collector.py",
    "credential_comparator.py",
    "credential_plan.py",
    "credential_shadow.py",
    "credential_wire.py",
    "credential_process.py",
    "credential_responsibility.py",
    "credential_gate.py",
    "credential_preflight.py",
    "credential_remote_transport.py",
    "credential_https_worker.py",
    "../batch_wire.py",
)


class SecretLeak(Exception):
    """Credential material reached a place that is logged or published."""


class BudgetExceeded(Exception):
    """The run tried to exceed an enforced bound."""


# --- redaction ----------------------------------------------------------------


def is_secret_key(key: str) -> bool:
    """Whether a record member holds credential material, judged by its name."""
    if key in NON_SECRET_KEY_NAMES:
        return False
    lowered = key.replace("-", "").replace("_", "").lower()
    return any(
        fragment.replace("_", "") in lowered for fragment in SECRET_KEY_FRAGMENTS
    )


def is_module_digest(key: str, value: Any) -> bool:
    """Whether this member is a source file keyed to its own sha256.

    The collector binding maps file names to digests, and a name such as
    `credential_cases.py` contains a secret fragment. Exempting the `.py` suffix alone
    would let a token ride under a key like `refresh_token.py`, so the value must also
    be exactly a 64-character lowercase hex digest.
    """
    return (
        key.endswith(".py")
        and isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def publishable(value: Any, key: str = "") -> Any:
    """Return the projection that may be committed: no secret value, no secret digest."""
    if key and is_secret_key(key) and not is_module_digest(key, value):
        if value is None:
            return {"present": False, "type": "null"}
        # Only a string or a container can carry credential material. Masking a boolean
        # or a number would hide a result without protecting anything.
        if isinstance(value, (bool, int, float)):
            return value
        return {"present": True, "type": _json_type(value)}
    if isinstance(value, dict):
        return {name: publishable(item, name) for name, item in sorted(value.items())}
    if isinstance(value, list):
        return [publishable(item, key) for item in value]
    return value


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def secret_digest(value: str) -> str:
    """Digest credential material for the private receipt. Never publish the result."""
    if not isinstance(value, str) or not value:
        raise ValueError("a non-empty string is required")
    return hashlib.sha256(value.encode()).hexdigest()


def assert_no_secret(target: Any, secrets: list[str]) -> None:
    """Fail closed when credential material appears in an argument list or log line."""
    serialized = target if isinstance(target, str) else json.dumps(target)
    for secret in secrets:
        if secret and secret in serialized:
            raise SecretLeak("credential material reached a logged or passed value")


def safe_log(line: str, secrets: list[str]) -> str:
    """Replace any known credential material in a log line."""
    for secret in secrets:
        if secret:
            line = line.replace(secret, "[REDACTED]")
    return line


# --- claim shapes --------------------------------------------------------------


# Local diagnostic parser limit, not a service quota or a JWT validity limit.
MAX_TOKEN_BYTES = 262_144
MAX_TOKEN_JSON_DEPTH = 128


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def _finite_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _decode_base64url(segment: str) -> bytes:
    # A JWT's compact segments use unpadded base64url, not permissive MIME base64.
    if not re.fullmatch(r"[A-Za-z0-9_-]*", segment) or len(segment) % 4 == 1:
        raise ValueError("token segment is not base64url")
    try:
        return base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("token segment is not base64url") from None


def _decode_segment(segment: str) -> dict[str, Any]:
    try:
        raw = _decode_base64url(segment)
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_float=_finite_json_float,
            parse_constant=_reject_constant,
        )
        pending = [(decoded, 1)]
        while pending:
            item, depth = pending.pop()
            if isinstance(item, (dict, list)):
                if depth > MAX_TOKEN_JSON_DEPTH:
                    raise ValueError("token JSON exceeds local depth boundary")
                values = item.values() if isinstance(item, dict) else item
                pending.extend((value, depth + 1) for value in values)
    except (ValueError, RecursionError):
        # Do not expose parser messages, keys, or token fragments in diagnostics.
        raise ValueError("token segment is not unambiguous UTF-8 JSON") from None
    if not isinstance(decoded, dict):
        raise ValueError("token segment is not a JSON object")  # noqa: TRY004
    return decoded


def _jwt_objects(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse the compact envelope only. This does NOT authenticate its signature."""
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    if len(token) > MAX_TOKEN_BYTES or not token.isascii():
        raise ValueError("token exceeds local encoding or size boundary")
    segments = token.split(".")
    if len(segments) != 3 or not segments[0] or not segments[1]:
        raise ValueError("token is not a three-segment JWT")
    header, payload = _decode_segment(segments[0]), _decode_segment(segments[1])
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or not algorithm:
        raise ValueError("token header declares no algorithm")
    if (algorithm == "none") != (segments[2] == ""):
        raise ValueError("token algorithm and signature presence disagree")
    _decode_base64url(segments[2])
    return header, payload


def custom_signin_response_uid(
    status: Any, body: Any, *, project: str, requested_uid: str
) -> str | None:
    """Project a custom sign-in response onto its verified campaign UID shape.

    This helper only parses the response's compact token envelope. It does not verify
    JWT signatures and must only receive the exact response body from an already
    admitted transport. An arbitrary caller-supplied token must never reach an
    ownership decision through this function.
    """
    if (
        type(status) is not int
        or status != 200
        or type(body) is not dict
        or "error" in body
        or type(body.get("isNewUser")) is not bool
        or type(project) is not str
        or not project
        or type(requested_uid) is not str
        or not 1 <= len(requested_uid) <= 128
    ):
        return None
    for name in ("idToken", "refreshToken"):
        value = body.get(name)
        if type(value) is not str or not 0 < len(value) <= 8192:
            return None
    if "localId" in body and body["localId"] != requested_uid:
        return None
    try:
        _, claims = _jwt_objects(body["idToken"])
    except (ValueError, TypeError):
        return None
    if (
        claims.get("sub") != requested_uid
        or claims.get("aud") != project
        or claims.get("iss") != f"https://securetoken.google.com/{project}"
        or ("user_id" in claims and claims["user_id"] != requested_uid)
    ):
        return None
    firebase = claims.get("firebase")
    if type(firebase) is not dict or "tenant" in firebase:
        return None
    if firebase.get("sign_in_provider") != "custom":
        return None
    return claims["sub"]


def claim_shape(token: str, reveal: tuple[str, ...] = ()) -> dict[str, Any]:
    """Describe a token by its claim names, types, times and trust root.

    The token bytes, its signature and every unrequested string value stay out of the
    result, so the result is publishable. `reveal` may name only claims the campaign
    itself chose; an account-derived claim such as `email` is refused.
    """
    for name in reveal:
        if name not in REVEALABLE_CLAIM_NAMES:
            raise ValueError(f"reveal refused for account-derived claim {name!r}")
    header, payload = _jwt_objects(token)
    algorithm = header["alg"]
    # Classification of a declared envelope, not evidence of signature verification.
    trust_root = "unsigned-emulator" if algorithm == "none" else "signed"
    issuer = payload.get("iss")
    firebase = payload.get("firebase")
    return {
        "trustRoot": trust_root,
        "algorithm": algorithm,
        "issuer": issuer if isinstance(issuer, str) else None,
        "claimNames": sorted(payload),
        "claimTypes": {
            name: _json_type(value) for name, value in sorted(payload.items())
        },
        # The nested `firebase` block is where the runtime keeps its provider and
        # session markers, so its names and types are recorded the same way.
        "firebase": {
            "claimNames": sorted(firebase),
            "claimTypes": {
                name: _json_type(value) for name, value in sorted(firebase.items())
            },
        }
        if isinstance(firebase, dict)
        else None,
        "times": {
            name: payload[name]
            for name in TIME_CLAIM_NAMES
            if type(payload.get(name)) is int
        },
        "claimValues": {name: payload[name] for name in reveal if name in payload},
    }


def claim_set(shape: dict[str, Any]) -> dict[str, Any]:
    """The publishable claim set a row records from a decoded shape: names and types.

    No value and no time is carried here; the comparison contract strips the
    local-only claims from it before judging equality.
    """
    return {
        "claimNames": list(shape["claimNames"]),
        "claimTypes": dict(shape["claimTypes"]),
        "firebase": None if shape.get("firebase") is None else {
            "claimNames": list(shape["firebase"]["claimNames"]),
            "claimTypes": dict(shape["firebase"]["claimTypes"]),
        },
    }


def _subject(token: str) -> str | None:
    """Return a token's `sub` claim when it is a non-empty string, else None.

    The subject is an account identifier, so it never leaves this module: only the
    boolean `subjects_match` derives from it may be recorded. A malformed token answers
    None rather than raising, because an undecidable subject is not a match and an
    assertion must stay decidable.
    """
    if not isinstance(token, str):
        return None
    try:
        _, payload = _jwt_objects(token)
    except ValueError:
        return None
    subject = payload.get("sub")
    if isinstance(subject, bool) or not isinstance(subject, str) or not subject:
        return None
    return subject


def subjects_match(first: str, second: str) -> bool:
    """Whether two tokens name the same subject, publishing only the answer.

    Both payloads are decoded in memory and compared here. Checking that a `sub` claim
    merely exists would accept a session cookie minted for another account, which is the
    one thing this assertion is for.
    """
    subject = _subject(first)
    return subject is not None and subject == _subject(second)


def id_token_matches_account(token: str, *, uid: str, project: str) -> bool:
    """Project an admitted ID-token response's identity without exposing its values.

    This compares the subject to the account identified by this run, not to a
    UID from another run or just another token. Namespace is the campaign's
    default project namespace. It does NOT verify a signature or grant auth,
    creation ownership or cleanup authority. A measured disagreement is data.
    """
    if (
        type(uid) is not str or not 1 <= len(uid) <= 128
        or type(project) is not str or not project
    ):
        raise ValueError("known account and project required for identity comparison")
    try:
        _, payload = _jwt_objects(token)
    except (ValueError, TypeError):
        return False
    firebase = payload.get("firebase")
    return (
        payload.get("sub") == uid
        and payload.get("aud") == project
        and payload.get("iss") == f"https://securetoken.google.com/{project}"
        and ("user_id" not in payload or payload["user_id"] == uid)
        and type(firebase) is dict
        and "tenant" not in firebase
    )


def lookup_matches_account(status: Any, body: Any, *, uid: str) -> bool:
    """Measure the default-namespace end-user lookup, without recording its data.

    This is not Admin batch lookup, token authentication or cleanup authority.
    Optional user fields are not new requirements. A bad or empty success stays
    an observed false result, rather than being changed to a successful control.
    """
    if type(status) is not int or status != 200 or type(body) is not dict:
        return False
    if type(uid) is not str or not uid or "error" in body:
        return False
    users = body.get("users")
    if type(users) is not list or len(users) != 1 or type(users[0]) is not dict:
        return False
    user = users[0]
    return (
        "error" not in user
        and type(user.get("localId")) is str
        and user["localId"] == uid
        and user.get("tenantId") in (None, "")
    )


# --- owned resources ------------------------------------------------------------


def new_tracker(nonce: str) -> dict[str, Any]:
    """Start tracking the accounts one run owns, keyed by its run nonce."""
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("a 32-character hexadecimal nonce is required")
    return {"nonce": nonce, "accounts": {}}


def owned_email(tracker: dict[str, Any], index: int) -> str:
    """Return the throwaway address for one owned account of this run."""
    return f"fireemu-cred-{tracker['nonce'][:8]}-{index}@{OWNED_EMAIL_DOMAIN}"


def track_account(tracker: dict[str, Any], uid: str, email: str | None) -> None:
    """Record an account this run created, before it can be used.

    A custom-token sign-in creates an account with no address. Passing `None` records
    that honestly, so cleanup never claims an address readback that could not happen.
    """
    if email is not None and tracker["nonce"][:8] not in email:
        raise ValueError("an owned account must carry the run nonce prefix")
    tracker["accounts"][uid] = {
        "email": email,
        "uidAbsent": False,
        "emailAbsent": False,
        "addressReadback": email is not None,
    }


def mark_deleted(
    tracker: dict[str, Any], uid: str, *, uid_absent: bool, email_absent: bool
) -> None:
    """Record the readback after deleting one owned account."""
    if type(uid_absent) is not bool or type(email_absent) is not bool:
        raise ValueError("absence evidence must be boolean")
    account = tracker["accounts"][uid]
    account["uidAbsent"] = uid_absent
    account["emailAbsent"] = email_absent
    if uid_absent is True and (email_absent is True or account["addressReadback"] is False):
        responsibility.note_recovery(tracker, uid)


def cleanup_report(tracker: dict[str, Any]) -> dict[str, Any]:
    """Summarize cleanup without naming any account.

    Deletion alone is not cleanup: both the UID and the address must read back absent.
    """
    accounts = list(tracker["accounts"].values())
    remaining = [
        a
        for a in accounts
        if not (
            a["uidAbsent"] is True
            and (a["emailAbsent"] is True or a["addressReadback"] is False)
        )
    ]
    return {
        "ownedAccounts": len(accounts),
        "remainingAccounts": len(remaining),
        # Only accounts that actually had an address can contribute a readback.
        "addressReadbacks": sum(
            1 for a in accounts if a["addressReadback"] is True and a["emailAbsent"] is True
        ),
        "cleanupComplete": not remaining and not any(
            intent["state"] == "unknown" for intent in tracker.get("creationIntents", {}).values()
        ),
    }


# --- budget ----------------------------------------------------------------------


RUN_PHASE = "run"
RECOVERY_PHASE = "recovery"


def _finite_nonnegative(value: Any) -> float:
    if type(value) not in (int, float):
        raise ValueError("finite non-negative number required")
    try:
        result = float(value)
    except OverflowError:
        raise ValueError("finite non-negative number required") from None
    if not math.isfinite(result) or result < 0:
        raise ValueError("finite non-negative number required")
    return result


def _budget_fault(budget: dict[str, Any], reason: str) -> None:
    if budget.get("integrityFailure") is None:
        budget["integrityFailure"] = reason


def _clock_reading(budget: dict[str, Any], now: Any) -> float:
    if budget.get("integrityFailure") is not None:
        raise BudgetExceeded("budget integrity failure latched")
    try:
        reading = _finite_nonnegative(now)
        start = _finite_nonnegative(budget["startedMonotonic"])
        last = _finite_nonnegative(budget.get("lastClockMonotonic", start))
        if reading < max(start, last):
            raise ValueError("clock moved backwards")
    except (ValueError, TypeError, KeyError):
        _budget_fault(budget, "invalid-monotonic-clock")
        raise BudgetExceeded("invalid monotonic clock") from None
    budget["lastClockMonotonic"] = reading
    return reading


def new_budget(
    max_requests: int,
    max_wall_seconds: float,
    max_cost_usd: float,
    *,
    started_monotonic: float,
    recovery_requests: int = 0,
    recovery_wall_seconds: float = 0.0,
) -> dict[str, Any]:
    """Create an enforced budget. The ceiling is checked here, not merely declared.

    Part of the total is held back for recovery. Cleanup has to delete every account the
    run created and read both its UID and its address back, and a run that spent its last
    request observing a case would have nothing left to do that with. The reserve is
    carved out of the total rather than added to it, so the declared bound still holds.

    Time is bounded by deadlines taken from `started_monotonic`, the caller's monotonic
    reading when the campaign started, rather than by the durations of the requests that
    were sent. A run that stalls between two cases spends the campaign's time exactly as
    a slow response does, and summing request durations cannot see that. The clock stays
    the caller's: this module reads none, so a run and a test measure the same way.

    The observation phase runs until `max_wall_seconds` less the recovery reserve. The
    reserve is then granted absolutely, from the moment recovery starts, however the
    observation ended: what an owner approves is a bounded observation plus a bounded
    cleanup tail, not a single total that cleanup might not fit inside. Deleting the
    accounts a run created is the last thing that should lose a race against a clock.
    """
    try:
        cost = _finite_nonnegative(max_cost_usd)
    except ValueError:
        raise ValueError("finite non-negative cost below the ceiling required") from None
    if not cost < COST_CEILING_USD:
        raise ValueError(f"cost ceiling is US${COST_CEILING_USD}")
    max_wall_seconds = _finite_nonnegative(max_wall_seconds)
    if type(max_requests) is not int or max_requests < 1 or max_wall_seconds <= 0:
        raise ValueError("positive request and wall-clock bounds are required")
    try:
        recovery_wall_seconds = _finite_nonnegative(recovery_wall_seconds)
    except ValueError:
        raise ValueError("a recovery reserve must be finite and non-negative") from None
    if type(recovery_requests) is not int or recovery_requests < 0:
        raise ValueError("a recovery reserve must be a non-negative integer")
    if recovery_requests >= max_requests or recovery_wall_seconds >= max_wall_seconds:
        raise ValueError("the recovery reserve must leave the run something to spend")
    started = _finite_nonnegative(started_monotonic)
    total_deadline = _finite_nonnegative(started + max_wall_seconds)
    observation_deadline = _finite_nonnegative(started + max_wall_seconds - recovery_wall_seconds)
    if not started < observation_deadline <= total_deadline:
        raise ValueError("representable positive deadlines required")
    return {
        "maxRequests": max_requests,
        "maxWallSeconds": max_wall_seconds,
        "maxCostUsd": max_cost_usd,
        "recoveryRequests": recovery_requests,
        "recoveryWallSeconds": recovery_wall_seconds,
        "requests": 0,
        "wallSeconds": 0.0,
        "phase": RUN_PHASE,
        "enforced": True,
        # Absolute readings, stripped from the published receipt: a monotonic origin is
        # a property of the machine that ran, and only the relative seconds are evidence.
        "startedMonotonic": started,
        "lastClockMonotonic": started,
        "integrityFailure": None,
        "observationDeadlineMonotonic": observation_deadline,
        # The total an undisturbed run fits inside: the observation deadline plus the
        # reserve. A run that overran its observation still gets the whole reserve, so
        # this is the nominal total rather than a second bound.
        "totalDeadlineMonotonic": total_deadline,
        "recoveryDeadlineMonotonic": None,
        "recoveryEnteredSeconds": None,
        # Every phase whose deadline stopped work, recorded separately: a run that both
        # overran its observation and reached the total says so twice.
        "deadlineExceeded": {},
    }


def phase_deadline(budget: dict[str, Any]) -> float:
    """The absolute monotonic reading this phase may not send past."""
    if budget["phase"] == RUN_PHASE:
        return budget["observationDeadlineMonotonic"]
    recovery = budget["recoveryDeadlineMonotonic"]
    return budget["totalDeadlineMonotonic"] if recovery is None else recovery


def elapsed_seconds(budget: dict[str, Any], now: float) -> float:
    """How long the campaign has been running, by the caller's monotonic clock."""
    return _clock_reading(budget, now) - budget["startedMonotonic"]


def remaining_seconds(budget: dict[str, Any], now: float) -> float:
    """How long this phase may still spend. Never negative, so a caller cannot wait."""
    return max(0.0, phase_deadline(budget) - _clock_reading(budget, now))


def _note_deadline(budget: dict[str, Any], now: float) -> None:
    """Record, once per phase, that a deadline is what stopped the work."""
    budget["deadlineExceeded"].setdefault(
        budget["phase"],
        {
            "elapsedSeconds": elapsed_seconds(budget, now),
            "limitSeconds": phase_deadline(budget) - budget["startedMonotonic"],
        },
    )


def check_deadline(budget: dict[str, Any], now: float) -> None:
    """Fail closed once this phase's deadline has passed.

    A wait between two cases spends the same campaign time a request does. Checking
    after a wait is what keeps a stalled run from opening one more observation.
    """
    if remaining_seconds(budget, now) <= 0.0:
        _note_deadline(budget, now)
        raise BudgetExceeded("wall-clock deadline reached")


def request_allowance(budget: dict[str, Any]) -> int:
    """How many requests this phase may spend in total."""
    held_back = budget["recoveryRequests"] if budget["phase"] == RUN_PHASE else 0
    return budget["maxRequests"] - held_back


def wall_allowance(budget: dict[str, Any]) -> float:
    """How many wall-clock seconds this phase may spend in total."""
    held_back = budget["recoveryWallSeconds"] if budget["phase"] == RUN_PHASE else 0.0
    return budget["maxWallSeconds"] - held_back


def reserve_request(budget: dict[str, Any], now: float) -> float:
    """Reserve one request before it is sent and return the seconds it may take.

    Charging after the fact would let an exhausted budget spend one more request against
    the service, which is the one thing an enforced bound exists to prevent. The returned
    allowance is what is left before this phase's deadline, so a caller that caps its
    transport to it cannot wait past the bound the campaign was approved against.
    """
    if budget.get("integrityFailure") is not None:
        raise BudgetExceeded("budget integrity failure latched")
    if type(budget["requests"]) is not int or budget["requests"] < 0:
        _budget_fault(budget, "invalid-request-counter")
        raise BudgetExceeded("invalid request counter")
    if budget["requests"] + 1 > request_allowance(budget):
        raise BudgetExceeded("request budget exhausted")
    check_deadline(budget, now)
    if budget["wallSeconds"] >= wall_allowance(budget):
        raise BudgetExceeded("wall-clock budget exhausted")
    budget["requests"] += 1
    return remaining_seconds(budget, now)


def charge_elapsed(budget: dict[str, Any], elapsed_seconds: float) -> None:
    """Charge the wall time a sent request took.

    This never raises. The response is already in hand by the time it is called, and a
    sign-up whose result is thrown away leaves a live account nothing knows about. The
    overrun stops the run at the next reservation instead.
    """
    # Never replace an already received ACK with a timing exception. Preserve
    # the existing charge, latch the fault, then forbid further sends.
    try:
        amount = _finite_nonnegative(elapsed_seconds)
        total = _finite_nonnegative(_finite_nonnegative(budget["wallSeconds"]) + amount)
    except (ValueError, TypeError, KeyError):
        _budget_fault(budget, "invalid-elapsed-charge")
        return
    budget["wallSeconds"] = total


def enter_recovery(budget: dict[str, Any], now: float) -> None:
    """Release the reserve so cleanup can run after the run's own bound is spent.

    Recovery gets its reserved seconds in full, from the moment it starts, whatever the
    observation phase did with its own. A reserve capped at the nominal total would be
    empty exactly when it is needed most, which is the run that stalled and stopped late:
    the accounts are already created, and nothing else will delete them. The campaign is
    therefore declared as a bounded observation plus a bounded cleanup tail.
    """
    # Re-entering cleanup must not refill its time or request allowance.
    # Keep this transition non-throwing on clock faults: callers use it in
    # finally, and still must stop their owned daemon. Reservation fails closed.
    try:
        reading = _clock_reading(budget, now)
        deadline = _finite_nonnegative(reading + budget["recoveryWallSeconds"])
    except (BudgetExceeded, ValueError, TypeError, KeyError):
        _budget_fault(budget, "invalid-recovery-clock")
        return
    if budget["phase"] == RECOVERY_PHASE:
        return
    budget["phase"] = RECOVERY_PHASE
    budget["recoveryEnteredSeconds"] = reading - budget["startedMonotonic"]
    budget["recoveryDeadlineMonotonic"] = deadline


# --- collector binding ---------------------------------------------------------------


def module_digests() -> dict[str, str]:
    """Digest each bound module, so a later edit cannot be read back onto a receipt."""
    here = Path(__file__).parent
    return {
        name: hashlib.sha256((here / name).read_bytes()).hexdigest()
        if (here / name).is_file()
        else "ABSENT"
        for name in BOUND_MODULES
    }


def collector_binding(commit: str | None = None) -> dict[str, Any]:
    """Bind the collector that recorded a receipt.

    The commit is what the operator says the checkout was; nothing here verifies it.
    The module digests are computed from the bytes actually running.
    """
    return {
        "commit": commit,
        "commitStatus": "operator-asserted; not verified by this run",
        "modules": module_digests(),
    }


# --- receipt -----------------------------------------------------------------------


def unobserved_reason(row: Any) -> str | None:
    """Why this row records no observation, or None when it records one.

    A run that stops part way still writes a row for every case, so a row has to say for
    itself whether anything was observed. Every reader derives that here rather than
    trusting a receipt-level boolean, which a collector fills in and could be wrong.
    """
    if not isinstance(row, dict):
        return "row-is-not-an-object"
    status = row.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        return "status-is-not-an-integer"
    if not HTTP_STATUS_RANGE[0] <= status <= HTTP_STATUS_RANGE[1]:
        return "status-is-outside-the-http-range"
    if row.get("errorCode") == NOT_RUN_ERROR_CODE:
        return "row-is-marked-not-run"
    if not isinstance(row.get("assertions"), dict):
        return "assertions-are-not-an-object"
    return None


def budget_record(budget: dict[str, Any]) -> dict[str, Any]:
    """The publishable projection of a budget: no absolute reading of a machine clock."""
    return {
        name: value
        for name, value in budget.items()
        if not name.endswith("Monotonic") and name != "deadlineExceeded"
    }


def deadline_record(budget: dict[str, Any]) -> dict[str, Any]:
    """What the deadlines were and which phase, if any, one of them stopped.

    Reaching the observation deadline and reaching the end of the cleanup window are
    separate facts, and a receipt that merged them would not say whether cleanup ever got
    its own window or what it did with it.
    """
    entered = budget["recoveryEnteredSeconds"]
    return {
        "observationSeconds": budget["maxWallSeconds"] - budget["recoveryWallSeconds"],
        "recoverySeconds": budget["recoveryWallSeconds"],
        "nominalTotalSeconds": budget["maxWallSeconds"],
        "recoveryEnteredSeconds": entered,
        # Where cleanup's own window ends, which is the observation deadline plus the
        # reserve for a run that finished on time and later for one that overran.
        "recoveryDeadlineSeconds": None
        if entered is None
        else entered + budget["recoveryWallSeconds"],
        "exceeded": dict(budget["deadlineExceeded"]),
    }


def build_receipt(
    *,
    side: str,
    rows: list[dict[str, Any]],
    tracker: dict[str, Any],
    budget: dict[str, Any],
    source_binding: dict[str, Any] | None = None,
    production_executed: bool = False,
) -> dict[str, Any]:
    """Assemble a publishable receipt, failing closed on a missing or reordered row."""
    if side not in RECEIPT_SIDES:
        raise ValueError(f"side must be one of {RECEIPT_SIDES}")
    expected = [case["id"] for case in observation_cases()]
    if [row.get("caseId") for row in rows] != expected:
        raise ValueError("rows must be every case in the declared order")
    cleanup = cleanup_report(tracker)
    # Recording completion and cleanup completion are separate facts. A run that stopped
    # part way still cleans up after itself, and a clean cleanup has never been evidence
    # that every case was observed.
    # An owned-nothing run never signed anybody in, so it never observed anything either.
    complete = (
        all(unobserved_reason(row) is None for row in rows)
        and cleanup["ownedAccounts"] > 0
        and budget.get("integrityFailure") is None
        and tracker.get("responsibilityRecordingComplete") is not False
    )
    return {
        "side": side,
        "productionExecuted": bool(production_executed),
        "recordingComplete": complete,
        "sourceBinding": dict(
            source_binding or {"commit": None, "artifactSha256": None}
        ),
        # The comparison contract requires both sides to name the same collector.
        "collectorBinding": collector_binding((source_binding or {}).get("commit")),
        "budget": budget_record(budget),
        "deadlines": deadline_record(budget),
        "cleanup": cleanup,
        "rows": publishable(rows),
        **({"creationResponsibility": responsibility.summary(tracker)}
           if responsibility.summary(tracker) is not None else {}),
    }
