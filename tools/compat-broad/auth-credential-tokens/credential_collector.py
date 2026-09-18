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
import re
from pathlib import Path
from typing import Any

from credential_cases import observation_cases

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

#: Modules whose bytes every receipt binds. The comparison contract requires both sides
#: to have been recorded by the same collector, so this binding is what makes a pair
#: comparable at all.
BOUND_MODULES = (
    "credential_cases.py",
    "credential_collector.py",
    "credential_comparator.py",
    "credential_plan.py",
    "credential_shadow.py",
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


def _decode_segment(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as error:
        raise ValueError("token segment is not base64url") from error
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("token segment is not JSON") from error
    if not isinstance(decoded, dict):
        # A non-object segment is malformed input, not a caller type error.
        raise ValueError("token segment is not a JSON object")  # noqa: TRY004
    return decoded


def claim_shape(token: str, reveal: tuple[str, ...] = ()) -> dict[str, Any]:
    """Describe a token by its claim names, types, times and trust root.

    The token bytes, its signature and every unrequested string value stay out of the
    result, so the result is publishable. `reveal` may name only claims the campaign
    itself chose; an account-derived claim such as `email` is refused.
    """
    for name in reveal:
        if name not in REVEALABLE_CLAIM_NAMES:
            raise ValueError(f"reveal refused for account-derived claim {name!r}")
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    segments = token.split(".")
    if len(segments) != 3 or not segments[0] or not segments[1]:
        raise ValueError("token is not a three-segment JWT")
    header, payload = _decode_segment(segments[0]), _decode_segment(segments[1])
    algorithm = header.get("alg")
    if algorithm == "none":
        trust_root = "unsigned-emulator"
    elif isinstance(algorithm, str) and algorithm:
        trust_root = "signed"
    else:
        raise ValueError("token header declares no algorithm")
    issuer = payload.get("iss")
    return {
        "trustRoot": trust_root,
        "algorithm": algorithm,
        "issuer": issuer if isinstance(issuer, str) else None,
        "claimNames": sorted(payload),
        "claimTypes": {
            name: _json_type(value) for name, value in sorted(payload.items())
        },
        "times": {
            name: payload[name]
            for name in TIME_CLAIM_NAMES
            if isinstance(payload.get(name), int)
        },
        "claimValues": {name: payload[name] for name in reveal if name in payload},
    }


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
    account = tracker["accounts"][uid]
    account["uidAbsent"] = bool(uid_absent)
    account["emailAbsent"] = bool(email_absent)


def cleanup_report(tracker: dict[str, Any]) -> dict[str, Any]:
    """Summarize cleanup without naming any account.

    Deletion alone is not cleanup: both the UID and the address must read back absent.
    """
    accounts = list(tracker["accounts"].values())
    remaining = [
        a
        for a in accounts
        if not (a["uidAbsent"] and (a["emailAbsent"] or not a["addressReadback"]))
    ]
    return {
        "ownedAccounts": len(accounts),
        "remainingAccounts": len(remaining),
        # Only accounts that actually had an address can contribute a readback.
        "addressReadbacks": sum(
            1 for a in accounts if a["addressReadback"] and a["emailAbsent"]
        ),
        "cleanupComplete": not remaining,
    }


# --- budget ----------------------------------------------------------------------


RUN_PHASE = "run"
RECOVERY_PHASE = "recovery"


def new_budget(
    max_requests: int,
    max_wall_seconds: float,
    max_cost_usd: float,
    *,
    recovery_requests: int = 0,
    recovery_wall_seconds: float = 0.0,
) -> dict[str, Any]:
    """Create an enforced budget. The ceiling is checked here, not merely declared.

    Part of the total is held back for recovery. Cleanup has to delete every account the
    run created and read both its UID and its address back, and a run that spent its last
    request observing a case would have nothing left to do that with. The reserve is
    carved out of the total rather than added to it, so the declared bound still holds.
    """
    if not max_cost_usd < COST_CEILING_USD:
        raise ValueError(f"cost ceiling is US${COST_CEILING_USD}")
    if max_requests < 1 or max_wall_seconds <= 0:
        raise ValueError("positive request and wall-clock bounds are required")
    if recovery_requests < 0 or recovery_wall_seconds < 0:
        raise ValueError("a recovery reserve cannot be negative")
    if recovery_requests >= max_requests or recovery_wall_seconds >= max_wall_seconds:
        raise ValueError("the recovery reserve must leave the run something to spend")
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
    }


def request_allowance(budget: dict[str, Any]) -> int:
    """How many requests this phase may spend in total."""
    held_back = budget["recoveryRequests"] if budget["phase"] == RUN_PHASE else 0
    return budget["maxRequests"] - held_back


def wall_allowance(budget: dict[str, Any]) -> float:
    """How many wall-clock seconds this phase may spend in total."""
    held_back = budget["recoveryWallSeconds"] if budget["phase"] == RUN_PHASE else 0.0
    return budget["maxWallSeconds"] - held_back


def reserve_request(budget: dict[str, Any]) -> None:
    """Reserve one request before it is sent; an exhausted bound sends nothing.

    Charging after the fact would let an exhausted budget spend one more request against
    the service, which is the one thing an enforced bound exists to prevent.
    """
    if budget["requests"] + 1 > request_allowance(budget):
        raise BudgetExceeded("request budget exhausted")
    if budget["wallSeconds"] >= wall_allowance(budget):
        raise BudgetExceeded("wall-clock budget exhausted")
    budget["requests"] += 1


def charge_elapsed(budget: dict[str, Any], elapsed_seconds: float) -> None:
    """Charge the wall time a sent request took.

    This never raises. The response is already in hand by the time it is called, and a
    sign-up whose result is thrown away leaves a live account nothing knows about. The
    overrun stops the run at the next reservation instead.
    """
    budget["wallSeconds"] += float(elapsed_seconds)


def enter_recovery(budget: dict[str, Any]) -> None:
    """Release the reserve so cleanup can run after the run's own bound is spent."""
    budget["phase"] = RECOVERY_PHASE


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
    # An owned-nothing run never signed anybody in, so it never observed anything.
    complete = cleanup["cleanupComplete"] and cleanup["ownedAccounts"] > 0
    return {
        "side": side,
        "productionExecuted": bool(production_executed),
        "recordingComplete": complete,
        "sourceBinding": dict(
            source_binding or {"commit": None, "artifactSha256": None}
        ),
        # The comparison contract requires both sides to name the same collector.
        "collectorBinding": collector_binding((source_binding or {}).get("commit")),
        "budget": dict(budget),
        "cleanup": cleanup,
        "rows": publishable(rows),
    }
