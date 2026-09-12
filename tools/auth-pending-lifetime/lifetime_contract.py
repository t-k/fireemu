"""Finite observations of an MFA pending credential's usability at increasing ages.

This is a lifetime and experiment-feasibility corpus (AUTH-U03 expiry), not a precedence
corpus: it records, at each sampled pending age, whether mfaSignIn:start and (on an
acceptance) mfaSignIn:finalize still succeed. Every row carries a `timing` region measured
on the aging clock, saved on acceptance and refusal alike, so the pending age at start and
the session age at finalize are recorded as separate intervals and a refused row keeps its
measured age. The run declares an observation budget (accounts, requests split into an
observation and a recovery reserve, total wall time, configuration-hold time and a cleanup
reserve) and `complete()` checks the recorded usage against it.

It does not pin a TTL or an error precedence. A fully-verified success at every sampled age
establishes a lower bound, never an infinite lifetime; a refusal records the age and its
error but, in this revision, never establishes an upper bound, because the corpus does not
prove that a refusal is due to expiry rather than some other cause (that proof, an aged
pending against an independently valid code, is a later corpus).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require

# Revision 1 is a modest feasibility probe: small ages that keep the production run short
# while exercising the whole machinery (independent account per age, fresh session, clock
# vs real-time aging). Later revisions extend toward the boundary under a larger budget.
AGE_SECONDS = (2, 120, 300)
# Rows are emitted in run order: each age's start is immediately followed by its finalize,
# because the finalize consumes the SMS session that its own start just minted.
CASES = (
    "baseline-fresh-finalize",
    *[name for a in AGE_SECONDS for name in (f"age-{a}s-start", f"age-{a}s-finalize")],
    "final-fresh-finalize",
)
DIAGNOSTIC = tuple(c for c in CASES if c.startswith("age-"))
CONTROLS = ("baseline-fresh-finalize", "final-fresh-finalize")
CORPUS = {"slice": "auth-pending-lifetime", "revision": 1, "cases": list(CASES)}

ERRORS = {
    "INVALID_MFA_PENDING_CREDENTIAL",
    "MISSING_MFA_PENDING_CREDENTIAL",
    "INVALID_SESSION_INFO",
    "SESSION_EXPIRED",
    "INVALID_CODE",
    "MFA_ENROLLMENT_NOT_FOUND",
    "MISSING_RECAPTCHA_TOKEN",
    "INVALID_RECAPTCHA_TOKEN",
    "CAPTCHA_CHECK_FAILED",
    "OPERATION_NOT_ALLOWED",
    "TOKEN_EXPIRED",
    "USER_DISABLED",
    "USER_NOT_FOUND",
    "TOO_MANY_ATTEMPTS_TRY_LATER",
    "QUOTA_EXCEEDED",
}
CLASSIFIED_STATUSES = {400, 403}
TRANSIENT_ERRORS = {"TOO_MANY_ATTEMPTS_TRY_LATER", "QUOTA_EXCEEDED"}
COMPLETING_ERRORS = ERRORS - TRANSIENT_ERRORS

# The identity checks a fully-verified MFA completion must satisfy. A diagnostic finalize
# may record any of these as False (an HTTP 200 with no usable token is an observation, not
# a completion); only a row with every check True counts toward the usable lower bound.
FINALIZE_CHECKS = {
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "claimSubMatches",
    "claimEmailMatches",
    "secondFactorClaim",
    "derivedLookup",
}
# A start row records only whether a session was returned; the measured ages live in the
# separate timing region, so a refused start (checks == {}) still keeps its age.
START_CHECKS = {"sessionInfoPresent"}
# The session opened fresh at a diagnostic must be young when the finalize consumes it.
MAX_SESSION_AGE_SECONDS = 30
# The budget keys every run declares. maxRequests covers auth API calls (admin/client/mfa);
# recoveryRequestReserve is the slice of maxRequests kept for cleanup so a request-exhausted
# observation can still delete its accounts. Configuration reads/writes are counted and
# reported separately (configRequests), not against maxRequests.
BUDGET_KEYS = {
    "maxAccounts",
    "maxRequests",
    "recoveryRequestReserve",
    "totalBudgetSeconds",
    "configHoldMaxSeconds",
    "cleanupReserveSeconds",
}
# A run that finished the corpus. A run stopped by a budget guard records the guard instead.
STOP_REASONS = {
    "completed",
    "time-budget",
    "config-hold-budget",
    "request-budget",
    "error",
    "terminated",
}
TEST_PHONE = "+15555550100"
TEST_CODE = "135790"


def error_code(value):
    error = value.get("error") if isinstance(value, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    message = message.split(" : ", 1)[0] if isinstance(message, str) else None
    return (
        message
        if isinstance(message, str) and message in ERRORS
        else "UNCLASSIFIED_ERROR"
    )


def _number(value):
    # bool is excluded (type is bool, not int); NaN fails the >= 0 comparison.
    return type(value) in (int, float) and value >= 0


def _interval(value):
    return (
        isinstance(value, dict)
        and set(value) == {"lower", "upper"}
        and _number(value["lower"])
        and _number(value["upper"])
        and value["lower"] <= value["upper"]
    )


def validate_timing(timing, name, outcome, skipped):
    """The timing region for one row. Measured on the aging clock (monotonic in production,
    the virtual clock locally). Saved on acceptance and refusal alike; empty only when the
    row was skipped (its request was never sent)."""
    require(isinstance(timing, dict))
    if skipped:
        require(timing == {})
        return
    is_start = name.endswith("-start")
    if is_start:
        require(
            set(timing)
            == {"pendingAcquiredAt", "startSent", "startReceived", "pendingAgeAtStart"}
        )
        for key in ("pendingAcquiredAt", "startSent", "startReceived"):
            require(_number(timing[key]))
        require(timing["startSent"] <= timing["startReceived"])
        require(_interval(timing["pendingAgeAtStart"]))
        return
    # A finalize row (a control or an age finalize) that actually ran: it sent both a start
    # and a finalize, so it carries both timestamps and both derived age intervals.
    require(
        set(timing)
        == {
            "pendingAcquiredAt",
            "startSent",
            "startReceived",
            "finalizeSent",
            "finalizeReceived",
            "sessionAgeAtFinalize",
            "pendingAgeAtFinalize",
        }
    )
    for key in (
        "pendingAcquiredAt",
        "startSent",
        "startReceived",
        "finalizeSent",
        "finalizeReceived",
    ):
        require(_number(timing[key]))
    require(timing["startSent"] <= timing["startReceived"] <= timing["finalizeSent"])
    require(timing["finalizeSent"] <= timing["finalizeReceived"])
    require(_interval(timing["sessionAgeAtFinalize"]))
    require(_interval(timing["pendingAgeAtFinalize"]))
    # The session was minted during the start request, so its age at finalize is bounded by
    # (finalizeSent - startReceived, finalizeReceived - startSent); require exactly that.
    require(
        timing["sessionAgeAtFinalize"]["lower"]
        == timing["finalizeSent"] - timing["startReceived"]
    )
    require(
        timing["sessionAgeAtFinalize"]["upper"]
        == timing["finalizeReceived"] - timing["startSent"]
    )
    if outcome == "accepted":
        require(timing["sessionAgeAtFinalize"]["upper"] <= MAX_SESSION_AGE_SECONDS)


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
            "timing",
            "elapsedMs",
            "skipped",
        }
    )
    require(row["id"] == name and type(row["elapsedMs"]) is int)
    require(0 <= row["elapsedMs"] <= 3_600_000 and type(row["skipped"]) is bool)
    validate_timing(row["timing"], name, row["outcome"], row["skipped"])
    if row["skipped"]:
        # A finalize is skipped when its own start did not return a session.
        require(name.endswith("-finalize") and name in DIAGNOSTIC)
        require(row["httpStatus"] is None and row["outcome"] == "skipped")
        require(row["observedError"] is None and row["checks"] == {})
        return
    require(type(row["httpStatus"]) is int)
    if row["outcome"] == "refused":
        require(name in DIAGNOSTIC)
        require(400 <= row["httpStatus"] <= 599)
        require(row["observedError"] in ERRORS | {"UNCLASSIFIED_ERROR"})
        require(row["checks"] == {})
        return
    require(
        row["outcome"] == "accepted"
        and row["httpStatus"] == 200
        and row["observedError"] is None
    )
    require(isinstance(row["checks"], dict) and row["checks"] != {})
    if name.endswith("-start"):
        require(set(row["checks"]) == START_CHECKS)
        require(type(row["checks"]["sessionInfoPresent"]) is bool)
        # The pending was at least the sampled age when start processed it.
        require(row["checks"]["sessionInfoPresent"] is True)
        require(row["timing"]["pendingAgeAtStart"]["lower"] >= age_of(name))
        return
    require(name.endswith("-finalize"))
    require(set(row["checks"]) == FINALIZE_CHECKS)
    if name in CONTROLS:
        require(all(v is True for v in row["checks"].values()))
    else:
        require(all(type(v) is bool for v in row["checks"].values()))


def age_of(name):
    require(name.startswith("age-") and "s-" in name)
    return int(name[len("age-") : name.index("s-")])


def classified(row):
    return row["outcome"] != "refused" or (
        row["httpStatus"] in CLASSIFIED_STATUSES
        and row["observedError"] in COMPLETING_ERRORS
    )


def _budget_respected(report):
    budget = report["budget"]
    require(set(budget) == BUDGET_KEYS)
    require(all(type(v) is int and v > 0 for v in budget.values()))
    require(budget["recoveryRequestReserve"] < budget["maxRequests"])
    require(report["accountsUsed"] <= budget["maxAccounts"])
    require(report["agingMode"] in {"real-time", "virtual-clock"})
    require(report["stopReason"] == "completed")
    counts = report["requestCount"]
    require(
        isinstance(counts, dict)
        and set(counts) == {"observation", "recovery", "config"}
    )
    require(all(type(v) is int and v >= 0 for v in counts.values()))
    # The observation stayed inside its reserve, and observation plus recovery inside the
    # total, so cleanup requests were guaranteed room even at the observation limit.
    require(
        counts["observation"]
        <= budget["maxRequests"] - budget["recoveryRequestReserve"]
    )
    require(counts["observation"] + counts["recovery"] <= budget["maxRequests"])
    require(
        _number(report["wallElapsedSeconds"])
        and report["wallElapsedSeconds"] <= budget["totalBudgetSeconds"]
    )
    require(
        _number(report["configHoldSeconds"])
        and report["configHoldSeconds"] <= budget["configHoldMaxSeconds"]
    )


def complete(report):
    try:
        require(
            not any(
                k in report
                for k in ("failure", "cleanupFailure", "configRestoreFailure")
            )
        )
        require(
            report["status"] == "observed"
            and [r["id"] for r in report["cases"]] == list(CASES)
        )
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_row(row, name)
            require(classified(row))
        require(report["setup"] is True)
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(
            report["configRestored"] is True and report["configDigestMatches"] is True
        )
        _budget_respected(report)
        rows = {r["id"]: r for r in report["cases"]}
        for a in AGE_SECONDS:
            start = rows[f"age-{a}s-start"]
            accepted = (
                start["outcome"] == "accepted"
                and start["checks"].get("sessionInfoPresent") is True
            )
            require(rows[f"age-{a}s-finalize"]["skipped"] == (not accepted))
        if report["target"] == "production":
            require(
                report["committedCheckout"] is True
                and report["agingMode"] == "real-time"
            )
    except (KeyError, TypeError, ValueError):
        return False
    return True


def _verified_success(start, finalize):
    """A sampled age is usable only when start returned a session AND its finalize both
    succeeded and passed every identity check. An HTTP 200 without a usable token is not a
    completion, so it is not evidence of a lower bound."""
    return (
        start["outcome"] == "accepted"
        and start["checks"].get("sessionInfoPresent") is True
        and finalize["outcome"] == "accepted"
        and not finalize["skipped"]
        and all(finalize["checks"].get(k) is True for k in FINALIZE_CHECKS)
    )


def lifetime_summary(report):
    """Classify each sampled age from its observation, never beyond it.

    - usableAges: a fully-verified success (session, finalize, every identity check).
    - refusedAges / refusalReasons: start or finalize was refused; the error is recorded.
    - indeterminateAges: accepted but not fully verified (e.g. an HTTP 200 with no token),
      which is neither a usable success nor a refusal.

    lowerBoundSeconds is the largest usable age (a lower bound, never an infinite lifetime).
    upperBoundEstablished is always False in this revision: a refusal records the age and
    its error but does not by itself prove expiry, so no lifetime upper bound is asserted.
    """
    rows = {r["id"]: r for r in report["cases"]}
    usable, refused, indeterminate, reasons = [], [], [], {}
    for a in AGE_SECONDS:
        start, finalize = rows[f"age-{a}s-start"], rows[f"age-{a}s-finalize"]
        if _verified_success(start, finalize):
            usable.append(a)
        elif start["outcome"] == "refused":
            refused.append(a)
            reasons[str(a)] = start["observedError"]
        elif finalize["outcome"] == "refused":
            refused.append(a)
            reasons[str(a)] = finalize["observedError"]
        else:
            indeterminate.append(a)
    return {
        "usableAges": usable,
        "refusedAges": refused,
        "refusalReasons": reasons,
        "indeterminateAges": indeterminate,
        "lowerBoundSeconds": max(usable) if usable else None,
        "upperBoundEstablished": False,
    }


def semantic_rows(rows):
    """Elapsed timing and the measured-age timing region vary across runs and clocks; both
    are excluded, so the semantic projection is each row's outcome, error and checks."""
    return [
        {k: v for k, v in row.items() if k not in {"elapsedMs", "timing"}}
        for row in rows
    ]
