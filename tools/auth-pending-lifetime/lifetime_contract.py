"""Finite observations of an MFA pending credential's usability at increasing ages.

This is a lifetime and experiment-feasibility corpus (AUTH-U03 expiry), not a precedence
corpus: it records, at each sampled pending age, whether mfaSignIn:start and (on an
acceptance) mfaSignIn:finalize still succeed, with the pending age and the SMS session age
kept separate (the session is opened fresh at the diagnostic, so only the pending age
varies). It does not pin a TTL or an error precedence, and "still usable at every sampled
age within the budget" is a valid outcome that establishes a lower bound, not an
infinite lifetime.
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

FINALIZE_CHECKS = {
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "claimSubMatches",
    "claimEmailMatches",
    "secondFactorClaim",
    "derivedLookup",
}
# A start row records the diagnostic session presence and the measured ages.
START_CHECKS = {"sessionInfoPresent", "pendingAgeSeconds", "sessionAgeSeconds"}
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
    require(0 <= row["elapsedMs"] <= 3_600_000 and type(row["skipped"]) is bool)
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
        for key in ("pendingAgeSeconds", "sessionAgeSeconds"):
            require(type(row["checks"][key]) is int and row["checks"][key] >= 0)
        # The session is opened fresh at the diagnostic; only the pending age is large.
        require(row["checks"]["sessionAgeSeconds"] <= 30)
        return
    require(name.endswith("-finalize"))
    require(set(row["checks"]) == FINALIZE_CHECKS)
    if name in CONTROLS:
        require(all(v is True for v in row["checks"].values()))
    else:
        require(all(type(v) is bool for v in row["checks"].values()))


def classified(row):
    return row["outcome"] != "refused" or (
        row["httpStatus"] in CLASSIFIED_STATUSES
        and row["observedError"] in COMPLETING_ERRORS
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
        # The observation budget was declared and respected.
        budget = report["budget"]
        require(
            set(budget)
            == {
                "maxAccounts",
                "maxRequests",
                "totalBudgetSeconds",
                "configHoldMaxSeconds",
                "cleanupReserveSeconds",
            }
        )
        require(all(type(v) is int and v > 0 for v in budget.values()))
        require(report["accountsUsed"] <= budget["maxAccounts"])
        require(report["agingMode"] in {"real-time", "virtual-clock"})
        rows = {r["id"]: r for r in report["cases"]}
        for a in AGE_SECONDS:
            start = rows[f"age-{a}s-start"]
            accepted = (
                start["outcome"] == "accepted"
                and start["checks"].get("sessionInfoPresent") is True
            )
            require(rows[f"age-{a}s-finalize"]["skipped"] == (not accepted))
            if accepted:
                # The recorded pending age is at least the sampled age (allowing request latency).
                require(start["checks"]["pendingAgeSeconds"] >= a)
        if report["target"] == "production":
            require(
                report["committedCheckout"] is True
                and report["agingMode"] == "real-time"
            )
    except (KeyError, TypeError, ValueError):
        return False
    return True


def lifetime_summary(report):
    """Classify the run: the largest sampled age still usable, and whether any age was
    refused. Never asserts an exact TTL; a fully-usable run reports the lower bound only."""
    rows = {r["id"]: r for r in report["cases"]}
    usable, refused = [], []
    for a in AGE_SECONDS:
        start, finalize = rows[f"age-{a}s-start"], rows[f"age-{a}s-finalize"]
        if start["outcome"] == "accepted" and finalize["outcome"] == "accepted":
            usable.append(a)
        elif start["outcome"] == "refused" or finalize["outcome"] == "refused":
            refused.append(a)
    return {
        "usableAges": usable,
        "refusedAges": refused,
        "lowerBoundSeconds": max(usable) if usable else None,
        "upperBoundEstablished": bool(refused),
    }


def semantic_rows(rows):
    """Elapsed timing and the measured ages vary across runs and clocks; exclude them."""
    out = []
    for row in rows:
        checks = {
            k: v
            for k, v in row["checks"].items()
            if k not in {"pendingAgeSeconds", "sessionAgeSeconds"}
        }
        out.append(
            {**{k: v for k, v in row.items() if k != "elapsedMs"}, "checks": checks}
        )
    return out
