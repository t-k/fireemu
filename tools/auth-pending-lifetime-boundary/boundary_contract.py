"""Revision 2: finite MFA usability observations, never a proof of a common TTL.

Independent accounts sample 600/1800/3300/3900 seconds. A verified completion supplies
an observed lower bound; later refusals supply measured, stage-specific candidates.
Age causality, account equivalence and monotonicity remain unproven. Revision 1 stays pinned.
"""

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require

# Fixed sampling schedule; target ages are not refusal interval endpoints.
AGE_SECONDS = (600, 1800, 3300, 3900)
CASES = (
    "baseline-fresh-finalize",
    *[name for a in AGE_SECONDS for name in (f"age-{a}s-start", f"age-{a}s-finalize")],
    "final-fresh-finalize",
)
DIAGNOSTIC = tuple(c for c in CASES if c.startswith("age-"))
CONTROLS = ("baseline-fresh-finalize", "final-fresh-finalize")
CORPUS = {"slice": "auth-pending-lifetime", "revision": 2, "cases": list(CASES)}

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
# These names indicate an input/account-state problem, not age-caused expiry.
INPUT_STATE_ERRORS = {"MISSING_MFA_PENDING_CREDENTIAL", "MFA_ENROLLMENT_NOT_FOUND"}

FINALIZE_CHECKS = {
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "claimSubMatches",
    "claimEmailMatches",
    "secondFactorClaim",
    "derivedLookup",
}
START_CHECKS = {"sessionInfoPresent"}
MAX_SESSION_AGE_SECONDS = 30
START_TIMING = {
    "pendingSent",
    "pendingReceived",
    "startSent",
    "startReceived",
    "pendingAgeAtStart",
}
FINALIZE_TIMING = {
    "pendingSent",
    "pendingReceived",
    "startSent",
    "startReceived",
    "finalizeSent",
    "finalizeReceived",
    "sessionAgeAtFinalize",
    "pendingAgeAtFinalize",
}
START_ORDER = ("pendingSent", "pendingReceived", "startSent", "startReceived")
FINALIZE_ORDER = (*START_ORDER, "finalizeSent", "finalizeReceived")
BUDGET_KEYS = {
    "maxAccounts",
    "maxRequests",
    "recoveryRequestReserve",
    "totalBudgetSeconds",
    "configHoldMaxSeconds",
    "cleanupReserveSeconds",
    "adminTokenMaxAgeSeconds",
}
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
    return type(value) in (int, float) and value >= 0


def _interval(value):
    return (
        isinstance(value, dict)
        and set(value) == {"lower", "upper"}
        and _number(value["lower"])
        and _number(value["upper"])
        and value["lower"] <= value["upper"]
    )


def _ordered(timing, order):
    for key in order:
        require(_number(timing[key]))
    for earlier, later in itertools.pairwise(order):
        require(timing[earlier] <= timing[later])


def _derived(timing, interval_key, low_from, low_sub, high_from, high_sub):
    require(_interval(timing[interval_key]))
    require(timing[interval_key]["lower"] == timing[low_from] - timing[low_sub])
    require(timing[interval_key]["upper"] == timing[high_from] - timing[high_sub])


def validate_timing(timing, name, outcome, skipped):
    require(isinstance(timing, dict))
    if skipped:
        require(timing == {})
        return
    if name.endswith("-start"):
        require(set(timing) == START_TIMING)
        _ordered(timing, START_ORDER)
        _derived(
            timing,
            "pendingAgeAtStart",
            "startSent",
            "pendingReceived",
            "startReceived",
            "pendingSent",
        )
        return
    require(set(timing) == FINALIZE_TIMING)
    _ordered(timing, FINALIZE_ORDER)
    _derived(
        timing,
        "sessionAgeAtFinalize",
        "finalizeSent",
        "startReceived",
        "finalizeReceived",
        "startSent",
    )
    _derived(
        timing,
        "pendingAgeAtFinalize",
        "finalizeSent",
        "pendingReceived",
        "finalizeReceived",
        "pendingSent",
    )
    if outcome == "accepted":
        require(timing["sessionAgeAtFinalize"]["upper"] <= MAX_SESSION_AGE_SECONDS)


def age_of(name):
    require(name.startswith("age-") and "s-" in name)
    return int(name[len("age-") : name.index("s-")])


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
    require(0 <= row["elapsedMs"] <= 21_600_000 and type(row["skipped"]) is bool)
    validate_timing(row["timing"], name, row["outcome"], row["skipped"])
    if row["skipped"]:
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
        require(row["checks"]["sessionInfoPresent"] is True)
        require(row["timing"]["pendingAgeAtStart"]["lower"] >= age_of(name))
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
    ages = report["adminTokenAges"]
    require(isinstance(ages, list) and all(_number(a) for a in ages))
    require(all(a <= budget["adminTokenMaxAgeSeconds"] for a in ages))
    evidence = report["privilegedRequests"]
    counts = report["privilegedRequestCount"]
    require(set(counts) == {"observation", "recovery"})
    require(all(type(n) is int and n >= 0 for n in counts.values()))
    if report["target"] == "production":
        require(bool(evidence) and len(evidence) == len(ages) == sum(counts.values()))
        require(
            sum(e["action"].startswith("config:") for e in evidence)
            == report["requestCount"]["config"]
        )
        for phase in counts:
            require(sum(e["phase"] == phase for e in evidence) == counts[phase])
        for i, entry in enumerate(evidence):
            require(entry["sequence"] == i + 1 and entry["tokenAgeSeconds"] == ages[i])
            require(
                entry["action"]
                in {
                    "config:read",
                    "config:patch",
                    "admin:lookup",
                    "admin:update",
                    "admin:delete",
                    "project:read",
                }
            )
            require(
                all(
                    _number(entry[k])
                    for k in ("started", "verifiedExpiry", "remainingSeconds")
                )
            )
            require(
                entry["remainingSeconds"] == entry["verifiedExpiry"] - entry["started"]
            )
            require(entry["remainingSeconds"] >= 20)
            limit = budget["totalBudgetSeconds"] - (
                budget["cleanupReserveSeconds"]
                if entry["phase"] == "observation"
                else 0
            )
            require(entry["started"] + 20 <= limit)
        public = report["publicRequestCount"]
        require(set(public) == {"observation", "recovery"})
        for phase in public:
            require(type(public[phase]) is int and public[phase] >= 0)
            require(
                sum(
                    e["action"].startswith("admin:") and e["phase"] == phase
                    for e in evidence
                )
                + public[phase]
                == report["requestCount"][phase]
            )
        require(sum(e["action"] == "project:read" for e in evidence) == 1)
        attempts = report["authRefreshAttempts"]
        require(set(attempts) == {"observation", "recovery"})
        for phase, n in attempts.items():
            require(type(n) is int and 0 <= n <= 2)
            require(
                sum(
                    e["operation"] == "refresh" and e["phase"] == phase
                    for e in report["authOperations"]
                )
                == n
            )
        for entry in report["authOperations"]:
            require(entry["phase"] in attempts)
            require(entry["operation"] in {"refresh", "tokeninfo", "preflight-command"})
            reserve = 20 if entry["operation"] == "tokeninfo" else 60
            require(entry["reserveSeconds"] == reserve and _number(entry["started"]))
            limit = budget["totalBudgetSeconds"] - (
                budget["cleanupReserveSeconds"]
                if entry["phase"] == "observation"
                else 0
            )
            require(entry["started"] + reserve <= limit)
    else:
        require(ages == [] and evidence == [] and sum(counts.values()) == 0)


def complete(report):
    try:
        require(
            not any(
                k in report
                for k in (
                    "failure",
                    "cleanupFailure",
                    "configRestoreFailure",
                    "recoveryIncomplete",
                )
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
            finalize = rows[f"age-{a}s-finalize"]
            accepted = (
                start["outcome"] == "accepted"
                and start["checks"].get("sessionInfoPresent") is True
            )
            require(finalize["skipped"] == (not accepted))
            require(start["timing"]["pendingAgeAtStart"]["lower"] >= a)
            if not finalize["skipped"]:
                for key in START_ORDER:
                    require(finalize["timing"][key] == start["timing"][key])
        if report["target"] == "production":
            require(
                report["committedCheckout"] is True
                and report["agingMode"] == "real-time"
            )
    except (KeyError, TypeError, ValueError):
        return False
    return True


def _verified_success(start, finalize):
    return (
        start["outcome"] == "accepted"
        and start["checks"].get("sessionInfoPresent") is True
        and finalize["outcome"] == "accepted"
        and not finalize["skipped"]
        and all(finalize["checks"].get(k) is True for k in FINALIZE_CHECKS)
    )


def lifetime_summary(report):
    """Report successes and measured refusal candidates; never establish age causality."""
    rows = {r["id"]: r for r in report["cases"]}
    usable, refused, indeterminate, reasons, observations, starts = (
        [],
        [],
        [],
        {},
        [],
        [],
    )
    for a in AGE_SECONDS:
        start, finalize = rows[f"age-{a}s-start"], rows[f"age-{a}s-finalize"]
        if (
            start["outcome"] == "accepted"
            and start["checks"].get("sessionInfoPresent") is True
        ):
            starts.append(a)
        if _verified_success(start, finalize):
            usable.append(a)
        elif start["outcome"] == "refused" or finalize["outcome"] == "refused":
            stage = "start" if start["outcome"] == "refused" else "finalize"
            row = start if stage == "start" else finalize
            error = row["observedError"]
            refused.append(a)
            reasons[str(a)] = error
            observations.append(
                {
                    "targetAgeSeconds": a,
                    "stage": stage,
                    "error": error,
                    "pendingAge": dict(
                        row["timing"]["pendingAgeAt" + stage.capitalize()]
                    ),
                    "classification": "input-or-account-state"
                    if error in INPUT_STATE_ERRORS
                    else "cause-unestablished",
                }
            )
        else:
            indeterminate.append(a)
    lower = max(usable) if usable else None
    nonmonotonic = any(a < success for a in refused for success in usable)
    candidates = []
    if lower is not None and not nonmonotonic:
        for refusal in observations:
            if (
                refusal["error"] == "INVALID_MFA_PENDING_CREDENTIAL"
                and refusal["pendingAge"]["lower"] > lower
            ):
                candidates.append(
                    {
                        **refusal,
                        "lowerSeconds": lower,
                        "upperSeconds": refusal["pendingAge"]["upper"],
                        "assessment": "candidate",
                    }
                )
    return {
        "usableAges": usable,
        "startAcceptedAges": starts,
        "refusedAges": refused,
        "refusalReasons": reasons,
        "refusalObservations": observations,
        "indeterminateAges": indeterminate,
        "lowerBoundSeconds": lower,
        "upperBoundEstablished": False,
        "upperBoundSeconds": None,
        "ageCausedExpiryEstablished": False,
        "nonMonotonic": nonmonotonic,
        "boundaryCandidates": candidates,
    }


def semantic_rows(rows):
    return [
        {k: v for k, v in row.items() if k not in {"elapsedMs", "timing"}}
        for row in rows
    ]
