"""Closed request-count projection for the revision-3 recorder's Auth paths.

This is a planning contract, not a transport or Gate adapter. It counts actual
Auth requests from the recorder's setup, conditional diagnostic, and recovery
paths; result rows are deliberately not used as a request denominator.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

import window_recorder
from window_contract import CASES, CORPUS

CAMPAIGN_ID = "AUTH-MFA-AGE-TOTP-01"
SELECTOR = "pending-lifetime-rev3-v1"
WALL_SECONDS = 1500
RECOVERY_SECONDS = 300
MAX_ACCOUNTS = 5
MAX_AUTH_REQUESTS = 300
RECOVERY_AUTH_RESERVE = 60
OBSERVATION_AUTH_LIMIT = MAX_AUTH_REQUESTS - RECOVERY_AUTH_RESERVE
RECORDER_BUDGET_SHA256 = (
    "77484edd8094d03f1a0d035bddf5b797c8125b9262c1e1c41b5c97f3b1ece7c0"
)
RECORDER_BUDGET_EXPECTED = {
    "maxAccounts": 5,
    "maxRequests": 300,
    "recoveryRequestReserve": 60,
    "totalBudgetSeconds": 1500,
    "configHoldMaxSeconds": 1500,
    "cleanupReserveSeconds": 300,
    "adminTokenMaxAgeSeconds": 3000,
}
CASES_SHA256 = "f48a38ec71c1ce70d0ed140c298bf70bf4e4330592641d15d0c1f111b77e8d6f"
CORPUS_SHA256 = "f219caea7f12cc431f87994fe814f7d8cb393f39ad29562d42362897e92510a3"
_ACTUAL_CORPUS_SHA256 = hashlib.sha256(
    json.dumps(CORPUS, separators=(",", ":"), ensure_ascii=False).encode()
).hexdigest()
_ACTUAL_CASES_SHA256 = hashlib.sha256(
    json.dumps(CASES, separators=(",", ":"), ensure_ascii=False).encode()
).hexdigest()

AgeOutcome = Literal["accepted", "start-refused", "finalize-refused"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_selection(selector: str, cases: tuple[str, ...]) -> None:
    """Reject unbound selectors and any ordering or membership drift."""
    require(selector == SELECTOR, "unsupported revision-3 selector")
    require(cases == CASES, "revision-3 case set or order changed")
    require(len(CASES) == 17, "revision-3 corpus size changed")
    require(_ACTUAL_CASES_SHA256 == CASES_SHA256, "revision-3 case digest changed")
    require(_ACTUAL_CORPUS_SHA256 == CORPUS_SHA256, "revision-3 corpus digest changed")


def validate_recorder_budget(budget: dict) -> None:
    """Require the complete recorder budget to match its frozen digest and fields."""
    require(type(budget) is dict, "recorder budget must be a dictionary")
    encoded = json.dumps(
        budget, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    require(digest == RECORDER_BUDGET_SHA256, "recorder budget digest changed")
    require(budget == RECORDER_BUDGET_EXPECTED, "recorder budget fields changed")
    require(
        window_recorder.BUDGET == RECORDER_BUDGET_EXPECTED,
        "window recorder budget no longer matches the frozen contract",
    )


def observation_auth_requests(age_outcomes: tuple[AgeOutcome, ...]) -> int:
    """Count recorder Auth calls for one outcome per sampled age.

    A refusal path includes state readback. The fresh control contributes four
    requests only when state matches and a session is returned. A successful
    finalize contributes its derived client lookup.
    """
    require(len(age_outcomes) == 3, "one outcome per sampled age required")
    require(
        all(
            value in ("accepted", "start-refused", "finalize-refused")
            for value in age_outcomes
        ),
        "unsupported age outcome",
    )
    # Five account setups each issue email lookup, signup, email lookup, update,
    # and UID lookup. Baseline/final fresh controls issue pending/start/finalize/
    # derived lookup. Three held pending credentials precede the age schedule.
    total = MAX_ACCOUNTS * 5 + 2 * 4 + 3
    for outcome in age_outcomes:
        if outcome == "accepted":
            # Aged start, finalize, and successful-finalize identity lookup.
            total += 3
        else:
            # Old start, optional old finalize, state readback, then the
            # same-account fresh pending/start/finalize/identity lookup path.
            total += 1 + (outcome == "finalize-refused") + 1 + 4
    require(total <= OBSERVATION_AUTH_LIMIT, "observation Auth request limit exceeded")
    return total


def recovery_auth_requests(existing_accounts: int = MAX_ACCOUNTS) -> int:
    """Worst-case cleanup: email lookup, UID lookup, delete, and two absences."""
    require(
        type(existing_accounts) is int and 0 <= existing_accounts <= MAX_ACCOUNTS,
        "invalid recovery account count",
    )
    return existing_accounts * 5


def validate_budget() -> None:
    validate_recorder_budget(window_recorder.BUDGET)
    require(CAMPAIGN_ID == "AUTH-MFA-AGE-TOTP-01", "stable task ID changed")
    require(SELECTOR == "pending-lifetime-rev3-v1", "selector changed")
    require(
        WALL_SECONDS == 1500 and RECOVERY_SECONDS == 300,
        "revision-3 wall/recovery envelope changed",
    )
    require(
        MAX_ACCOUNTS == 5 and MAX_AUTH_REQUESTS == 300,
        "revision-3 account/request budget changed",
    )
    require(RECOVERY_AUTH_RESERVE == 60, "recovery request reserve changed")
    require(
        observation_auth_requests(("start-refused",) * 3) <= OBSERVATION_AUTH_LIMIT,
        "refusal-path observation budget exceeded",
    )
    require(
        recovery_auth_requests() <= RECOVERY_AUTH_RESERVE,
        "recovery Auth request reserve insufficient",
    )
