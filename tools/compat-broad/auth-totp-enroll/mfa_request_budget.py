"""MFA-local pre-dispatch accounting, not a production or restart capability.

The whole-run allowance remains 400 requests. Reserve two calls for every one
of the 14 possible owned accounts, leaving at most 372 observation attempts.
Inspection and clock-control requests consume the same allowance. Failed calls
stay charged. Recovery never refills a counter and admits only one delete then
one lookup for each confirmed in-process UID supplied by the caller.

This is in-process accounting for the serial local runner, not packet billing,
a durable cross-process lease, or proof that a supplied UID is actually owned.
"""
from __future__ import annotations

from contextlib import contextmanager
from threading import RLock
from typing import Any, Iterator

from mfa_collector import digest
from mfa_manifest import LIMITS

SCHEMA = "o2-mfa-local-request-budget-v1"


class RequestBudgetError(ValueError):
    """No request was started by this refused reservation."""


def _uid(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= 1024 and all(ord(c) >= 32 and ord(c) != 127 for c in value)
    except UnicodeEncodeError:
        return False


class RequestBudget:
    """One local run, one-way phases and a bounded, immutable request allowance."""

    def __init__(self, max_requests: int = LIMITS["maxRequests"],
                 max_accounts: int = LIMITS["maxOwnedAccounts"]) -> None:
        if (type(max_requests) is not int or not 1 <= max_requests <= LIMITS["maxRequests"]
                or type(max_accounts) is not int or not 1 <= max_accounts <= LIMITS["maxOwnedAccounts"]
                or max_requests <= 2 * max_accounts):
            raise ValueError("finite local request and recovery allowances required")
        self._maximum = max_requests
        self._accounts = max_accounts
        self._observation_limit = max_requests - 2 * max_accounts
        self._observation = self._recovery = 0
        self._phase = "observation"
        self._scope: dict[str, int] | None = None
        self._bound: str | None = None
        self._in_flight = False
        self._observation_blocked = False
        self._lock = RLock()

    @property
    def requests(self) -> int:
        with self._lock:
            return self._observation + self._recovery

    def bind(self, plan: dict) -> None:
        """A new plan may not reset a used instance, nor expand its frozen caps."""
        from mfa_manifest import PROJECT, validate_campaign
        with self._lock:
            if (self._bound is not None or self.requests or self._phase != "observation"
                    or self._in_flight or not validate_campaign(plan)
                    or plan.get("project") != PROJECT
                    or type(plan["limits"]["maxRequests"]) is not int
                    or type(plan["limits"]["maxOwnedAccounts"]) is not int
                    or plan["limits"]["maxRequests"] != self._maximum
                    or plan["limits"]["maxOwnedAccounts"] != self._accounts):
                raise RequestBudgetError("fresh local plan binding required")
            self._bound = digest(plan)

    def begin_recovery(self, owned_uids: tuple[str, ...]) -> None:
        # Validate everything before changing phase. UID registration remains the
        # responsibility of run_sequence; this object does not discover accounts.
        if (type(owned_uids) is not tuple or len(owned_uids) > self._accounts
                or any(not _uid(uid) for uid in owned_uids)
                or len(set(owned_uids)) != len(owned_uids)):
            raise RequestBudgetError("bounded distinct confirmed account scope required")
        with self._lock:
            if self._in_flight or self._phase == "closed":
                raise RequestBudgetError("request is active or budget is closed")
            if self._phase == "recovery":
                if set(owned_uids) != set(self._scope or {}):
                    raise RequestBudgetError("recovery scope cannot change")
                return  # Idempotent, never replenish counters or per-UID slots.
            self._scope = dict.fromkeys(owned_uids, 0)
            self._phase = "recovery"

    @contextmanager
    def attempt(self, *, operation: str | None = None, uid: str | None = None) -> Iterator[None]:
        """Debit once, before the sender is invoked; never refund an exception."""
        with self._lock:
            if self._in_flight or self._phase == "closed":
                raise RequestBudgetError("request is active or budget is closed")
            if self._phase == "observation":
                if self._observation >= self._observation_limit:
                    self._observation_blocked = True
                    raise RequestBudgetError("observation allowance exhausted; recovery reserved")
                self._observation += 1
            else:
                scope = self._scope or {}
                expected = {"delete": 0, "lookup": 1}.get(operation)
                if (expected is None or not _uid(uid) or uid not in scope
                        or scope[uid] != expected or self.requests >= self._maximum):
                    raise RequestBudgetError("request is outside the remaining recovery slots")
                scope[uid] += 1
                self._recovery += 1
            self._in_flight = True
        try:
            yield
        finally:
            with self._lock:
                self._in_flight = False

    def close(self) -> None:
        with self._lock:
            if self._in_flight:
                raise RequestBudgetError("cannot close an active request")
            self._phase = "closed"

    def snapshot(self) -> dict:
        """Private mutable UIDs are never returned; this is a value copy."""
        with self._lock:
            return {
                "schema": SCHEMA, "authorizesCleanup": False,
                "planDigest": self._bound, "phase": self._phase,
                "maxRequests": self._maximum, "maxOwnedAccounts": self._accounts,
                "observationLimit": self._observation_limit,
                "reservedRecoveryRequests": 2 * self._accounts,
                "observationRequests": self._observation, "recoveryRequests": self._recovery,
                "requestsCharged": self.requests,
                "recoveryAccounts": len(self._scope or {}),
                "recoveryEntered": self._scope is not None,
                "observationLimitHit": self._observation_blocked,
                "inFlight": self._in_flight,
            }


def valid_summary(value: Any, plan: Any, requests: Any, *, successful: bool = True) -> bool:
    """Check explicit accounting consistency; no historical/producer attestation."""
    fields = {"schema", "authorizesCleanup", "planDigest", "phase", "maxRequests", "maxOwnedAccounts",
              "observationLimit", "reservedRecoveryRequests", "observationRequests", "recoveryRequests",
              "requestsCharged", "recoveryAccounts", "recoveryEntered", "observationLimitHit", "inFlight"}
    if not isinstance(value, dict) or set(value) != fields or not isinstance(plan, dict):
        return False
    try:
        limits = plan["limits"]
        numbers = ("maxRequests", "maxOwnedAccounts", "observationLimit", "reservedRecoveryRequests",
                   "observationRequests", "recoveryRequests", "requestsCharged", "recoveryAccounts")
        if (any(type(value[k]) is not int or value[k] < 0 for k in numbers)
                or type(requests) is not int or requests < 0
                or type(limits["maxRequests"]) is not int or type(limits["maxOwnedAccounts"]) is not int
                or value["schema"] != SCHEMA or value["authorizesCleanup"] is not False
                or value["phase"] != "closed" or value["inFlight"] is not False
                or value["recoveryEntered"] is not True
                or type(value["observationLimitHit"]) is not bool
                or (successful and value["observationLimitHit"] is not False)
                or value["planDigest"] != digest(plan)):
            return False
        maximum, accounts = value["maxRequests"], value["maxOwnedAccounts"]
        return (
            1 <= maximum <= LIMITS["maxRequests"] and 1 <= accounts <= LIMITS["maxOwnedAccounts"]
            and maximum > 2 * accounts
            and maximum == limits["maxRequests"] and accounts == limits["maxOwnedAccounts"]
            and value["reservedRecoveryRequests"] == 2 * accounts
            and value["observationLimit"] == maximum - 2 * accounts
            and value["observationRequests"] <= value["observationLimit"]
            and value["recoveryRequests"] <= 2 * value["recoveryAccounts"] <= 2 * accounts
            and value["observationRequests"] + value["recoveryRequests"] == value["requestsCharged"] == requests
            and requests <= maximum
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
