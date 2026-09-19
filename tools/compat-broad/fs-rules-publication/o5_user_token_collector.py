"""Bounded collector for the FS-RULES user-token observation matrix.

The collector performs no I/O of its own except its journal. All traffic goes
through an injected ``execute`` callable, so a test drives the whole contract
without a network, a credential, or a process.

Redaction is structural rather than best effort. A compiled operation carries a
credential *reference* label, never a token, so the collector never holds an ID
token, a refresh token, an API key or a password. The transport resolves the
label. A receipt is scanned recursively: a credential-shaped key or a
token-shaped value anywhere inside it aborts the run, and no later row is
attempted. Observation and recovery receipts share the same allowlist.

Budgets are enforced, not declared. A request ceiling and a monotonic deadline
bound observation; a separate reserve and a separate, longer deadline bound
recovery, so cleanup cannot be starved by an exhausted observation budget and
also cannot run unbounded.

Owned resources are the campaign's documents *and* the throwaway accounts it
created. Both are recovered here.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from o5_user_token_case import digest, validate_case

COLLECTOR_CONTRACT = "fs-rules-user-token-collector-v2"

ROLE_PRODUCTION = "production-user-token"
ROLE_LOCAL_SHADOW = "local-fireemu-shadow"
ROLES = (ROLE_PRODUCTION, ROLE_LOCAL_SHADOW)

# A key containing any of these substrings, at any depth and in any case, means
# a credential escaped the transport.
FORBIDDEN_KEY_TOKENS = (
    "apikey",
    "assertion",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "password",
    "passwd",
    "privatekey",
    "refresh",
    "secret",
    "serviceaccount",
    "token",
)

# Receipt keys the collector accepts. Anything else is a contract drift.
OBSERVATION_RECEIPT_KEYS = frozenset(
    {"status", "code", "httpStatus", "documentPresent", "fields", "failure", "complete"}
)
RECOVERY_RECEIPT_KEYS = frozenset(
    {
        "status",
        "code",
        "httpStatus",
        "documentPresent",
        "accountPresent",
        "version",
        "uid",
        "failure",
        "complete",
    }
)

_MAX_RECEIPT_KEYS = 24
_MAX_DEPTH = 6
_MAX_NODES = 256
_MAX_STRING = 4096
_JWT_SHAPE = re.compile(r"^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$")


class BudgetExhausted(RuntimeError):
    """Raised internally when a bound stops further requests."""


def _now() -> float:
    return time.monotonic()


def _credential_fingerprint(nonce: str, ref: str) -> str:
    """Bind a row to its principal without recording anything secret."""
    return digest(["credential-ref", nonce, ref])[:16]


def _scan(value: Any, depth: int, budget: list[int]) -> str | None:
    """Recursively reject credential-shaped keys and token-shaped values."""
    budget[0] -= 1
    if budget[0] < 0:
        return "receipt-too-large"
    if depth > _MAX_DEPTH:
        return "receipt-too-deep"
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                return "non-string-receipt-key"
            lowered = key.lower()
            for marker in FORBIDDEN_KEY_TOKENS:
                if marker in lowered:
                    return f"credential-leak:{key}"
            failure = _scan(nested, depth + 1, budget)
            if failure is not None:
                return failure
        return None
    if isinstance(value, (list, tuple)):
        for nested in value:
            failure = _scan(nested, depth + 1, budget)
            if failure is not None:
                return failure
        return None
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            return "receipt-string-too-long"
        if any(character < " " or character == "\x7f" for character in value):
            return "control-character-in-receipt"
        if _JWT_SHAPE.fullmatch(value):
            return "credential-leak:token-shaped-value"
        return None
    if isinstance(value, (bool, int, float)) or value is None:
        return None
    return "unsupported-receipt-value"


def _accept(
    receipt: Any, allowed: frozenset[str]
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(receipt, Mapping):
        return None, "invalid-receipt"
    if len(receipt) > _MAX_RECEIPT_KEYS:
        return None, "receipt-too-large"
    failure = _scan(receipt, 0, [_MAX_NODES])
    if failure is not None:
        return None, failure
    unknown = sorted(key for key in receipt if key not in allowed)
    if unknown:
        return None, "unknown-receipt-key:" + ",".join(unknown)
    return dict(receipt), None


class _Journal:
    """Append-only, fsynced record of every intent and outcome.

    A process that dies mid-run still leaves the list of resources it touched,
    so an orphan document or account can be found and removed.
    """

    def __init__(self, path: str | os.PathLike[str] | None) -> None:
        self.path = Path(path) if path is not None else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self.path.open("a", encoding="utf-8")
        else:
            self._handle = None

    def record(self, kind: str, payload: dict[str, Any]) -> None:
        if self._handle is None:
            return
        line = json.dumps(
            {"kind": kind, **payload}, sort_keys=True, separators=(",", ":")
        )
        self._handle.write(line + "\n")
        self._handle.flush()
        os.fsync(self._handle.fileno())

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


class _Budget:
    def __init__(
        self,
        *,
        requests: int,
        recovery: int,
        deadline: float,
        recovery_deadline: float,
        clock: Callable[[], float],
    ) -> None:
        self._requests = requests
        self._recovery = recovery
        self._deadline = deadline
        self._recovery_deadline = recovery_deadline
        self._clock = clock
        self.spent = 0
        self.recovery_spent = 0

    def take_observation(self) -> None:
        if self.spent >= self._requests:
            raise BudgetExhausted("observation-request-ceiling")
        if self._clock() >= self._deadline:
            raise BudgetExhausted("deadline-exhausted")
        self.spent += 1

    def take_recovery(self) -> None:
        if self.recovery_spent >= self._recovery:
            raise BudgetExhausted("recovery-request-ceiling")
        if self._clock() >= self._recovery_deadline:
            raise BudgetExhausted("recovery-deadline-exhausted")
        self.recovery_spent += 1


def _request(operation: Mapping[str, Any], nonce: str) -> dict[str, Any]:
    return {
        "caseId": operation["caseId"],
        "index": operation["index"],
        "ruleset": operation["ruleset"],
        "method": operation["method"],
        "resources": list(operation["resources"]),
        "writes": [dict(write) for write in operation["writes"]],
        "createdDocuments": list(operation["createdDocuments"]),
        "credentialRef": operation["credential"]["ref"],
        "credentialClass": operation["credential"]["class"],
        "credentialFingerprint": _credential_fingerprint(
            nonce, operation["credential"]["ref"]
        ),
    }


def collect(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    *,
    role: str,
    run_id: str,
    deadline_seconds: float = 600.0,
    recovery_deadline_seconds: float = 900.0,
    clock: Callable[[], float] = _now,
    journal_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Run the compiled matrix through ``execute`` under enforced bounds.

    The returned bundle is always ``productionReady: False``. Collecting rows is
    not authority to promote them; that is a separate review.
    """
    validate_case(plan)
    if role not in ROLES:
        raise ValueError("unknown collector role")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run identity required")
    for value in (deadline_seconds, recovery_deadline_seconds):
        if not isinstance(value, (int, float)) or not 0 < value <= 3600:
            raise ValueError("deadline out of range")
    if recovery_deadline_seconds < deadline_seconds:
        raise ValueError("recovery deadline must not precede the observation deadline")

    nonce = plan["nonce"]
    operations = plan["observation"]
    accounts = plan["ownedAccounts"]
    started = clock()
    budget = _Budget(
        requests=len(operations),
        recovery=3 * (len(plan["ownedResources"]) + len(accounts)),
        deadline=started + float(deadline_seconds),
        recovery_deadline=started + float(recovery_deadline_seconds),
        clock=clock,
    )
    journal = _Journal(journal_path)
    journal.record("run", {"runId": run_id, "role": role, "plan": plan["planDigest"]})

    rows: list[dict[str, Any]] = []
    attempted: list[str] = []
    # Every account exists before the first row, so all of them are owned.
    attempted_accounts = [entry["ref"] for entry in accounts]
    journal.record("accounts", {"refs": attempted_accounts})
    failures: list[str] = []
    abort: str | None = None

    try:
        for operation in operations:
            request = _request(operation, nonce)
            try:
                budget.take_observation()
            except BudgetExhausted as error:
                abort = str(error)
                break
            for document in operation["createdDocuments"]:
                resource = _resource_for(plan, document)
                if resource not in attempted:
                    attempted.append(resource)
                    journal.record("attempt", {"resource": resource})
            journal.record(
                "request", {"caseId": request["caseId"], "index": request["index"]}
            )
            try:
                raw = execute(dict(request))
            except Exception as error:  # noqa: BLE001 - type name only, no message
                raw, receipt_failure = None, f"transport:{type(error).__name__}"
            else:
                raw, receipt_failure = _accept(raw, OBSERVATION_RECEIPT_KEYS)
            if receipt_failure is not None:
                rows.append(_row(request, None, receipt_failure))
                failures.append(f"{operation['caseId']}:{receipt_failure}")
                abort = receipt_failure
                journal.record(
                    "outcome",
                    {"caseId": request["caseId"], "failure": receipt_failure},
                )
                break
            rows.append(_row(request, raw, None))
            journal.record(
                "outcome",
                {"caseId": request["caseId"], "status": raw.get("status")},
            )
            if raw.get("complete") is not True:
                failures.append(f"{operation['caseId']}:incomplete")
                abort = "incomplete-receipt"
                break

        cleanup = _recover(plan, execute, budget, attempted, journal)
    finally:
        journal.close()

    complete = (
        abort is None
        and len(rows) == len(operations)
        and not failures
        and cleanup["cleanupComplete"] is True
    )
    return {
        "contract": COLLECTOR_CONTRACT,
        "status": "PREPARATION_ONLY",
        "provenance": {
            "role": role,
            "runId": run_id,
            "collectorContract": COLLECTOR_CONTRACT,
            "caseContract": plan["contract"],
        },
        "planDigest": plan["planDigest"],
        "rows": rows,
        "attemptedResources": attempted,
        "attemptedAccounts": attempted_accounts,
        "cleanup": cleanup,
        "budget": {
            "observationCeiling": len(operations),
            "observationSpent": budget.spent,
            "recoveryCeiling": 3 * (len(plan["ownedResources"]) + len(accounts)),
            "recoverySpent": budget.recovery_spent,
            "deadlineSeconds": float(deadline_seconds),
            "recoveryDeadlineSeconds": float(recovery_deadline_seconds),
        },
        "journal": str(journal.path) if journal.path is not None else None,
        "infrastructureFailures": failures,
        "abort": abort,
        "recordingComplete": complete,
        "productionExecuted": False,
        "productionReady": False,
    }


def _resource_for(plan: Mapping[str, Any], document: str) -> str:
    suffix = f"/cases/{document}"
    for resource in plan["ownedResources"]:
        if resource.endswith(suffix):
            return resource
    raise ValueError("unknown owned document")


def _row(
    request: Mapping[str, Any], receipt: Mapping[str, Any] | None, failure: str | None
) -> dict[str, Any]:
    row = {
        "caseId": request["caseId"],
        "index": request["index"],
        "ruleset": request["ruleset"],
        "method": request["method"],
        "resources": list(request["resources"]),
        "credentialRef": request["credentialRef"],
        "credentialClass": request["credentialClass"],
        "credentialFingerprint": request["credentialFingerprint"],
        "observed": None,
        "failure": failure,
    }
    if receipt is not None:
        row["observed"] = {
            "status": receipt.get("status"),
            "code": receipt.get("code"),
            "documentPresent": receipt.get("documentPresent"),
            "fields": receipt.get("fields"),
        }
    return row


def _recover(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget,
    attempted: list[str],
    journal: _Journal,
) -> dict[str, Any]:
    """Version-bound cleanup of every owned document and account.

    Deletion is only authorized by a readback that proves the resource exists
    with a concrete version, or, for an account, with a concrete uid. An absent
    resource is already recovered. An unreadable resource stays an open
    responsibility and is never force deleted.
    """
    document_steps: list[dict[str, Any]] = []
    outstanding: list[str] = []
    for resource in plan["ownedResources"]:
        readback = _cleanup_step(
            execute, budget, journal, "readback", resource=resource
        )
        document_steps.append(readback)
        observed = readback.get("observed") or {}
        if readback["failure"] is not None:
            outstanding.append(resource)
            continue
        if observed.get("documentPresent") is False:
            continue
        version = observed.get("version")
        if not isinstance(version, str) or not version:
            outstanding.append(resource)
            continue
        delete = _cleanup_step(
            execute, budget, journal, "delete", resource=resource, version=version
        )
        document_steps.append(delete)
        absence = _cleanup_step(execute, budget, journal, "absence", resource=resource)
        document_steps.append(absence)
        absent = (absence.get("observed") or {}).get("documentPresent") is False
        if delete["failure"] is not None or not absent:
            outstanding.append(resource)

    account_steps: list[dict[str, Any]] = []
    outstanding_accounts: list[str] = []
    for entry in plan["ownedAccounts"]:
        ref = entry["ref"]
        readback = _cleanup_step(
            execute, budget, journal, "account-readback", account=ref
        )
        account_steps.append(readback)
        observed = readback.get("observed") or {}
        if readback["failure"] is not None:
            outstanding_accounts.append(ref)
            continue
        if observed.get("accountPresent") is False:
            continue
        uid = observed.get("uid")
        if not isinstance(uid, str) or not uid:
            outstanding_accounts.append(ref)
            continue
        delete = _cleanup_step(
            execute, budget, journal, "account-delete", account=ref, uid=uid
        )
        account_steps.append(delete)
        absence = _cleanup_step(
            execute, budget, journal, "account-absence", account=ref
        )
        account_steps.append(absence)
        absent = (absence.get("observed") or {}).get("accountPresent") is False
        if delete["failure"] is not None or not absent:
            outstanding_accounts.append(ref)

    unrecovered = [resource for resource in attempted if resource in outstanding]
    return {
        "documentSteps": document_steps,
        "accountSteps": account_steps,
        "outstandingResources": outstanding,
        "outstandingAccounts": outstanding_accounts,
        "unrecoveredAttempted": unrecovered,
        "cleanupComplete": not outstanding and not outstanding_accounts,
    }


def _cleanup_step(
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget,
    journal: _Journal,
    kind: str,
    *,
    resource: str | None = None,
    account: str | None = None,
    version: str | None = None,
    uid: str | None = None,
) -> dict[str, Any]:
    subject = resource if resource is not None else account
    request: dict[str, Any] = {
        "kind": kind,
        "phase": "recovery",
        "resource": resource,
        "accountRef": account,
        "credentialRef": "administrator",
        "credentialClass": "administrator",
        "precondition": None,
    }
    if version is not None:
        request["precondition"] = {"updateTime": version}
    elif uid is not None:
        request["precondition"] = {"uid": uid}

    def outcome(failure: str | None, observed: dict[str, Any] | None) -> dict[str, Any]:
        journal.record(
            "recovery", {"step": kind, "subject": subject, "failure": failure}
        )
        return {
            "kind": kind,
            "resource": resource,
            "accountRef": account,
            "observed": observed,
            "failure": failure,
        }

    try:
        budget.take_recovery()
    except BudgetExhausted as error:
        return outcome(str(error), None)
    try:
        raw = execute(dict(request))
    except Exception as error:  # noqa: BLE001 - type name only, never a message
        return outcome(f"transport:{type(error).__name__}", None)
    accepted, failure = _accept(raw, RECOVERY_RECEIPT_KEYS)
    if failure is not None:
        return outcome(failure, None)
    if accepted.get("complete") is not True:
        return outcome("incomplete", None)
    return outcome(
        None,
        {
            "documentPresent": accepted.get("documentPresent"),
            "accountPresent": accepted.get("accountPresent"),
            "version": accepted.get("version"),
            "uid": accepted.get("uid"),
            "status": accepted.get("status"),
        },
    )
