"""Bounded collector for the FS-RULES user-token observation matrix.

The collector performs no I/O of its own. All traffic goes through an injected
``execute`` callable, so a test drives the whole contract without a network, a
credential, or a process.

Redaction is structural rather than best effort. A compiled operation carries a
credential *reference* label, never a token, so the collector never holds an ID
token, a refresh token, an API key or a password. The transport resolves the
label. A receipt that carries any credential-shaped key is rejected as a leak,
the run aborts, and no later row is attempted.

Budgets are enforced, not declared: a request ceiling and a monotonic deadline
bound observation, and a separate reserve bounds recovery so that cleanup
cannot be starved by an exhausted observation budget.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

from o5_user_token_case import digest, validate_case

COLLECTOR_CONTRACT = "fs-rules-user-token-collector-v1"

ROLE_PRODUCTION = "production-user-token"
ROLE_LOCAL_SHADOW = "local-fireemu-shadow"
ROLES = (ROLE_PRODUCTION, ROLE_LOCAL_SHADOW)

# Any of these keys in a receipt means a credential escaped the transport.
FORBIDDEN_RECEIPT_KEYS = frozenset(
    {
        "authorization",
        "Authorization",
        "apiKey",
        "customToken",
        "headers",
        "idToken",
        "password",
        "refreshToken",
        "token",
    }
)

_ALLOWED_RECEIPT_KEYS = frozenset(
    {"status", "code", "httpStatus", "documentPresent", "fields", "failure", "complete"}
)

_MAX_RECEIPT_KEYS = 24


class BudgetExhausted(RuntimeError):
    """Raised internally when a bound stops further requests."""


def _now() -> float:
    return time.monotonic()


def _credential_fingerprint(nonce: str, ref: str) -> str:
    """Bind a row to its principal without recording anything secret."""
    return digest(["credential-ref", nonce, ref])[:16]


def _scrub(receipt: Any) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(receipt, Mapping):
        return None, "invalid-receipt"
    leaked = sorted(set(receipt) & FORBIDDEN_RECEIPT_KEYS)
    if leaked:
        return None, "credential-leak:" + ",".join(leaked)
    if len(receipt) > _MAX_RECEIPT_KEYS:
        return None, "receipt-too-large"
    unknown = sorted(key for key in receipt if key not in _ALLOWED_RECEIPT_KEYS)
    if unknown:
        return None, "unknown-receipt-key:" + ",".join(unknown)
    return dict(receipt), None


def _request(operation: Mapping[str, Any], nonce: str) -> dict[str, Any]:
    return {
        "caseId": operation["caseId"],
        "index": operation["index"],
        "ruleset": operation["ruleset"],
        "method": operation["method"],
        "resources": list(operation["resources"]),
        "createdDocuments": list(operation["createdDocuments"]),
        "credentialRef": operation["credential"]["ref"],
        "credentialClass": operation["credential"]["class"],
        "credentialFingerprint": _credential_fingerprint(nonce, operation["credential"]["ref"]),
    }


class _Budget:
    def __init__(self, *, requests: int, recovery: int, deadline: float, clock) -> None:
        self._requests = requests
        self._recovery = recovery
        self._deadline = deadline
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
        self.recovery_spent += 1


def collect(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    *,
    role: str,
    run_id: str,
    deadline_seconds: float = 600.0,
    clock: Callable[[], float] = _now,
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
    if not isinstance(deadline_seconds, (int, float)) or not 0 < deadline_seconds <= 3600:
        raise ValueError("deadline out of range")

    nonce = plan["nonce"]
    operations = plan["observation"]
    budget = _Budget(
        requests=len(operations),
        recovery=3 * len(plan["ownedResources"]),
        deadline=clock() + float(deadline_seconds),
        clock=clock,
    )

    rows: list[dict[str, Any]] = []
    attempted: list[str] = []
    failures: list[str] = []
    abort: str | None = None

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
        try:
            raw = execute(dict(request))
        except Exception as error:  # noqa: BLE001 - type name only, never a message
            raw, scrub_failure = None, f"transport:{type(error).__name__}"
        else:
            raw, scrub_failure = _scrub(raw)
        if scrub_failure is not None:
            rows.append(_row(request, None, scrub_failure))
            failures.append(f"{operation['caseId']}:{scrub_failure}")
            abort = scrub_failure
            break
        rows.append(_row(request, raw, None))
        if raw.get("complete") is not True:
            failures.append(f"{operation['caseId']}:incomplete")
            abort = "incomplete-receipt"
            break

    cleanup = _recover(plan, execute, budget, attempted)
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
        "cleanup": cleanup,
        "budget": {
            "observationCeiling": len(operations),
            "observationSpent": budget.spent,
            "recoveryCeiling": 3 * len(plan["ownedResources"]),
            "recoverySpent": budget.recovery_spent,
            "deadlineSeconds": float(deadline_seconds),
        },
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
) -> dict[str, Any]:
    """Version-bound cleanup of every resource whose creation was attempted.

    Deletion is only authorized by a readback that proves the resource exists
    with a concrete version. An absent resource is already recovered. An
    unreadable resource stays an open responsibility and is never force
    deleted.
    """
    steps: list[dict[str, Any]] = []
    outstanding: list[str] = []
    targets = [*plan["ownedResources"]]
    for resource in targets:
        readback = _cleanup_step(execute, budget, "readback", resource, None)
        steps.append(readback)
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
        delete = _cleanup_step(execute, budget, "delete", resource, version)
        steps.append(delete)
        absence = _cleanup_step(execute, budget, "absence", resource, None)
        steps.append(absence)
        absent = (absence.get("observed") or {}).get("documentPresent") is False
        if delete["failure"] is not None or not absent:
            outstanding.append(resource)
    unrecovered = [resource for resource in attempted if resource in outstanding]
    return {
        "steps": steps,
        "outstandingResources": outstanding,
        "unrecoveredAttempted": unrecovered,
        "cleanupComplete": not outstanding,
    }


def _cleanup_step(
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget,
    kind: str,
    resource: str,
    version: str | None,
) -> dict[str, Any]:
    request = {
        "kind": kind,
        "phase": "recovery",
        "resource": resource,
        "credentialRef": "administrator",
        "credentialClass": "administrator",
        "precondition": {"updateTime": version} if version is not None else None,
    }
    try:
        budget.take_recovery()
    except BudgetExhausted as error:
        return {"kind": kind, "resource": resource, "observed": None, "failure": str(error)}
    try:
        raw = execute(dict(request))
    except Exception as error:  # noqa: BLE001 - type name only, never a message
        return {
            "kind": kind,
            "resource": resource,
            "observed": None,
            "failure": f"transport:{type(error).__name__}",
        }
    if not isinstance(raw, Mapping):
        return {"kind": kind, "resource": resource, "observed": None, "failure": "invalid-receipt"}
    leaked = sorted(set(raw) & FORBIDDEN_RECEIPT_KEYS)
    if leaked:
        return {
            "kind": kind,
            "resource": resource,
            "observed": None,
            "failure": "credential-leak:" + ",".join(leaked),
        }
    if raw.get("complete") is not True:
        return {"kind": kind, "resource": resource, "observed": None, "failure": "incomplete"}
    return {
        "kind": kind,
        "resource": resource,
        "observed": {
            "documentPresent": raw.get("documentPresent"),
            "version": raw.get("version"),
            "status": raw.get("status"),
        },
        "failure": None,
    }
