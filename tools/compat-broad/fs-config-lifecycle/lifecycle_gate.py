"""Typed configuration gate for the FS-CONFIG-LIFECYCLE collector.

The shared Gate in `tools/compat-broad/shared_gate.py` charges document campaigns: it
refuses a plan that owns no document and proves cleanup by typed document absence.
This campaign owns no document; it owns two field configurations that must be put
back exactly as they were. This gate keeps the shared Gate's discipline for that
shape: a private journal under a file lock, every request charged before it is sent,
an absolute deadline per request, a recovery reserve the observation phase cannot
spend, a bounded receipt or a stop, and a locked step per configuration change whose
pre-value digest, post-value digest and restore status are the run's evidence.

It grants nothing. The shared Ledger reservation and the private credential handoff
remain the authority; this file only refuses to let a run exceed what they admitted.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import math
import os
import time
from pathlib import Path

from .cases import EXECUTION_ORDER, NONCE_PATTERN, locked_steps
from .manifest import (
    HARD_CEILING_MICROUSD,
    MAX_OPERATIONS,
    MAX_REQUESTS,
    MAX_WALL_SECONDS,
    POLL_ATTEMPTS,
    POLL_BACKOFF_SECONDS,
    POLL_DEADLINE_SECONDS,
    RECOVERY_RESERVE_SECONDS,
    REQUEST_ALLOWANCE_MICROUSD,
    REQUEST_SLOT_SECONDS,
)
from .surface_matrix import CASE_ID, digest

PLAN_KIND = "fs-config-lifecycle-gate-plan-v1"
LEDGER_JOB = "configuration"
PHASES = ("observation", "recovery")
MAX_RECEIPT_BYTES = 256 * 1024
LOCK_WAIT_SECONDS = 15

# The restore states one locked step can be in. Only the first three are terminal
# states a finished run may carry; the others hold the reservation.
NOT_APPLIED = "not-applied"
APPLY_REFUSED = "apply-refused"
RESTORED = "restored"
APPLIED = "applied"
APPLY_UNCERTAIN = "apply-uncertain"
UNVERIFIED = "unverified"
REVERT_REFUSED = "revert-refused"
REVERT_NOT_ATTEMPTED = "revert-not-attempted"
REVERT_UNCERTAIN = "revert-uncertain"
RESTORE_STATES = (
    NOT_APPLIED,
    APPLY_REFUSED,
    RESTORED,
    APPLIED,
    APPLY_UNCERTAIN,
    UNVERIFIED,
    REVERT_REFUSED,
    REVERT_NOT_ATTEMPTED,
    REVERT_UNCERTAIN,
)
FINISHED_STATES = frozenset({NOT_APPLIED, APPLY_REFUSED, RESTORED})


def gate_plan(
    nonce: str, *, baseline_projection_digest: str, permission_expires_at=None
):
    """The bounded shape of one run, every figure taken from the manifest."""
    if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
    if (
        not isinstance(baseline_projection_digest, str)
        or len(baseline_projection_digest) != 64
    ):
        raise ValueError("frozen baseline projection digest required")
    plan = {
        "kind": PLAN_KIND,
        "campaignId": CASE_ID,
        "nonce": nonce,
        "maxRequests": MAX_REQUESTS,
        "wallSeconds": MAX_WALL_SECONDS,
        "recoverySeconds": RECOVERY_RESERVE_SECONDS,
        "requestSlotSeconds": REQUEST_SLOT_SECONDS,
        "pollDeadlineSeconds": POLL_DEADLINE_SECONDS,
        "pollAttempts": POLL_ATTEMPTS,
        "pollBackoffSeconds": list(POLL_BACKOFF_SECONDS),
        "maxOperations": MAX_OPERATIONS,
        "requestCostMicrousd": REQUEST_ALLOWANCE_MICROUSD,
        "costCeilingMicrousd": HARD_CEILING_MICROUSD,
        "executionOrder": list(EXECUTION_ORDER),
        "steps": [
            {key: step[key] for key in ("id", "resource", "lockKey", "lockMode")}
            for step in locked_steps(nonce)
        ],
        "baselineProjectionDigest": baseline_projection_digest,
        # The shared Ledger reads a Gate-shaped projection when it reserves: one job
        # that owns no document and dispatches no data slot, the request ceiling as
        # the observation allowance, and the admission cost. These keys make the one
        # plan the Ledger binds and the plan this gate journals the same bytes.
        "jobs": {LEDGER_JOB: {"resources": [], "observation": [], "recovery": []}},
        "observationRequests": MAX_REQUESTS,
        "costMicrousd": MAX_REQUESTS * REQUEST_ALLOWANCE_MICROUSD,
    }
    if permission_expires_at is not None:
        plan["permissionExpiresAt"] = permission_expires_at
    return plan


def _positive(value) -> bool:
    return (
        type(value) in (int, float)
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def validate_plan(plan) -> None:
    if not isinstance(plan, dict) or plan.get("kind") != PLAN_KIND:
        raise ValueError("configuration gate plan required")
    required = {
        "kind",
        "campaignId",
        "nonce",
        "maxRequests",
        "wallSeconds",
        "recoverySeconds",
        "requestSlotSeconds",
        "pollDeadlineSeconds",
        "pollAttempts",
        "pollBackoffSeconds",
        "maxOperations",
        "requestCostMicrousd",
        "costCeilingMicrousd",
        "executionOrder",
        "steps",
        "baselineProjectionDigest",
        "jobs",
        "observationRequests",
        "costMicrousd",
    }
    if not required <= set(plan) or set(plan) - required - {"permissionExpiresAt"}:
        raise ValueError("configuration gate plan required")
    if (
        plan["campaignId"] != CASE_ID
        or not isinstance(plan["nonce"], str)
        or NONCE_PATTERN.fullmatch(plan["nonce"]) is None
        or type(plan["maxRequests"]) is not int
        or plan["maxRequests"] <= 0
        or not _positive(plan["wallSeconds"])
        or not _positive(plan["recoverySeconds"])
        or not plan["recoverySeconds"] < plan["wallSeconds"] <= 1200
        or not _positive(plan["requestSlotSeconds"])
        or plan["requestSlotSeconds"] > plan["recoverySeconds"]
        or not _positive(plan["pollDeadlineSeconds"])
        or type(plan["pollAttempts"]) is not int
        or plan["pollAttempts"] <= 0
        or type(plan["maxOperations"]) is not int
        or plan["maxOperations"] <= 0
        or type(plan["requestCostMicrousd"]) is not int
        or plan["requestCostMicrousd"] <= 0
        or type(plan["costCeilingMicrousd"]) is not int
        or plan["maxRequests"] * plan["requestCostMicrousd"]
        > plan["costCeilingMicrousd"]
        or plan["jobs"]
        != {LEDGER_JOB: {"resources": [], "observation": [], "recovery": []}}
        or plan["observationRequests"] != plan["maxRequests"]
        or plan["costMicrousd"] != plan["maxRequests"] * plan["requestCostMicrousd"]
        or plan["executionOrder"] != list(EXECUTION_ORDER)
        or not isinstance(plan["steps"], list)
        or not plan["steps"]
        or not isinstance(plan["baselineProjectionDigest"], str)
        or len(plan["baselineProjectionDigest"]) != 64
    ):
        raise ValueError("invalid configuration gate allocation")
    expected = [
        {key: step[key] for key in ("id", "resource", "lockKey", "lockMode")}
        for step in locked_steps(plan["nonce"])
    ]
    if plan["steps"] != expected:
        raise ValueError("gate steps differ from the nonce-owned locked steps")
    if "permissionExpiresAt" in plan and not _positive(plan["permissionExpiresAt"]):
        raise ValueError("invalid configuration gate allocation")


def _save(path: Path, state: dict) -> None:
    encoded = json.dumps(state, sort_keys=True, allow_nan=False).encode()
    temporary = path / "state.json.tmp"
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path / "state.json")
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def create(path, plan) -> None:
    """Create one private gate directory for a validated plan; never reuse one."""
    validate_plan(plan)
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    (path / "lock").touch(mode=0o600, exist_ok=False)
    state = {
        "plan": plan,
        "planDigest": digest(plan),
        "started": time.monotonic(),
        "phase": "observation",
        "total": 0,
        "observation": 0,
        "recovery": 0,
        "costMicrousd": 0,
        "operationsSeen": 0,
        "stopped": False,
        "stopReason": None,
        "credentialRejected": False,
        "coordinatorPid": os.getpid(),
        "inflight": False,
        "events": [],
        "steps": {
            step["id"]: {
                "resource": step["resource"],
                "restore": NOT_APPLIED,
                "preDigest": None,
                "preBodyRef": None,
                "appliedOperation": None,
                "postDigest": None,
                "revertOperation": None,
                "revertAttempts": 0,
                "verifyDigest": None,
                "refusal": None,
            }
            for step in plan["steps"]
        },
        "reconciliation": None,
        "complete": False,
    }
    _save(path, state)


def _valid_receipt(receipt) -> bool:
    if not isinstance(receipt, dict) or set(receipt) - {"raw"} != {
        "status",
        "body",
        "complete",
        "failure",
    }:
        return False
    status, complete, failure = (
        receipt["status"],
        receipt["complete"],
        receipt["failure"],
    )
    if type(complete) is not bool:
        return False
    if failure is not None and (not isinstance(failure, str) or not failure):
        return False
    if status is None:
        if complete:
            return False
    elif (
        type(status) is not int or isinstance(status, bool) or not 100 <= status <= 599
    ):
        return False
    raw = receipt.get("raw")
    if raw is not None and (not isinstance(raw, bytes) or len(raw) > MAX_RECEIPT_BYTES):
        return False
    try:
        encoded = json.dumps(receipt["body"], allow_nan=False).encode()
    except (TypeError, ValueError):
        return False
    return len(encoded) <= MAX_RECEIPT_BYTES


class ConfigurationGate:
    """One run's charged journal and locked-step ledger."""

    def __init__(self, path) -> None:
        self.path = Path(path)
        self.plan_digest = self.snapshot()["planDigest"]

    @contextlib.contextmanager
    def locked(self):
        if (
            self.path.is_symlink()
            or self.path.stat().st_mode & 0o077
            or any((self.path / name).is_symlink() for name in ("lock", "state.json"))
        ):
            raise ValueError("private regular gate files required")
        with (self.path / "lock").open("r+") as stream:
            wait_until = time.monotonic() + LOCK_WAIT_SECONDS
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= wait_until:
                        raise ValueError("gate lock deadline") from None
                    time.sleep(0.01)
            state = json.loads((self.path / "state.json").read_bytes())
            if digest(state["plan"]) != state["planDigest"] or state[
                "planDigest"
            ] != getattr(self, "plan_digest", state["planDigest"]):
                raise ValueError("gate plan changed")
            yield state

    def snapshot(self) -> dict:
        with self.locked() as state:
            return state

    @property
    def plan(self) -> dict:
        return self.snapshot()["plan"]

    def _phase_deadline(self, state, phase):
        plan = state["plan"]
        reserve = plan["recoverySeconds"] if phase == "observation" else 0
        return state["started"] + plan["wallSeconds"] - reserve

    def charge(self, phase, request, send) -> dict:
        """Debit one request before its bounded transport runs.

        `send(deadline)` receives the absolute monotonic deadline and returns a bounded
        receipt `{status, body, complete, failure[, raw]}`. A refusal here is a typed
        stop: the request bound, the observation wall, the cost ceiling, the owner's
        permission expiry and a stopped observation phase are all checked under the
        journal lock, so a request that would exceed any of them is never sent.
        """
        if phase not in PHASES or not isinstance(request, dict):
            raise ValueError("closed gate phase and request required")
        with self.locked() as state:
            plan = state["plan"]
            if state["complete"] or state["inflight"]:
                raise ValueError("gate is complete or in flight")
            if state["coordinatorPid"] != os.getpid():
                raise ValueError("gate belongs to another coordinator")
            if phase == "observation" and (
                state["stopped"] or state["phase"] != "observation"
            ):
                raise ValueError("observation stopped")
            if phase == "recovery" and state["phase"] != "recovery":
                raise ValueError("recovery not begun")
            if state["total"] >= plan["maxRequests"]:
                self._refuse(state, "request-bound", "request bound reached")
            cost = plan["requestCostMicrousd"]
            if state["costMicrousd"] + cost > plan["costCeilingMicrousd"]:
                self._refuse(state, "cost-ceiling", "cost ceiling reached")
            now = time.monotonic()
            seconds = plan["requestSlotSeconds"]
            if now + seconds > self._phase_deadline(state, phase):
                self._refuse(state, f"{phase}-wall", f"{phase} wall exhausted")
            expires = plan.get("permissionExpiresAt")
            if expires is not None and time.time() + seconds > expires:
                self._refuse(
                    state,
                    "permission-expiry",
                    "owner permission expires before the request",
                )
            deadline = min(now + seconds, self._phase_deadline(state, phase))
            event = {
                "index": len(state["events"]),
                "phase": phase,
                "case": request.get("case"),
                "role": request.get("role"),
                "method": request.get("method"),
                "path": request.get("path"),
                "requestDigest": digest(request),
                "started": now,
                "deadline": deadline,
                "completed": False,
                "status": None,
                "responseDigest": None,
                "failure": None,
            }
            state["events"].append(event)
            state["total"] += 1
            state[phase] += 1
            state["costMicrousd"] += cost
            state["inflight"] = True
            _save(self.path, state)
            try:
                receipt = send(deadline)
                if not _valid_receipt(receipt):
                    raise ValueError("bounded configuration receipt required")
                ended = time.monotonic()
                status = receipt["status"]
                event.update(
                    status=status,
                    responseDigest=digest(receipt["body"]),
                    failure=receipt["failure"],
                    ended=ended,
                    completed=bool(receipt["complete"] and ended <= deadline),
                )
                if status in (401, 403):
                    state["credentialRejected"] = True
                    self._stop(state, "credential-refused")
                if not event["completed"] and not state["stopped"]:
                    self._stop(state, receipt["failure"] or "incomplete-receipt")
                state["inflight"] = False
                _save(self.path, state)
                return receipt
            except BaseException as error:
                event["failure"] = type(error).__name__[:80]
                event["ended"] = time.monotonic()
                state["inflight"] = False
                self._stop(state, "transport-" + type(error).__name__[:60])
                _save(self.path, state)
                raise

    def _stop(self, state, reason) -> None:
        if not state["stopped"]:
            state["stopped"] = True
            state["stopReason"] = str(reason)[:128]

    def _refuse(self, state, reason, message) -> None:
        """A bound refusal is journaled before it is raised, so it is never silent."""
        self._stop(state, reason)
        _save(self.path, state)
        raise ValueError(message)

    def stop(self, reason) -> None:
        with self.locked() as state:
            self._stop(state, reason)
            _save(self.path, state)

    def begin_recovery(self) -> None:
        """Enter the recovery phase; allowed after a stop, and exactly once."""
        with self.locked() as state:
            if state["phase"] != "observation":
                raise ValueError("recovery already begun")
            state["phase"] = "recovery"
            _save(self.path, state)

    def count_operation(self) -> None:
        with self.locked() as state:
            if state["operationsSeen"] >= state["plan"]["maxOperations"]:
                self._stop(state, "operation-bound")
                _save(self.path, state)
                raise ValueError("operation bound reached")
            state["operationsSeen"] += 1
            _save(self.path, state)

    def record_step(self, step_id, **fields) -> dict:
        """Update one locked step under the lock; restore states are closed."""
        with self.locked() as state:
            step = state["steps"].get(step_id)
            if step is None:
                raise ValueError("unknown locked step")
            unknown = set(fields) - (set(step) - {"resource"})
            if unknown:
                raise ValueError(f"unknown locked step fields: {sorted(unknown)}")
            restore = fields.get("restore", step["restore"])
            if restore not in RESTORE_STATES:
                raise ValueError("closed restore state required")
            if step["restore"] in FINISHED_STATES and step["restore"] != NOT_APPLIED:
                raise ValueError("locked step already terminal")
            step.update(fields)
            _save(self.path, state)
            return dict(step)

    def record_reconciliation(self, record) -> None:
        with self.locked() as state:
            if not isinstance(record, dict) or type(record.get("ok")) is not bool:
                raise ValueError("typed reconciliation record required")
            state["reconciliation"] = record
            _save(self.path, state)

    def unrestored(self) -> list[str]:
        with self.locked() as state:
            return [
                name
                for name, step in state["steps"].items()
                if step["restore"] not in FINISHED_STATES
            ]

    def finish(self) -> None:
        """Mark the run terminal only when every locked step is back at its baseline."""
        with self.locked() as state:
            if state["inflight"] or state["phase"] != "recovery":
                raise ValueError("finish requires a quiet recovery phase")
            unrestored = [
                name
                for name, step in state["steps"].items()
                if step["restore"] not in FINISHED_STATES
            ]
            if unrestored:
                raise ValueError(f"restore incomplete: {unrestored}")
            reconciliation = state["reconciliation"]
            if (
                not isinstance(reconciliation, dict)
                or reconciliation.get("ok") is not True
            ):
                raise ValueError("reconciliation incomplete")
            state["complete"] = True
            _save(self.path, state)
