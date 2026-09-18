"""A bounded, resumable collector state machine for the next MFA campaign.

The collector never sleeps. A step that must wait for a pending credential or an
enrollment session to age returns a `WAIT` action carrying the instant it becomes due;
the caller writes the checkpoint, leaves, and calls back later. Resuming from the
checkpoint reproduces the same decision, so a wall-clock wait is a file on disk rather
than a blocked process.

Budgets are enforced here rather than described: exceeding the request or wall-clock
budget latches an abort, and an aborted run still has to finish its cleanup contract
before it is allowed to report completion.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mfa_cases import CAMPAIGN_ID, observation_cases

SCHEMA = "o2-mfa-collector-v1"
ACTIONS = ("RUN", "WAIT", "CLEANUP", "DONE")
# A bare "code" substring would also swallow `errorCode`, which is the field the whole
# comparison rests on, so the policy is exact names plus unambiguous substrings.
_SENSITIVE_KEY_PARTS = (
    "secret",
    "password",
    "token",
    "credential",
    "verifier",
    "otp",
    "sessioninfo",
)
_SENSITIVE_KEY_NAMES = frozenset(
    {"code", "verificationcode", "smscode", "session", "pin"}
)


def is_sensitive_key(key: str) -> bool:
    """Return True when a field name names secret or credential material."""
    lowered = key.lower()
    return lowered in _SENSITIVE_KEY_NAMES or any(
        part in lowered for part in _SENSITIVE_KEY_PARTS
    )


class CheckpointError(RuntimeError):
    """Raised when a checkpoint is missing, malformed, or altered."""


class SensitiveMaterialError(RuntimeError):
    """Raised when an observation would record secret or credential material."""


class BudgetError(RuntimeError):
    """Raised when a caller tries to act after the collector latched an abort."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def assert_no_sensitive_material(value: Any, what: str = "observation") -> None:
    """Refuse a structure that names secret or credential material, before it is stored."""
    if _contains_sensitive(value):
        raise SensitiveMaterialError(
            f"{what} must not carry secret or credential material"
        )


def _contains_sensitive(value: Any, key: str = "") -> bool:
    if key and is_sensitive_key(key):
        return True
    if isinstance(value, dict):
        return any(_contains_sensitive(item, name) for name, item in value.items())
    if isinstance(value, list):
        return any(_contains_sensitive(item, key) for item in value)
    return False


def initial_state(plan: dict[str, Any], now: float) -> dict[str, Any]:
    """Build the starting state for one run of `plan`."""
    if plan.get("campaignId") != CAMPAIGN_ID:
        raise ValueError("plan does not belong to this campaign")
    limits = plan["limits"]
    return {
        "schema": SCHEMA,
        "campaignId": CAMPAIGN_ID,
        "nonce": plan["owner"]["nonceDigest"],
        "planDigest": digest(plan),
        "startedAt": float(now),
        "deadline": float(now) + float(limits["maxWallSeconds"]),
        "maxRequests": int(limits["maxRequests"]),
        "requests": 0,
        "steps": [
            {"id": case["id"], "status": "pending", "dueAt": None, "observation": None}
            for case in observation_cases()
        ],
        "ownedResources": [],
        "aborted": False,
        "abortReason": None,
    }


def _step(state: dict[str, Any], step_id: str) -> dict[str, Any]:
    for step in state["steps"]:
        if step["id"] == step_id:
            return step
    raise KeyError(f"unknown step: {step_id}")


def _abort(state: dict[str, Any], reason: str) -> None:
    if not state["aborted"]:
        state["aborted"] = True
        state["abortReason"] = reason


def outstanding_cleanup(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the owned resources that still need deletion or absence proof."""
    return [
        resource
        for resource in state["ownedResources"]
        if not (resource["deleted"] and resource["absenceVerified"])
    ]


def cleanup_complete(state: dict[str, Any]) -> bool:
    """Cleanup is complete only when every owned resource is deleted and proved absent."""
    return outstanding_cleanup(state) == []


def next_action(state: dict[str, Any], now: float) -> dict[str, Any]:
    """Decide the next action without blocking or sleeping.

    This is not a pure inspection: a request or wall-clock budget that has already been
    exceeded is latched here, so asking a run that outlived its deadline what to do next
    aborts it. That is deliberate, because an expired run must not be resumable, but it
    means a caller cannot use this to peek at a stale checkpoint without consequence.
    """
    now = float(now)
    if not state["aborted"]:
        if state["requests"] > state["maxRequests"]:
            _abort(state, "request-budget-exhausted")
        elif now > state["deadline"]:
            _abort(state, "wall-budget-exhausted")
    if state["aborted"]:
        if cleanup_complete(state):
            return {"action": "DONE", "stepId": None, "dueAt": None, "aborted": True}
        return {
            "action": "CLEANUP",
            "stepId": None,
            "dueAt": None,
            "aborted": True,
            "outstanding": [resource["id"] for resource in outstanding_cleanup(state)],
        }
    for step in state["steps"]:
        if step["status"] != "pending":
            continue
        due_at = step["dueAt"]
        if due_at is not None and due_at > now:
            return {
                "action": "WAIT",
                "stepId": step["id"],
                "dueAt": due_at,
                "waitSeconds": due_at - now,
                "aborted": False,
            }
        return {
            "action": "RUN",
            "stepId": step["id"],
            "dueAt": due_at,
            "aborted": False,
        }
    if not cleanup_complete(state):
        return {
            "action": "CLEANUP",
            "stepId": None,
            "dueAt": None,
            "aborted": False,
            "outstanding": [resource["id"] for resource in outstanding_cleanup(state)],
        }
    return {"action": "DONE", "stepId": None, "dueAt": None, "aborted": False}


def register_owned(
    state: dict[str, Any], kind: str, identifier: str, now: float
) -> None:
    """Record a resource this run created, before it can be lost."""
    if any(resource["id"] == identifier for resource in state["ownedResources"]):
        return
    state["ownedResources"].append(
        {
            "kind": kind,
            "id": identifier,
            "createdAt": float(now),
            "deleted": False,
            "absenceVerified": False,
        }
    )


def mark_deleted(
    state: dict[str, Any], identifier: str, absence_verified: bool
) -> None:
    """Mark one owned resource deleted; absence has to be proved separately."""
    for resource in state["ownedResources"]:
        if resource["id"] == identifier:
            resource["deleted"] = True
            resource["absenceVerified"] = bool(absence_verified)
            return
    raise KeyError(f"unknown owned resource: {identifier}")


def record_step(
    state: dict[str, Any],
    step_id: str,
    observation: dict[str, Any],
    now: float,
    schedule: dict[str, float] | None = None,
    requests: int = 1,
) -> dict[str, Any]:
    """Store one observation, charge the request budget, and schedule dependent steps."""
    if state["aborted"]:
        raise BudgetError(f"run aborted: {state['abortReason']}")
    if _contains_sensitive(observation):
        raise SensitiveMaterialError(
            "observations must not carry secret or credential material"
        )
    step = _step(state, step_id)
    if step["status"] != "pending":
        raise BudgetError(f"step already resolved: {step_id}")
    step["status"] = "done"
    step["observation"] = observation
    step["recordedAt"] = float(now)
    state["requests"] += int(requests)
    for dependent, due_at in (schedule or {}).items():
        _step(state, dependent)["dueAt"] = float(due_at)
    if state["requests"] > state["maxRequests"]:
        _abort(state, "request-budget-exhausted")
    return state


def skip_step(
    state: dict[str, Any], step_id: str, reason: str, now: float
) -> dict[str, Any]:
    """Resolve a step that a refused precondition makes unobservable."""
    if state["aborted"]:
        raise BudgetError(f"run aborted: {state['abortReason']}")
    step = _step(state, step_id)
    if step["status"] != "pending":
        raise BudgetError(f"step already resolved: {step_id}")
    step["status"] = "skipped"
    step["observation"] = {"skippedReason": reason}
    step["recordedAt"] = float(now)
    return state


def checkpoint_bytes(state: dict[str, Any]) -> bytes:
    """Serialize a resumable checkpoint with a digest over its own contents."""
    return _canonical({"state": state, "checkpointDigest": digest(state)})


def load_checkpoint(data: bytes) -> dict[str, Any]:
    """Load a checkpoint, refusing anything altered since it was written."""
    try:
        loaded = json.loads(data)
    except (TypeError, ValueError) as error:
        raise CheckpointError("checkpoint is not JSON") from error
    if not isinstance(loaded, dict) or set(loaded) != {"state", "checkpointDigest"}:
        raise CheckpointError("checkpoint has an unexpected shape")
    state = loaded["state"]
    if not isinstance(state, dict) or state.get("schema") != SCHEMA:
        raise CheckpointError("checkpoint does not hold a collector state")
    if digest(state) != loaded["checkpointDigest"]:
        raise CheckpointError("checkpoint digest does not match its contents")
    return state


def run_complete(state: dict[str, Any]) -> bool:
    """A run is complete when every step is resolved, cleanup is proved, and no abort latched."""
    return (
        not state["aborted"]
        and all(step["status"] in {"done", "skipped"} for step in state["steps"])
        and cleanup_complete(state)
        and state["requests"] <= state["maxRequests"]
    )
