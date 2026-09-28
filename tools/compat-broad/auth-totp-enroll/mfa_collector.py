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

import copy
import hashlib
import json
import math
import re
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
        if any(not isinstance(name, str) for name in value):
            raise ValueError("observation keys must be strings")
        return any(_contains_sensitive(item, name) for name, item in value.items())
    if isinstance(value, list):
        return any(_contains_sensitive(item, key) for item in value)
    return False


def selected_case_ids(plan: dict[str, Any]) -> list[str]:
    """Return the manifest-bound denominator; callers cannot supply an arbitrary filter."""
    selector = plan.get("selector")
    if selector is None:
        return [case["id"] for case in observation_cases()]
    if not isinstance(selector, dict) or selector.get("name") != "pending-age-300-v1":
        raise ValueError("unsupported MFA selector")
    expected = [
        "age-300s-start",
        "age-300s-finalize",
        "age-300s-same-account-fresh-control",
    ]
    if selector.get("caseIds") != expected:
        raise ValueError("selected MFA case denominator differs")
    return expected


# Checkpoints are private diagnostic state, never authority to perform a request.
MAX_CHECKPOINT_BYTES = 2 * 1024 * 1024


def _number(value: Any) -> float:
    if type(value) not in (int, float):
        raise ValueError("time must be a finite non-negative number")
    try:
        converted = float(value)
    except OverflowError:
        raise ValueError("time must be a finite non-negative number") from None
    if not math.isfinite(converted) or converted < 0:
        raise ValueError("time must be a finite non-negative number")
    return converted


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_state(state: Any) -> None:
    """Validate this schema's full case denominator; a self-hash is not enough."""
    required = {
        "schema",
        "campaignId",
        "nonce",
        "planDigest",
        "startedAt",
        "deadline",
        "maxRequests",
        "requests",
        "steps",
        "ownedResources",
        "aborted",
        "abortReason",
    }
    if not isinstance(state, dict) or set(state) not in (
        required,
        required | {"selectedCaseIds"},
    ):
        raise ValueError("invalid collector state fields")
    if state["schema"] != SCHEMA or state["campaignId"] != CAMPAIGN_ID:
        raise ValueError("invalid collector identity")
    for name in ("nonce", "planDigest"):
        if not isinstance(state[name], str) or not re.fullmatch(
            r"[0-9a-f]{64}", state[name]
        ):
            raise ValueError("invalid collector binding")
    start, deadline = _number(state["startedAt"]), _number(state["deadline"])
    if deadline <= start:
        raise ValueError("invalid collector deadline")
    if (
        type(state["maxRequests"]) is not int
        or state["maxRequests"] < 1
        or type(state["requests"]) is not int
        or state["requests"] < 0
    ):
        raise ValueError("invalid collector request count")
    if type(state["aborted"]) is not bool:
        raise ValueError("invalid collector abort flag")
    if (state["aborted"] and not _nonempty(state["abortReason"])) or (
        not state["aborted"] and state["abortReason"] is not None
    ):
        raise ValueError("invalid collector abort reason")
    steps = state["steps"]
    selected = state.get("selectedCaseIds")
    expected = (
        selected
        if selected is not None
        else [case["id"] for case in observation_cases()]
    )
    if selected is not None and selected != [
        "age-300s-start",
        "age-300s-finalize",
        "age-300s-same-account-fresh-control",
    ]:
        raise ValueError("selected collector denominator differs")
    if not isinstance(steps, list) or len(steps) != len(expected):
        raise ValueError("collector cases are missing or duplicated")
    for step, identifier in zip(steps, expected, strict=True):
        if not isinstance(step, dict) or step.get("id") != identifier:
            raise ValueError("collector case identity or order differs")
        status = step.get("status")
        if status not in {"pending", "done", "skipped"}:
            raise ValueError("invalid collector step status")
        fields = {"id", "status", "dueAt", "observation"}
        if status != "pending":
            fields.add("recordedAt")
        if set(step) != fields:
            raise ValueError("invalid collector step fields")
        if step["dueAt"] is not None and _number(step["dueAt"]) < start:
            raise ValueError("invalid collector due time")
        if status == "pending":
            if step["observation"] is not None:
                raise ValueError("pending step contains an observation")
        else:
            if _number(step["recordedAt"]) < start or not isinstance(
                step["observation"], dict
            ):
                raise ValueError("invalid recorded observation")
            if (
                status == "done"
                and step["dueAt"] is not None
                and step["recordedAt"] < step["dueAt"]
            ):
                raise ValueError("observation predates its scheduled due time")
            assert_no_sensitive_material(step["observation"])
            if status == "skipped" and (
                set(step["observation"]) != {"skippedReason"}
                or not _nonempty(step["observation"]["skippedReason"])
            ):
                raise ValueError("invalid skipped observation")
    resources = state["ownedResources"]
    if not isinstance(resources, list):
        raise TypeError("invalid owned resources")
    ids = set()
    for resource in resources:
        if not isinstance(resource, dict) or set(resource) != {
            "kind",
            "id",
            "createdAt",
            "deleted",
            "absenceVerified",
        }:
            raise ValueError("invalid owned resource shape")
        if (
            not _nonempty(resource["kind"])
            or not _nonempty(resource["id"])
            or resource["id"] in ids
        ):
            raise ValueError("invalid or duplicate owned resource")
        ids.add(resource["id"])
        if _number(resource["createdAt"]) < start:
            raise ValueError("invalid resource creation time")
        if (
            type(resource["deleted"]) is not bool
            or type(resource["absenceVerified"]) is not bool
        ):
            raise ValueError("invalid cleanup flag")
        if resource["absenceVerified"] and not resource["deleted"]:
            raise ValueError("absence without deletion acknowledgement")
    # Reject unsupported/non-finite Python values before creating private checkpoint bytes.
    _canonical(state)


def initial_state(plan: dict[str, Any], now: float) -> dict[str, Any]:
    """Build the starting state for one run of `plan`."""
    if not isinstance(plan, dict) or plan.get("campaignId") != CAMPAIGN_ID:
        raise ValueError("plan does not belong to this campaign")
    limits = plan["limits"]
    start = _number(now)
    wall = _number(limits["maxWallSeconds"])
    if wall <= 0 or type(limits["maxRequests"]) is not int or limits["maxRequests"] < 1:
        raise ValueError("positive typed collector bounds required")
    deadline = _number(start + wall)
    if deadline <= start:
        raise ValueError("unrepresentable collector deadline")
    state = {
        "schema": SCHEMA,
        "campaignId": CAMPAIGN_ID,
        "nonce": plan["owner"]["nonceDigest"],
        "planDigest": digest(plan),
        "startedAt": start,
        "deadline": deadline,
        "maxRequests": limits["maxRequests"],
        "requests": 0,
        "steps": [
            {"id": identifier, "status": "pending", "dueAt": None, "observation": None}
            for identifier in selected_case_ids(plan)
        ],
        "ownedResources": [],
        "aborted": False,
        "abortReason": None,
    }
    if plan.get("selector") is not None:
        state["selectedCaseIds"] = selected_case_ids(plan)
    return state


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
        if not (resource["deleted"] is True and resource["absenceVerified"] is True)
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
    try:
        now = _number(now)
        if now < state["startedAt"]:
            raise ValueError("clock precedes start")
    except ValueError:
        _abort(state, "invalid-clock")
        raise BudgetError("collector clock is invalid") from None
    if not state["aborted"]:
        if state["requests"] > state["maxRequests"] or (
            state["requests"] == state["maxRequests"]
            and any(step["status"] == "pending" for step in state["steps"])
        ):
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
    created_at = _number(now)
    if (
        created_at < state["startedAt"]
        or not _nonempty(kind)
        or not _nonempty(identifier)
    ):
        raise ValueError("invalid owned resource")
    for resource in state["ownedResources"]:
        if resource["id"] == identifier:
            if resource["kind"] != kind:
                raise ValueError("resource kind changed")
            return
    state["ownedResources"].append(
        {
            "kind": kind,
            "id": identifier,
            "createdAt": created_at,
            "deleted": False,
            "absenceVerified": False,
        }
    )


def mark_deleted(
    state: dict[str, Any], identifier: str, absence_verified: bool
) -> None:
    """Mark one owned resource deleted; absence has to be proved separately."""
    if type(absence_verified) is not bool:
        raise ValueError("absence evidence must be boolean")
    for resource in state["ownedResources"]:
        if resource["id"] == identifier:
            resource["deleted"] = True
            resource["absenceVerified"] = absence_verified
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
    if type(requests) is not int or requests < 0:
        raise ValueError("request charge must be a non-negative integer")
    recorded_at = _number(now)
    if recorded_at < state["startedAt"] or not isinstance(observation, dict):
        raise ValueError("invalid observation or recording time")
    assert_no_sensitive_material(observation)
    # Freeze the observation; a caller must not mutate a previously accepted record.
    _canonical(observation)
    recorded = copy.deepcopy(observation)
    step = _step(state, step_id)
    if step["status"] != "pending":
        raise BudgetError(f"step already resolved: {step_id}")
    if step["dueAt"] is not None and recorded_at < step["dueAt"]:
        raise ValueError("observation predates its scheduled due time")
    if schedule is not None and not isinstance(schedule, dict):
        raise ValueError("schedule must be an object")
    changes = []
    for dependent, due_at in (schedule or {}).items():
        target = _step(state, dependent)
        due = _number(due_at)
        if target is step or target["status"] != "pending" or due < recorded_at:
            raise ValueError("invalid dependent schedule")
        if target["dueAt"] is not None and target["dueAt"] != due:
            raise ValueError("dependent was already scheduled")
        changes.append((target, due))
    # Commit only after every input and dependent has been validated.
    step["status"] = "done"
    step["observation"] = recorded
    step["recordedAt"] = recorded_at
    state["requests"] += requests
    for target, due in changes:
        target["dueAt"] = due
    if state["requests"] > state["maxRequests"]:
        _abort(state, "request-budget-exhausted")
    elif recorded_at > state["deadline"]:
        # Keep a late response and its charge, but never turn it into a completed run.
        _abort(state, "wall-budget-exhausted")
    return state


def skip_step(
    state: dict[str, Any], step_id: str, reason: str, now: float
) -> dict[str, Any]:
    """Resolve a step that a refused precondition makes unobservable."""
    if state["aborted"]:
        raise BudgetError(f"run aborted: {state['abortReason']}")
    recorded_at = _number(now)
    if recorded_at < state["startedAt"] or not _nonempty(reason):
        raise ValueError("invalid skipped step")
    step = _step(state, step_id)
    if step["status"] != "pending":
        raise BudgetError(f"step already resolved: {step_id}")
    step["status"] = "skipped"
    step["observation"] = {"skippedReason": reason}
    step["recordedAt"] = recorded_at
    if recorded_at > state["deadline"]:
        _abort(state, "wall-budget-exhausted")
    return state


def checkpoint_bytes(state: dict[str, Any]) -> bytes:
    """Serialize well-formed private state. A digest is not authentication."""
    try:
        _validate_state(state)
        result = _canonical({"state": state, "checkpointDigest": digest(state)})
        if len(result) > MAX_CHECKPOINT_BYTES:
            raise ValueError("checkpoint exceeds local limit")
        return result
    except (ValueError, TypeError, KeyError, RecursionError, SensitiveMaterialError):
        raise CheckpointError("checkpoint state is invalid") from None


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate checkpoint member")
        result[name] = value
    return result


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite checkpoint number")
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite checkpoint number")


def load_checkpoint(
    data: bytes, *, plan: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Read a complete schema, optionally bound to the caller's independently held plan.

    Even a valid, plan-bound checkpoint is private state, not current resource/ownership
    evidence and not authorization to delete resources after a restart.
    """
    try:
        if not isinstance(data, bytes) or len(data) > MAX_CHECKPOINT_BYTES:
            raise ValueError("invalid checkpoint bytes")
        loaded = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (TypeError, ValueError, RecursionError):
        raise CheckpointError("checkpoint is not unambiguous UTF-8 JSON") from None
    if not isinstance(loaded, dict) or set(loaded) != {"state", "checkpointDigest"}:
        raise CheckpointError("checkpoint has an unexpected shape")
    state = loaded["state"]
    try:
        if digest(state) != loaded["checkpointDigest"]:
            raise CheckpointError("checkpoint digest does not match its contents")
        _validate_state(state)
        if plan is not None:
            expected = initial_state(plan, state["startedAt"])
            for field in (
                "campaignId",
                "nonce",
                "planDigest",
                "maxRequests",
                "deadline",
                "selectedCaseIds",
            ):
                if state.get(field) != expected.get(field):
                    raise CheckpointError("checkpoint does not match the expected plan")
    except (ValueError, TypeError, KeyError, RecursionError, SensitiveMaterialError):
        raise CheckpointError("checkpoint state is invalid") from None
    return state


def run_complete(state: dict[str, Any]) -> bool:
    """A full case denominator, no abort, typed cleanup and a bounded charge are required."""
    try:
        _validate_state(state)
    except (ValueError, TypeError, KeyError, RecursionError, SensitiveMaterialError):
        return False
    return (
        state["aborted"] is False
        and all(step["status"] in {"done", "skipped"} for step in state["steps"])
        and all(step["recordedAt"] <= state["deadline"] for step in state["steps"])
        and cleanup_complete(state)
        and state["requests"] <= state["maxRequests"]
    )
