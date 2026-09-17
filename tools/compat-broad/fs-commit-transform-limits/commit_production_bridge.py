"""Bounded transport adapter for the Commit transform campaign.

This module only admits compiler-produced Commit operations.  Admission and
the charged Gate callback belong to the caller; this adapter performs the
campaign-specific binding immediately before the transport call.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

from transform_compiler import MAX_TRANSFORMS, compile_plan

_FIELD_PATH = re.compile(r"t(?:0|[1-9][0-9]{0,2}|500)$")
_RESOURCE = re.compile(
    r"^projects/[A-Za-z0-9_-]+/databases/(?:\(default\)|[A-Za-z0-9_-]+)/"
    r"documents/oracle/[0-9a-f]{32}/commit-limits-03/(?:exact-500|over-501)$"
)


def _exact(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def request_digest(operation: dict[str, Any]) -> str:
    """Return the canonical digest used to bind a charged operation."""
    return hashlib.sha256(
        json.dumps(operation, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _commit_operations(plan: dict[str, Any]) -> list[dict[str, Any]]:
    operations = [
        operation
        for operation in plan.get("observation", [])
        if isinstance(operation, dict) and operation.get("kind") == "commit-transform"
    ]
    if len(operations) != 2:
        raise ValueError("compiler plan must contain exactly two Commit operations")
    resources = plan.get("ownedResources")
    if not isinstance(resources, list) or len(resources) != 2 or len(set(resources)) != 2:
        raise ValueError("compiler plan must contain two unique owned resources")
    if set(resources) != {
        operation.get("resources", [None])[0] for operation in operations
    }:
        raise ValueError("Commit resources differ from owned resource set")
    return operations


def _validate_compiler_plan(plan: dict[str, Any]) -> None:
    """Prove that the caller's frozen plan is the canonical compiler output."""
    if not isinstance(plan, dict):
        raise TypeError("compiler plan must be an object")
    try:
        canonical = compile_plan(plan["project"], plan["database"], plan["nonce"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("malformed compiler plan") from error
    if not _exact(plan, canonical):
        raise ValueError("compiler plan differs from canonical output")


def validate_commit_operation(plan: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    """Validate a Commit operation against the frozen compiler plan.

    All checks happen before the caller's transport callback is invoked.  The
    exact JSON comparison also rejects query strings, fragments, extra writes,
    type changes, field-path changes, and metadata flag drift.
    """
    if not isinstance(operation, dict):
        raise TypeError("Commit operation must be an object")
    expected_operations = _commit_operations(plan)
    expected = next((item for item in expected_operations if _exact(item, operation)), None)
    if expected is None:
        raise ValueError("Commit operation differs from frozen compiler plan")
    if (
        expected.get("service") != "firestore"
        or expected.get("method") != "POST"
        or not isinstance(expected.get("path"), str)
        or not expected["path"].startswith("/v1/projects/")
        or not expected["path"].endswith("/documents:commit")
        or "?" in expected["path"]
        or "#" in expected["path"]
        or expected.get("privileged") is not True
        or expected.get("form") is not False
    ):
        raise ValueError("invalid Commit route")
    body = expected.get("body")
    writes = body.get("writes") if isinstance(body, dict) else None
    if not isinstance(writes, list) or len(writes) != 2:
        raise ValueError("Commit must contain exactly two writes")
    owned = set(plan["ownedResources"])
    count = 0
    seen: set[str] = set()
    for write in writes:
        transform = write.get("transform") if isinstance(write, dict) else None
        target = transform.get("document") if isinstance(transform, dict) else None
        fields = transform.get("fieldTransforms") if isinstance(transform, dict) else None
        if target not in owned or not isinstance(fields, list):
            raise ValueError("Commit transform target is outside owned resources")
        for item in fields:
            field = item.get("fieldPath") if isinstance(item, dict) else None
            if not isinstance(field, str) or not _FIELD_PATH.fullmatch(field) or field in seen:
                raise ValueError("invalid or duplicate Commit field path")
            if set(item) != {"fieldPath", "increment"} or item["increment"] != {"integerValue": "1"}:
                raise ValueError("Commit transform literal differs")
            seen.add(field)
            count += 1
    expected_count = expected.get("transformCount")
    if count != expected_count or expected_count not in (MAX_TRANSFORMS, MAX_TRANSFORMS + 1):
        raise ValueError("Commit transform count differs")
    if any(not isinstance(resource, str) or _RESOURCE.fullmatch(resource) is None for resource in owned):
        raise ValueError("invalid owned resource")
    return copy.deepcopy(expected)


def classify_receipt(receipt: Any) -> dict[str, Any]:
    """Normalize a bounded wire receipt without inventing an error body."""
    if not isinstance(receipt, dict) or receipt.get("complete") is not True:
        failure = receipt.get("failure", "incomplete-wire") if isinstance(receipt, dict) else "invalid-wire-receipt"
        return {"classification": "indeterminate", "status": None, "body": None, "failure": failure}
    if receipt.get("failure") is not None:
        return {
            "classification": "indeterminate",
            "status": receipt.get("status"),
            "body": receipt.get("body"),
            "failure": "wire-failure",
        }
    status, body = receipt.get("status"), receipt.get("body")
    if type(status) is not int or not 100 <= status <= 599 or not isinstance(body, dict):
        return {"classification": "indeterminate", "status": status, "body": body, "failure": "invalid-complete-receipt"}
    try:
        json.dumps(body, allow_nan=False)
    except (TypeError, ValueError):
        return {"classification": "indeterminate", "status": status, "body": None, "failure": "invalid-complete-receipt"}
    if status == 429 or status >= 500:
        return {"classification": "indeterminate", "status": status, "body": body, "failure": "infrastructure-response"}
    return {"classification": "semantic", "status": status, "body": body, "failure": None}


class CommitProductionBridge:
    """A single campaign-bound send operation for an already-admitted callback."""

    def __init__(self, plan: dict[str, Any], *, transmit: Callable[[dict[str, Any]], Any]):
        self._plan = copy.deepcopy(plan)
        self._transmit = transmit
        _validate_compiler_plan(self._plan)
        _commit_operations(self._plan)

    @property
    def plan_digest(self) -> str:
        return request_digest(self._plan)

    def send(self, operation: dict[str, Any]) -> dict[str, Any]:
        bound = validate_commit_operation(self._plan, operation)
        return classify_receipt(self._transmit(bound))
