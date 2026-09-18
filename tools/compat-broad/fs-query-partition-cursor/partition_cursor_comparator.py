"""Offline comparator for two retained partition/cursor bundles.

Each side is validated against a plan recompiled from its own recorded identity,
so a production run and a local run with different nonces can still be compared.
Only the compiled owned identities, opaque pagination tokens and server-assigned
timestamps are canonicalized; Firestore Value types, query shapes, document order
and typed error objects stay exact. The result is semantic only and never marks
acquisition validated or a promotion ready.
"""

from __future__ import annotations

import copy
from typing import Any

from partition_cursor_case import CAMPAIGN, compile_plan

TIMESTAMP_KEYS = frozenset({"createTime", "updateTime", "readTime", "commitTime"})
TOKEN_KEYS = frozenset({"pageToken", "nextPageToken"})
RESPONSE_DERIVED_SKIPS = frozenset(
    {
        "no-page-token",
        "range-not-required",
        "reconstruction-slots-exceeded",
        "no-partition-response",
        "malformed-partition-cursor",
    }
)
_DISPATCHED = frozenset({"pass", "mismatch"})


def _plan_for(bundle: Any) -> dict[str, Any] | None:
    if not isinstance(bundle, dict) or bundle.get("campaignId") != CAMPAIGN:
        return None
    try:
        plan = compile_plan(
            bundle.get("project"), bundle.get("database"), bundle.get("nonce")
        )
    except (TypeError, ValueError):
        return None
    if (
        plan["planDigest"] != bundle.get("planDigest")
        or plan["ownedScope"] != bundle.get("ownedScope")
        or plan["groupCollection"] != bundle.get("groupCollection")
    ):
        return None
    cleanup = bundle.get("cleanup")
    if (
        not isinstance(bundle.get("rows"), list)
        or len(bundle["rows"]) != len(plan["observation"])
        or not isinstance(cleanup, dict)
        or not isinstance(cleanup.get("rows"), list)
        or len(cleanup["rows"]) != len(plan["recovery"])
    ):
        return None
    return plan


def _canonical(value: Any, plan: dict[str, Any], key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            name: _canonical(item, plan, name) for name, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [_canonical(item, plan) for item in value]
    if isinstance(value, str):
        if key in TIMESTAMP_KEYS:
            # No compiled case in this set asserts a time relation. A future case
            # that does must compare these values exactly instead.
            return "<timestamp>"
        if key in TOKEN_KEYS:
            return "<token>"
        return (
            value.replace(plan["ownedScope"], "<scope>")
            .replace(plan["groupCollection"], "<group>")
            .replace(plan["databaseRoot"], "<database>")
        )
    return value


def _comparable(row: dict[str, Any]) -> dict[str, Any]:
    """Keep the semantic receipt members; byte counts and content-type parameters
    differ between a production endpoint and a local artifact by construction."""
    receipt = row.get("receipt")
    if not isinstance(receipt, dict):
        return {"request": row.get("request"), "receipt": receipt}
    media = receipt.get("contentType")
    return {
        "request": row.get("request"),
        "receipt": {
            "status": receipt.get("status"),
            "complete": receipt.get("complete"),
            "contentType": media.split(";")[0].strip().lower()
            if isinstance(media, str)
            else media,
            "body": receipt.get("body"),
        },
    }


def _row_pair(
    left: Any, right: Any, left_plan: dict[str, Any], right_plan: dict[str, Any]
) -> tuple[str, bool]:
    """Classify one slot as equivalent, mismatching or indeterminate."""
    if not isinstance(left, dict) or not isinstance(right, dict):
        return "INDETERMINATE", False
    if left.get("kind") != right.get("kind"):
        return "INDETERMINATE", False
    states = (left.get("status"), right.get("status"))
    if any(state not in _DISPATCHED and state != "skipped" for state in states):
        return "INDETERMINATE", False
    if states == ("skipped", "skipped"):
        if left.get("skipReason") == right.get("skipReason"):
            return "EQUIVALENT", False
        reasons = {left.get("skipReason"), right.get("skipReason")}
        return (
            "SEMANTIC_MISMATCH"
            if reasons <= RESPONSE_DERIVED_SKIPS
            else "INDETERMINATE"
        ), False
    if "skipped" in states:
        reason = left.get("skipReason") or right.get("skipReason")
        return (
            "SEMANTIC_MISMATCH" if reason in RESPONSE_DERIVED_SKIPS else "INDETERMINATE"
        ), False
    comparable_left, comparable_right = _comparable(left), _comparable(right)
    if _canonical(comparable_left, left_plan) != _canonical(
        comparable_right, right_plan
    ):
        return "SEMANTIC_MISMATCH", False
    return "EQUIVALENT", comparable_left != comparable_right


def _indeterminate(reason: str) -> dict[str, Any]:
    return {
        "kind": "fs-query-partition-cursor-comparison-v1",
        "campaignId": CAMPAIGN,
        "classification": "INDETERMINATE",
        "reason": reason,
        "rows": 0,
        "nondeterministic": 0,
        "differences": [],
        "acquisitionValidated": False,
        "promotionReady": False,
        "productionExecuted": False,
    }


def compare_evidence(production: Any, local: Any) -> dict[str, Any]:
    """Compare two retained bundles; the result is semantic evidence only."""
    production_plan, local_plan = _plan_for(production), _plan_for(local)
    if production_plan is None or local_plan is None:
        return _indeterminate("unbound-bundle")
    executed = any(
        side.get("productionExecuted") is True for side in (production, local)
    )
    differences: list[dict[str, Any]] = []
    nondeterministic = 0
    indeterminate = False
    compared = 0
    pairs = list(zip(production["rows"], local["rows"])) + list(
        zip(production["cleanup"]["rows"], local["cleanup"]["rows"])
    )
    for left, right in pairs:
        verdict, verbatim = _row_pair(left, right, production_plan, local_plan)
        compared += 1
        nondeterministic += int(verbatim)
        if verdict == "EQUIVALENT":
            continue
        indeterminate = indeterminate or verdict == "INDETERMINATE"
        differences.append(
            {
                "phase": left.get("phase") if isinstance(left, dict) else None,
                "index": left.get("index") if isinstance(left, dict) else None,
                "kind": left.get("kind") if isinstance(left, dict) else None,
                "classification": verdict,
            }
        )
    if indeterminate:
        classification = "INDETERMINATE"
    elif differences:
        classification = "SEMANTIC_MISMATCH"
    else:
        classification = "EQUIVALENT"
    return {
        "kind": "fs-query-partition-cursor-comparison-v1",
        "campaignId": CAMPAIGN,
        "classification": classification,
        "reason": None,
        "rows": compared,
        "nondeterministic": nondeterministic,
        "differences": copy.deepcopy(differences),
        "acquisitionValidated": False,
        "promotionReady": False,
        "productionExecuted": executed,
    }
