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
import hashlib
import json
from pathlib import Path
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


def _retention_fault(bundle: dict[str, Any]) -> str | None:
    """Refuse a side whose rows are not covered by retained wire bytes."""
    raw = bundle.get("raw")
    dispatched = [
        row
        for row in bundle["rows"] + bundle["cleanup"]["rows"]
        if isinstance(row, dict) and row.get("status") != "skipped"
    ]
    if not isinstance(raw, dict) or not dispatched:
        return "unbound-retention"
    if raw.get("complete") is not True or raw.get("bindings") != len(dispatched):
        return "raw-bindings-below-dispatched-rows"
    if any((row.get("raw") or {}).get("present") is not True for row in dispatched):
        return "unretained-dispatched-row"
    return None


def _production_claim_fault(bundle: dict[str, Any]) -> str | None:
    """A bundle collected from the local artifact can never claim production."""
    if (
        bundle.get("productionExecuted") is True
        and bundle.get("target") == "owned-local-artifact"
    ):
        return "local-artifact-claims-production"
    return None


def verify_retained_bytes(bundle: dict[str, Any], directory: str | Path) -> list[str]:
    """Re-read each sidecar and bind it to the decoded body it stands for.

    The original response bytes are the comparison authority, so a decoded body
    that the retained bytes do not reproduce disqualifies its row.
    """
    faults = []
    root = Path(directory) / "raw"
    for row in bundle["rows"] + bundle["cleanup"]["rows"]:
        binding = row.get("raw") or {}
        if row.get("status") == "skipped" or binding.get("present") is not True:
            continue
        path = root / str(binding.get("path"))
        try:
            payload = path.read_bytes()
        except OSError:
            faults.append(f"{row['phase']}-{row['index']}:unreadable")
            continue
        if hashlib.sha256(payload).hexdigest() != binding.get("sha256"):
            faults.append(f"{row['phase']}-{row['index']}:digest")
            continue
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            faults.append(f"{row['phase']}-{row['index']}:undecodable")
            continue
        if decoded != (row.get("receipt") or {}).get("body"):
            faults.append(f"{row['phase']}-{row['index']}:body-differs-from-bytes")
    return faults


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


def compare_evidence(
    production: Any,
    local: Any,
    *,
    production_directory: str | Path | None = None,
    local_directory: str | Path | None = None,
) -> dict[str, Any]:
    """Compare two retained bundles; the result is semantic evidence only.

    When a retained directory is supplied for a side, every dispatched row is
    re-bound to its sidecar bytes before any row is compared.
    """
    production_plan, local_plan = _plan_for(production), _plan_for(local)
    if production_plan is None or local_plan is None:
        return _indeterminate("unbound-bundle")
    for side in (production, local):
        fault = _retention_fault(side) or _production_claim_fault(side)
        if fault:
            return _indeterminate(fault)
    for side, directory in (
        (production, production_directory),
        (local, local_directory),
    ):
        if directory is not None and verify_retained_bytes(side, directory):
            return _indeterminate("retained-bytes-disagree-with-receipt")
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
