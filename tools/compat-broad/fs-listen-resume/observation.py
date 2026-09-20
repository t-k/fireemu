"""Comparator contract for FS-LISTEN-SDK observation receipts.

This is a separate schema and API from the offline preparation comparator in
`comparator.py`. That module always answers `PREPARATION_ONLY`; this one can
answer `MATCH`, but only when both receipts carry acquisition evidence that a
self-reported preparation ledger cannot fabricate:

* the receipt binds the frozen campaign digest and the case catalog digest;
* the collector and adapter sources are bound by path-specific SHA-256 digests
  that are recomputed from the files on disk, not copied from the receipt;
* the production receipt names the campaign permission and carries a transport
  timeline with connect, disconnect and reconnect timestamps;
* every case row reports collector-counted events, invariant results, listener
  shutdown and typed cleanup outcomes.

A missing or unproven element yields `INDETERMINATE`, never `MATCH`.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from . import cases
from .campaign import STATUS_PREPARED, campaign_digest, validate_campaign
from .manifest import digest

SCHEMA = "o6-listen-observation-v1"
COMPARISON_SCHEMA = "o6-listen-observation-comparison-v1"

MATCH = "MATCH"
SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"
INDETERMINATE = "INDETERMINATE"
REFUSED = "REFUSED"

# Sources whose bytes the comparator recomputes before trusting any receipt.
BOUND_SOURCES = (
    "tools/compat-broad/fs-listen-resume/listen_collector.mjs",
    "tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs",
    "tools/compat-broad/fs-listen-resume/listen_journal.mjs",
    "tools/compat-broad/fs-listen-resume/cases.py",
    "tools/compat-broad/fs-listen-resume/campaign.py",
    "tools/compat-broad/fs-listen-resume/observation.py",
)

# The same vocabulary the collector's redactor strips, so the producing and the
# admitting side cannot disagree about what counts as a secret.
FORBIDDEN_KEY = re.compile(
    r"password|secret|id[_-]?token|access[_-]?token|refresh[_-]?token|bearer"
    r"|authorization|api[_-]?key|credential|assertion",
    re.IGNORECASE,
)
BEARER_VALUE = re.compile(r"^(Bearer\s|ey[A-Za-z0-9_-]{10,}\.)")
REDACTED = "[redacted]"

_LOCAL_ENVIRONMENTS = ("local-fireemu",)
_PRODUCTION_ENVIRONMENTS = ("production-oracle",)


def compute_source_digests(base_dir: str | Path) -> dict[str, str]:
    """Recompute the bound source digests from the working tree."""
    root = Path(base_dir)
    result: dict[str, str] = {}
    for relative in BOUND_SOURCES:
        path = root / relative
        result[relative] = (
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file()
            else "missing"
        )
    return result


def _contains_forbidden(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if FORBIDDEN_KEY.search(str(key)) and item not in (None, REDACTED):
                return True
            if _contains_forbidden(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    if isinstance(value, str):
        return bool(BEARER_VALUE.match(value))
    return False


def _timeline_errors(timeline: Any) -> list[str]:
    if not isinstance(timeline, list) or not timeline:
        return ["transport-timeline-missing"]
    kinds = []
    previous = None
    for entry in timeline:
        if not isinstance(entry, dict):
            return ["transport-timeline-shape"]
        stamp = entry.get("atMs")
        if not isinstance(stamp, int) or (previous is not None and stamp < previous):
            return ["transport-timeline-unordered"]
        previous = stamp
        kinds.append(entry.get("kind"))
    required = {"connect", "disconnect", "reconnect"}
    missing = sorted(required - set(kinds))
    return [f"transport-timeline-missing:{name}" for name in missing]


def receipt_errors(
    campaign: dict[str, Any],
    receipt: Any,
    *,
    side: str,
    base_dir: str | Path,
) -> list[str]:
    """Structural admission for one receipt. It never inspects agreement."""
    errors: list[str] = []
    if not isinstance(receipt, dict):
        return ["receipt-shape"]
    if receipt.get("schema") != SCHEMA:
        errors.append("receipt-schema")
    if receipt.get("campaignDigest") != campaign_digest(campaign):
        errors.append("campaign-binding")
    if receipt.get("catalogDigest") != cases.catalog_digest():
        errors.append("catalog-binding")

    expected_sources = compute_source_digests(base_dir)
    declared = receipt.get("sourceDigests")
    if not isinstance(declared, dict) or not expected_sources:
        errors.append("source-digests-missing")
    elif declared != expected_sources:
        errors.append("source-digest-drift")

    executed = receipt.get("productionExecuted")
    environment = receipt.get("environment")
    kind = environment.get("kind") if isinstance(environment, dict) else None
    if side == "local":
        if executed is not False:
            errors.append("local-claims-production")
        if kind not in _LOCAL_ENVIRONMENTS:
            errors.append("local-environment")
    else:
        if executed is not True:
            errors.append("production-not-executed")
        if kind not in _PRODUCTION_ENVIRONMENTS:
            errors.append("production-environment")
        if receipt.get("permission") != campaign.get("permission") or not receipt.get(
            "permission"
        ):
            errors.append("permission-binding")
        if campaign.get("status") != STATUS_PREPARED:
            errors.append("campaign-not-prepared")
        errors.extend(_timeline_errors(receipt.get("transportTimeline")))
        if receipt.get("sdkResolved") != campaign.get("sdk"):
            errors.append("sdk-resolved-drift")

    budget = receipt.get("budget")
    if not isinstance(budget, dict) or budget.get("exhausted") is not False:
        errors.append("budget-unproven")
    cleanup = receipt.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("complete") is not True:
        errors.append("cleanup-unproven")
    if receipt.get("complete") is not True:
        errors.append("receipt-incomplete")

    rows = receipt.get("cases")
    if not isinstance(rows, list) or not rows:
        errors.append("cases-missing")
    else:
        observed_ids = [row.get("caseId") for row in rows if isinstance(row, dict)]
        if observed_ids != list(cases.case_ids()):
            errors.append("case-coverage")
    if _contains_forbidden(receipt):
        errors.append("secret-material")
    return sorted(set(errors))


def _normalize_event(event: Any, compared_fields: tuple[str, ...]) -> dict[str, Any]:
    """Project one event onto the fields this case compares.

    A case whose listener did not request metadata changes drops `fromCache`
    and `hasPendingWrites`: the values are recorded in the receipt but reflect
    delivery timing rather than a semantic difference.
    """
    if not isinstance(event, dict):
        return {"invalid": True}
    return {field: event.get(field) for field in compared_fields}


def _row_by_id(receipt: dict[str, Any], case_id: str) -> dict[str, Any] | None:
    for row in receipt.get("cases", []):
        if isinstance(row, dict) and row.get("caseId") == case_id:
            return row
    return None


def _compare_case(case: dict[str, Any], left: Any, right: Any) -> dict[str, Any]:
    row = {
        "caseId": case["caseId"],
        "role": case["role"],
        "comparison": case["comparison"],
        "classification": INDETERMINATE,
        "reasons": [],
    }
    if left is None or right is None:
        row["reasons"] = ["case-not-observed"]
        return row
    reasons: list[str] = []
    for side, record in (("local", left), ("production", right)):
        if record.get("complete") is not True:
            reasons.append(f"{side}-incomplete")
        if record.get("listenersClosed") is not True:
            reasons.append(f"{side}-listener-leak")
        if record.get("invariantViolations"):
            reasons.append(f"{side}-invariant-violation")
        if not record.get("observed") and case["expectedLocal"]:
            reasons.append(f"{side}-no-events")
    if reasons:
        row["reasons"] = sorted(set(reasons))
        return row
    compared_fields = tuple(case["comparedFields"])
    left_events = [
        _normalize_event(event, compared_fields) for event in left["observed"]
    ]
    right_events = [
        _normalize_event(event, compared_fields) for event in right["observed"]
    ]
    if left_events == right_events:
        row["classification"] = MATCH
        return row
    row["classification"] = SEMANTIC_MISMATCH
    row["reasons"] = ["event-sequence-differs"]
    row["localDigest"] = digest(left_events)
    row["productionDigest"] = digest(right_events)
    return row


def compare_observations(
    campaign: dict[str, Any],
    local: Any,
    production: Any,
    *,
    base_dir: str | Path,
) -> dict[str, Any]:
    """Compare a local fireemu receipt against a production oracle receipt."""
    result: dict[str, Any] = {
        "schema": COMPARISON_SCHEMA,
        "caseId": campaign.get("caseId") if isinstance(campaign, dict) else None,
        "classification": INDETERMINATE,
        "acquisitionValidated": False,
        "promotionReady": False,
        "errors": [],
        "rows": [],
        "unobservedPaths": [],
    }
    if not validate_campaign(campaign):
        result["classification"] = REFUSED
        result["errors"] = ["campaign-invalid"]
        return result
    result["unobservedPaths"] = [entry["path"] for entry in campaign["unobservedPaths"]]

    errors = [
        f"local:{name}"
        for name in receipt_errors(campaign, local, side="local", base_dir=base_dir)
    ]
    if production is None:
        errors.append("production:not-observed")
    else:
        errors.extend(
            f"production:{name}"
            for name in receipt_errors(
                campaign, production, side="production", base_dir=base_dir
            )
        )
    if errors:
        result["errors"] = sorted(set(errors))
        result["rows"] = [
            {
                "caseId": case_id,
                "classification": INDETERMINATE,
                "reasons": ["admission-failed"],
            }
            for case_id in cases.case_ids()
        ]
        return result

    result["acquisitionValidated"] = True
    rows = [
        _compare_case(
            case,
            _row_by_id(local, case["caseId"]),
            _row_by_id(production, case["caseId"]),
        )
        for case in cases.CASES
    ]
    result["rows"] = rows
    classifications = {row["classification"] for row in rows}
    if classifications == {MATCH}:
        result["classification"] = MATCH
        result["promotionReady"] = True
    elif SEMANTIC_MISMATCH in classifications:
        result["classification"] = SEMANTIC_MISMATCH
    else:
        result["classification"] = INDETERMINATE
    return result
