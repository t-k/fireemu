"""Comparator contract for AUTH-MFA-AGE-TOTP-01.

The earlier preparation comparator could not say anything because its source binding was
whatever the caller wrote into the receipt. This one recomputes the binding from the
worktree it runs in, so a receipt either matches the code that is actually present or it
does not. That makes a real classification possible without inventing provenance.

Agreement still requires a production side that says it was executed. A preparation
receipt carries `productionExecuted=false`, so no preparation input can reach `MATCH`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mfa_cases import CAMPAIGN_ID, CASE_IDS
from mfa_provenance import repository_root, verify_binding

CLASSIFICATIONS = (
    "MATCH",
    "DIFF",
    "EXPECTED_NONDETERMINISM",
    "PREPARATION_ONLY",
    "INDETERMINATE",
)
_SENSITIVE = (
    "secret",
    "otp",
    "code",
    "password",
    "token",
    "session",
    "credential",
    "verifier",
)
# Values that legitimately differ between two correct runs.
_NONDETERMINISTIC = ("localid", "uid", "email", "enrollmentid", "enrolledat", "elapsed", "age")


def _project(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(part in lowered for part in _SENSITIVE):
        return "[REDACTED]"
    if any(part in lowered for part in _NONDETERMINISTIC):
        return f"[DYNAMIC:{type(value).__name__}]"
    if isinstance(value, dict):
        return {name: _project(item, name) for name, item in sorted(value.items())}
    if isinstance(value, list):
        return [_project(item, key) for item in value]
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _receipt_problems(record: Any, side: str, root: Path) -> list[str]:
    problems: list[str] = []
    if not isinstance(record, dict):
        return ["receipt is not an object"]
    if record.get("campaignId") != CAMPAIGN_ID:
        problems.append("campaignId does not match")
    if record.get("side") != side:
        problems.append(f"side is not {side}")
    if record.get("recordingComplete") is not True:
        problems.append("recording is incomplete")
    if not verify_binding(record.get("provenance"), root):
        problems.append("provenance does not match the worktree")
    worktree = record.get("worktree")
    if not isinstance(worktree, dict) or worktree.get("resolved") is not True:
        problems.append("worktree identity is unresolved")
    elif worktree.get("clean") is not True:
        problems.append("worktree was not clean when the run was recorded")
    rows = record.get("rows")
    if not isinstance(rows, list) or [
        row.get("id") for row in rows if isinstance(row, dict)
    ] != list(CASE_IDS):
        problems.append("rows are missing, reordered, or duplicated")
    else:
        for row in rows:
            status = row.get("status")
            if type(status) is not int:
                problems.append(f"row {row.get('id')} has a non-integer status")
            if row.get("outcome") not in {"observed", "skipped"}:
                problems.append(f"row {row.get('id')} has no typed outcome")
    recovery = record.get("recovery")
    if not isinstance(recovery, dict):
        problems.append("recovery evidence is missing")
    else:
        if recovery.get("cleanupVerified") is not True:
            problems.append("cleanup was not verified")
        if type(recovery.get("remainingOwnedResources")) is not int or recovery[
            "remainingOwnedResources"
        ] != 0:
            problems.append("owned resources remain")
        if recovery.get("configurationRestored") is not True:
            problems.append("project configuration was not restored")
    return problems


def compare(local: Any, production: Any, root: Path | None = None) -> dict[str, Any]:
    """Classify a local and a production receipt for this campaign."""
    root = repository_root() if root is None else Path(root)
    local_problems = _receipt_problems(local, "local", root)
    production_problems = _receipt_problems(production, "production", root)
    result: dict[str, Any] = {
        "campaignId": CAMPAIGN_ID,
        "localProblems": local_problems,
        "productionProblems": production_problems,
        "productionExecuted": bool(
            isinstance(production, dict) and production.get("productionExecuted") is True
        ),
        "rowDifferences": [],
    }
    if local is production:
        result["classification"] = "INDETERMINATE"
        result["reason"] = "a receipt cannot be compared against itself"
        result["normalizedDigest"] = _digest([_project(local), _project(production)])
        return result
    if local_problems or production_problems:
        result["classification"] = "INDETERMINATE"
        result["reason"] = "at least one receipt is incomplete or unbound"
        result["normalizedDigest"] = _digest([_project(local), _project(production)])
        return result
    if local["provenance"] != production["provenance"]:
        result["classification"] = "INDETERMINATE"
        result["reason"] = "the two sides were recorded from different bound inputs"
        result["normalizedDigest"] = _digest([_project(local), _project(production)])
        return result
    differences = []
    nondeterministic = []
    for left, right in zip(local["rows"], production["rows"], strict=True):
        if _project(left) != _project(right):
            differences.append(
                {
                    "id": left["id"],
                    "local": {"status": left["status"], "errorCode": left.get("errorCode")},
                    "production": {"status": right["status"], "errorCode": right.get("errorCode")},
                }
            )
        elif left != right:
            nondeterministic.append(left["id"])
    result["rowDifferences"] = differences
    result["nondeterministicRows"] = nondeterministic
    result["normalizedDigest"] = _digest([_project(local), _project(production)])
    if not result["productionExecuted"]:
        result["classification"] = "PREPARATION_ONLY"
        result["reason"] = (
            "no production observation exists; a bound pair of preparation receipts cannot "
            "become agreement"
        )
        return result
    if differences:
        result["classification"] = "DIFF"
        result["reason"] = f"{len(differences)} of {len(CASE_IDS)} rows differ"
        return result
    if nondeterministic:
        result["classification"] = "EXPECTED_NONDETERMINISM"
        result["reason"] = (
            f"{len(nondeterministic)} rows differ only in redacted or dynamic values"
        )
        return result
    result["classification"] = "MATCH"
    result["reason"] = "every row agrees under the declared projection"
    return result
