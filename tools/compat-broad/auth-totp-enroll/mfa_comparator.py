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
import re
from pathlib import Path
from typing import Any

from mfa_cases import CAMPAIGN_ID
from mfa_collector import digest, is_sensitive_key
from mfa_manifest import validate_campaign
from mfa_provenance import repository_root, verify_binding

CLASSIFICATIONS = (
    "MATCH",
    "DIFF",
    "EXPECTED_NONDETERMINISM",
    "PREPARATION_ONLY",
    "INDETERMINATE",
)
# Values that legitimately differ between two correct runs. These are exact field names,
# not substrings: a substring rule for "age" also swallows `message`, `stage`, `usage`,
# `language` and `storage`, which would erase a real difference in the service's error
# prose instead of reporting it.
_NONDETERMINISTIC = frozenset(
    {
        "localid",
        "uid",
        "email",
        "mfaenrollmentid",
        "enrollmentid",
        "enrolledat",
        "createdat",
        "recordedat",
        "startedat",
        "elapsedms",
        "elapsedseconds",
        "pendingageseconds",
        "sessionageseconds",
        "observedageseconds",
        "requestedat",
    }
)


def is_dynamic_key(key: str) -> bool:
    """Return True for fields that legitimately differ between two correct runs."""
    return key.lower() in _NONDETERMINISTIC


def _project(value: Any, key: str = "") -> Any:
    if key and is_sensitive_key(key):
        return "[REDACTED]"
    if key and is_dynamic_key(key):
        return f"[DYNAMIC:{type(value).__name__}]"
    if isinstance(value, dict):
        return {name: _project(item, name) for name, item in sorted(value.items())}
    if isinstance(value, list):
        return [_project(item, key) for item in value]
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _approval_problems(record: dict, campaign: Any) -> list[str]:
    """An executed production side has to carry approval bound to its own manifest."""
    if record.get("productionExecuted") is not True:
        return []
    approval = record.get("ownerApproval")
    if not isinstance(approval, dict):
        return ["production execution is asserted without owner approval evidence"]
    problems = []
    if (
        not isinstance(approval.get("approvedBy"), str)
        or not approval["approvedBy"].strip()
    ):
        problems.append("owner approval names no approver")
    if not isinstance(campaign, dict):
        problems.append("owner approval cannot be bound without a valid manifest")
        return problems
    if approval.get("manifestDigest") != digest(campaign):
        problems.append("owner approval is not bound to this manifest")
    if approval.get("nonceDigest") != campaign.get("owner", {}).get("nonceDigest"):
        problems.append("owner approval is not bound to this run's nonce")
    if approval.get("grant") != "one-run":
        problems.append("owner approval does not grant exactly one run")
    return problems


def _case_ids(campaign: Any) -> list[str]:
    if not isinstance(campaign, dict) or not isinstance(campaign.get("cases"), list):
        return []
    return [case.get("id") for case in campaign["cases"] if isinstance(case, dict)]


def _runtime_identity_problems(
    local: Any, expected: Any | None
) -> list[str]:
    """Validate local runtime bytes against an independently retained anchor.

    A receipt may self-report a well-formed digest, but that is not evidence that the
    executable which answered the requests had those bytes. The caller must supply the
    retained artifact/configuration anchor for a new final-artifact comparison.
    """
    identity = local.get("runtimeIdentity") if isinstance(local, dict) else None
    if not isinstance(identity, dict):
        return ["local runtime identity unavailable"]
    required = {"artifactSha256", "executionCommit", "configurationDigest", "runId"}
    if set(identity) != required:
        return ["local runtime identity shape is invalid"]

    def valid(value: Any, length: int) -> bool:
        return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None

    if (
        not valid(identity["artifactSha256"], 64)
        or not valid(identity["executionCommit"], 40)
        or not valid(identity["configurationDigest"], 64)
        or not isinstance(identity["runId"], str)
        or not identity["runId"]
    ):
        return ["local runtime identity digest is invalid"]
    if expected is None:
        return ["independent local runtime anchor required"]
    if not isinstance(expected, dict) or set(expected) != required:
        return ["independent local runtime anchor is invalid"]
    if (
        not valid(expected.get("artifactSha256"), 64)
        or not valid(expected.get("executionCommit"), 40)
        or not valid(expected.get("configurationDigest"), 64)
        or not isinstance(expected.get("runId"), str)
        or not expected["runId"]
    ):
        return ["independent local runtime anchor is invalid"]
    if identity != expected:
        return ["local runtime identity differs from independent anchor"]
    worktree = local.get("worktree")
    provenance = local.get("provenance")
    if not isinstance(worktree, dict) or identity["executionCommit"] != worktree.get("commit"):
        return ["local runtime source commit is not bound to worktree"]
    if not isinstance(provenance, dict) or not isinstance(provenance.get("digest"), str):
        return ["local source-input provenance unavailable"]
    recovery = local.get("recovery")
    if (
        not isinstance(recovery, dict)
        or not isinstance(recovery.get("runId"), str)
        or recovery.get("runId") != identity["runId"]
    ):
        return ["local runtime cleanup identity unavailable"]
    return []


def _without_owner(campaign: dict) -> dict:
    """The manifest minus the per-run owner block, which each side holds separately."""
    return {name: value for name, value in campaign.items() if name != "owner"}


def _receipt_problems(record: Any, side: str, root: Path) -> list[str]:
    problems: list[str] = []
    if not isinstance(record, dict):
        return ["receipt is not an object"]
    if record.get("campaignId") != CAMPAIGN_ID:
        problems.append("campaignId does not match")
    campaign = record.get("campaign")
    if not validate_campaign(campaign):
        problems.append(
            "the receipt carries no manifest that recompiles from this code"
        )
        campaign = None
    elif campaign["campaignId"] != CAMPAIGN_ID:
        problems.append("the receipt's manifest belongs to another campaign")
        campaign = None
    problems.extend(_approval_problems(record, campaign))
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
    expected_ids = _case_ids(campaign)
    if not expected_ids:
        problems.append("the receipt's manifest lists no cases to compare against")
    elif (
        not isinstance(rows, list)
        or [row.get("id") for row in rows if isinstance(row, dict)] != expected_ids
    ):
        problems.append("rows do not match the manifest's cases in order")
    else:
        for row in rows:
            status = row.get("status")
            if type(status) is not int:
                problems.append(f"row {row.get('id')} has a non-integer status")
            if row.get("outcome") not in {"observed", "skipped"}:
                problems.append(f"row {row.get('id')} has no typed outcome")
    if "requestBudget" in record:
        from mfa_request_budget import valid_summary
        if not valid_summary(record["requestBudget"], campaign, record.get("requestsCharged")):
            problems.append("transport request budget is incomplete or inconsistent")
    recovery = record.get("recovery")
    if not isinstance(recovery, dict):
        problems.append("recovery evidence is missing")
    else:
        if "creationResponsibility" in recovery:
            from mfa_persistence import complete_summary
            if not complete_summary(recovery["creationResponsibility"], recovery.get("ownedAccounts")):
                problems.append("creation responsibility is incomplete or inconsistent")
        if recovery.get("cleanupVerified") is not True:
            problems.append("cleanup was not verified")
        if (
            type(recovery.get("remainingOwnedResources")) is not int
            or recovery["remainingOwnedResources"] != 0
        ):
            problems.append("owned resources remain")
        if recovery.get("configurationRestored") is not True:
            problems.append("project configuration was not restored")
    return problems


def compare(
    local: Any,
    production: Any,
    root: Path | None = None,
    *,
    runtime_anchor: Any | None = None,
) -> dict[str, Any]:
    """Classify a local and a production receipt for this campaign."""
    root = repository_root() if root is None else Path(root)
    local_problems = _receipt_problems(local, "local", root)
    production_problems = _receipt_problems(production, "production", root)
    result: dict[str, Any] = {
        "campaignId": CAMPAIGN_ID,
        "localProblems": local_problems,
        "productionProblems": production_problems,
        "productionExecuted": bool(
            isinstance(production, dict)
            and production.get("productionExecuted") is True
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
    if result["productionExecuted"]:
        runtime_problems = _runtime_identity_problems(local, runtime_anchor)
        if runtime_problems:
            result["runtimeProblems"] = runtime_problems
            result["classification"] = "INDETERMINATE"
            result["reason"] = "local runtime artifact is not independently bound"
            result["normalizedDigest"] = _digest([_project(local), _project(production)])
            return result
    if local["provenance"] != production["provenance"]:
        result["classification"] = "INDETERMINATE"
        result["reason"] = "the two sides were recorded from different bound inputs"
        result["normalizedDigest"] = _digest([_project(local), _project(production)])
        return result
    if _without_owner(local["campaign"]) != _without_owner(production["campaign"]):
        result["classification"] = "INDETERMINATE"
        result["reason"] = "the two sides ran different manifests"
        result["normalizedDigest"] = _digest([_project(local), _project(production)])
        return result
    differences = []
    nondeterministic = []
    for left, right in zip(local["rows"], production["rows"], strict=True):
        if _project(left) != _project(right):
            differences.append(
                {
                    "id": left["id"],
                    "local": {
                        "status": left["status"],
                        "errorCode": left.get("errorCode"),
                    },
                    "production": {
                        "status": right["status"],
                        "errorCode": right.get("errorCode"),
                    },
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
        result["reason"] = f"{len(differences)} of {len(local['rows'])} rows differ"
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
