"""Comparison contract for the AUTH-CREDENTIAL token and session-cookie campaign.

The contract classifies rows; it never approves them. `parityEstablished` is always
false here, because a classification is an input to review, not the result of one.

Three rules carry most of the weight:

* The local runtime issues unsigned emulator tokens while production issues signed ones.
  A trust-root difference is therefore expected and is never a semantic difference. The
  roots observed on each side are reported separately so review can see them.
* The same-second revocation boundary is classified `EXPECTED_NONDETERMINISM` unless both
  sides recorded that they pinned the boundary from server-reported values. A run that
  could not pin it observed something real but not the boundary.
* The boundary row means nothing unless its neighbouring controls held. A refusal below
  and an acceptance above are what place the boundary; without them the boundary row is
  `INDETERMINATE` however the two sides happened to agree.
"""

from __future__ import annotations

import copy
from typing import Any

from credential_cases import CAMPAIGN_ID, case_by_id, observation_cases
from credential_collector import is_secret_key

CONTRACT = "auth-credential-tokens-v1"

CLASSIFICATIONS = ("MATCH", "DIFFERENT", "EXPECTED_NONDETERMINISM", "INDETERMINATE")

#: Row members excluded from semantic equality: they describe how a token was trusted,
#: which differs between an unsigned local runtime and signed production.
TRUST_MEMBERS = ("trustRoot", "algorithm")

#: Row members that record absolute server-reported values. Two services never agree on
#: a wall-clock second, so these are retained for review and excluded from equality.
DIAGNOSTIC_MEMBERS = ("diagnostics", "boundarySeconds")


def _carries_credential_material(node: Any, key: str = "") -> bool:
    if key and is_secret_key(key) and isinstance(node, str):
        return True
    if isinstance(node, dict):
        return any(_carries_credential_material(v, k) for k, v in node.items())
    if isinstance(node, list):
        return any(_carries_credential_material(v, key) for v in node)
    return False


def _receipt_reason(receipt: Any, side: str) -> str | None:
    """Return why this receipt cannot be compared, or None when it can."""
    if not isinstance(receipt, dict):
        return "malformed-receipt"
    if receipt.get("side") != side:
        return "side-mismatch"
    if _carries_credential_material(receipt):
        return "credential-material-present"
    if receipt.get("recordingComplete") is not True:
        return "incomplete-recording"
    cleanup = receipt.get("cleanup")
    if (
        not isinstance(cleanup, dict)
        or cleanup.get("cleanupComplete") is not True
        or cleanup.get("remainingAccounts") != 0
    ):
        return "incomplete-cleanup"
    rows = receipt.get("rows")
    expected = [case["id"] for case in observation_cases()]
    if (
        not isinstance(rows, list)
        or [r.get("caseId") if isinstance(r, dict) else None for r in rows] != expected
    ):
        return "row-set-mismatch"
    return None


def _pair_reason(local: Any, production: Any) -> str | None:
    for receipt, side in ((local, "local"), (production, "production")):
        reason = _receipt_reason(receipt, side)
        if reason is not None:
            return reason
    binding = local.get("collectorBinding")
    if (
        not isinstance(binding, dict)
        or not binding
        or binding != production.get("collectorBinding")
    ):
        return "collector-binding-mismatch"
    if production.get("productionExecuted") is not True:
        return "production-unobserved"
    if local.get("productionExecuted") is True:
        return "local-side-claims-production"
    return None


def _semantic(row: dict[str, Any]) -> dict[str, Any]:
    """The part of a row that is compared: everything but trust and pinning members."""
    dropped = {*TRUST_MEMBERS, *DIAGNOSTIC_MEMBERS, "boundaryPinned"}
    return {k: v for k, v in row.items() if k not in dropped}


def _trust_roots(receipt: dict[str, Any]) -> list[str]:
    roots = {
        row.get("trustRoot")
        for row in receipt["rows"]
        if isinstance(row.get("trustRoot"), str)
    }
    return sorted(roots)


def compare(local: Any, production: Any) -> dict[str, Any]:
    """Classify a local and production receipt pair without claiming parity."""
    case_ids = [case["id"] for case in observation_cases()]
    reason = (
        _pair_reason(local, production)
        if isinstance(local, dict) and isinstance(production, dict)
        else "malformed-receipt"
    )
    if reason is not None:
        return _report(
            {case_id: "INDETERMINATE" for case_id in case_ids},
            reason=reason,
            compared=False,
            trust_roots=None,
        )

    left = {row["caseId"]: copy.deepcopy(row) for row in local["rows"]}
    right = {row["caseId"]: copy.deepcopy(row) for row in production["rows"]}
    classes: dict[str, str] = {}
    for case_id in case_ids:
        case = case_by_id(case_id)
        agree = _semantic(left[case_id]) == _semantic(right[case_id])
        if case["nondeterminism"] == "SAME_SECOND_BOUNDARY":
            pinned = (
                left[case_id].get("boundaryPinned") is True
                and right[case_id].get("boundaryPinned") is True
            )
            classes[case_id] = (
                ("MATCH" if agree else "DIFFERENT")
                if pinned
                else "EXPECTED_NONDETERMINISM"
            )
        else:
            classes[case_id] = "MATCH" if agree else "DIFFERENT"

    # A boundary row is only readable while the controls that place the boundary held.
    for case in observation_cases():
        controls = case.get("boundaryControls")
        if controls and any(
            classes[control] != "MATCH" for control in controls.values()
        ):
            classes[case["id"]] = "INDETERMINATE"

    return _report(
        classes,
        reason="classified",
        compared=True,
        trust_roots={
            "local": _trust_roots(local),
            "production": _trust_roots(production),
        },
    )


def _report(
    classes: dict[str, str],
    *,
    reason: str,
    compared: bool,
    trust_roots: dict[str, list[str]] | None,
) -> dict[str, Any]:
    counts = {
        "match": sum(1 for value in classes.values() if value == "MATCH"),
        "different": sum(1 for value in classes.values() if value == "DIFFERENT"),
        "expectedNondeterminism": sum(
            1 for value in classes.values() if value == "EXPECTED_NONDETERMINISM"
        ),
        "indeterminate": sum(
            1 for value in classes.values() if value == "INDETERMINATE"
        ),
    }
    return {
        "campaignId": CAMPAIGN_ID,
        "contract": CONTRACT,
        "productionCompared": compared,
        # A classification is an input to review, never its outcome.
        "parityEstablished": False,
        "reason": reason,
        "summary": counts,
        "trustRoots": trust_roots,
        "rows": [
            {"caseId": case_id, "classification": value}
            for case_id, value in classes.items()
        ],
    }


__all__ = ["CLASSIFICATIONS", "CONTRACT", "compare"]
