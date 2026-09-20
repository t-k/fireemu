"""Comparison contract for the AUTH-CREDENTIAL token and session-cookie campaign.

The contract classifies rows; it never approves them. `parityEstablished` is always
false here, because a classification is an input to review, not the result of one.

Three rules carry most of the weight:

* The local runtime issues unsigned emulator tokens while production issues signed ones.
  A trust-root difference is therefore expected and is never a semantic difference. The
  roots observed on each side are reported separately so review can see them.
* The same-second revocation boundary is classified `EXPECTED_NONDETERMINISM` unless both
  sides pinned the boundary from server-reported values, which is judged from the seconds
  each side recorded rather than from its own claim to have pinned them. A run that could
  not pin it observed something real but not the boundary.
* The boundary row means nothing unless its neighbouring controls held on each side
  independently. A refusal below and an acceptance above are what place the boundary;
  two sides that both accepted the older session agree with each other and have still
  placed no boundary, so the row is `INDETERMINATE` however well they agreed. The refusal
  below has to be the expiry the endpoint documents: a 401, a 403, a rate limit or an
  INVALID_ID_TOKEN refuses the call for a reason that has nothing to do with how old the
  session is, and is compared as data without placing anything.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from credential_cases import (
    CAMPAIGN_ID,
    REVOCATION_REFUSAL_STATUS,
    case_by_id,
    observation_cases,
    revocation_refusal_codes,
)
from credential_collector import (
    is_module_digest,
    is_secret_key,
    unobserved_reason,
)

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
        return not is_module_digest(key, node)
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
    budget = receipt.get("budget")
    if isinstance(budget, dict) and budget.get("integrityFailure") is not None:
        return "budget-integrity-failure"
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


def _whole_second(value: Any) -> int | None:
    """Read a server-reported whole second, which may arrive as a string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    return None


def _boundary_pinned(row: dict[str, Any]) -> bool:
    """Whether this side pinned the boundary from server-reported values.

    The side's own boolean is not enough. A row claiming a pinned boundary while
    reporting auth_time 100 against validSince 102 pinned nothing, and comparing it
    would read a two-second gap as the same-second boundary.
    """
    if row.get("boundaryPinned") is not True:
        return False
    seconds = row.get("boundarySeconds")
    if not isinstance(seconds, dict):
        return False
    auth_time = _whole_second(seconds.get("authTime"))
    return auth_time is not None and auth_time == _whole_second(
        seconds.get("validSince")
    )


def _control_holds(row: dict[str, Any], requires: str, operation: str) -> bool:
    """Whether one boundary control did on this side what places the boundary.

    A refusal has to be the one the endpoint documents for an expired or revoked
    session. Accepting any refusal at all would read INVALID_ID_TOKEN, an unauthenticated
    caller, a denied permission or a rate limit as proof that the older session was
    refused for being older, and two sides failing the same unrelated way would then
    agree their way to a boundary nobody placed.
    """
    status = row.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        return False
    if requires == "accepted":
        return status == 200 and row.get("errorCode") is None
    return status == REVOCATION_REFUSAL_STATUS and row.get(
        "errorCode"
    ) in revocation_refusal_codes(operation)


def _boundary_is_placed(
    case: dict[str, Any], *sides: dict[str, dict[str, Any]]
) -> bool:
    """Whether both controls held independently on every side that recorded them."""
    return all(
        _control_holds(
            side[control["case"]],
            control["requires"],
            case_by_id(control["case"])["operation"],
        )
        for side in sides
        for control in case["boundaryControls"].values()
    )


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
        # A row nobody ran is not a row that agreed. This is re-derived from the row
        # itself, because `recordingComplete` is written by the collector under review.
        if any(unobserved_reason(side[case_id]) is not None for side in (left, right)):
            classes[case_id] = "INDETERMINATE"
            continue
        agree = _semantic(left[case_id]) == _semantic(right[case_id])
        if case["nondeterminism"] == "SAME_SECOND_BOUNDARY":
            if not _boundary_is_placed(case, left, right):
                classes[case_id] = "INDETERMINATE"
            elif _boundary_pinned(left[case_id]) and _boundary_pinned(right[case_id]):
                classes[case_id] = "MATCH" if agree else "DIFFERENT"
            else:
                classes[case_id] = "EXPECTED_NONDETERMINISM"
        else:
            classes[case_id] = "MATCH" if agree else "DIFFERENT"

    # A boundary row is only readable while the controls that place it agreed as well.
    # Holding on each side is necessary but not sufficient: two sides can each place a
    # boundary and still disagree about where it sits.
    for case in observation_cases():
        controls = case.get("boundaryControls")
        if controls and any(
            classes[control["case"]] != "MATCH" for control in controls.values()
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
