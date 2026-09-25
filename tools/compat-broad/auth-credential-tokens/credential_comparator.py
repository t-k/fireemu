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
* A claim set is compared after the local-only claims are stripped. The local runtime
  may add `firebase.fireemu_session_epoch` to an ID token; production never issues it,
  so its presence on one side is not a difference. Every other claim name or type that
  differs is a semantic mismatch.
"""

from __future__ import annotations

import copy
import json
import math
import re
from typing import Any

from credential_cases import (
    CAMPAIGN_ID,
    LOCAL_ONLY_CLAIMS,
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

#: The two outcomes of a claim-set comparison. Neither is a compatibility claim.
CLAIM_SET_MATCH = "MATCH"
CLAIM_SET_MISMATCH = "SEMANTIC_MISMATCH"

#: The row member a claim set is recorded under. It carries names and types only.
CLAIMS_MEMBER = "claims"


def strip_local_only_claims(claims: Any) -> Any:
    """Remove the claims only the local runtime issues, wherever they are recorded.

    A claim set is recorded as claim names and claim types, at the top level and
    under `firebase`. `firebase.fireemu_session_epoch` is a private local session
    marker that never appears in a production token, so it is dropped from both the
    names and the types before equality is judged. Nothing else is touched: a claim
    present on one side only remains a difference.
    """
    if not isinstance(claims, dict):
        return claims
    result = copy.deepcopy(claims)
    for path in LOCAL_ONLY_CLAIMS:
        node: Any = result
        for segment in path[:-1]:
            node = node.get(segment) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            continue
        name = path[-1]
        names = node.get("claimNames")
        if isinstance(names, list):
            node["claimNames"] = [item for item in names if item != name]
        types = node.get("claimTypes")
        if isinstance(types, dict):
            types.pop(name, None)
    return result


def compare_claim_sets(local: Any, production: Any) -> str:
    """Classify two recorded claim sets, ignoring the local-only claims.

    Both inputs are the `claims` member a row records: claim names and types, with a
    nested `firebase` block of the same shape. The local-only claims are stripped from
    both sides, so a local token carrying `firebase.fireemu_session_epoch` and a
    production token without it still compare equal on everything else. A malformed
    claim set on either side is a mismatch, never a match by default.
    """
    if not _claim_shape_complete(local) or not _claim_shape_complete(production):
        return CLAIM_SET_MISMATCH
    if _same_json(strip_local_only_claims(local), strip_local_only_claims(production)):
        return CLAIM_SET_MATCH
    return CLAIM_SET_MISMATCH



def _claim_shape_complete(claims: Any) -> bool:
    """Validate the collector's projection, not the validity of the JWT itself.

    A complete empty projection is legal; a missing projection is not. Do this
    before dropping local-only fields, otherwise an incomplete local marker can
    erase the very inconsistency that should prevent a comparison.
    """
    if type(claims) is not dict or not _json_value(claims):
        return False
    if set(claims) != {"claimNames", "claimTypes", "firebase"}:
        return False

    def names_and_types(node: dict[str, Any]) -> bool:
        names, types = node.get("claimNames"), node.get("claimTypes")
        return (
            type(names) is list
            and all(type(name) is str for name in names)
            and len(names) == len(set(names))
            and type(types) is dict
            and set(names) == set(types)
            and all(type(kind) is str and kind in {
                "null", "bool", "int", "float", "string", "array", "object"
            } for kind in types.values())
        )

    if not names_and_types(claims):
        return False
    firebase = claims["firebase"]
    if claims["claimTypes"].get("firebase") != "object":
        return firebase is None
    return (
        type(firebase) is dict
        and set(firebase) == {"claimNames", "claimTypes"}
        and names_and_types(firebase)
    )


def _row_claims_complete(row: dict[str, Any], case: dict[str, Any]) -> bool:
    """A returned token must carry its measured claim shape, not just a flag."""
    assertions = row["assertions"]
    required = (
        assertions.get("idTokenReturned") is True
        or assertions.get("sessionCookieReturned") is True
        or (case["group"] == "claim-precedence"
            and row["status"] == 200 and row.get("errorCode") is None)
    )
    claims = row.get(CLAIMS_MEMBER)
    if claims is None:
        return not required
    return _claim_shape_complete(claims)


def _json_value(value: Any, depth: int = 0, active: set[int] | None = None) -> bool:
    """Receipts are finite JSON, not arbitrary Python object graphs."""
    if depth > 128:
        return False
    kind = type(value)
    if kind is int:
        return value.bit_length() <= 4096
    if kind in (str, bool) or value is None:
        return True
    if kind is float:
        return math.isfinite(value)
    if kind not in (dict, list):
        return False
    active = set() if active is None else active
    identity = id(value)
    if identity in active:
        return False
    active.add(identity)
    try:
        if kind is dict and any(type(key) is not str for key in value):
            return False
        members = value.values() if kind is dict else value
        return all(_json_value(member, depth + 1, active) for member in members)
    finally:
        active.remove(identity)


def _same_json(left: Any, right: Any) -> bool:
    # The receipt validator already excludes non-JSON graphs and nonfinite numbers.
    # Encoded equality preserves bool/int/float distinctions at every depth.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


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
    if type(receipt) is not dict or not _json_value(receipt):
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
        or type(cleanup.get("remainingAccounts")) is not int
        or cleanup["remainingAccounts"] != 0
        or type(cleanup.get("ownedAccounts")) is not int
        or cleanup["ownedAccounts"] < 0
        or type(cleanup.get("addressReadbacks")) is not int
        or not 0 <= cleanup["addressReadbacks"] <= cleanup["ownedAccounts"]
    ):
        return "incomplete-cleanup"
    responsibility = receipt.get("creationResponsibility")
    if responsibility is not None:
        counts = ("intentCount", "unknownCreates", "confirmedCreates", "existingAccounts")
        if (
            type(responsibility) is not dict
            or any(type(responsibility.get(key)) is not int
                   or not 0 <= responsibility[key] <= 4 for key in counts)
            or responsibility["intentCount"] != sum(responsibility[key] for key in counts[1:])
            or responsibility["unknownCreates"] != 0
            or responsibility["confirmedCreates"] > cleanup["ownedAccounts"]
            or responsibility.get("recordingComplete") is not True
            or type(responsibility.get("durable")) is not bool
            or responsibility.get("authorizesCleanup") is not False
        ):
            return "incomplete-creation-responsibility"
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
        or not _same_json(binding, production.get("collectorBinding"))
    ):
        return "collector-binding-mismatch"
    if production.get("productionExecuted") is not True:
        return "production-unobserved"
    if local.get("productionExecuted") is not False:
        return "local-side-claims-production"
    return None


def _whole_second(value: Any) -> int | None:
    """Read a server-reported whole second, which may arrive as a string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and len(value) <= 32 and re.fullmatch(r"-?[0-9]+", value):
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
        if status != 200 or row.get("errorCode") is not None:
            return False
        # A 200 without the intended account does not demonstrate that the
        # newer session works, even when both sides returned the same bad body.
        return operation != "identity.accounts-lookup" or (
            isinstance(row.get("assertions"), dict)
            and row["assertions"].get("lookupMatchesAccount") is True
        )
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
    """The part of a row that is compared: everything but trust and pinning members.

    A recorded claim set is compared with the local-only claims stripped, so the
    private local session marker never counts as a difference while every other claim
    name or type still does.
    """
    dropped = {*TRUST_MEMBERS, *DIAGNOSTIC_MEMBERS, "boundaryPinned"}
    semantic = {k: v for k, v in row.items() if k not in dropped}
    if CLAIMS_MEMBER in semantic:
        semantic[CLAIMS_MEMBER] = strip_local_only_claims(semantic[CLAIMS_MEMBER])
    return semantic


def _fresh_control_holds(row: dict[str, Any], requires: str) -> bool:
    """Whether the fresh-session control recorded on a refusal row did what it must.

    The control is a second exchange on the same account with a freshly issued
    refresh token. Only an accepted exchange shows the refusal above it was about the
    stale credential rather than the account, so a row whose control did not hold is
    not a refusal-class observation, however well the two sides agreed on the code.
    """
    control = row.get("freshSessionRefresh")
    if not isinstance(control, dict):
        return False
    status = control.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        return False
    if requires == "accepted":
        return status == 200 and control.get("errorCode") is None
    return status == REVOCATION_REFUSAL_STATUS and isinstance(control.get("errorCode"), str)


def _assertion_shape_complete(row: dict[str, Any], case: dict[str, Any]) -> bool:
    """Require the declared measurements, not their expected local truth values.

    A recorded refusal need not contain checks on a token it never returned. Keep
    that existing path comparable, but never treat an empty successful observation
    or a partial/renamed assertion set as complete evidence.
    """
    assertions = row["assertions"]  # unobserved_reason checked this is an object.
    if set(assertions) == set(case["expectedLocal"]["assertions"]):
        return True
    return (
        not assertions
        and 400 <= row["status"] <= 599
        and isinstance(row.get("errorCode"), str)
        and bool(row["errorCode"])
    )


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
        if any(
            unobserved_reason(side[case_id]) is not None
            or not _assertion_shape_complete(side[case_id], case)
            or not _row_claims_complete(side[case_id], case)
            or any(type(value) is not bool for value in side[case_id]["assertions"].values())
            or (side[case_id].get("errorCode") is not None
                and type(side[case_id]["errorCode"]) is not str)
            for side in (left, right)
        ):
            classes[case_id] = "INDETERMINATE"
            continue
        agree = _same_json(_semantic(left[case_id]), _semantic(right[case_id]))
        fresh = case.get("freshControl")
        if fresh is not None and not all(
            _fresh_control_holds(side[case_id], fresh["requires"]) for side in (left, right)
        ):
            classes[case_id] = "INDETERMINATE"
            continue
        if case["nondeterminism"] == "SAME_SECOND_BOUNDARY":
            if not _boundary_is_placed(case, left, right):
                classes[case_id] = "INDETERMINATE"
            elif any(
                side[case_id]["status"] == 200
                and side[case_id]["assertions"].get("lookupMatchesAccount") is not True
                for side in (left, right)
            ):
                # A body/identity defect is not a wall-clock boundary effect.
                # Preserve an observed difference; equal bad responses place no
                # usable same-second boundary and remain indeterminate.
                classes[case_id] = "DIFFERENT" if not agree else "INDETERMINATE"
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


__all__ = [
    "CLAIM_SET_MATCH",
    "CLAIM_SET_MISMATCH",
    "CLASSIFICATIONS",
    "CONTRACT",
    "compare",
    "compare_claim_sets",
    "strip_local_only_claims",
]
