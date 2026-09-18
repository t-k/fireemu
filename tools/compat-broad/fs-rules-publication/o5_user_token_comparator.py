"""Comparator contract for the FS-RULES user-token observation matrix.

The comparator joins one production bundle with one local shadow bundle and
classifies each row. It refuses to classify anything it cannot bind:

* both bundles must come from the checked-in collector contract and the same
  compiled case digest;
* the production side must declare the production user-token role, so a local
  shadow bundle with a flipped flag cannot stand in for it;
* the two sides must be distinct runs, so a bundle cannot be compared with
  itself;
* neither side may claim acquisition or promotion authority.

A ``MATCH`` here is a row-level agreement between two collected bundles. It is
not a compatibility verdict: ``promotionReady`` is always false and promoting
this lane is a separate review.
"""

from __future__ import annotations

from typing import Any

from o5_user_token_case import validate_case
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
)

COMPARATOR_CONTRACT = "fs-rules-user-token-comparator-v1"

MATCH = "MATCH"
SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"
EXPECTED_NONDETERMINISM = "EXPECTED_NONDETERMINISM"
INDETERMINATE = "INDETERMINATE"

_PRECEDENCE = (SEMANTIC_MISMATCH, INDETERMINATE, EXPECTED_NONDETERMINISM, MATCH)

# Field values that may legitimately differ between two runs of the same case.
_NONDETERMINISTIC_FIELDS = ("createTime", "updateTime", "readTime", "uid", "name")


def _validate_side(
    bundle: Any, expected_role: str, plan: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        raise TypeError(f"{expected_role}:not-a-bundle")
    if bundle.get("contract") != COLLECTOR_CONTRACT:
        raise ValueError(f"{expected_role}:collector-contract-drift")
    if (
        bundle.get("productionReady") is True
        or bundle.get("acquisitionValidated") is True
    ):
        raise ValueError(f"{expected_role}:bundle-claims-authority")
    provenance = bundle.get("provenance")
    if not isinstance(provenance, dict):
        raise TypeError(f"{expected_role}:missing-provenance")
    if provenance.get("role") != expected_role:
        raise ValueError(f"{expected_role}:role-mismatch")
    if provenance.get("collectorContract") != COLLECTOR_CONTRACT:
        raise ValueError(f"{expected_role}:provenance-contract-drift")
    if not isinstance(provenance.get("runId"), str) or not provenance["runId"]:
        raise ValueError(f"{expected_role}:missing-run-identity")
    if bundle.get("planDigest") != plan["planDigest"]:
        raise ValueError(f"{expected_role}:case-digest-drift")
    rows = bundle.get("rows")
    if not isinstance(rows, list) or len(rows) != len(plan["observation"]):
        raise ValueError(f"{expected_role}:row-count")
    for row, operation in zip(rows, plan["observation"], strict=True):
        if not isinstance(row, dict):
            raise TypeError(f"{expected_role}:row-shape")
        if (
            row.get("caseId") != operation["caseId"]
            or row.get("index") != operation["index"]
        ):
            raise ValueError(f"{expected_role}:row-identity")
        if row.get("credentialRef") != operation["credential"]["ref"]:
            raise ValueError(f"{expected_role}:principal-drift")
        if row.get("resources") != operation["resources"]:
            raise ValueError(f"{expected_role}:target-drift")
    cleanup = bundle.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("cleanupComplete") is not True:
        raise ValueError(f"{expected_role}:cleanup-incomplete")
    if bundle.get("recordingComplete") is not True:
        raise ValueError(f"{expected_role}:recording-incomplete")
    return bundle


def _classify_row(
    production: dict[str, Any], local: dict[str, Any], expected: dict[str, Any]
) -> dict[str, Any]:
    if production.get("failure") is not None or local.get("failure") is not None:
        return {"classification": INDETERMINATE, "reason": "row-failure"}
    seen_production = production.get("observed")
    seen_local = local.get("observed")
    if not isinstance(seen_production, dict) or not isinstance(seen_local, dict):
        return {"classification": INDETERMINATE, "reason": "missing-observation"}
    if seen_production.get("status") != seen_local.get("status"):
        return {"classification": SEMANTIC_MISMATCH, "reason": "status"}
    if seen_production.get("status") != expected["expect"]["status"]:
        return {"classification": SEMANTIC_MISMATCH, "reason": "expected-status"}
    if seen_production.get("documentPresent") != seen_local.get("documentPresent"):
        return {"classification": SEMANTIC_MISMATCH, "reason": "document-presence"}
    fields_production = seen_production.get("fields")
    fields_local = seen_local.get("fields")
    if fields_production == fields_local:
        return {"classification": MATCH, "reason": "identical"}
    if _only_nondeterministic(fields_production, fields_local):
        return {
            "classification": EXPECTED_NONDETERMINISM,
            "reason": "server-assigned-values",
        }
    return {"classification": SEMANTIC_MISMATCH, "reason": "fields"}


def _only_nondeterministic(production: Any, local: Any) -> bool:
    if not isinstance(production, dict) or not isinstance(local, dict):
        return False
    if set(production) != set(local):
        return False
    for key, value in production.items():
        if value == local[key]:
            continue
        if key not in _NONDETERMINISTIC_FIELDS:
            return False
    return True


def compare(production: Any, local: Any, plan: Any) -> dict[str, Any]:
    result = {
        "contract": COMPARATOR_CONTRACT,
        "classification": INDETERMINATE,
        "rows": [],
        "conditions": {},
        "acquisitionValidated": False,
        "promotionReady": False,
        "errors": [],
    }
    try:
        validate_case(plan)
    except (TypeError, ValueError) as error:
        result["errors"].append(f"plan:{error}")
        return result
    try:
        production_bundle = _validate_side(production, ROLE_PRODUCTION, plan)
        local_bundle = _validate_side(local, ROLE_LOCAL_SHADOW, plan)
    except (TypeError, ValueError) as error:
        result["errors"].append(str(error))
        return result
    if production_bundle["provenance"]["runId"] == local_bundle["provenance"]["runId"]:
        result["errors"].append("self-comparison")
        return result

    rows = []
    for production_row, local_row, operation in zip(
        production_bundle["rows"],
        local_bundle["rows"],
        plan["observation"],
        strict=True,
    ):
        verdict = _classify_row(production_row, local_row, operation)
        rows.append(
            {
                "index": operation["index"],
                "caseId": operation["caseId"],
                "condition": operation["condition"],
                **verdict,
            }
        )
    result["rows"] = rows
    present = {row["classification"] for row in rows}
    for candidate in _PRECEDENCE:
        if candidate in present:
            result["classification"] = candidate
            break
    conditions: dict[str, str] = {}
    for row in rows:
        current = conditions.get(row["condition"])
        if current is None or _PRECEDENCE.index(
            row["classification"]
        ) < _PRECEDENCE.index(current):
            conditions[row["condition"]] = row["classification"]
    result["conditions"] = conditions
    return result
