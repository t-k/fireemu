"""Comparator contract for the FS-RULES user-token observation matrix.

This comparator has no positive classification. Every call returns
``INDETERMINATE``. That is deliberate and it is the reviewed position of this
lane: a collected pair of bundles is not evidence about production until each
bundle binds the facts that make it an *acquisition* rather than a recording.

The unlock conditions come from the earlier O5 reduction review. A bundle must
bind, and this comparator must verify:

* the endpoint the requests actually reached;
* the observer identity, as a digest of the harness that produced the bundle;
* the campaign manifest the run was admitted under;
* the Ruleset releases that were active, with their readback;
* an exclusive reservation of the campaign nonce;
* sequential wire, cost and execution-window counts;
* version-bound cleanup and final absence for every owned resource.

None of those exist yet, so this module refuses every input and names what is
missing. A self-declared role string is not an acquisition: collecting the same
matrix twice locally and labelling one bundle ``production-user-token`` must
never produce agreement, and it does not, because there is no path to
agreement at all.

Restoring a positive classification requires a separate review of a collector
that produces the bindings above. Until then this module is the place where
that decision is recorded, not bypassed.
"""

from __future__ import annotations

from typing import Any

from o5_user_token_case import validate_case
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
)

COMPARATOR_CONTRACT = "fs-rules-user-token-comparator-v2"

INDETERMINATE = "INDETERMINATE"

# The only classification this module can emit.
CLASSIFICATIONS = (INDETERMINATE,)

REQUIRED_ACQUISITION_BINDINGS = (
    "endpoint",
    "observerDigest",
    "campaignManifestDigest",
    "rulesetReleases",
    "nonceReservation",
    "wireCounts",
    "ownerPermission",
)

UNLOCK_CONDITIONS = (
    "a collector that records the endpoint each request reached",
    "an observer digest bound to the harness source and artifact",
    "the campaign manifest digest the run was admitted under",
    "the Ruleset release identifiers with their readback",
    "an exclusive reservation of the campaign nonce",
    "sequential wire, cost and execution-window counts",
    "version-bound cleanup and final absence for documents and accounts",
    "an independent review that re-opens positive classification",
)


def _validate_side(bundle: Any, expected_role: str, plan: dict[str, Any]) -> list[str]:
    """Collect every reason this bundle cannot be treated as an acquisition."""
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return [f"{expected_role}:not-a-bundle"]
    if bundle.get("contract") != COLLECTOR_CONTRACT:
        errors.append(f"{expected_role}:collector-contract-drift")
    if (
        bundle.get("productionReady") is True
        or bundle.get("acquisitionValidated") is True
    ):
        errors.append(f"{expected_role}:bundle-claims-authority")
    provenance = bundle.get("provenance")
    if not isinstance(provenance, dict):
        errors.append(f"{expected_role}:missing-provenance")
    else:
        if provenance.get("role") != expected_role:
            errors.append(f"{expected_role}:role-mismatch")
        if not isinstance(provenance.get("runId"), str) or not provenance["runId"]:
            errors.append(f"{expected_role}:missing-run-identity")
    if bundle.get("planDigest") != plan["planDigest"]:
        errors.append(f"{expected_role}:case-digest-drift")
    rows = bundle.get("rows")
    if not isinstance(rows, list) or len(rows) != len(plan["observation"]):
        errors.append(f"{expected_role}:row-count")
    else:
        errors.extend(_row_errors(rows, plan, expected_role))
    cleanup = bundle.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("cleanupComplete") is not True:
        errors.append(f"{expected_role}:cleanup-incomplete")
    if bundle.get("recordingComplete") is not True:
        errors.append(f"{expected_role}:recording-incomplete")
    errors.extend(_missing_bindings(bundle, expected_role))
    return errors


def _row_errors(rows: list[Any], plan: dict[str, Any], role: str) -> list[str]:
    errors: list[str] = []
    for row, operation in zip(rows, plan["observation"], strict=True):
        if not isinstance(row, dict):
            errors.append(f"{role}:row-shape")
            break
        if (
            row.get("caseId") != operation["caseId"]
            or row.get("index") != operation["index"]
        ):
            errors.append(f"{role}:row-identity")
            break
        if row.get("credentialRef") != operation["credential"]["ref"]:
            errors.append(f"{role}:principal-drift")
            break
        if row.get("resources") != operation["resources"]:
            errors.append(f"{role}:target-drift")
            break
    return errors


def _missing_bindings(bundle: dict[str, Any], role: str) -> list[str]:
    acquisition = bundle.get("acquisition")
    if not isinstance(acquisition, dict):
        return [f"{role}:missing-acquisition-bindings"]
    missing = [
        name for name in REQUIRED_ACQUISITION_BINDINGS if not acquisition.get(name)
    ]
    return [f"{role}:missing-binding:{name}" for name in missing]


def compare(production: Any, local: Any, plan: Any) -> dict[str, Any]:
    """Refuse to classify, and say exactly why.

    The result is always ``INDETERMINATE``. ``errors`` names what is missing so
    a later, separately reviewed collector can close each item.
    """
    result: dict[str, Any] = {
        "contract": COMPARATOR_CONTRACT,
        "status": "PREPARATION_ONLY",
        "classification": INDETERMINATE,
        "rows": [],
        "conditions": {},
        "acquisitionValidated": False,
        "productionObserved": False,
        "promotionReady": False,
        "unlockConditions": list(UNLOCK_CONDITIONS),
        "errors": [],
    }
    try:
        validate_case(plan)
    except (TypeError, ValueError) as error:
        result["errors"].append(f"plan:{error}")
        return result
    result["errors"].extend(_validate_side(production, ROLE_PRODUCTION, plan))
    result["errors"].extend(_validate_side(local, ROLE_LOCAL_SHADOW, plan))
    production_run = _run_id(production)
    local_run = _run_id(local)
    if production_run is not None and production_run == local_run:
        result["errors"].append("self-comparison")
    result["errors"].append("positive-classification-locked-pending-review")
    return result


def _run_id(bundle: Any) -> str | None:
    if not isinstance(bundle, dict):
        return None
    provenance = bundle.get("provenance")
    if not isinstance(provenance, dict):
        return None
    run_id = provenance.get("runId")
    return run_id if isinstance(run_id, str) else None
