"""Deterministic, Gate-bound recovery plan for one held request-byte probe.

This module compiles only a recovery plan. It does not read credentials, touch
the Ledger, perform transport, or fabricate creation proofs. The existing Gate
will refuse a conditional delete until a trusted parent lifecycle has installed
the creation proof; that refusal is intentional until a separate lifecycle API
is approved.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from typing import Any

import shared_gate
from request_bytes_collector import owned_document, typed_not_found

RECOVERY_JOB = "request-bytes-recovery-extension"
PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
PROBES = ("under", "exact", "over")
DOCUMENTS_PER_PROBE = 17
ALL_RESOURCES = DOCUMENTS_PER_PROBE * len(PROBES)
INSPECTION_READS = DOCUMENTS_PER_PROBE
CONDITIONAL_DELETES = DOCUMENTS_PER_PROBE
ABSENCE_READS = ALL_RESOURCES
MAXIMUM_REQUESTS = INSPECTION_READS + CONDITIONAL_DELETES + ABSENCE_READS
READ_MICROUSD = 0.6
DELETE_MICROUSD = 0.2
TARIFF_COST_MICROUSD = math.ceil(
    (INSPECTION_READS + ABSENCE_READS) * READ_MICROUSD
    + CONDITIONAL_DELETES * DELETE_MICROUSD
)


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _operation(source: dict[str, Any], *, kind: str, version_from: str | None = None) -> dict[str, Any]:
    result = copy.deepcopy(source)
    result["kind"] = kind
    result.pop("expect", None)
    if version_from is not None:
        result["versionFrom"] = version_from
    return result


def compile_recovery_plan(
    parent_plan: dict[str, Any], *, selected_probe: str, recovery_nonce: str
) -> dict[str, Any]:
    """Compile 17 selected ownership/delete pairs plus all 51 absence reads."""
    if selected_probe not in PROBES:
        raise ValueError("unknown recovery probe")
    parent_nonce = parent_plan.get("nonce")
    if not isinstance(parent_nonce, str) or not parent_nonce:
        raise ValueError("parent nonce required")
    if not isinstance(recovery_nonce, str) or len(recovery_nonce) != 32:
        raise ValueError("recovery nonce must be 32 characters")
    if recovery_nonce == parent_nonce:
        raise ValueError("recovery nonce must be distinct")
    probes = {probe["label"]: probe for probe in parent_plan.get("probes", [])}
    if set(probes) != set(PROBES):
        raise ValueError("parent probe set required")
    source_by_kind = {
        (operation["probe"], operation["resource"], operation["kind"]): operation
        for operation in parent_plan.get("recovery", [])
    }
    selected = probes[selected_probe]["resources"]
    operations: list[dict[str, Any]] = []
    for resource in selected:
        read = source_by_kind[(selected_probe, resource, "cleanup-ownership-read")]
        delete = source_by_kind[(selected_probe, resource, "cleanup-version-bound-delete")]
        operations.append(_operation(read, kind="recovery-inspection-read"))
        operations.append(
            _operation(delete, kind="recovery-conditional-delete", version_from="recovery-inspection-read")
        )
    for probe in PROBES:
        for resource in probes[probe]["resources"]:
            source = source_by_kind[(probe, resource, "cleanup-verify-absence")]
            operations.append(_operation(source, kind="recovery-absence-read"))
    return {
        "schemaVersion": 1,
        "campaignId": "FS-LIMIT-API-REQUEST-BYTES-RECOVERY",
        "project": parent_plan.get("project", PROJECT),
        "database": parent_plan.get("database", DATABASE),
        "parentNonce": parent_nonce,
        "recoveryNonce": recovery_nonce,
        "selectedProbe": selected_probe,
        "parentPlanDigest": _sha(parent_plan),
        "resourceNamesDigest": _sha([op["resource"] for op in operations]),
        "bounds": {
            "inspectionReads": INSPECTION_READS,
            "conditionalDeletes": CONDITIONAL_DELETES,
            "absenceReads": ABSENCE_READS,
            "maximumRequests": MAXIMUM_REQUESTS,
            "tariffCostMicrousd": TARIFF_COST_MICROUSD,
        },
        "operations": operations,
    }


def compile_gate_plan(recovery_plan: dict[str, Any]) -> dict[str, Any]:
    """Compile the actual Shared Gate plan consumed by ``shared_gate.create``."""
    operations = recovery_plan.get("operations")
    if not isinstance(operations, list) or len(operations) != MAXIMUM_REQUESTS:
        raise ValueError("recovery operation count drifted")
    resources = sorted({operation["resource"] for operation in operations})
    if len(resources) != ALL_RESOURCES:
        raise ValueError("full parent resource scope required")
    schedule = [
        {"phase": "recovery", "index": index, "seconds": 2.5, "creates": False}
        for index in range(len(operations))
    ]
    return {
        "contract": "shared-local-v2",
        "campaignId": recovery_plan["campaignId"],
        "nonce": recovery_plan["parentNonce"],
        "recoveryNonce": recovery_plan["recoveryNonce"],
        "jobSlots": 1,
        "ownershipMarker": {"field": "_owner", "binding": "nonce"},
        "requestSeconds": 2.5,
        "wallSeconds": 1200,
        "recoverySeconds": 1190,
        "intervalSeconds": shared_gate.INTERVAL_FLOOR_SECONDS,
        "observationRequests": 0,
        "recoveryRequests": MAXIMUM_REQUESTS,
        "requestCostMicrousd": 1,
        "costMicrousd": MAXIMUM_REQUESTS,
        "tariffCostMicrousd": TARIFF_COST_MICROUSD,
        "jobs": {
            RECOVERY_JOB: {
                "resources": resources,
                "observation": [],
                "recovery": copy.deepcopy(operations),
                "schedule": schedule,
            }
        },
    }


def validate_ownership_response(
    parent_plan: dict[str, Any], resource: str, response: dict[str, Any]
) -> dict[str, Any]:
    """Accept only frozen-content ownership or a typed absence response."""
    if typed_not_found(response):
        return {"owned": False, "updateTime": None}
    expected = parent_plan.get("documents", {}).get(resource)
    if not isinstance(expected, dict) or not owned_document(
        response, resource, expected.get("fieldsSha256"), parent_plan.get("nonce")
    ):
        raise ValueError("frozen ownership proof required")
    return {"owned": True, "updateTime": response["body"]["updateTime"]}


def owned_document_body(operation: dict[str, Any]) -> dict[str, Any]:
    """Fixture-only body shape; production callers must validate real content."""
    return {"name": operation["resource"], "fields": {"_owner": {"stringValue": "fixture"}}}
