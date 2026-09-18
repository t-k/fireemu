"""Comparator boundary for the FS-CONFIG-LIFECYCLE preparation contract.

This version cannot classify anything as a production match. It accepts preparation
receipts only, states the normalization rules a future measurement version must apply,
and always returns PREPARATION_ONLY with no rows.
"""

from __future__ import annotations

import json
from typing import Any

from .manifest import SCHEMA as MANIFEST_SCHEMA
from .manifest import compile_manifest
from .surface_matrix import CASE_ID, digest

SCHEMA = "fs-config-lifecycle-preparation-v1"

_OBSERVED_FIELDS = frozenset(
    {"responses", "observations", "collector", "transport", "operations", "receiptRows"}
)

_VALUE_NORMALIZED = (
    "earliestVersionTime",
    "etag",
    "createTime",
    "updateTime",
    "deleteTime",
    "uid",
    "snapshotTime",
)

_NAME_NORMALIZED = (
    "the run nonce inside any database id, collection group id or operation name",
    "the long-running operation identifier assigned by the server",
)

_TERMINAL_STATES = {
    "ttlConfig.state": ["ACTIVE"],
    "indexConfig.reverting": [False],
    "index.state": ["READY"],
}

_SIGNIFICANT = (
    "field presence and absence",
    "JSON types",
    "array order",
    "enum spelling",
    "HTTP status and canonical error code",
)

_REPORTED_NOT_REQUIRED = (
    "error message prose",
    "long-running operation metadata progress counters",
    "response latency",
)

_INDETERMINATE = (
    (
        "A non-terminal configuration state read before the poll deadline is "
        "indeterminate, never a mismatch."
    ),
    "A transport failure, authentication refusal or quota refusal is indeterminate.",
    "A case whose revert did not complete is indeterminate and marks its run invalid.",
    (
        "A field present on one side and absent on the other is a mismatch, not an "
        "indeterminate result; only the listed value-normalized fields are exempt."
    ),
)

_FUTURE_REQUIREMENTS = (
    "Path-specific SHA-256 digests for the source, collector, comparator and lockfiles.",
    "A resolved runtime identity and artifact digest for the local side.",
    "Per-case request and response records with status, canonical code and typed body.",
    "The owned-resource ledger in its final state with every entry recovered.",
    "The operation checkpoint showing every poll and its terminal state.",
    "A separately supplied owner permission bound to this manifest and an unused nonce.",
)

COMPARISON_CONTRACT: dict[str, Any] = {
    "kind": "fs-config-lifecycle-comparison-contract-v1",
    "valueNormalizedFields": list(_VALUE_NORMALIZED),
    "valueNormalizedRule": (
        "Presence and JSON type are compared; the value is not. These fields either "
        "advance on their own or identify one provisioning instance, so an equal value "
        "would be accidental and an unequal value is not evidence of incompatibility."
    ),
    "nameNormalized": list(_NAME_NORMALIZED),
    "acceptableTerminalStates": {k: list(v) for k, v in _TERMINAL_STATES.items()},
    "significant": list(_SIGNIFICANT),
    "reportedButNotRequiredToMatch": list(_REPORTED_NOT_REQUIRED),
    "indeterminate": list(_INDETERMINATE),
    "matchRequires": (
        "Both sides carry the same ordered case list, the same abstract request for each "
        "case, a complete recording and a completed cleanup. A case missing on both "
        "sides is invalid even when the two records agree with each other."
    ),
}


def _receipt_errors(manifest: dict[str, Any], receipt: Any) -> list[str]:
    if not isinstance(receipt, dict):
        return ["receipt-shape"]
    errors: list[str] = []
    if receipt.get("schema") != SCHEMA:
        errors.append("receipt-shape")
    if receipt.get("caseId") != CASE_ID:
        errors.append("case-binding")
    if receipt.get("manifestDigest") != digest(manifest):
        errors.append("manifest-binding")
    if receipt.get("status") != "PREPARATION_ONLY":
        errors.append("status")
    if receipt.get("productionExecuted") is not False:
        errors.append("production-executed")
    if _OBSERVED_FIELDS & set(receipt.keys()):
        errors.append("observation-shaped-fields")
    if not isinstance(receipt.get("expectedCaseOutcomes"), list):
        errors.append("expected-outcomes-shape")
    binding = receipt.get("sourceBinding")
    if not isinstance(binding, dict) or binding.get("commit") is not None:
        errors.append("source-binding")
    return errors


def compare(
    manifest: dict[str, Any], left: Any, right: Any, nonce: str | None = None
) -> dict[str, Any]:
    """Always returns PREPARATION_ONLY; no input can make this version report a match."""
    result: dict[str, Any] = {
        "kind": SCHEMA,
        "classification": "PREPARATION_ONLY",
        "promotionReady": False,
        "acquisitionValidated": False,
        "productionUnobservedConditionsReduced": 0,
        "contract": COMPARISON_CONTRACT,
        "futureMeasurementRequires": list(_FUTURE_REQUIREMENTS),
        "rows": [],
        "errors": [],
    }
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        result["errors"] = ["manifest-invalid"]
        return result
    if nonce is not None:
        try:
            if json.loads(json.dumps(manifest)) != json.loads(
                json.dumps(compile_manifest(nonce))
            ):
                result["errors"] = ["manifest-drift"]
                return result
        except ValueError:
            result["errors"] = ["manifest-invalid"]
            return result
    errors = _receipt_errors(manifest, left) + _receipt_errors(manifest, right)
    if errors:
        result["errors"] = sorted(set(errors))
    else:
        result["errors"] = ["preparation-only"]
    return result
