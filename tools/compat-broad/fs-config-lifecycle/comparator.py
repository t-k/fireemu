"""Comparator for FS-CONFIG-LIFECYCLE collection records.

A record is `{executionKind, collection}` where `collection` is a result written by
`lifecycle_collector.collect`. The comparator lines the two records up case by case
on observation-phase rows the collector marked `role: case`, and compares HTTP
status, typed error code and the body shape: field presence, JSON types and enums.
Values are never compared; the shape already collapsed them.

It can classify a comparison as MATCH only when the production side is bound to a
verified acquisition: a `VerifiedAcquisition` object that only
`lifecycle_production.verify_saved` builds, after checking a saved O8 receipt
directory (receipt, frozen inputs, gate snapshot, evidence digests, reviewed worker
digest) against its shared Ledger reservation row. The `executionKind` label on a
record is a claim, not evidence: a record labelled `fixed-production-wire` without
that object, or with an object bound to some other collection, is REFUSED with a
named reason and no rows. Two local records are PREPARATION_ONLY. So a local
rehearsal compared against a fake, against another local run, or against a copy of
itself relabelled as production can never read as production evidence. Promotion is
never decided here.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

from .cases import EXECUTION_ORDER, compile_cases
from .manifest import SCHEMA as MANIFEST_SCHEMA
from .manifest import MAX_REQUESTS, compile_manifest
from .surface_matrix import CASE_ID, digest

SCHEMA = "fs-config-lifecycle-comparison-v3"
PRODUCTION_KIND = "fixed-production-wire"
LOCAL_KIND = "injected-local-transport"
EXECUTION_KINDS = (PRODUCTION_KIND, LOCAL_KIND)

MATCH = "MATCH"
MISMATCH = "MISMATCH"
INDETERMINATE = "INDETERMINATE"
EXPECTED_LOCAL_DEVIATION = "EXPECTED_LOCAL_DEVIATION"
REFUSED = "REFUSED"
PREPARATION_ONLY = "PREPARATION_ONLY"

# The only origin the reviewed remote transport can reach; a test pins it to
# lifecycle_remote_transport.ORIGIN so the two cannot drift apart silently.
PRODUCTION_ORIGIN = "https://firestore.googleapis.com"
ACQUISITION_UNVERIFIED = "production-acquisition-unverified"
ACQUISITION_BINDING = "production-acquisition-binding"
_HEX64 = re.compile(r"[a-f0-9]{64}")


@dataclass(frozen=True, eq=False)
class VerifiedAcquisition:
    """What the O8 boundary verified about one saved production acquisition.

    Built and registered only by `lifecycle_production.verify_saved`, which checks
    the receipt directory and the shared Ledger row before naming these values. The
    comparator accepts nothing else on the production side: not a dict, not a label,
    and not an instance constructed elsewhere (`eq=False` keeps identity semantics,
    and `lifecycle_production.verified` is asked for that identity). Every field is
    a binding the comparator re-checks against the collection it is handed.
    `synthetic` is True when the anchor was a proof Ledger, and such an object never
    validates acquisition.
    """

    campaign_id: str
    execution_kind: str
    endpoint: str
    reservation: str
    ledger_identity: str
    receipt_digest: str
    gate_digest: str
    artifact_sha256: str
    worker_sha256: str
    collection_digest: str
    synthetic: bool

    def summary(self) -> dict[str, Any]:
        return {
            "reservation": self.reservation,
            "ledgerIdentity": self.ledger_identity,
            "receiptDigest": self.receipt_digest,
            "gateDigest": self.gate_digest,
            "artifactSha256": self.artifact_sha256,
            "workerSha256": self.worker_sha256,
            "endpoint": self.endpoint,
            "collectionDigest": self.collection_digest,
            "synthetic": self.synthetic,
        }


_VALUE_NORMALIZED = (
    "earliestVersionTime",
    "etag",
    "createTime",
    "updateTime",
    "deleteTime",
    "uid",
    "snapshotTime",
    "startTime",
    "endTime",
    "name",
)

COMPARISON_CONTRACT: dict[str, Any] = {
    "kind": "fs-config-lifecycle-comparison-contract-v3",
    "valueNormalizedFields": list(_VALUE_NORMALIZED),
    "valueNormalizedRule": (
        "Presence and JSON type are compared; the value is not. These fields either "
        "advance on their own, identify one provisioning instance or carry the run "
        "nonce, so an equal value would be accidental and an unequal value is not "
        "evidence of incompatibility."
    ),
    "significant": [
        "HTTP status",
        "typed error code and status",
        "field presence and absence",
        "JSON types",
        "array order",
        "enum spelling",
    ],
    "reportedButNotRequiredToMatch": [
        "error message prose",
        "long-running operation metadata progress counters",
        "response latency",
        "the number of operation polls",
    ],
    "indeterminate": [
        "A case one side never reached is indeterminate, never a mismatch.",
        "A transport failure, credential refusal or quota refusal is indeterminate.",
        "A run whose observation or cleanup did not complete is indeterminate as a whole.",
        "A duplicate, unknown or reordered observation identity is indeterminate.",
        "Full comparison requires each side's nonce digest to bind its declared nonce.",
        "Recovery rows never replace missing observation-phase rows.",
    ],
    "rowKernel": (
        "compare_rows is a semantic-only kernel; its nonce is the local rehearsal "
        "nonce. Only full compare binds the production nonce to the manifest and "
        "checks VerifiedAcquisition. Kernel rows never validate acquisition."
    ),
    "expectedLocalDeviation": (
        "A case the classification matrix says the local runtime refuses is reported "
        "as an expected local deviation only when the local side answered exactly "
        "that typed UNIMPLEMENTED refusal and the production side served the request "
        "with a 2xx; it is neither a match nor a mismatch and never counts toward "
        "one. A refusal on both sides is compared like any other row."
    ),
    "matchRequires": (
        "The production record is bound to a VerifiedAcquisition built by the O8 "
        "boundary from a saved receipt directory and its shared Ledger row, both "
        "sides completed observation and cleanup without a stop or failure, the "
        "declared nonces and ordered unique observation identities are verified, "
        "and every case is MATCH. Expected local deviations remain deviations."
    ),
    "acquisitionValidated": (
        "True only when the production collection's digest is the one the verified "
        "acquisition names, the acquisition is the object lifecycle_production "
        "registered when it verified the receipt directory, it names this campaign, "
        "the fixed production wire and the production origin, its anchor was not a "
        "proof Ledger (synthetic is false), and the whole-run classification is "
        "MATCH or MISMATCH. The reviewed worker digest, the receipt, the frozen "
        "inputs, the gate snapshot and the Ledger row are checked where the object "
        "is built. An executionKind label never establishes it."
    ),
    "syntheticAnchor": (
        "An acquisition anchored in a proof Ledger is reported with synthetic true "
        "on the object and syntheticAnchor true on the comparison; its rows are the "
        "semantic result of a local proof and acquisitionValidated stays false."
    ),
    "refused": (
        "A production record without a VerifiedAcquisition, or with one bound to "
        "another collection, is REFUSED with the reason named in errors and no rows; "
        "it is never a production comparison."
    ),
}


def _json_value(value: Any, depth: int = 0, remaining: list[int] | None = None) -> bool:
    """Bounded JSON validation before hashing/equality; bool is not an integer."""
    if remaining is None:
        remaining = [100_000]
    remaining[0] -= 1
    if depth > 64 or remaining[0] < 0:
        return False
    kind = type(value)
    if value is None or kind in (str, bool):
        return True
    if kind is int:
        return value.bit_length() <= 4096
    if kind is float:
        return math.isfinite(value)
    if kind is list:
        return all(_json_value(v, depth + 1, remaining) for v in value)
    if kind is dict and all(type(k) is str for k in value):
        return all(_json_value(v, depth + 1, remaining) for v in value.values())
    return False


def _same_json(left: Any, right: Any) -> bool:
    # Called only after _json_value; keep numeric types, but not object-key order.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def _collection_errors(collection: Any, side: str, nonce: str | None) -> list[str]:
    """Validate identity, not outcomes. Partial runs may still have useful rows.

    A recovery attempt can legitimately repeat a case ID. Only observation-phase
    case rows must be unique and ordered; a recovery response cannot fill a hole.
    This check does not authenticate local execution or replace O8 verification.
    """
    if type(collection) is not dict or not _json_value(collection):
        return [f"{side}-collection-json"]
    errors = []
    if collection.get("campaignId") != CASE_ID:
        errors.append(f"{side}-collection-campaign")
    nonce_digest = collection.get("nonceDigest")
    if (
        type(nonce_digest) is not str
        or _HEX64.fullmatch(nonce_digest) is None
        or (nonce is not None and nonce_digest != digest(nonce))
    ):
        errors.append(f"{side}-collection-nonce")
    rows = collection.get("rows")
    if type(rows) is not list or len(rows) > MAX_REQUESTS:
        return [*errors, f"{side}-collection-rows"]
    if type(collection.get("rowCount")) is not int or collection["rowCount"] != len(
        rows
    ):
        errors.append(f"{side}-collection-row-count")
    order = {case_id: i for i, case_id in enumerate(EXECUTION_ORDER)}
    seen: set[str] = set()
    last = -1
    roles = {"case", "poll", "verify", "reconcile", "preflight"}
    for index, row in enumerate(rows):
        if type(row) is not dict:
            errors.append(f"{side}-row-shape")
            continue
        if type(row.get("index")) is not int or row["index"] != index:
            errors.append(f"{side}-row-index")
        if row.get("phase") not in ("observation", "recovery"):
            errors.append(f"{side}-row-phase")
        role = row.get("role")
        if type(role) is not str or role not in roles:
            errors.append(f"{side}-row-role")
            continue
        if role != "case":
            continue
        case_id = row.get("case")
        if type(case_id) is not str or case_id not in order:
            errors.append(f"{side}-unknown-case")
            continue
        if row.get("phase") != "observation":
            continue
        if case_id in seen:
            errors.append(f"{side}-duplicate-observation:{case_id}")
        elif order[case_id] <= last:
            errors.append(f"{side}-observation-order")
        seen.add(case_id)
        last = order[case_id]
    return sorted(set(errors))


def _case_rows(collection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    # _collection_errors must run first; never resolve duplicates by picking one.
    return {
        row["case"]: row
        for row in collection["rows"]
        if row["role"] == "case" and row["phase"] == "observation"
    }


def _observation_errors(row: dict[str, Any] | None) -> list[str]:
    if row is None:
        return ["missing-observation"]
    errors = []
    if row.get("complete") is not True:
        errors.append("incomplete-observation")
    if "failure" not in row or row["failure"] is not None:
        errors.append("failed-observation")
    status = row.get("status")
    if type(status) is not int or not 200 <= status <= 599:
        errors.append("invalid-http-status")
    elif status in (401, 403, 429):
        # This Admin campaign tests field settings, not authentication or quotas.
        errors.append("credential-or-quota-refusal")
    if "shape" not in row:
        errors.append("missing-response-shape")
    error = row.get("typedError")
    if "typedError" not in row or (
        error is not None
        and (
            type(error) is not dict
            or set(error) != {"code", "status"}
            or type(error.get("code")) is not int
            or not (error.get("status") is None or type(error["status"]) is str)
        )
    ):
        errors.append("invalid-typed-error")
    return errors


def _run_errors(collection: dict[str, Any], side: str) -> list[str]:
    errors = []
    if collection.get("completed") is not True:
        errors.append(f"{side}-observation-incomplete")
    if "stopPoint" not in collection or collection["stopPoint"] is not None:
        errors.append(f"{side}-observation-stopped")
    if "failure" not in collection or collection["failure"] is not None:
        errors.append(f"{side}-collection-failed")
    if collection.get("cleanupComplete") is not True:
        errors.append(f"{side}-cleanup-incomplete")
    return errors


def _record_errors(record: Any, side: str) -> list[str]:
    if not isinstance(record, dict):
        return [f"{side}-record-shape"]
    errors = []
    if record.get("executionKind") not in EXECUTION_KINDS:
        errors.append(f"{side}-execution-kind")
    collection = record.get("collection")
    if type(collection) is not dict or collection.get("campaignId") != CASE_ID:
        errors.append(f"{side}-collection-shape")
    elif not _json_value(collection):
        errors.append(f"{side}-collection-json")
    return errors


def compare_rows(
    local: dict[str, Any], production: dict[str, Any], nonce: str
) -> list[dict[str, Any]]:
    # Legacy descriptor.comparator supplies its saved LOCAL rehearsal nonce, not
    # the fresh production nonce. This kernel compares shapes only; full compare()
    # independently binds production to its manifest before it calls this function.
    expected_local = {
        case["id"]: case["expectedLocal"] for case in compile_cases(nonce)
    }
    errors = _collection_errors(local, "local", nonce) + _collection_errors(
        production, "production", None
    )
    if errors:
        return [
            {
                "case": case_id,
                "local": None,
                "production": None,
                "classification": INDETERMINATE,
                "errors": errors,
            }
            for case_id in expected_local
        ]
    local_rows, production_rows = _case_rows(local), _case_rows(production)
    rows = []
    for case_id, expected in expected_local.items():
        left, right = local_rows.get(case_id), production_rows.get(case_id)
        row: dict[str, Any] = {
            "case": case_id,
            "local": _summary(left),
            "production": _summary(right),
        }
        errors = [
            f"{side}:{error}"
            for side, observed in (("local", left), ("production", right))
            for error in _observation_errors(observed)
        ]
        if errors:
            row["classification"] = INDETERMINATE
            row["errors"] = errors
        elif (
            expected["outcome"] == "not-served"
            and left["status"] == 501
            and left["typedError"] == {"code": 501, "status": "UNIMPLEMENTED"}
            and right["typedError"] is None
            and type(right["status"]) is int
            and 200 <= right["status"] < 300
        ):
            # Only when production served the request that the classification
            # matrix says the local runtime refuses. A refusal on both sides is
            # compared like any other row, so it reads MATCH or MISMATCH and never
            # hides behind the expected deviation.
            row["classification"] = EXPECTED_LOCAL_DEVIATION
            row["reason"] = expected.get("refusalReason")
        elif all(
            _same_json(left[key], right[key])
            for key in ("status", "typedError", "shape")
        ):
            row["classification"] = MATCH
        else:
            row["classification"] = MISMATCH
            row["differs"] = [
                key
                for key in ("status", "typedError", "shape")
                if not _same_json(left[key], right[key])
            ]
        rows.append(row)
    return rows


def _summary(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "status": row.get("status"),
        "typedError": row.get("typedError"),
        "shapeDigest": digest(row.get("shape")),
        "complete": row.get("complete"),
    }


def _registered(acquisition: Any) -> bool:
    """Ask the O8 boundary whether it built this exact object.

    Imported here rather than at module level: the boundary imports this module,
    and the local rehearsal child must not load the O8 stack to compare rows.
    """
    from fs_config_lifecycle import lifecycle_production

    return lifecycle_production.verified(acquisition)


def _acquisition_errors(acquisition: Any, collection: dict[str, Any]) -> list[str]:
    """The comparator's own re-check of the verified acquisition against the record.

    The object's identity is required (a dict is a copy, not a verification; an
    instance the boundary did not register is a construction, not a verification),
    and every binding it names is compared here rather than trusted.
    """
    if type(acquisition) is not VerifiedAcquisition or not _registered(acquisition):
        return [ACQUISITION_UNVERIFIED]
    digests = (
        acquisition.receipt_digest,
        acquisition.gate_digest,
        acquisition.artifact_sha256,
        acquisition.worker_sha256,
        acquisition.collection_digest,
        acquisition.reservation,
    )
    if (
        acquisition.campaign_id != CASE_ID
        or acquisition.execution_kind != PRODUCTION_KIND
        or acquisition.endpoint != PRODUCTION_ORIGIN
        or not isinstance(acquisition.ledger_identity, str)
        or not acquisition.ledger_identity
        or any(not isinstance(v, str) or _HEX64.fullmatch(v) is None for v in digests)
        or acquisition.collection_digest != digest(collection)
        or type(acquisition.synthetic) is not bool
    ):
        return [ACQUISITION_BINDING]
    return []


def compare(
    manifest: dict[str, Any],
    local: Any,
    production: Any,
    nonce: str,
    *,
    acquisition: VerifiedAcquisition | None = None,
    local_nonce: str | None = None,
) -> dict[str, Any]:
    """Compare a local record with a verified production record under a drift-checked
    manifest.

    `acquisition` is the object `lifecycle_production.verify_saved` returned for the
    receipt directory `production` was read from. Without it, or with one bound to
    another collection, the comparison is REFUSED: the production label alone is not
    an acquisition. ``nonce`` binds the production manifest; ``local_nonce``
    explicitly names a saved local rehearsal with another nonce (defaults to nonce).
    Neither nonce is inferred from an input record's self-reported digest.
    """
    result: dict[str, Any] = {
        "kind": SCHEMA,
        "classification": PREPARATION_ONLY,
        "promotionReady": False,
        "acquisitionValidated": False,
        "syntheticAnchor": None,
        "productionUnobservedConditionsReduced": 0,
        "contract": COMPARISON_CONTRACT,
        "rows": [],
        "errors": [],
    }
    if (
        type(manifest) is not dict
        or not _json_value(manifest)
        or manifest.get("schema") != MANIFEST_SCHEMA
    ):
        result["errors"] = ["manifest-invalid"]
        return result
    try:
        expected = compile_manifest(nonce)
    except ValueError:
        result["errors"] = ["nonce-invalid"]
        return result
    if not _same_json(manifest, expected):
        result["errors"] = ["manifest-drift"]
        return result
    errors = _record_errors(local, "local") + _record_errors(production, "production")
    if errors:
        result["errors"] = sorted(set(errors))
        return result
    if local["executionKind"] != LOCAL_KIND or production["executionKind"] != (
        PRODUCTION_KIND
    ):
        result["errors"] = ["preparation-only"]
        return result
    errors = _acquisition_errors(acquisition, production["collection"])
    if errors:
        result["classification"] = REFUSED
        result["errors"] = errors
        return result
    local_nonce = nonce if local_nonce is None else local_nonce
    try:
        compile_cases(local_nonce)
    except (TypeError, ValueError):
        result["classification"] = INDETERMINATE
        result["errors"] = ["local-nonce-invalid"]
        return result
    errors = _collection_errors(
        local["collection"], "local", local_nonce
    ) + _collection_errors(production["collection"], "production", nonce)
    if errors:
        result["classification"] = INDETERMINATE
        result["errors"] = sorted(set(errors))
        return result
    result["acquisition"] = acquisition.summary()
    result["syntheticAnchor"] = acquisition.synthetic
    rows = compare_rows(local["collection"], production["collection"], local_nonce)
    result["rows"] = rows
    result["localCleanupComplete"] = local["collection"].get("cleanupComplete") is True
    result["productionCleanupComplete"] = (
        production["collection"].get("cleanupComplete") is True
    )
    classes = {row["classification"] for row in rows}
    result["errors"] = _run_errors(local["collection"], "local") + _run_errors(
        production["collection"], "production"
    )
    # A known mismatch remains in rows, but an incomplete run is not a completed
    # acquisition comparison. Neither missing rows nor expected deviations are MATCH.
    if result["errors"] or not rows or INDETERMINATE in classes:
        result["classification"] = INDETERMINATE
    elif MISMATCH in classes:
        result["classification"] = MISMATCH
    elif EXPECTED_LOCAL_DEVIATION in classes:
        result["classification"] = EXPECTED_LOCAL_DEVIATION
    else:
        result["classification"] = MATCH
    result["acquisitionValidated"] = not acquisition.synthetic and result[
        "classification"
    ] in (MATCH, MISMATCH)
    return result
