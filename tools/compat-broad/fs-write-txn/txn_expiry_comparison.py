"""Credential-free comparator for the transaction expiry / retry campaign.

The comparator reads two collector receipts, one produced against production and
one against the local emulator, and reports one of four verdicts:

``MATCH``
    Every case agrees after projecting away the volatile identities, and the
    identities agree too.
``EXPECTED_NONDETERMINISM``
    Every case agrees, but the identities differ. Two runs against different
    projects with different nonces and tokens always land here.
``SEMANTIC_MISMATCH``
    At least one case's code or normalized diagnostic differs.
``INDETERMINATE``
    A receipt is incomplete, unbound, unrecovered, or was collected against the
    wrong target. An infrastructure failure is never a semantic mismatch.

The comparator never claims acquisition validity or parent promotion. Those are
separate, later judgements.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
import txn_expiry_collector as collector
from broad_contract import digest

CONTRACT = "txn-expiry-comparison-v1"

MATCH = "MATCH"
EXPECTED_NONDETERMINISM = "EXPECTED_NONDETERMINISM"
SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"
INDETERMINATE = "INDETERMINATE"

RESOURCE_SLOT = "<fireemu:o3-txn-expiry:resource>"
TOKEN_SLOT = "<fireemu:o3-txn-expiry:token>"

#: Strings that must never appear in a receipt handed to the comparator.
CREDENTIAL_MARKERS = ("refresh_token", "client_secret", "ya29.", "Bearer ")

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z")


def normalize_message(message, receipt):
    """Replace request-bound resource identities and instants with fixed slots."""
    if not message:
        return message
    value = message
    project = receipt.get("projectId") or ""
    prefix = receipt.get("documentPrefix") or ""
    nonce = receipt.get("nonce") or ""
    for role in cases.RESOURCE_ROLES:
        if prefix:
            full = collector.document_name(
                project, receipt.get("database") or "", f"{prefix}/{role}"
            )
            value = value.replace(full, RESOURCE_SLOT)
            value = value.replace(f"{prefix}/{role}", RESOURCE_SLOT)
    if prefix:
        value = value.replace(prefix, RESOURCE_SLOT)
    if nonce:
        value = value.replace(nonce, TOKEN_SLOT)
    if project:
        value = value.replace(project, RESOURCE_SLOT)
    return _TIMESTAMP.sub(TOKEN_SLOT, value)


def _case_rows(receipt):
    return {row["caseId"]: row for row in receipt.get("rows", []) if row.get("caseId")}


def _projection(receipt):
    projected = {}
    for case_id, row in _case_rows(receipt).items():
        projected[case_id] = {
            "code": row["observed"]["code"],
            "status": row["observed"]["status"],
            "message": normalize_message(row["observed"]["message"], receipt),
            "rpc": row["rpc"],
            "role": row["role"],
        }
    return projected


def _identities(receipt):
    return {
        "projectId": receipt.get("projectId"),
        "documentPrefix": receipt.get("documentPrefix"),
        "nonce": receipt.get("nonce"),
        "database": receipt.get("database"),
    }


def _timing(receipt):
    timing = {}
    for case_id, row in _case_rows(receipt).items():
        waited = row.get("waited")
        timing[case_id] = None if waited is None else dict(waited)
    return timing


def _reasons(receipt, side, *, expect_target):
    reasons = []
    if not isinstance(receipt, dict):
        reasons.append({"code": "receipt-missing", "side": side})
        return reasons
    if receipt.get("kind") != collector.CONTRACT:
        reasons.append({"code": "receipt-kind", "side": side})
    if receipt.get("casesDigest") != cases.cases_digest():
        reasons.append({"code": "cases-digest", "side": side})
    if receipt.get("target") != expect_target:
        reasons.append({"code": "wrong-target", "side": side})
    if receipt.get("failure"):
        reasons.append(
            {"code": "collection-failed", "side": side, "detail": receipt["failure"]}
        )
    if receipt.get("missingCases"):
        reasons.append(
            {
                "code": "missing-cases",
                "side": side,
                "detail": list(receipt["missingCases"]),
            }
        )
    if receipt.get("unrecovered"):
        reasons.append(
            {
                "code": "unrecovered-resources",
                "side": side,
                "detail": list(receipt["unrecovered"]),
            }
        )
    if expect_target == "production" and receipt.get("timing") != collector.WALL_CLOCK:
        reasons.append({"code": "production-timing-simulated", "side": side})
    rendered = repr(receipt)
    for marker in CREDENTIAL_MARKERS:
        if marker in rendered:
            reasons.append({"code": "credential-material-in-receipt", "side": side})
            break
    return reasons


def _elapsed_reasons(receipt, side):
    reasons = []
    rows = _case_rows(receipt)
    for case in cases.CASES:
        required = case["requiresElapsedSeconds"]
        if not required:
            continue
        row = rows.get(case["id"])
        if row is None:
            continue
        reached = _reached_seconds(receipt, case["id"])
        if reached < required:
            reasons.append(
                {
                    "code": "elapsed-time-not-reached",
                    "side": side,
                    "detail": {
                        "case": case["id"],
                        "required": required,
                        "reached": reached,
                    },
                }
            )
    return reasons


def _reached_seconds(receipt, case_id):
    total = 0
    for row in receipt.get("rows", []):
        waited = row.get("waited")
        if waited:
            total += waited.get("seconds", 0)
        if row.get("caseId") == case_id:
            return total
    return total


def compare(production, local):
    """Compare a production receipt against a local receipt."""
    result = {
        "kind": CONTRACT,
        "campaign": cases.CAMPAIGN,
        "acquisitionValidated": False,
        "promotionReady": False,
    }
    reasons = _reasons(production, "production", expect_target="production")
    reasons += _reasons(local, "local", expect_target="local")
    if not reasons:
        reasons += _elapsed_reasons(production, "production")
        reasons += _elapsed_reasons(local, "local")
    if reasons:
        return {**result, "classification": INDETERMINATE, "reasons": reasons}

    production_projection = _projection(production)
    local_projection = _projection(local)
    differences = {
        case_id: {
            "production": production_projection.get(case_id),
            "local": local_projection.get(case_id),
        }
        for case_id in sorted(set(production_projection) | set(local_projection))
        if production_projection.get(case_id) != local_projection.get(case_id)
    }
    timing = {
        "production": _timing(production),
        "local": _timing(local),
        "mechanismDiffers": production.get("timing") != local.get("timing"),
        "note": (
            "The elapsed-time mechanism is allowed to differ. Production waits "
            "real seconds; the local emulator advances its virtual clock. Only "
            "the observed codes, diagnostics and post-state are compared."
        ),
    }
    bindings = {
        "casesDigest": cases.cases_digest(),
        "productionSourceDigest": production.get("sourceDigest"),
        "localSourceDigest": local.get("sourceDigest"),
        "productionProjectionDigest": digest(production_projection),
        "localProjectionDigest": digest(local_projection),
    }
    if differences:
        return {
            **result,
            "classification": SEMANTIC_MISMATCH,
            "differences": differences,
            "timing": timing,
            "bindings": bindings,
        }
    identical = _identities(production) == _identities(local)
    return {
        **result,
        "classification": MATCH if identical else EXPECTED_NONDETERMINISM,
        "timing": timing,
        "bindings": bindings,
        "casesCompared": sorted(production_projection),
    }


def local_self_contract(local):
    """Check a local receipt against the frozen expected local results.

    This is not a production comparison. It only reports whether the local
    emulator did what the frozen case table says it should.
    """
    reasons = _reasons(local, "local", expect_target="local")
    reasons += _elapsed_reasons(local, "local")
    if reasons:
        return {
            "kind": "txn-expiry-local-self-contract-v1",
            "classification": INDETERMINATE,
            "reasons": reasons,
        }
    rows = _case_rows(local)
    disagreements = {}
    for case in cases.CASES:
        row = rows[case["id"]]
        expected = case["expectedLocal"]
        observed = row["observed"]
        message = observed["message"]
        agrees = observed["code"] == expected["code"] and (
            expected["message"] is None
            or (message is not None and expected["message"] in message)
        )
        if not agrees:
            disagreements[case["id"]] = {"expected": expected, "observed": observed}
    return {
        "kind": "txn-expiry-local-self-contract-v1",
        "classification": SEMANTIC_MISMATCH if disagreements else MATCH,
        "disagreements": disagreements,
        "casesChecked": sorted(rows),
    }
