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

RESOURCE_SLOT = collector.RESOURCE_SLOT
TOKEN_SLOT = collector.TOKEN_SLOT

#: The suffix a post-state entry carries in a difference or disagreement map,
#: so a reader can tell "the backend answered differently" from "the backend
#: left the document in a different state".
POST_STATE = "#postState"

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


def _post_states(receipt):
    """The document each case left behind, keyed by the case it verifies."""
    states = {}
    for row in receipt.get("rows", []):
        case_id = row.get("verifiesCase")
        if case_id:
            states[case_id] = {"role": row.get("role"), "document": row.get("document")}
    return states


def _observed_state(entry):
    """The marker state a readback found, or None when there is no document."""
    document = (entry or {}).get("document") or {}
    if not document.get("exists"):
        return None
    field = (document.get("fields") or {}).get("state") or {}
    return field.get("stringValue")


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
    if receipt.get("complete") is not True:
        reasons.append({"code": "receipt-not-complete", "side": side})
    if receipt.get("clockIntegrityFailure") is not None or receipt.get("virtualClockConfirmed", True) is not True:
        reasons.append({"code": "clock-not-confirmed", "side": side})
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
    if receipt.get("unconfirmedTransactionStarts"):
        reasons.append({"code": "transaction-start-unconfirmed", "side": side})
    if receipt.get("openTransactions"):
        reasons.append(
            {
                "code": "open-transactions",
                "side": side,
                "detail": list(receipt["openTransactions"]),
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
    unconfirmed = [
        entry
        for entry in receipt.get("responsibility") or []
        if not entry.get("resolved")
    ]
    if unconfirmed:
        # The run sent a create and never learned whether it took effect. The
        # workspace it claims to describe is not known to be its own.
        reasons.append(
            {
                "code": "unconfirmed-resource-ownership",
                "side": side,
                "detail": unconfirmed,
            }
        )
    if receipt.get("authorityRefusal"):
        # The run was told it may not act, so it stopped sending. Whatever it
        # did record before that is not a complete observation.
        reasons.append(
            {
                "code": "authority-refused",
                "side": side,
                "detail": receipt["authorityRefusal"],
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
    """Refuse a receipt whose measured idle time does not support its cases.

    The number checked is what the run observed, not what the plan asked for. A
    collector that skipped its waits, or whose clock advance was not applied,
    fails here rather than producing a semantic verdict.
    """
    reasons = []
    rows = _case_rows(receipt)
    limit = cases.DECLARED_IDLE_LIMIT_SECONDS
    for case in cases.CASES:
        required = case["requiresElapsedSeconds"]
        if not required:
            continue
        row = rows.get(case["id"])
        if row is None:
            continue
        measured = row.get("idleSeconds")
        if measured is None:
            reasons.append(
                {
                    "code": "elapsed-time-not-measured",
                    "side": side,
                    "detail": {"case": case["id"]},
                }
            )
            continue
        if not collector.finite_seconds(measured):
            reasons.append({"code": "elapsed-time-invalid", "side": side,
                            "detail": {"case": case["id"]}})
            continue
        if measured < required:
            reasons.append(
                {
                    "code": "elapsed-time-not-reached",
                    "side": side,
                    "detail": {
                        "case": case["id"],
                        "required": required,
                        "measured": measured,
                    },
                }
            )
        elif case["kind"] == "control" and measured >= limit:
            # A control that was meant to stay below the idle limit but aged
            # past it during a slow run proves nothing; it is not a mismatch.
            reasons.append(
                {
                    "code": "control-aged-past-idle-limit",
                    "side": side,
                    "detail": {
                        "case": case["id"],
                        "limit": limit,
                        "measured": measured,
                    },
                }
            )
    reasons += _wait_reasons(receipt, side)
    reasons += _post_state_reasons(receipt, side)
    return reasons


def _wait_reasons(receipt, side):
    """Every recorded wait must report the interval it actually observed."""
    reasons = []
    for row in receipt.get("rows", []):
        waited = row.get("waited")
        if not waited:
            continue
        measured = waited.get("measuredSeconds")
        if measured is None:
            reasons.append(
                {
                    "code": "wait-not-measured",
                    "side": side,
                    "detail": {"slot": row.get("slot")},
                }
            )
        elif not collector.finite_seconds(measured) or not collector.finite_seconds(waited.get("requestedSeconds")):
            reasons.append({"code": "wait-time-invalid", "side": side,
                            "detail": {"slot": row.get("slot")}})
        elif measured < waited.get("requestedSeconds", 0):
            reasons.append(
                {
                    "code": "wait-shorter-than-requested",
                    "side": side,
                    "detail": {
                        "slot": row.get("slot"),
                        "requested": waited.get("requestedSeconds"),
                        "measured": measured,
                    },
                }
            )
    return reasons


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
    production_states = _post_states(production)
    local_states = _post_states(local)
    for case_id in sorted(set(production_states) | set(local_states)):
        if production_states.get(case_id) != local_states.get(case_id):
            differences[case_id + POST_STATE] = {
                "production": production_states.get(case_id),
                "local": local_states.get(case_id),
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
        "productionPostStateDigest": digest(_post_states(production)),
        "localPostStateDigest": digest(_post_states(local)),
    }
    if differences:
        return {
            **result,
            "classification": SEMANTIC_MISMATCH,
            "differences": differences,
            "timing": timing,
            "bindings": bindings,
        }
    if production.get("sourceDigest") != local.get("sourceDigest"):
        return {
            **result,
            "classification": INDETERMINATE,
            "reasons": [{"code": "collector-source-digest-differs"}],
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


def _post_state_reasons(receipt, side):
    """A declared post state that was never read back proves nothing.

    This is an incomplete receipt, not a disagreement, so it makes the whole
    comparison indeterminate rather than reporting a mismatch nobody observed.
    """
    states = _post_states(receipt)
    reasons = []
    for case in cases.CASES:
        declared = case["postState"]
        if not declared:
            continue
        entry = states.get(case["id"])
        if entry is None:
            reasons.append(
                {
                    "code": "post-state-not-read",
                    "side": side,
                    "detail": {"case": case["id"]},
                }
            )
        elif (entry.get("document") or {}).get("incomplete"):
            # The readback did not describe the requested document, so it is a
            # missing observation rather than a state anyone disagrees about.
            reasons.append(
                {
                    "code": "post-state-readback-incomplete",
                    "side": side,
                    "detail": {
                        "case": case["id"],
                        "incomplete": entry["document"]["incomplete"],
                    },
                }
            )
        elif entry["role"] not in declared:
            reasons.append(
                {
                    "code": "post-state-reads-another-resource",
                    "side": side,
                    "detail": {"case": case["id"], "role": entry["role"]},
                }
            )
    return reasons


def _post_state_disagreements(local):
    """Check each case's declared post state against the readback that follows it.

    A code is what the backend said. The declared post state is what the case
    claims the backend did. A commit that returns OK without writing, and a
    refusal that writes anyway, both agree on the code and disagree here.
    """
    states = _post_states(local)
    found = {}
    for case in cases.CASES:
        declared = case["postState"]
        if not declared:
            continue
        key = case["id"] + POST_STATE
        entry = states.get(case["id"])
        if entry is None:
            continue
        expected = declared.get(entry["role"])
        if expected is None:
            continue
        observed = _observed_state(entry)
        if observed != expected:
            found[key] = {
                "expected": expected,
                "observed": observed,
                "role": entry["role"],
            }
    return found


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
    disagreements.update(_post_state_disagreements(local))
    return {
        "kind": "txn-expiry-local-self-contract-v1",
        "classification": SEMANTIC_MISMATCH if disagreements else MATCH,
        "disagreements": disagreements,
        "casesChecked": sorted(rows),
    }
