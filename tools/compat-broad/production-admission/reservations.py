"""One-host shared reservations underneath O7; never grants production permission.

Full campaign upper bounds remain allocated forever, including unused capacity.
Only locks/concurrency are released after the registered Gate proves cleanup.
The O7 caller must use one shared root and bind its identity into every campaign.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import hashlib
import json
import math
import re
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import os
import platform
import stat

from broad_contract import digest
from shared_gate import (
    LIMITS_PREPARATION_RECEIPT,
    LIMITS_PREPARATION_TRANSPORT,
    Gate,
    _management_receipt_valid,
    _auth_creation_ownership,
    _auth_recovery_operation_valid,
    _save,
    abandoned_cleanup_complete,
    auth_typed_absence,
    canonical_body_bytes,
    non_creating_dispatches,
    typed_absence,
    unconfirmed_creates,
    validate_absence_proofs,
    validate_limits_preparation_plan,
    validate_limits_preparation_response,
    validate_limits_preparation_success,
)

DIMENSIONS = {"requests", "accounts", "resources", "costMicrousd"}
# The owner's US$10 is per production observation task, identified by the
# claim's campaignId, and never cumulative across the program. Every earlier
# reservation of the task counts whatever state it reached, because an
# allocation is never refunded.
TASK_CAP_MICROUSD = 10_000_000
TASK_BUDGET_REFUSAL = "task-budget-exceeded:"
AUTH_REV3_WALL_SECONDS = 1500
AUTH_REV3_CAMPAIGN_ID = "AUTH-MFA-AGE-TOTP-01"
AUTH_REV3_SELECTOR = "pending-lifetime-rev3-v1"
# The closed set of production observation tasks that budget is authorized
# for: the stable campaign id each lane declares, without attempt or version
# suffixes (the write-txn stream lane's v2..v9 records are re-checks of the
# one task). A claim naming anything else (a nonce, a fixture label, a
# versioned id) is refused at reservation time, so an attempt cannot earn
# itself a fresh US$10 by renaming its task. Rows already in a ledger are
# not re-validated against this set: a reservation is history once written.
CATALOGUED_CAMPAIGN_IDS = frozenset(
    {
        "AUTH-ACTION-OOB-DELIVERY-BOUNDARY-01",
        "AUTH-CREDENTIAL-TOKENS-01",
        "AUTH-MFA-AGE-TOTP-01",
        "AUTH-MFA-TOTP-ENROLL-RETRY-01",
        "FS-CONFIG-LIFECYCLE-01",
        "FS-DATA-QUERY-IN-BOUNDARY-04",
        "FS-DATA-WRITE-COMMIT-TRANSFORMS-03",
        "FS-DATA-WRITE-LIMITS-02",
        "FS-LIMIT-API-REQUEST-BYTES",
        "FS-QUERY-PARTITION-CURSOR-04",
        "FS-RULES-PUBLICATION-USER-TOKEN-01",
        "FS-RULES-USER-TOKEN-MATRIX-01",
        "FS-TRANSACTION-EXPIRY-RETRY-04",
        "FS-WRITE-LIMITS-03",
        "FS-WRITE-TXN-PRECEDENCE-01",
    }
)
GENERATION_FIELDS = {"sourceCommit", "collectorSourceDigest", "sourceDigests"}
MAX_GENERATION_SOURCES = 64
# The source closure of the reservations written before a reservation recorded
# its own generation. Rows without a recorded generation predate that binding
# and can only be retired by proving this closure; every new row binds the
# generation it was acquired under instead. This is history, not a default.
COMMIT_SOURCE_COMMIT = "09c02557e9a537208a7912f039edb23c1131b1fc"
COMMIT_COLLECTOR_SOURCE_DIGEST = (
    "b9ae95ca922873d477fc171b08b2bc542721a699c5c0c6714ef22a4f846b54ca"
)
COMMIT_SOURCE_DIGESTS = {
    "shared_gate.py": "7913f62224ffe89a943adc5fa88437a3e94f38ff9c6eac5037599ee9233d7bcc",
    "reservations.py": "96adb8b4d6c482914f0eaf155fb70a9a3b6fc2b5f7f642d24638d2daac0bb7c9",
    "commit_reserved_adapter.py": "bd3baf3d46a0a252237d1b7b9cda950d4db8eb2658b2f7502a27d0d04b6fc2e3",
    "gate_adapter.py": "a5221f4c4d572a95018772067e5a8364fffea0bd199528da43cf45b470cdd2fa",
    "commit_acquisition.py": "b5c1df452eed0f4c322083b233e94fa77da3c1db27f443c3328e780e3d2d10b0",
}
LEGACY_COMMIT_GENERATION = {
    "sourceCommit": COMMIT_SOURCE_COMMIT,
    "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
    "sourceDigests": COMMIT_SOURCE_DIGESTS,
}
# The production preflight an acquisition actually issues: the Coordinator takes
# two credential slots before any observation, then the adapter makes four
# privileged metadata GETs in this order. A no-data stop can happen at any one
# of them, so the evidence contract admits a prefix rather than one fixed point.
CREDENTIAL_MANAGEMENT = (
    "observation:oauth-refresh",
    "observation:oauth-tokeninfo",
)
PREFLIGHT_OBSERVATIONS = (
    "observation:project",
    "observation:database",
    "observation:auth",
    "observation:key",
)
MODES = {"READ": 0, "WRITE": 1, "EXCLUSIVE": 2}
MAX_BYTES = 16 * 1024 * 1024
MAX_RESERVATIONS = 10000

CONFIGURATION_RELEASE_KIND = "fs-config-lifecycle-release-v1"
CONFIGURATION_GATE_PLAN_KIND = "fs-config-lifecycle-gate-plan-v1"
CONFIGURATION_CAMPAIGN = "FS-CONFIG-LIFECYCLE-01"
CONFIGURATION_FINISHED_STATES = frozenset({"not-applied", "apply-refused", "restored"})

# The recovery compiler reserves the complete bounded Gate plan.  Its separate
# tariff estimate is descriptive only; it is never substituted for Gate cost.
RECOVERY_CHILD_KIND = "shared-recovery-child-claim-v2"
RECOVERY_CHILD_REQUESTS = 85
RECOVERY_CHILD_COST_MICROUSD = 85
RECOVERY_TARIFF_ESTIMATE_MICROUSD = 45
RECOVERY_INSPECTION_REQUESTS = 17
RECOVERY_ABSENCE_REQUESTS = 51
RECOVERY_DELETE_REQUESTS = 17
RECOVERY_OPERATION_CLASS = "read-inspect-conditional-delete-v1"
RECOVERY_GATE_JOB = "request-bytes-recovery-extension"
RECOVERY_SENTINEL_CASE_ID = "FS-LIMIT-API-REQUEST-BYTES-RAW-16MIB-OVER"
RECOVERY_SENTINEL_REQUESTS = 60
RECOVERY_SENTINEL_COST_MICROUSD = 60
RECOVERY_SENTINEL_INSPECTION_REQUESTS = 20
RECOVERY_SENTINEL_ABSENCE_REQUESTS = 20
RECOVERY_SENTINEL_DELETE_REQUESTS = 20
RECOVERY_SENTINEL_TARIFF_ESTIMATE_MICROUSD = 28
RECOVERY_CHILD_FIELDS = {
    "kind", "version", "campaignId", "manifestDigest", "nonceDigest",
    "gatePath", "gatePlanDigest", "locks", "budget", "durationSeconds",
    "generation", "parentClaimDigest", "parentPlanDigest", "recoveryNonce",
    "selectedProbe", "resourceDigest", "ownedResources", "ownerIdentity",
    "recoveryOwner", "operationClass", "readCount", "inspectionCount",
    "absenceCount", "deleteCount", "tariffEstimateMicrousd", "expiresAt",
    "executionHost", "permissionDigest",
}

# Auth packet05 uses a deliberately separate recovery contract. It is not a
# variant of the request-bytes 85-slot compiler: the child can perform one
# lookup for the one planned custom UID, and it can never authorize deletion.
AUTH_RECOVERY_CHILD_KIND = "auth-custom-uid-recovery-child-v1"
AUTH_RECOVERY_OPERATION_CLASS = "auth-custom-uid-lookup-only-v1"
AUTH_RECOVERY_ABSENCE_KIND = "auth-uid-absence-proof-v1"
AUTH_RECOVERY_PARENT_EVIDENCE_KIND = "auth-parent-uncertain-create-v1"
AUTH_RECOVERY_LEGACY_PARENT_EVIDENCE_KIND = "auth-parent-legacy-200-unproven-v1"
AUTH_RECOVERY_LEGACY_SOURCE_COMMIT = "2d7d9b76c0f8bf3e3716ac98b19b132d0b8e1f1f"
AUTH_RECOVERY_LEGACY_CLAIM_DIGEST = "515fcaffc285efe7a0c7e6d4556a6427327f05e95a695f5f20ca43cdbf7af072"
AUTH_RECOVERY_LEGACY_PLAN_DIGEST = "59d1b40a4d2b6e34dc8664470fa08d38eca0a11b35fce165649bc7b2554dc1cc"
AUTH_RECOVERY_LEGACY_GATE_DIGEST = "6aae5fc3bde659f8b18eef8d2e58d9932c2f896a9fec1d230690cc54ee8827fe"
AUTH_RECOVERY_LEGACY_EVENT_INDEX = 13
AUTH_RECOVERY_CAMPAIGN = "AUTH-CREDENTIAL-TOKENS-01"
AUTH_RECOVERY_MAX_COST_MICROUSD = 50_000
AUTH_PARENT_OBSERVATION_KINDS = frozenset({
    "sign-up", "custom-sign-in", "refresh", "refresh-unknown", "sign-in",
    "update", "lookup", "admin-lookup", "create-session-cookie",
    "send-oob-code", "reset-password",
})
AUTH_PARENT_RECOVERY_KINDS = frozenset({"delete", "uid-absence", "address-absence"})
AUTH_PARENT_SIGNUP_PATH = "identitytoolkit.googleapis.com/v1/accounts:signUp"
AUTH_PARENT_CUSTOM_SIGN_IN_PATH = "identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken"
AUTH_RECOVERY_CHILD_FIELDS = {
    "kind", "version", "campaignId", "manifestDigest", "nonceDigest", "gatePath",
    "gateJob", "parentGateJob", "gatePlanDigest", "parentClaimDigest", "parentPlanDigest",
    "parentGateDigest", "parentEvidenceDigest", "parentEventIndex", "parentRequestDigest",
    "recoveryNonce", "resourceDigest", "ownedResources", "locks", "budget",
    "durationSeconds", "generation", "ownerIdentity", "recoveryOwner", "operationClass",
    "readCount", "inspectionCount", "absenceCount", "deleteCount", "expiresAt",
    "executionHost", "permissionDigest", "sourceBindingDigest", "transportBindingDigest",
    "o7BindingDigest", "o8BindingDigest",
}


ABANDON_KIND = "shared-abandoned-cleanup-close-v1"
ABANDON_FIELDS = {"kind", "ticket", "gateDigest", "receiptPath", "receiptDigest"}
ESCALATION_KIND = "shared-owner-escalation-close-v1"
ATTESTATION_KIND = "owner-escalation-attestation-v1"
ESCALATION_FIELDS = {
    "kind",
    "ticket",
    "gateDigest",
    "receiptPath",
    "receiptDigest",
    "attestation",
    "absence",
}
ATTESTATION_FIELDS = {
    "kind",
    "status",
    "campaignId",
    "nonceDigest",
    "claimDigest",
    "ledgerRoot",
    "reservation",
    "receiptDigest",
    "gateDigest",
    "ownerIdentity",
    "recoveryOwner",
    "residueRemoved",
    "resourceCount",
    "resourcesDigest",
    "attestedAt",
    "expiresAt",
    "executionHost",
}
MAX_ATTESTATION_SECONDS = 86400
DEFAULT_RECEIPT_KIND = "commit-acquisition-receipt-v2"
DEFAULT_CREDENTIAL_SLOTS = ("refresh", "tokeninfo")
# The closed set of no-data receipt shapes. The Gate plan names the receipt
# kind its campaign publishes (`gatePlanDigest` binds that name to the claim),
# and the kind selects which evidence contract the receipt is held to. A kind
# outside this map has no retirement contract and is refused: an unfamiliar
# shape is never read as "close enough" to one of these.
COMMIT_NO_DATA_SCHEMA = "commit-credential-slots-v1"
REQUEST_BYTES_NO_DATA_SCHEMA = "request-bytes-management-attestation-v1"
REQUEST_BYTES_RECEIPT_KIND = "request-bytes-acquisition-receipt-v1"
# The transaction-expiry lane projects its receipt onto the Commit vocabulary
# (credential slot items, management slot ids in `metadata`) under a kind of
# its own, so it is held to the Commit contract by name, not by resemblance.
TXN_EXPIRY_RECEIPT_KIND = "txn-expiry-acquisition-receipt-v1"
PARTITION_CURSOR_RECEIPT_KIND = "partition-cursor-acquisition-receipt-v1"
# The limits-03 and auth-credential lanes both load
# fs-request-bytes-boundary/request_bytes_preflight.py at runtime for their own
# credential attestation (limits_03_preflight.py and credential_preflight.py
# each `_load` it as SHARED_PREFLIGHT_MODULE/REQUEST_BYTES_PREFLIGHT), and
# their receipts use the same field names the request-byte contract already
# binds row for row: `metadata`/`routeDigest`, `managementEvidence` rows of
# exactly {id, response, responseDigest}, `credentialEvidence` bodies of kind
# request-byte-token-attestation-v1, and a single declared `oauth-tokeninfo`
# credential id. They are not guessed into this contract: they run the same
# code that produces it.
LIMITS_03_RECEIPT_KIND = "limits-03-acquisition-receipt-v1"
AUTH_CREDENTIAL_RECEIPT_KIND = "auth-credential-acquisition-receipt-v1"
NO_DATA_RECEIPT_SCHEMAS = {
    LIMITS_PREPARATION_RECEIPT: REQUEST_BYTES_NO_DATA_SCHEMA,
    DEFAULT_RECEIPT_KIND: COMMIT_NO_DATA_SCHEMA,
    TXN_EXPIRY_RECEIPT_KIND: COMMIT_NO_DATA_SCHEMA,
    # The partition/cursor lane emits the Commit vocabulary verbatim: one
    # tokeninfo credential item, management attestation rows in metadata,
    # no collection and productionExecuted false on a preflight stop.
    PARTITION_CURSOR_RECEIPT_KIND: COMMIT_NO_DATA_SCHEMA,
    REQUEST_BYTES_RECEIPT_KIND: REQUEST_BYTES_NO_DATA_SCHEMA,
    LIMITS_03_RECEIPT_KIND: REQUEST_BYTES_NO_DATA_SCHEMA,
    AUTH_CREDENTIAL_RECEIPT_KIND: REQUEST_BYTES_NO_DATA_SCHEMA,
}
TOKEN_ATTESTATION_KIND = "request-byte-token-attestation-v1"
TOKEN_ATTESTATION_FIELDS = {
    "kind",
    "principalDigest",
    "requiredScopeVerified",
    "identityMode",
    "identityVerified",
    "oauthClientVerified",
    "expiresInSeconds",
    "remainingSecondsAtVerification",
    "requiredSeconds",
    "complete",
    "workerReaped",
}
MANAGEMENT_ROW_FIELDS = {"id", "response", "responseDigest"}
ROUTE_ROW_FIELDS = {"id", "route", "status", "responseDigest"}


def _gate_plan(gate):
    plan = gate.get("plan") if isinstance(gate, dict) else None
    return plan if isinstance(plan, dict) else {}


def _management(gate):
    """The campaign's credential and preflight management slots, in plan order.

    The sequence is read from the Gate plan, which `gatePlanDigest` binds to the
    claim and O7 binds to the approval, rather than from a literal that only
    describes the Commit campaign. A plan that declares neither keeps the Commit
    lane's own two credential slots, so its recorded rows read unchanged.
    """
    management = _gate_plan(gate).get("management")
    management = management if isinstance(management, dict) else {}
    declared = [
        "observation:" + item["id"]
        for item in management.get("observation", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    credential_ids = management.get("credentialIds")
    if not isinstance(credential_ids, list):
        credential_ids = [
            name.removeprefix("observation:") for name in CREDENTIAL_MANAGEMENT
        ]
    credentials = [
        "observation:" + name for name in credential_ids if isinstance(name, str)
    ]
    head = [name for name in declared if name in credentials]
    return head, [name for name in declared if name not in credentials]


def _credential_slots(gate):
    declared = _gate_plan(gate).get("management")
    declared = declared.get("credentialSlots") if isinstance(declared, dict) else None
    if not isinstance(declared, list) or not all(
        isinstance(name, str) for name in declared
    ):
        return list(DEFAULT_CREDENTIAL_SLOTS)
    return declared


def _receipt_kind(gate):
    declared = _gate_plan(gate).get("receiptKind")
    return declared if isinstance(declared, str) and declared else DEFAULT_RECEIPT_KIND


def _no_data_schema(gate):
    """The evidence contract the reserving plan's receipt kind selects, or None."""
    return NO_DATA_RECEIPT_SCHEMAS.get(_receipt_kind(gate))


def _commit_no_data_receipt(receipt, gate):
    """The Commit acquisition shape: credential slot items, management ids in `metadata`.

    Unchanged from the contract the recorded `aborted-no-data` rows validated
    under: two verified credential slots, then a prefix of the four privileged
    metadata observations, every one answered 200.
    """
    return (
        receipt.get("productionExecuted") is False
        and receipt.get("collection", object()) is None
        and [item.get("slot") for item in receipt.get("credentialEvidence", [])]
        == _credential_slots(gate)
        and not any(
            item.get("workerReaped") is not True
            or item.get("complete") is not True
            or item.get("verified") is not True
            or item.get("status") != 200
            for item in receipt["credentialEvidence"]
        )
        and _preflight_stop(receipt, gate) is not None
        and not any(item.get("status") != 200 for item in receipt["metadata"])
    )


def _request_bytes_no_data_receipt(receipt, gate):
    """The request-byte acquisition shape, bound row by row to the Gate journals.

    This campaign publishes no `slot`/`verified` credential items. Its receipt
    carries the charged management slots as `managementEvidence` rows, one per
    entry of the Gate's `managementUsed`, each holding the bounded response the
    Gate charged and digested; `credentialEvidence` holds the token attestation
    body of every credential slot that completed; and `metadata` is the data
    route journal, one row per Gate data event. A stop can fall before the
    first management slot, inside the management sequence, or during the
    non-creating ownership reads: each leaves a prefix of the declared
    observation slots, and the receipt must reproduce exactly that prefix.

    Nothing here decides whether data was written; `_no_data_gate` and the
    Gate's own `abort_no_data` do, from the journal. What this proves is that
    the receipt presented is the one this Gate produced.
    """
    management = _gate_plan(gate).get("management")
    management = management if isinstance(management, dict) else {}
    declared = [
        "observation:" + item["id"]
        for item in management.get("observation", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    credential_ids = management.get("credentialIds")
    if not isinstance(credential_ids, list) or not all(
        isinstance(name, str) for name in credential_ids
    ):
        return False
    credentials = ["observation:" + name for name in credential_ids]
    used = gate.get("managementUsed")
    events = gate.get("managementEvents")
    rows = receipt.get("managementEvidence")
    attestations = receipt.get("credentialEvidence")
    routes = receipt.get("metadata")
    if (
        not isinstance(used, list)
        or not isinstance(events, list)
        or not isinstance(rows, list)
        or not isinstance(attestations, list)
        or not isinstance(routes, list)
        or used != declared[: len(used)]
        or [event.get("id") for event in events] != used
        or [row.get("id") if isinstance(row, dict) else None for row in rows] != used
        or receipt.get("mayHaveCreated") is not False
        or receipt.get("preflightComplete") not in (True, False)
        or receipt.get("postflightComplete") is not False
        or receipt.get("routeDigest") != digest(routes)
    ):
        return False
    completed_credentials = []
    for row, event in zip(rows, events, strict=True):
        response = row.get("response") if isinstance(row, dict) else None
        if (
            set(row) != MANAGEMENT_ROW_FIELDS
            or not isinstance(response, dict)
            or row.get("responseDigest") != digest(response)
            or event.get("responseDigest") != row["responseDigest"]
            or event.get("bodyDigest") != digest(response.get("body"))
            or event.get("status") != response.get("status")
        ):
            return False
        if row["id"] in credentials and response.get("complete") is True:
            body = response.get("body")
            if (
                not isinstance(body, dict)
                or set(body) != TOKEN_ATTESTATION_FIELDS
                or body["kind"] != TOKEN_ATTESTATION_KIND
                or event.get("completed") is not True
            ):
                return False
            completed_credentials.append(body)
    if attestations != completed_credentials:
        return False
    # The data route journal must be the Gate's data journal, event for event:
    # a row per event, in order, on the same route digest and status. The
    # events themselves are non-creating by `_no_data_gate`; here only their
    # identity with the receipt is checked.
    data_events = gate.get("events")
    if (
        not isinstance(data_events, list)
        or len(routes) != len(data_events)
        or receipt.get("productionExecuted") is not bool(routes)
        or (receipt.get("collection") is None) is not (routes == [])
    ):
        return False
    for route, event in zip(routes, data_events, strict=True):
        if (
            not isinstance(route, dict)
            or set(route) != ROUTE_ROW_FIELDS
            or not isinstance(route["id"], str)
            or re.fullmatch(r"observation:[0-9]{3}", route["id"]) is None
            or event.get("phase") != "observation"
        ):
            return False
        if event.get("completed") is True and (
            route["status"] != event.get("status")
            or route["responseDigest"] != event.get("responseDigest")
        ):
            return False
        if event.get("completed") is not True and route["status"] is not None:
            return False
    return True


def _preflight_stop(receipt, gate):
    """How many preflight slots a no-data attempt consumed, or None if it is not one.

    A slot is charged before its evidence is appended, so a stop at slot `n`
    leaves `n` observations when the request was sent and its baseline
    comparison failed, and `n - 1` when the transport itself failed.
    """
    if not isinstance(gate, dict):
        return None
    head, preflight = _management(gate)
    used = gate.get("managementUsed")
    observed = [item.get("id") for item in receipt.get("metadata", [])]
    if used == head and observed == []:
        # A stop before the first preflight request, which for a campaign that
        # declares no preflight at all is the only shape it can stop in.
        return 0
    for count in range(1, len(preflight) + 1):
        expected = preflight[:count]
        if used == [*head, *expected] and observed in (expected, expected[:-1]):
            return count
    return None


def _owner_value(value):
    """An owner supplied identity: present, non-blank and not a template."""
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not value.strip().startswith("<<")
        and not value.strip().endswith(">>")
    )


def _owned_resources(gate):
    plan = _gate_plan(gate)
    jobs = plan.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return None
    names = [
        name
        for job in jobs.values()
        for name in (job.get("resources") or [])
        if isinstance(name, str)
    ]
    return sorted(names) if names else None


def _gate_plan_consistent(gate):
    """Whether the receipt's embedded Gate plan matches its own recorded digest.

    The retirement contract is read out of that plan, so `abort_no_data` pins it
    to its digest before any value is taken from it. Order independent: `digest`
    is canonical, so a re-serialized plan with the same content still matches.
    The check lives at the boundary that receives the untrusted receipt, not in
    `_no_data_gate`, which is a predicate over a snapshot's counters.
    """
    return isinstance(gate, dict) and digest(gate.get("plan")) == gate.get("planDigest")


def _no_data_gate(gate):
    """Whether a receipt's Gate snapshot proves that no document was written.

    A campaign whose probes read before they write sends data requests that
    create nothing, and a stop during them is a genuine no-data stop. Which
    slots can create is declared by the reviewed plan; a campaign that declares
    nothing is held to the stricter rule that no data request was sent at all.
    """
    jobs = gate.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return False
    dispatched = non_creating_dispatches(gate)
    return (
        dispatched is not None
        and gate.get("total") == len(gate.get("managementUsed", [])) + dispatched
        and gate.get("observation") == gate.get("total")
        and gate.get("recovery") == 0
        and all(
            job.get("recovery") == 0
            and job.get("owned") == []
            and job.get("creationProofs") == {}
            and job.get("absent") == []
            for job in jobs.values()
        )
    )


def _hash(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValueError("SHA-256 binding required")


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("finite nonnegative timestamp required")


def _budget(value):
    if (
        not isinstance(value, dict)
        or set(value) != DIMENSIONS
        or any(type(n) is not int or not 0 <= n < 2**63 for n in value.values())
    ):
        raise ValueError("closed integer budget required")


def _generation(value):
    """The source closure one reservation was acquired under.

    Proving it establishes that the abort runs sources identical to the
    acquisition's. It is an identity binding, not evidence of review.
    """
    if not isinstance(value, dict) or set(value) != GENERATION_FIELDS:
        raise ValueError("closed source generation required")
    if (
        not isinstance(value["sourceCommit"], str)
        or re.fullmatch(r"[a-f0-9]{40}", value["sourceCommit"]) is None
    ):
        raise ValueError("frozen source commit required")
    _hash(value["collectorSourceDigest"])
    sources = value["sourceDigests"]
    if (
        not isinstance(sources, dict)
        or not 1 <= len(sources) <= MAX_GENERATION_SOURCES
        or any(
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) is None
            or name in {".", ".."}
            for name in sources
        )
    ):
        raise ValueError("bounded acquisition source closure required")
    for name in sorted(sources):
        _hash(sources[name])


def task_spent_microusd(ledger_state, campaign_id):
    """Micro-USD already allocated to one task, across every reservation state."""
    if not isinstance(ledger_state, dict) or not isinstance(campaign_id, str):
        raise ValueError("ledger state and campaign id required")  # noqa: TRY004 -- refusal class, not a type report
    total = 0
    for row in ledger_state.get("reservations", {}).values():
        claim = row.get("claim") if isinstance(row, dict) else None
        if not isinstance(claim, dict) or claim.get("campaignId") != campaign_id:
            continue
        cost = claim.get("budget", {}).get("costMicrousd")
        if type(cost) is not int or cost < 0:
            raise ValueError("closed integer budget required")
        total += cost
        for child in row.get("recoveryChildren", []):
            child_claim = child.get("claim") if isinstance(child, dict) else None
            if isinstance(child_claim, dict) and child_claim.get("campaignId") == campaign_id:
                child_cost = child_claim.get("budget", {}).get("costMicrousd")
                if type(child_cost) is not int or child_cost < 0:
                    raise ValueError("closed integer recovery budget required")
                total += child_cost
    return total


def task_budget_check(
    ledger_state, campaign_id, new_cost_microusd, cap_microusd=TASK_CAP_MICROUSD
):
    """Refuse a claim that would take one task past its cap.

    Returns the task's projected total when admitted. The sum is over every
    reservation whose claim names the task, in every state, plus the new
    claim; the refusal names the task so the operator knows which US$10 is
    exhausted. Preparation, failed attempts, retries, re-checks after a fix
    and recovery of one task all land here; independent tasks each have
    their own cap, and the program-wide total is never a stop condition.
    """
    if (
        type(new_cost_microusd) is not int
        or new_cost_microusd < 0
        or type(cap_microusd) is not int
        or cap_microusd <= 0
    ):
        raise ValueError("closed integer task budget required")
    if campaign_id == "FS-WRITE-LIMITS-03":
        cap_microusd = min(cap_microusd, 1_000_000)
    projected = task_spent_microusd(ledger_state, campaign_id) + new_cost_microusd
    if projected > cap_microusd:
        raise ValueError(
            f"{TASK_BUDGET_REFUSAL}{campaign_id} "
            f"({projected} > {cap_microusd} micro-USD)"
        )
    return projected


def _scope(lock):
    if (
        not isinstance(lock, dict)
        or set(lock) != {"key", "mode"}
        or not isinstance(lock["mode"], str)
        or lock["mode"] not in MODES
    ):
        raise ValueError("closed resource lock required")
    key = lock["key"]
    if not isinstance(key, str):
        raise TypeError("canonical scope required")
    parts = key.removesuffix("/*").split("/")
    if (
        len(parts) < 2
        or parts[0] != "project"
        or any(
            part in {".", ".."} or re.fullmatch(r"[A-Za-z0-9_().:@+-]+", part) is None
            for part in parts
        )
    ):
        raise ValueError("canonical project-qualified scope required")
    return tuple(parts)


def _ancestor(parent, child):
    return child[: len(parent)] == parent


def _firestore_resource_scope(resource):
    if not isinstance(resource, str):
        raise TypeError("canonical Firestore resource required")
    parts = resource.split("/")
    if (
        len(parts) < 7
        or parts[0] != "projects"
        or parts[2] != "databases"
        or parts[4] != "documents"
        or (len(parts) - 5) % 2 != 0
    ):
        raise ValueError("canonical Firestore resource required")
    key = "/".join(
        ("project", parts[1], "firestore", parts[3], "documents", *parts[5:])
    )
    return _scope({"key": key, "mode": "WRITE"})


_AUTH_ACCOUNT_IDENTIFIER = re.compile(r"[A-Za-z0-9_.@+-]{1,128}")


def _auth_account_scope(resource):
    if not isinstance(resource, str):
        raise TypeError("canonical Auth account resource required")
    parts = resource.split("/")
    if (
        len(parts) != 5
        or parts[0] != "projects"
        or not parts[1]
        or parts[2] != "auth"
        or parts[3] != "accounts"
        or _AUTH_ACCOUNT_IDENTIFIER.fullmatch(parts[4]) is None
        or parts[4] in {".", ".."}
    ):
        raise ValueError("canonical Auth account resource required")
    return _scope({"key": "/".join(("project", parts[1], "auth", "accounts", parts[4])), "mode": "WRITE"})


def _auth_config_scope(resource):
    if not isinstance(resource, str):
        raise TypeError("canonical Auth configuration resource required")
    parts = resource.split("/")
    if (
        len(parts) != 4
        or parts[0] != "projects"
        or not parts[1]
        or parts[2:] != ["auth", "config"]
    ):
        raise ValueError("canonical Auth configuration resource required")
    return _scope(
        {"key": "/".join(("project", parts[1], "auth", "config")), "mode": "WRITE"}
    )


def _resource_scope(resource):
    if not isinstance(resource, str):
        raise TypeError("canonical Auth account resource required")
    parts = resource.split("/")
    if len(parts) > 2 and parts[0] == "projects" and parts[2] == "auth":
        if parts == ["projects", parts[1], "auth", "config"]:
            return _auth_config_scope(resource)
        return _auth_account_scope(resource)
    return _firestore_resource_scope(resource)


def conflicts(left, right):
    a, b = _scope(left), _scope(right)
    return (_ancestor(a, b) or _ancestor(b, a)) and not (
        left["mode"] == right["mode"] == "READ"
    )


def _locks(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        raise ValueError("bounded explicit resource locks required")
    scopes = [_scope(lock) for lock in value]
    if len(set(scopes)) != len(scopes):
        raise ValueError("duplicate canonical scope")


def _envelope(value):
    if not isinstance(value, dict) or set(value) != {
        "permissionDigest",
        "issuedAt",
        "expiresAt",
        "limits",
        "concurrency",
        "scopes",
    }:
        raise ValueError("closed envelope required")
    _hash(value["permissionDigest"])
    _number(value["issuedAt"])
    _number(value["expiresAt"])
    _budget(value["limits"])
    _locks(value["scopes"])
    if (
        value["issuedAt"] >= value["expiresAt"]
        or type(value["concurrency"]) is not int
        or not 1 <= value["concurrency"] <= MAX_RESERVATIONS
    ):
        raise ValueError("bounded window and concurrency required")


def _gate_job(claim):
    """The Gate job this reservation addresses.

    A claim written before a campaign could name its job carries none, and those
    reservations are all the Commit-shaped ones whose job the lane fixed.
    """
    return claim.get("gateJob", "limits")


def _claim(value):
    if not isinstance(value, dict) or set(value) - {"gateJob"} != {
        "campaignId",
        "manifestDigest",
        "nonceDigest",
        "gatePath",
        "gatePlanDigest",
        "locks",
        "budget",
        "durationSeconds",
    }:
        raise ValueError("closed campaign claim required")
    if "gateJob" in value and (
        not isinstance(value["gateJob"], str)
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value["gateJob"]) is None
    ):
        raise ValueError("canonical Gate job name required")
    if (
        not isinstance(value["campaignId"], str)
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["campaignId"]) is None
    ):
        raise ValueError("campaign identifier required")
    for key in ("manifestDigest", "nonceDigest", "gatePlanDigest"):
        _hash(value[key])
    _budget(value["budget"])
    _locks(value["locks"])
    if (
        type(value["durationSeconds"]) is not int
        or not 1 <= value["durationSeconds"] <= 1200
        and not (
            value["campaignId"] == AUTH_REV3_CAMPAIGN_ID
            and 1200 < value["durationSeconds"] <= AUTH_REV3_WALL_SECONDS
        )
    ):
        raise ValueError("bounded duration required")
    path = value["gatePath"]
    if not isinstance(path, str) or str(Path(path).resolve()) != path:
        raise ValueError("absolute canonical Gate path required")


def _recovery_child_claim(value):
    if not isinstance(value, dict) or set(value) not in (
        RECOVERY_CHILD_FIELDS,
        RECOVERY_CHILD_FIELDS | {"caseId"},
    ):
        raise ValueError("exact recovery child claim required")
    sentinel = "caseId" in value
    if sentinel and value["caseId"] != RECOVERY_SENTINEL_CASE_ID:
        raise ValueError("unsupported recovery case identity")
    request_count = RECOVERY_SENTINEL_REQUESTS if sentinel else RECOVERY_CHILD_REQUESTS
    cost = RECOVERY_SENTINEL_COST_MICROUSD if sentinel else RECOVERY_CHILD_COST_MICROUSD
    inspection_count = RECOVERY_SENTINEL_INSPECTION_REQUESTS if sentinel else RECOVERY_INSPECTION_REQUESTS
    absence_count = RECOVERY_SENTINEL_ABSENCE_REQUESTS if sentinel else RECOVERY_ABSENCE_REQUESTS
    delete_count = RECOVERY_SENTINEL_DELETE_REQUESTS if sentinel else RECOVERY_DELETE_REQUESTS
    tariff_estimate = RECOVERY_SENTINEL_TARIFF_ESTIMATE_MICROUSD if sentinel else RECOVERY_TARIFF_ESTIMATE_MICROUSD
    if value["kind"] != RECOVERY_CHILD_KIND or type(value["version"]) is not int or value["version"] != 2:
        raise ValueError("versioned recovery child claim required")
    for key in ("manifestDigest", "nonceDigest", "gatePlanDigest", "parentClaimDigest", "parentPlanDigest", "resourceDigest", "permissionDigest"):
        _hash(value[key])
    _generation(value["generation"])
    _budget(value["budget"])
    _locks(value["locks"])
    if value["campaignId"] not in CATALOGUED_CAMPAIGN_IDS:
        raise ValueError("uncatalogued recovery campaign")
    if value["operationClass"] != RECOVERY_OPERATION_CLASS:
        raise ValueError("recovery operation class changed")
    if (
        any(type(value[key]) is not int for key in ("readCount", "inspectionCount", "absenceCount", "deleteCount"))
        or value["readCount"] != inspection_count + absence_count
        or value["inspectionCount"] != inspection_count
        or value["absenceCount"] != absence_count
        or value["deleteCount"] != delete_count
        or value["tariffEstimateMicrousd"] != tariff_estimate
        or value["budget"]["resources"] != len(value["ownedResources"])
        or value["budget"] != {"requests": request_count, "accounts": 0, "resources": value["budget"]["resources"], "costMicrousd": cost}
    ):
        raise ValueError("recovery allocation counts changed")
    if not isinstance(value["ownedResources"], list) or not value["ownedResources"] or len(set(value["ownedResources"])) != len(value["ownedResources"]):
        raise ValueError("exact owned recovery resources required")
    if digest(value["ownedResources"]) != value["resourceDigest"]:
        raise ValueError("recovery resource digest changed")
    if not isinstance(value["recoveryNonce"], str) or re.fullmatch(r"[0-9a-f]{32}", value["recoveryNonce"]) is None:
        raise ValueError("fresh recovery nonce required")
    if value["nonceDigest"] != digest(value["recoveryNonce"]):
        raise ValueError("recovery nonce digest binding changed")
    for key in ("campaignId", "ownerIdentity", "recoveryOwner", "selectedProbe"):
        if not _owner_value(value[key]):
            raise ValueError("recovery authority binding required")
    _number(value["expiresAt"])
    if type(value["durationSeconds"]) is not int or not 1 <= value["durationSeconds"] <= 1200:
        raise ValueError("bounded recovery duration required")
    if not isinstance(value["executionHost"], dict) or set(value["executionHost"]) != {"platform", "machine"} or not all(_owner_value(value["executionHost"][k]) for k in value["executionHost"]) or value["executionHost"] != {"platform": platform.system().lower(), "machine": platform.machine()}:
        raise ValueError("exact recovery execution host required")
    if not isinstance(value["gatePath"], str) or str(Path(value["gatePath"]).resolve()) != value["gatePath"]:
        raise ValueError("absolute recovery Gate path required")


def _auth_binding(value, kind):
    """Validate a lane-owned binding without persisting its payload."""
    if not isinstance(value, dict) or value.get("kind") != kind:
        raise ValueError("typed Auth recovery binding required")
    supplied = value.get("digest", value.get("bindingDigest"))
    if supplied is None:
        return digest(value)
    _hash(supplied)
    return supplied


def _auth_parent_evidence(value):
    if not isinstance(value, dict):
        raise ValueError("typed Auth parent evidence required")
    if value.get("kind") == AUTH_RECOVERY_LEGACY_PARENT_EVIDENCE_KIND:
        if set(value) != {
            "kind", "gateDigest", "gatePlanDigest", "job", "eventIndex", "requestDigest",
            "resource", "completed", "creationOutcome", "eventDigest", "responseDigest",
            "responsibility", "reason", "evidenceDigest",
        }:
            raise ValueError("typed legacy Auth parent evidence required")
        for key in ("gateDigest", "gatePlanDigest", "requestDigest", "eventDigest", "responseDigest", "evidenceDigest"):
            _hash(value[key])
        if (
            value.get("job") != "auth-credential"
            or value.get("eventIndex") != AUTH_RECOVERY_LEGACY_EVENT_INDEX
            or not isinstance(value.get("resource"), str)
            or value.get("completed") is not True
            or value.get("creationOutcome") != "refused"
            or value.get("responsibility") != "unknown-custom-create"
            or value.get("reason") != "legacy-200-without-creation-proof"
        ):
            raise ValueError("typed legacy Auth parent evidence required")
        expected = copy.deepcopy(value)
        expected.pop("evidenceDigest")
        if value["evidenceDigest"] != digest(expected):
            raise ValueError("legacy Auth parent evidence digest changed")
        return
    if set(value) != {
        "kind", "gateDigest", "gatePlanDigest", "job", "eventIndex", "requestDigest",
        "resource", "completed", "creationOutcome", "evidenceDigest",
    } or value["kind"] != AUTH_RECOVERY_PARENT_EVIDENCE_KIND:
        raise ValueError("typed Auth parent evidence required")
    for key in ("gateDigest", "gatePlanDigest", "requestDigest", "evidenceDigest"):
        _hash(value[key])
    if (
        not isinstance(value["job"], str)
        or type(value["eventIndex"]) is not int
        or value["eventIndex"] < 0
        or not isinstance(value["resource"], str)
        or value["completed"] is not False
        or value["creationOutcome"] not in {"pending", "unknown"}
    ):
        raise ValueError("typed Auth parent evidence required")
    expected = copy.deepcopy(value)
    expected.pop("evidenceDigest")
    if value["evidenceDigest"] != digest(expected):
        raise ValueError("Auth parent evidence digest changed")


def _auth_resource(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"projects/[A-Za-z0-9_.:@+-]+/auth/accounts/custom-[0-9a-f]{32}", value
    ):
        raise ValueError("exact planned custom UID resource required")


def _auth_recovery_child_claim(value):
    if not isinstance(value, dict) or set(value) != AUTH_RECOVERY_CHILD_FIELDS:
        raise ValueError("exact Auth recovery child claim required")
    if value["kind"] != AUTH_RECOVERY_CHILD_KIND or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("versioned Auth recovery child claim required")
    if value["campaignId"] != AUTH_RECOVERY_CAMPAIGN:
        raise ValueError("Auth recovery campaign family changed")
    for key in (
        "manifestDigest", "nonceDigest", "gatePlanDigest", "parentClaimDigest",
        "parentPlanDigest", "parentGateDigest", "parentEvidenceDigest", "parentRequestDigest",
        "resourceDigest", "permissionDigest", "sourceBindingDigest", "transportBindingDigest",
        "o7BindingDigest", "o8BindingDigest",
    ):
        _hash(value[key])
    _generation(value["generation"])
    _budget(value["budget"])
    _locks(value["locks"])
    if value["operationClass"] != AUTH_RECOVERY_OPERATION_CLASS:
        raise ValueError("Auth recovery operation class changed")
    if value["budget"]["requests"] != 1 or value["budget"]["accounts"] != 1 or value["budget"]["resources"] != 1:
        raise ValueError("one Auth recovery resource required")
    if not 1 <= value["budget"]["costMicrousd"] <= AUTH_RECOVERY_MAX_COST_MICROUSD:
        raise ValueError("Auth recovery cost exceeds packet ceiling")
    if any(type(value[key]) is not int for key in ("readCount", "inspectionCount", "absenceCount", "deleteCount")) or (
        value["readCount"] != 1
        or value["inspectionCount"] != 1
        or value["absenceCount"] != 1
        or value["deleteCount"] != 0
    ):
        raise ValueError("Auth recovery lookup-only counts required")
    if not isinstance(value["ownedResources"], list) or len(value["ownedResources"]) != 1:
        raise ValueError("one Auth recovery resource required")
    _auth_resource(value["ownedResources"][0])
    if digest(value["ownedResources"]) != value["resourceDigest"]:
        raise ValueError("Auth recovery resource digest changed")
    if not isinstance(value["recoveryNonce"], str) or re.fullmatch(r"[0-9a-f]{32}", value["recoveryNonce"]) is None:
        raise ValueError("fresh Auth recovery nonce required")
    if value["nonceDigest"] != digest(value["recoveryNonce"]):
        raise ValueError("Auth recovery nonce digest changed")
    if type(value["parentEventIndex"]) is not int or value["parentEventIndex"] < 0:
        raise ValueError("Auth parent event binding required")
    for key in ("ownerIdentity", "recoveryOwner", "gateJob", "parentGateJob"):
        if not _owner_value(value[key]):
            raise ValueError("Auth recovery authority binding required")
    if type(value["durationSeconds"]) is not int or not 1 <= value["durationSeconds"] <= 600:
        raise ValueError("bounded Auth recovery duration required")
    _number(value["expiresAt"])
    if not isinstance(value["executionHost"], dict) or set(value["executionHost"]) != {"platform", "machine"}:
        raise ValueError("exact Auth recovery execution host required")
    if value["executionHost"] != {"platform": platform.system().lower(), "machine": platform.machine()}:
        raise ValueError("Auth recovery execution host changed")
    if not isinstance(value["gatePath"], str) or str(Path(value["gatePath"]).resolve()) != value["gatePath"]:
        raise ValueError("absolute Auth recovery Gate path required")


def _auth_recovery_plan(child_plan, child_claim):
    if not isinstance(child_plan, dict) or child_plan.get("campaignId") != AUTH_RECOVERY_CAMPAIGN:
        raise ValueError("Auth recovery Gate plan required")
    if child_plan.get("nonce") != child_claim["recoveryNonce"] or digest(child_plan) != child_claim["gatePlanDigest"]:
        raise ValueError("Auth recovery Gate plan binding changed")
    for field in ("sourceBindingDigest", "transportBindingDigest", "o7BindingDigest", "o8BindingDigest"):
        if child_plan.get(field) != child_claim[field]:
            raise ValueError("Auth recovery Gate authority binding changed")
    plan_cost = child_plan.get("costMicrousd")
    request_cost = child_plan.get("requestCostMicrousd")
    budget_cost = child_claim["budget"]["costMicrousd"]
    if (
        type(plan_cost) is not int
        or type(request_cost) is not int
        or plan_cost <= 0
        or request_cost != plan_cost
        or plan_cost > budget_cost
        or child_plan.get("fixedCostMicrousd", 0) != 0
        or child_plan.get("coordinatorRequests", 0) != 0
    ):
        raise ValueError("Auth recovery Gate cost exceeds child budget")
    if (
        child_plan.get("observationRequests") != 0
        or child_plan.get("dataRequests") != 1
        or child_plan.get("managementRequests") != 0
        or child_plan.get("recoveryRequests") != 1
        or child_plan.get("costMicrousd") != child_plan.get("requestCostMicrousd")
        or not isinstance(child_plan.get("jobs"), dict)
        or len(child_plan["jobs"]) != 1
    ):
        raise ValueError("Auth recovery Gate must contain one lookup slot")
    job_name, job = next(iter(child_plan["jobs"].items()))
    if job_name != child_claim["gateJob"] or not isinstance(job, dict):
        raise ValueError("Auth recovery Gate job binding changed")
    if job.get("observation") != [] or not isinstance(job.get("recovery"), list) or len(job["recovery"]) != 1:
        raise ValueError("Auth recovery Gate must be lookup-only")
    if job.get("resources") != child_claim["ownedResources"]:
        raise ValueError("Auth recovery Gate resource binding changed")
    operation = job["recovery"][0]
    resource = child_claim["ownedResources"][0]
    project = resource.split("/", 2)[1]
    expected_binding = {"custom": {"resource": resource, "uidBinding": "customUid"}}
    expected_path = f"identitytoolkit.googleapis.com/v1/projects/{project}/accounts:lookup"
    if (
        child_plan.get("project") != project
        or job.get("accountBindings") != expected_binding
        or operation.get("kind") != "uid-absence"
        or operation.get("service") != "auth"
        or operation.get("method") != "POST"
        or operation.get("account") != "custom"
        or operation.get("uidBinding") != "customUid"
        or operation.get("resource") != resource
        or operation.get("body") != {"localId": ["$binding:customUid"]}
        or operation.get("path") != expected_path
        or operation.get("form") is not False
        or operation.get("owner") is not True
    ):
        raise ValueError("Auth recovery operation is not a UID lookup")
    schedule = job.get("schedule")
    if not isinstance(schedule, list) or len(schedule) != 1 or schedule != [{"phase": "recovery", "index": 0, "seconds": schedule[0].get("seconds")}]:
        raise ValueError("Auth recovery Gate schedule changed")


def _auth_legacy_parent_matches(gate, child_claim, operation, event, job):
    plan = gate.get("plan")
    if (
        digest(gate) != AUTH_RECOVERY_LEGACY_GATE_DIGEST
        or digest(plan) != AUTH_RECOVERY_LEGACY_PLAN_DIGEST
        or child_claim.get("parentClaimDigest") != AUTH_RECOVERY_LEGACY_CLAIM_DIGEST
        or child_claim.get("generation", {}).get("sourceCommit") != AUTH_RECOVERY_LEGACY_SOURCE_COMMIT
        or child_claim.get("parentEventIndex") != AUTH_RECOVERY_LEGACY_EVENT_INDEX
        or child_claim.get("parentGateJob") != "auth-credential"
    ):
        return False
    operations = plan.get("jobs", {}).get("auth-credential", {}).get("observation", [])
    nonce = plan.get("nonce")
    if AUTH_RECOVERY_CAMPAIGN != "AUTH-CREDENTIAL-TOKENS-01":
        return False
    resource = f"projects/fireemu-35fe6/auth/accounts/custom-{nonce}"
    if (
        not isinstance(operations, list)
        or len(operations) <= AUTH_RECOVERY_LEGACY_EVENT_INDEX
        or operation is not operations[AUTH_RECOVERY_LEGACY_EVENT_INDEX]
        or operation.get("kind") != "custom-sign-in"
        or operation.get("account") != "custom"
        or operation.get("service") != "auth"
        or operation.get("method") != "POST"
        or operation.get("path") != AUTH_PARENT_CUSTOM_SIGN_IN_PATH
        or operation.get("form") is not False
        or operation.get("owner") is not False
        or operation.get("body") != {"token": "$binding:customToken", "returnSecureToken": True}
        or operation.get("resource") != resource
        or operation.get("binds", {}).get("customUid") not in {"localId", "idToken.sub"}
        or child_claim.get("ownedResources") != [resource]
        or child_claim.get("parentRequestDigest") != digest(operation)
    ):
        return False
    evidence = event.get("authEvidence") if isinstance(event, dict) else None
    if (
        event.get("requestDigest") != digest(operation)
        or event.get("completed") is not True
        or event.get("creationOutcome") != "refused"
        or event.get("failure") is not None
        or type(event.get("status")) is not int
        or event.get("status") != 200
        or not isinstance(event.get("responseDigest"), str)
        or re.fullmatch(r"[a-f0-9]{64}", event["responseDigest"]) is None
        or type(event.get("ended")) not in (int, float)
        or not isinstance(evidence, dict)
        or set(evidence) != {"kind", "account", "status", "creationOutcome"}
        or evidence.get("kind") != "custom-sign-in"
        or evidence.get("account") != "custom"
        or evidence.get("status") != 200
        or evidence.get("creationOutcome") != "refused"
    ):
        return False
    accounts = job.get("authAccounts", {})
    proofs = job.get("creationProofs", {})
    return (
        isinstance(accounts, dict)
        and isinstance(proofs, dict)
        and "custom" not in accounts
        and resource not in proofs
    )


def _auth_parent_projection(gate, child_claim):
    if not isinstance(gate, dict) or digest(gate.get("plan")) != child_claim["parentPlanDigest"]:
        raise ValueError("Auth parent Gate plan changed")
    job_name = child_claim["parentGateJob"]
    plan_job = gate.get("plan", {}).get("jobs", {}).get(job_name)
    job = gate.get("jobs", {}).get(job_name)
    if not isinstance(plan_job, dict) or not isinstance(job, dict):
        raise ValueError("Auth parent Gate job missing")  # noqa: TRY004 -- refusal contract
    if gate.get("coordinatorInflight") or any(item.get("inflight") for item in gate.get("jobs", {}).values()):
        raise ValueError("Auth parent Gate is still in flight")
    operations = plan_job.get("observation", [])
    candidates = [
        (index, operation)
        for index, operation in enumerate(operations)
        if isinstance(operation, dict)
        and operation.get("kind") == "custom-sign-in"
        and operation.get("account") == "custom"
        and isinstance(operation.get("resource"), str)
        and operation.get("service") == "auth"
        and operation.get("method") == "POST"
        and operation.get("path") == AUTH_PARENT_CUSTOM_SIGN_IN_PATH
        and operation.get("form") is False
        and isinstance(operation.get("body"), dict)
        and operation["body"].get("token") in {
            "$binding:customToken",
            "$binding:customTokenReserved",
            "$binding:customTokenExpired",
        }
        and operation["body"].get("returnSecureToken") is True
    ]
    index = child_claim.get("parentEventIndex")
    selected = next((candidate for candidate in candidates if candidate[0] == index), None)
    if selected is None:
        raise ValueError("one uncertain Auth custom create is required")
    index, operation = selected
    binds = operation.get("binds")
    if (
        index != child_claim["parentEventIndex"]
        or operation.get("resource") != child_claim["ownedResources"][0]
        or operation.get("service") != "auth"
        or operation.get("method") != "POST"
        or operation.get("path") != "identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken"
        or operation.get("form") is not False
        or operation.get("body") != {
            "token": "$binding:customToken",
            "returnSecureToken": True,
        }
        or not isinstance(binds, dict)
        or binds.get("customUid") not in {"localId", "idToken.sub"}
    ):
        raise ValueError("Auth parent custom resource changed")
    events = [
        item for item in gate.get("events", [])
        if item.get("job") == job_name and item.get("phase") == "observation" and item.get("index") == index
    ]
    if len(events) != 1:
        raise ValueError("one uncertain Auth custom create event is required")
    event = events[0]
    legacy = _auth_legacy_parent_matches(gate, child_claim, operation, event, job)
    if not legacy and (
        not isinstance(event, dict)
        or event.get("completed") is not False
        or event.get("creationOutcome") not in {"pending", "unknown"}
        or type(event.get("ended")) not in (int, float)
        or event.get("service") != operation["service"]
        or event.get("method") != operation["method"]
        or event.get("requestDigest") != digest(operation)
        or child_claim["parentRequestDigest"] != digest(operation)
    ):
        raise ValueError("Auth parent custom create is not uncertain")
    projection = {
        "kind": AUTH_RECOVERY_LEGACY_PARENT_EVIDENCE_KIND if legacy else AUTH_RECOVERY_PARENT_EVIDENCE_KIND,
        "gateDigest": digest(gate),
        "gatePlanDigest": digest(gate["plan"]),
        "job": job_name,
        "eventIndex": index,
        "requestDigest": event["requestDigest"],
        "resource": operation["resource"],
        "completed": True if legacy else False,
        "creationOutcome": "refused" if legacy else event["creationOutcome"],
    }
    if legacy:
        projection.update(
            eventDigest=digest(event), responseDigest=event["responseDigest"],
            responsibility="unknown-custom-create", reason="legacy-200-without-creation-proof",
        )
    projection["evidenceDigest"] = digest(projection)
    return projection


def _auth_parent_responsibility_projection(gate, child_claim):
    """Project every Auth parent responsibility onto immutable Gate evidence.

    The recovery child is allowed to settle exactly the one uncertain custom
    create bound by ``_auth_parent_projection``. Every other planned creating
    slot must either have a canonical refusal, never have been dispatched, or
    have an owned account with a complete typed cleanup chain. Counts and
    caller summaries are deliberately not consulted here.
    """
    if not isinstance(gate, dict) or not isinstance(gate.get("plan"), dict):
        raise ValueError("Auth parent responsibility Gate required")
    plan = gate["plan"]
    if plan.get("campaignId") != AUTH_RECOVERY_CAMPAIGN or not isinstance(plan.get("project"), str) or not isinstance(plan.get("nonce"), str) or re.fullmatch(r"[0-9a-f]{32}", plan["nonce"]) is None:
        raise ValueError("Auth parent responsibility campaign binding differs")
    plan_jobs = plan.get("jobs")
    jobs = gate.get("jobs")
    events = gate.get("events")
    if not isinstance(plan_jobs, dict) or not isinstance(jobs, dict) or not isinstance(events, list):
        raise ValueError("Auth parent responsibility journal malformed")
    if set(plan_jobs) != set(jobs):
        raise ValueError("Auth parent responsibility jobs differ")
    management = plan.get("management", {})
    if management is None:
        management = {}
    if not isinstance(management, dict):
        raise ValueError("Auth parent responsibility management plan malformed")
    management_observation = management.get("observation", [])
    management_recovery = management.get("recovery", [])
    if (
        not isinstance(management_observation, list)
        or not isinstance(management_recovery, list)
        or not all(isinstance(slot, dict) and isinstance(slot.get("id"), str) for slot in management_observation + management_recovery)
    ):
        raise ValueError("Auth parent responsibility management plan malformed")
    declared_management = [
        phase + ":" + slot["id"]
        for phase, slots in (("observation", management_observation), ("recovery", management_recovery))
        for slot in slots
    ]
    if len(set(declared_management)) != len(declared_management):
        raise ValueError("Auth parent responsibility management plan malformed")
    management_used = gate.get("managementUsed", [])
    management_events = gate.get("managementEvents", [])
    management_skipped = gate.get("managementSkipped", [])
    if (
        not isinstance(management_used, list)
        or not isinstance(management_events, list)
        or not isinstance(management_skipped, list)
        or any(not isinstance(item, str) for item in management_used)
        or len(set(management_used)) != len(management_used)
        or len(set(item.get("id") for item in management_skipped if isinstance(item, dict))) != len(management_skipped)
    ):
        raise ValueError("Auth parent responsibility management journal differs")
    skipped_ids = []
    for item in management_skipped:
        if (
            not isinstance(item, dict)
            or item.get("id") not in declared_management
            or item.get("phase") not in {"observation", "recovery"}
            or item["id"].split(":", 1)[0] != item["phase"]
            or not isinstance(item.get("reason"), str)
        ):
            raise ValueError("Auth parent responsibility management journal differs")
        skipped_ids.append(item["id"])
    if len(set(skipped_ids) & set(management_used)):
        raise ValueError("Auth parent responsibility management journal differs")
    consumed_management = set(management_used) | set(skipped_ids)
    if consumed_management != set(declared_management[:len(consumed_management)]):
        raise ValueError("Auth parent responsibility management journal differs")
    expected_used = [identity for identity in declared_management[:len(consumed_management)] if identity not in skipped_ids]
    expected_skipped = [identity for identity in declared_management[:len(consumed_management)] if identity in skipped_ids]
    if (
        management_used != expected_used
        or skipped_ids != expected_skipped
        or len(management_events) != len(management_used)
    ):
        raise ValueError("Auth parent responsibility management journal differs")
    for identity, event in zip(management_used, management_events, strict=True):
        if (
            not isinstance(event, dict)
            or event.get("id") != identity
            or event.get("completed") is not True
            or event.get("complete") is not True
            or event.get("workerReaped") is not True
        ):
            raise ValueError("Auth parent responsibility management event differs")
    management_observation_count = sum(identity.startswith("observation:") for identity in management_used)
    management_recovery_count = sum(identity.startswith("recovery:") for identity in management_used)
    if any(
        not isinstance(job, dict)
        or type(job.get("observation")) is not int
        or job["observation"] < 0
        for job in jobs.values()
    ):
        raise ValueError("Auth parent responsibility observation cursor differs")
    if type(gate.get("observation")) is not int or gate["observation"] < 0 or gate["observation"] != management_observation_count + sum(
        job["observation"] for job in jobs.values()
    ):
        raise ValueError("Auth parent responsibility observation total differs")
    if type(gate.get("recovery")) is not int or gate["recovery"] < 0 or gate["recovery"] != management_recovery_count + sum(
        job["recovery"] for job in jobs.values()
    ):
        raise ValueError("Auth parent responsibility recovery total differs")
    coordinator_requests = plan.get("coordinatorRequests", 0)
    if type(coordinator_requests) is not int or coordinator_requests < 0 or type(gate.get("total")) is not int or gate["total"] < 0 or gate["total"] != coordinator_requests + len(management_used) + sum(
        job["observation"] + job["recovery"] for job in jobs.values()
    ):
        raise ValueError("Auth parent responsibility global total differs")

    event_by_slot = {}
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Auth parent responsibility event malformed")
        job_name = event.get("job")
        phase = event.get("phase")
        index = event.get("index")
        if (
            not isinstance(job_name, str)
            or not isinstance(phase, str)
            or job_name not in plan_jobs
            or phase not in {"observation", "recovery"}
            or type(index) is not int
            or index < 0
        ):
            raise ValueError("Auth parent responsibility event binding differs")
        plan_job = plan_jobs[job_name]
        operations = plan_job.get(phase)
        if not isinstance(operations, list) or index >= len(operations) or not isinstance(operations[index], dict):
            raise ValueError("Auth parent responsibility event slot differs")
        key = (job_name, phase, index)
        if key in event_by_slot:
            raise ValueError("duplicate Auth parent responsibility event")
        operation = operations[index]
        if (
            event.get("requestDigest") != digest(operation)
            or event.get("service") != operation.get("service")
            or event.get("method") != operation.get("method")
        ):
            raise ValueError("Auth parent responsibility event request differs")
        event_by_slot[key] = event

    child_job = plan_jobs.get(child_claim.get("parentGateJob"))
    child_index = child_claim.get("parentEventIndex")
    if (
        not isinstance(child_job, dict)
        or not isinstance(child_job.get("observation"), list)
        or type(child_index) is not int
        or child_index < 0
        or child_index >= len(child_job["observation"])
        or not isinstance(child_job["observation"][child_index], dict)
    ):
        raise ValueError("Auth parent responsibility child slot differs")
    child_key = (child_claim["parentGateJob"], "observation", child_index)
    if child_claim.get("parentRequestDigest") != digest(child_job["observation"][child_index]):
        raise ValueError("Auth parent responsibility child request differs")

    def _resource(value):
        return isinstance(value, str) and re.fullmatch(r"projects/[^/]+/auth/accounts/[^/]+", value) is not None

    def _event_index(value, label):
        if type(value) is not int or isinstance(value, bool) or not 0 <= value < len(events):
            raise ValueError(f"Auth parent responsibility {label} event differs")
        return value

    def _typed_cleanup_event(job_name, job, account, operation, position, kind):
        event = events[_event_index(position, kind)]
        operation_index = next(
            (index for index, candidate in enumerate(plan_jobs[job_name].get("recovery", [])) if candidate is operation),
            None,
        )
        if operation_index is None:
            operation_index = next(
                (index for index, candidate in enumerate(plan_jobs[job_name].get("recovery", [])) if candidate == operation),
                None,
            )
        if (
            event.get("job") != job_name
            or event.get("phase") != "recovery"
            or event.get("index") != operation_index
            or event.get("requestDigest") != digest(operation)
            or event.get("completed") is not True
            or event.get("failure") is not None
            or event.get("service") != operation.get("service")
            or event.get("method") != operation.get("method")
        ):
            raise ValueError(f"Auth parent responsibility {kind} event differs")
        evidence = event.get("authEvidence")
        body = evidence.get("body") if isinstance(evidence, dict) else None
        if not isinstance(evidence, dict) or evidence.get("account") != account:
            raise ValueError(f"Auth parent responsibility {kind} evidence differs")
        if event.get("responseDigest") != digest(body) or evidence.get("responseDigest") != event.get("responseDigest"):
            raise ValueError(f"Auth parent responsibility {kind} response differs")
        if kind == "delete":
            valid = type(event.get("status")) is int and event["status"] == 200 and body in (
                {}, {"kind": "identitytoolkit#DeleteAccountResponse"}
            )
        else:
            valid = auth_typed_absence(event.get("status"), body)
        if not valid:
            raise ValueError(f"Auth parent responsibility {kind} typed evidence required")
        return {"event": position, "requestDigest": event["requestDigest"]}

    def _validate_observation_semantics(operation):
        kind = operation.get("kind")
        project = plan["project"]
        expected_paths = {
            "sign-up": AUTH_PARENT_SIGNUP_PATH,
            "custom-sign-in": AUTH_PARENT_CUSTOM_SIGN_IN_PATH,
            "refresh": "securetoken.googleapis.com/v1/token",
            "refresh-unknown": "securetoken.googleapis.com/v1/token",
            "sign-in": "identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
            "update": f"identitytoolkit.googleapis.com/v1/projects/{project}/accounts:update",
            "lookup": "identitytoolkit.googleapis.com/v1/accounts:lookup",
            "admin-lookup": f"identitytoolkit.googleapis.com/v1/projects/{project}/accounts:lookup",
            "create-session-cookie": f"identitytoolkit.googleapis.com/v1/projects/{project}:createSessionCookie",
            "send-oob-code": f"identitytoolkit.googleapis.com/v1/projects/{project}/accounts:sendOobCode",
            "reset-password": "identitytoolkit.googleapis.com/v1/accounts:resetPassword",
        }
        if (
            operation.get("service") != "auth"
            or operation.get("method") != "POST"
            or operation.get("path") != expected_paths[kind]
            or operation.get("form") is not (kind in {"refresh", "refresh-unknown"})
            or not isinstance(operation.get("body"), dict)
        ):
            raise ValueError("Auth parent responsibility observation operation semantics differ")
        body = operation["body"]
        if kind == "refresh-unknown" and body != {
            "grant_type": "refresh_token",
            "refresh_token": "rt1.0.0.demo-app.unissued0000000000000",
        }:
            raise ValueError("Auth parent responsibility observation operation body differs")
        if kind == "refresh" and (
            body.get("grant_type") != "refresh_token"
            or not isinstance(body.get("refresh_token"), str)
            or not body["refresh_token"].startswith("$binding:")
        ):
            raise ValueError("Auth parent responsibility observation operation body differs")
        if kind in {"lookup", "admin-lookup"} and (
            set(body) != {"idToken"} if kind == "lookup" else set(body) != {"localId"}
        ):
            raise ValueError("Auth parent responsibility observation operation body differs")

    def _creating_operation(index, operation):
        kind = operation.get("kind")
        path = operation.get("path")
        is_signup = path == AUTH_PARENT_SIGNUP_PATH
        is_custom_sign_in = path == AUTH_PARENT_CUSTOM_SIGN_IN_PATH
        if kind in {"sign-up", "custom-sign-in"}:
            expected_path = AUTH_PARENT_SIGNUP_PATH if kind == "sign-up" else AUTH_PARENT_CUSTOM_SIGN_IN_PATH
            if path != expected_path:
                raise ValueError("Auth parent responsibility creating operation route differs")
        if is_signup:
            account = operation.get("account")
            expected_email = {
                "acct0": f"fireemu-cred-{plan['nonce'][:8]}-0@fireemu-credential.invalid",
                "acct1": f"fireemu-cred-{plan['nonce'][:8]}-1@fireemu-credential.invalid",
            }.get(account)
            if (
                kind != "sign-up"
                or operation.get("service") != "auth"
                or operation.get("method") != "POST"
                or operation.get("form") is not False
                or operation.get("body") != {
                    "email": expected_email,
                    "password": "$binding:password",
                    "returnSecureToken": True,
                }
            ):
                raise ValueError("Auth parent responsibility creating operation semantics differ")
            return index
        if is_custom_sign_in:
            body = operation.get("body")
            if (
                kind != "custom-sign-in"
                or operation.get("service") != "auth"
                or operation.get("method") != "POST"
                or operation.get("account") != "custom"
                or operation.get("form") is not False
                or body not in (
                    {"token": "$binding:customToken", "returnSecureToken": True},
                    {"token": "$binding:customTokenReserved", "returnSecureToken": True},
                    {"token": "$binding:customTokenExpired", "returnSecureToken": True},
                )
            ):
                raise ValueError("Auth parent responsibility creating operation semantics differ")
            return index
        if kind in {"sign-up", "custom-sign-in"}:
            raise ValueError("Auth parent responsibility creating operation semantics differ")
        return None

    responsibilities = []
    for job_name, plan_job in plan_jobs.items():
        job = jobs[job_name]
        if not isinstance(job, dict) or job.get("inflight") is True:
            raise ValueError("Auth parent responsibility job is in flight")
        resources = plan_job.get("resources")
        if (
            not isinstance(resources, list)
            or any(not isinstance(value, str) for value in resources)
            or len(resources) != len(set(resources))
            or any(not _resource(value) for value in resources)
        ):
            raise ValueError("Auth parent responsibility resources malformed")
        if job.get("resources") != resources:
            raise ValueError("Auth parent responsibility resources differ")
        observations = plan_job.get("observation")
        recovery = plan_job.get("recovery")
        if not isinstance(observations, list) or not all(isinstance(operation, dict) for operation in observations) or not isinstance(recovery, list) or not all(isinstance(operation, dict) for operation in recovery):
            raise ValueError("Auth parent responsibility plan malformed")
        if any(operation.get("kind") not in AUTH_PARENT_OBSERVATION_KINDS for operation in observations):
            raise ValueError("Auth parent responsibility observation operation is unsupported")
        if any(operation.get("kind") not in AUTH_PARENT_RECOVERY_KINDS for operation in recovery):
            raise ValueError("Auth parent responsibility recovery operation is unsupported")
        for operation in observations:
            _validate_observation_semantics(operation)
        creating_indices = {
            creating_index
            for index, operation in enumerate(observations)
            if (creating_index := _creating_operation(index, operation)) is not None
        }
        observation_events = [
            event for event in events
            if event.get("job") == job_name and event.get("phase") == "observation"
        ]
        if type(job.get("observation")) is not int or job["observation"] != len(observation_events):
            raise ValueError("Auth parent responsibility observation cursor differs")
        schedule = plan_job.get("schedule")
        expected_slots = {
            (phase, index)
            for phase, operations in (("observation", observations), ("recovery", recovery))
            for index in range(len(operations))
        }
        schedule_slots = []
        if not isinstance(schedule, list):
            raise ValueError("Auth parent responsibility schedule cursor differs")
        for entry in schedule:
            if not isinstance(entry, dict) or entry.get("phase") not in {"observation", "recovery"}:
                raise ValueError("Auth parent responsibility schedule differs")
            index = entry.get("index")
            phase = entry["phase"]
            if type(index) is not int or not 0 <= index < len(observations if phase == "observation" else recovery):
                raise ValueError("Auth parent responsibility schedule differs")
            slot = (phase, index)
            if slot in schedule_slots:
                raise ValueError("Auth parent responsibility schedule differs")
            schedule_slots.append(slot)
        if set(schedule_slots) != expected_slots:
            raise ValueError("Auth parent responsibility schedule differs")
        if type(job.get("scheduleDone")) is not int or not 0 <= job["scheduleDone"] <= len(schedule) or job["scheduleDone"] < job["observation"]:
            raise ValueError("Auth parent responsibility schedule cursor differs")
        account_resources = {}
        for operation in observations + recovery:
            account = operation.get("account")
            if account is None:
                continue
            resource = operation.get("resource")
            if not isinstance(account, str) or not _resource(resource) or resource not in resources:
                raise ValueError("Auth parent responsibility account binding differs")
            if account == "custom":
                identifier = f"custom-{plan['nonce']}"
            elif account == "acct0":
                identifier = f"fireemu-cred-{plan['nonce'][:8]}-0"
            elif account == "acct1":
                identifier = f"fireemu-cred-{plan['nonce'][:8]}-1"
            else:
                raise ValueError("Auth parent responsibility account identity differs")
            if resource != f"projects/{plan['project']}/auth/accounts/{identifier}":
                raise ValueError("Auth parent responsibility canonical resource differs")
            previous = account_resources.setdefault(account, resource)
            if previous != resource:
                raise ValueError("Auth parent responsibility account resource differs")
        if set(account_resources.values()) != set(resources):
            raise ValueError("Auth parent responsibility resource coverage incomplete")
        account_bindings = plan_job.get("accountBindings")
        if account_bindings is not None:
            if not isinstance(account_bindings, dict) or set(account_bindings) != set(account_resources):
                raise ValueError("Auth parent responsibility account bindings differ")
            for account, binding in account_bindings.items():
                if not isinstance(binding, dict) or binding.get("resource") != account_resources[account]:
                    raise ValueError("Auth parent responsibility account bindings differ")

        accounts = job.get("authAccounts", {})
        owned = job.get("owned", [])
        creation_proofs = job.get("creationProofs", {})
        absence_proofs = job.get("absenceProofs", {})
        if (
            not isinstance(accounts, dict)
            or not isinstance(owned, list)
            or not all(isinstance(resource, str) for resource in owned)
            or not isinstance(creation_proofs, dict)
            or not isinstance(absence_proofs, dict)
        ):
            raise ValueError("Auth parent responsibility ownership evidence malformed")
        if owned or creation_proofs:
            raise ValueError("Auth parent responsibility has unsupported creation proof")
        if len(owned) != len(set(owned)):
            raise ValueError("Auth parent responsibility ownership duplicated")
        if any(resource not in resources for resource in absence_proofs):
            raise ValueError("Auth parent responsibility absence resource differs")
        if any(account not in account_resources for account in accounts):
            raise ValueError("Auth parent responsibility account is unplanned")
        # CredentialGate's closed Auth contract has exactly two account-creating
        # operation kinds. Its schedule also contains non-creating token and
        # refresh slots, so the schedule's default ``creates`` value is not an
        # ownership declaration for this facade.
        creating = creating_indices
        # A real Gate advances the frozen cursor across the remaining
        # observation schedule when observation is abandoned.  Those slots
        # have no wire event by design, but only the exact contiguous suffix
        # described by the Gate's own stop journal is eligible for the
        # never-dispatched disposition.  In particular, a schedule cursor by
        # itself is not evidence: a lost response remains an unresolved
        # creation and must retain the parent lock.
        abandoned_observation_slots = set()
        skipped_by_stop = job.get("skippedByStop", 0)
        if type(skipped_by_stop) is not int or skipped_by_stop < 0:
            raise ValueError("Auth parent responsibility stop cursor differs")
        if skipped_by_stop:
            stop_reason = job.get("stopReason")
            observation_cursor = job.get("observation")
            recovery_cursor = job.get("recovery")
            if (
                not isinstance(stop_reason, str)
                or not stop_reason
                or job.get("stopped") is not True
                or type(observation_cursor) is not int
                or type(recovery_cursor) is not int
                or job.get("scheduleDone")
                != observation_cursor + recovery_cursor + skipped_by_stop
            ):
                raise ValueError("Auth parent responsibility stop evidence differs")
            skipped_slots = schedule[observation_cursor:observation_cursor + skipped_by_stop]
            if (
                len(skipped_slots) != skipped_by_stop
                or any(
                    entry.get("phase") != "observation"
                    or entry.get("index") != observation_cursor + offset
                    for offset, entry in enumerate(skipped_slots)
                )
            ):
                raise ValueError("Auth parent responsibility stop schedule differs")
            abandoned_observation_slots = {
                ("observation", observation_cursor + offset)
                for offset in range(skipped_by_stop)
            }
            if any(
                (job_name, phase, index) in event_by_slot
                for phase, index in abandoned_observation_slots
            ):
                raise ValueError("Auth parent responsibility stop journal has an event")
        created_accounts = set()
        for index in sorted(creating):
            operation = observations[index]
            key = (job_name, "observation", index)
            event = event_by_slot.get(key)
            account = operation.get("account")
            resource = operation.get("resource")
            if key == child_key:
                if account != "custom" or resource != child_claim["ownedResources"][0]:
                    raise ValueError("Auth parent responsibility child exception differs")
                responsibilities.append({"job": job_name, "phase": "observation", "index": index, "account": account, "resource": resource, "disposition": "child-absence"})
                continue
            if event is None:
                # A missing event is terminal only when the frozen cursor proves
                # that the slot was never dispatched.
                consumed = job.get("scheduleDone")
                slots = [entry for entry in schedule[:consumed] if isinstance(entry, dict)]
                if ("observation", index) in abandoned_observation_slots:
                    responsibilities.append({"job": job_name, "phase": "observation", "index": index, "account": account, "resource": resource, "disposition": "not-dispatched"})
                    continue
                if any(entry.get("phase") == "observation" and entry.get("index") == index for entry in slots):
                    raise ValueError("Auth parent responsibility creating event missing")
                responsibilities.append({"job": job_name, "phase": "observation", "index": index, "account": account, "resource": resource, "disposition": "not-dispatched"})
                continue
            if event.get("completed") is not True or event.get("failure") is not None:
                raise ValueError("Auth parent responsibility creating event unresolved")
            outcome = event.get("creationOutcome")
            if outcome == "refused":
                evidence = event.get("authEvidence")
                status = event.get("status")
                if not isinstance(evidence, dict) or evidence.get("account") != account or evidence.get("creationOutcome") != "refused" or not (type(status) is int and 400 <= status < 500):
                    raise ValueError("Auth parent responsibility typed refusal required")
                responsibilities.append({"job": job_name, "phase": "observation", "index": index, "account": account, "resource": resource, "disposition": "refused"})
                continue
            if outcome != "created":
                raise ValueError("Auth parent responsibility creating event unresolved")
            record = accounts.get(account)
            if not isinstance(record, dict) or record.get("resource") != resource:
                raise ValueError("Auth parent responsibility account ownership missing")
            created_accounts.add(account)
            if record.get("createEvent") != next((position for position, candidate in enumerate(events) if candidate is event), None):
                raise ValueError("Auth parent responsibility creation event differs")
            try:
                owns = _auth_creation_ownership(gate, job, operation)
            except (KeyError, TypeError, ValueError):
                owns = False
            if not owns:
                raise ValueError("Auth parent responsibility creation proof differs")
            responsibilities.append({"job": job_name, "phase": "observation", "index": index, "account": account, "resource": resource, "disposition": "owned"})

        if set(accounts) != created_accounts:
            raise ValueError("Auth parent responsibility account coverage differs")
        for account, record in accounts.items():
            uid = record.get("uid")
            if not isinstance(uid, str) or not uid or sum(other.get("uid") == uid for other in accounts.values() if isinstance(other, dict)) != 1:
                raise ValueError("Auth parent responsibility account identity differs")
            cleanup_operations = [operation for operation in recovery if operation.get("account") == account]
            cleanup = {operation.get("kind"): operation for operation in cleanup_operations}
            if len(cleanup) != len(cleanup_operations):
                raise ValueError("Auth parent responsibility cleanup plan duplicated")
            if set(cleanup) != {"delete", "uid-absence"} and set(cleanup) != {"delete", "uid-absence", "address-absence"}:
                raise ValueError("Auth parent responsibility cleanup plan differs")
            for kind, operation in cleanup.items():
                if (
                    operation.get("resource") != record.get("resource")
                    or operation.get("service") != "auth"
                    or operation.get("method") != "POST"
                    or operation.get("kind") != kind
                    or not _auth_recovery_operation_valid(operation, plan.get("project"), account_bindings)
                ):
                    raise ValueError("Auth parent responsibility cleanup operation differs")
            order = [record.get("createEvent"), record.get("deleteEvent"), record.get("absenceEvent")]
            if "address-absence" in cleanup:
                order.append(record.get("addressAbsenceEvent"))
            positions = [_event_index(value, "cleanup") for value in order]
            if positions != sorted(positions) or len(set(positions)) != len(positions):
                raise ValueError("Auth parent responsibility cleanup order differs")
            labels = ["create", "delete", "uid-absence"]
            if "address-absence" in cleanup:
                labels.append("address-absence")
            for kind, position in zip(labels, positions, strict=True):
                if kind == "create":
                    continue
                _typed_cleanup_event(job_name, job, account, cleanup[kind], position, kind)
            proof = absence_proofs.get(record.get("resource"))
            if not isinstance(proof, dict) or proof.get("eventIndex") != record.get("absenceEvent") or proof.get("body") != events[record["absenceEvent"]].get("authEvidence", {}).get("body"):
                raise ValueError("Auth parent responsibility typed absence proof differs")

        if set(absence_proofs) != {record.get("resource") for record in accounts.values()}:
            raise ValueError("Auth parent responsibility absence coverage differs")

    projection = {
        "kind": "auth-parent-responsibility-close-v1",
        "parentPlanDigest": digest(plan),
        "parentGateDigest": digest(gate),
        "childClaimDigest": digest(child_claim),
        "responsibilities": sorted(responsibilities, key=lambda value: (value["job"], value["phase"], value["index"])),
    }
    projection["projectionDigest"] = digest(projection)
    return projection


def _auth_validated_close_row(row):
    """Return whether a terminal Auth row carries the new close marker."""
    if not isinstance(row, dict) or row.get("state") != "closed-after-auth-recovery-child":
        return False
    marker = row.get("authRecoveryCloseResponsibilitiesDigest")
    if not isinstance(marker, str) or re.fullmatch(r"[a-f0-9]{64}", marker) is None:
        return False
    children = row.get("recoveryChildren")
    if not isinstance(children, list) or len(children) != 1:
        return False
    child = children[0]
    ticket = child.get("ticket") if isinstance(child, dict) else None
    parent_claim = row.get("claim")
    child_claim = child.get("claim") if isinstance(child, dict) else None
    if (
        not isinstance(child, dict)
        or not isinstance(ticket, dict)
        or not isinstance(parent_claim, dict)
        or not isinstance(child_claim, dict)
    ):
        return False
    if not (
        child.get("state") == "settled"
        and child.get("claimDigest") == row.get("authRecoveryCloseChildClaimDigest")
        and child.get("finalGateDigest") == row.get("finalGateDigest")
        and row.get("authRecoveryCloseChildTicketDigest") == digest(ticket)
    ):
        return False
    try:
        gate = Gate(parent_claim["gatePath"], _gate_job(parent_claim)).snapshot()
        projection = _auth_parent_responsibility_projection(gate, child_claim)
    except (KeyError, OSError, TypeError, ValueError):
        return False
    return (
        projection["projectionDigest"] == marker
        and projection["parentGateDigest"] == digest(gate)
        and child_claim.get("parentGateDigest") == projection["parentGateDigest"]
    )


def _auth_absence_proof(value, resource, operation):
    if not isinstance(value, dict) or set(value) != {
        "kind", "resource", "status", "bodyShape", "bodyDigest", "responseDigest",
        "eventIndex", "requestDigest",
    } or value["kind"] != AUTH_RECOVERY_ABSENCE_KIND:
        raise ValueError("typed Auth absence proof required")
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
    if (
        value["resource"] != resource
        or value["status"] != 200
        or value["bodyShape"] != body
        or value["bodyDigest"] != digest(body)
        or value["responseDigest"] != digest(body)
        or value["eventIndex"] != 0
        or value["requestDigest"] != digest(operation)
    ):
        raise ValueError("typed Auth absence proof required")
    _hash(value["bodyDigest"])
    _hash(value["responseDigest"])


def _auth_recovery_gate(gate, child_claim, proof):
    _auth_recovery_plan(gate.get("plan"), child_claim)
    if gate.get("planDigest") != child_claim["gatePlanDigest"] or gate.get("coordinatorInflight"):
        raise ValueError("Auth recovery Gate binding changed")
    job_name = child_claim["gateJob"]
    job = gate.get("jobs", {}).get(job_name)
    operation = gate["plan"]["jobs"][job_name]["recovery"][0]
    if (
        not isinstance(job, dict)
        or job.get("inflight")
        or job.get("complete") is not True
        or job.get("recovery") != 1
        or job.get("observation") != 0
        or job.get("absent") != child_claim["ownedResources"]
        or len(gate.get("events", [])) != 1
    ):
        raise ValueError("Auth recovery Gate terminal evidence incomplete")
    event = gate["events"][0]
    if (
        event.get("job") != job_name
        or event.get("phase") != "recovery"
        or event.get("index") != 0
        or event.get("requestDigest") != digest(operation)
        or event.get("method") != "POST"
        or event.get("service") != "auth"
        or event.get("completed") is not True
        or event.get("status") != 200
        or event.get("responseDigest") != proof["responseDigest"]
    ):
        raise ValueError("Auth recovery Gate absence event changed")
    if gate.get("skips") or job.get("creationProofs") not in (None, {}):
        raise ValueError("Auth recovery Gate must remain lookup-only")
    for pid in [gate.get("coordinatorPid"), job.get("pid")]:
        if pid is None:
            continue
        if type(pid) is not int or pid <= 0:
            raise ValueError("Auth recovery worker identity required")
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        raise ValueError("Auth recovery worker is still alive")
    return operation


def _validate_recovery_gate_plan(parent_plan, child_plan, child):
    if not isinstance(parent_plan, dict) or digest(parent_plan) != child["parentPlanDigest"]:
        raise ValueError("canonical parent plan binding changed")
    lane = Path(__file__).resolve().parent.parent / "fs-request-bytes-boundary"
    sys.path.insert(0, str(lane))
    try:
        import request_bytes_compiler as parent_compiler
        import request_bytes_recovery_campaign as recovery_campaign
        sentinel = child.get("caseId") == RECOVERY_SENTINEL_CASE_ID
        if sentinel:
            if parent_plan.get("caseMode") != "single-exploratory-sentinel":
                raise ValueError("sentinel parent case identity required")
            parent_compiler.validate_request_bytes_sentinel_plan(parent_plan)
        elif parent_plan.get("caseMode") == "single-exploratory-sentinel":
            raise ValueError("sentinel recovery case identity required")
        recovery = recovery_campaign.compile_recovery_plan(
            parent_plan,
            selected_probe=child["selectedProbe"],
            recovery_nonce=child["recoveryNonce"],
        )
        expected = recovery_campaign.compile_gate_plan(
            parent_plan,
            selected_probe=child["selectedProbe"],
            recovery_nonce=child["recoveryNonce"],
            recovery_plan=recovery,
        )
    except (ImportError, KeyError, TypeError, ValueError) as error:
        raise ValueError("authoritative recovery compiler refused plan") from error
    if not isinstance(child_plan, dict) or child_plan != expected or digest(expected) != child["gatePlanDigest"]:
        raise ValueError("authoritative recovery Gate plan differs")
    jobs = child_plan.get("jobs")
    if not isinstance(jobs, dict) or len(jobs) != 1:
        raise ValueError("one recovery Gate job required")
    operations = next(iter(jobs.values())).get("recovery")
    request_count = RECOVERY_SENTINEL_REQUESTS if child.get("caseId") else RECOVERY_CHILD_REQUESTS
    inspection_count = RECOVERY_SENTINEL_INSPECTION_REQUESTS if child.get("caseId") else RECOVERY_INSPECTION_REQUESTS
    delete_count = RECOVERY_SENTINEL_DELETE_REQUESTS if child.get("caseId") else RECOVERY_DELETE_REQUESTS
    absence_count = RECOVERY_SENTINEL_ABSENCE_REQUESTS if child.get("caseId") else RECOVERY_ABSENCE_REQUESTS
    if not isinstance(operations, list) or len(operations) != request_count:
        raise ValueError("recovery operation count changed")
    kinds = [operation.get("kind") for operation in operations]
    if kinds.count("recovery-inspection-read") != inspection_count or kinds.count("recovery-conditional-delete") != delete_count or kinds.count("recovery-absence-read") != absence_count:
        raise ValueError("recovery operation classes changed")
    if any(operation.get("versionFrom") != "recovery-inspection-read" for operation in operations if operation.get("kind") == "recovery-conditional-delete"):
        raise ValueError("version-bound delete inspection required")
    resources = sorted({operation.get("resource") for operation in operations})
    if digest(resources) != child["resourceDigest"] or resources != child["ownedResources"] or child["manifestDigest"] != digest(recovery):
        raise ValueError("recovery resources differ from canonical plan")


def _compile_request_bytes_parent(parent_inputs):
    """Compile exactly the legacy parent or the explicitly selected sentinel."""
    lane = Path(__file__).resolve().parent.parent / "fs-request-bytes-boundary"
    sys.path.insert(0, str(lane))
    try:
        import request_bytes_compiler as request_compiler

        plan_inputs = parent_inputs["plan"]
        case_id = plan_inputs.get("caseId")
        if case_id == RECOVERY_SENTINEL_CASE_ID:
            return request_compiler.compile_request_bytes_sentinel_plan(
                plan_inputs["project"], plan_inputs["database"], plan_inputs["nonce"]
            )
        if case_id is not None or plan_inputs.get("caseMode") is not None:
            raise ValueError("unsupported request-byte parent case identity")
        return request_compiler.compile_request_bytes_plan(
            plan_inputs["project"], plan_inputs["database"], plan_inputs["nonce"]
        )
    except (ImportError, KeyError, TypeError, ValueError) as error:
        raise ValueError("canonical parent compiler refused inputs") from error


def _validate_recovery_terminal_slots(gate, job_name, expected_fields, child_claim):
    """Bind every compiler recovery slot to its journal event or skip."""
    job = gate["jobs"][job_name]
    plan_job = gate["plan"]["jobs"][job_name]
    if job.get("creationProofs") != {}:
        raise ValueError("recovery child creation proofs must remain empty")
    operations = plan_job["recovery"]
    schedule = plan_job.get("schedule", [])
    request_count = RECOVERY_SENTINEL_REQUESTS if child_claim.get("caseId") else RECOVERY_CHILD_REQUESTS
    if len(operations) != request_count or len(schedule) != len(operations):
        raise ValueError("recovery schedule is not canonical")
    events, skips = {}, {}
    journal_events = gate.get("events", [])
    for event in gate.get("events", []):
        if event.get("job") == job_name and event.get("phase") == "recovery":
            index = event.get("index")
            if type(index) is not int or index in events:
                raise ValueError("recovery journal index changed")
            events[index] = event
    for skip in gate.get("skips", []):
        if skip.get("job") == job_name:
            index = skip.get("index")
            if type(index) is not int or index in skips:
                raise ValueError("recovery skip index changed")
            skips[index] = skip
    for index, operation in enumerate(operations):
        if schedule[index].get("phase") != "recovery" or schedule[index].get("index") != index or schedule[index].get("creates") is not False:
            raise ValueError("recovery schedule slot changed")
        event, skip = events.get(index), skips.get(index)
        if operation["kind"] == "recovery-inspection-read":
            if event is None or skip is not None or event.get("requestDigest") != digest(operation) or event.get("method") != "GET" or event.get("service") != operation["service"] or event.get("completed") is not True:
                raise ValueError("recovery inspection journal differs")
            status = event.get("status")
            capture = job.get("captures", {}).get(str(index), {})
            if status == 404:
                if (
                    capture.get("status") != 404
                    or capture.get("name") is not None
                    or capture.get("updateTime") is not None
                    or capture.get("fieldsDigest") != digest(None)
                ):
                    raise ValueError("recovery inspection absence proof differs")
                if re.fullmatch(r"[a-f0-9]{64}", capture.get("responseDigest", "")) is None or event.get("responseDigest") != capture["responseDigest"]:
                    raise ValueError("recovery inspection response binding differs")
            elif status == 200:
                if (
                    capture.get("status") != 200
                    or capture.get("name") != operation["resource"]
                    or not isinstance(capture.get("fieldsDigest"), str)
                    or re.fullmatch(r"[a-f0-9]{64}", capture["fieldsDigest"]) is None
                    or not isinstance(capture.get("updateTime"), str)
                    or not capture["updateTime"]
                ):
                    raise ValueError("recovery inspection capture differs")
                if capture["fieldsDigest"] != expected_fields.get(operation["resource"]):
                    raise ValueError("recovery inspection fields binding differs")
                if re.fullmatch(r"[a-f0-9]{64}", capture.get("responseDigest", "")) is None or event.get("responseDigest") != capture["responseDigest"]:
                    raise ValueError("recovery inspection response binding differs")
            else:
                raise ValueError("recovery inspection status differs")
        elif operation["kind"] == "recovery-conditional-delete":
            source_index = next((position for position, candidate in enumerate(operations[:index]) if candidate.get("kind") == operation.get("versionFrom") and candidate.get("resource") == operation["resource"]), None)
            if source_index is None:
                raise ValueError("recovery delete source differs")
            capture = job.get("captures", {}).get(str(source_index), {})
            if capture.get("status") == 404:
                if event is not None or skip is None or skip.get("reason") not in {"refused-create", "never-dispatched", "absent-or-unavailable-cleanup-read"}:
                    raise ValueError("recovery delete skip differs")
            elif capture.get("status") == 200:
                if skip is not None or event is None or event.get("completed") is not True:
                    raise ValueError("recovery delete event differs")
                wire = dict(operation)
                wire.pop("versionFrom", None)
                wire["path"] += "?currentDocument.updateTime=" + quote(capture["updateTime"], safe="")
                if event.get("requestDigest") != digest(wire) or event.get("method") != "DELETE" or event.get("service") != operation["service"]:
                    raise ValueError("recovery delete binding differs")
            else:
                raise ValueError("recovery delete source status differs")
        elif operation["kind"] == "recovery-absence-read":
            proof = job.get("absenceProofs", {}).get(operation["resource"])
            proof_event = (
                journal_events[proof["eventIndex"]]
                if isinstance(proof, dict)
                and type(proof.get("eventIndex")) is int
                and 0 <= proof["eventIndex"] < len(journal_events)
                else None
            )
            if event is None or skip is not None or event.get("requestDigest") != digest(operation) or event.get("method") != "GET" or event.get("service") != operation["service"] or event.get("completed") is not True or event.get("status") != 404 or not isinstance(proof, dict) or proof_event is not event or not typed_absence(404, proof.get("body")):
                raise ValueError("recovery absence journal differs")
        else:
            raise ValueError("unknown recovery operation kind")
    if set(events) | set(skips) != set(range(len(operations))) or set(events) & set(skips):
        raise ValueError("recovery journal does not cover every slot")


class Ledger:
    def __init__(self, path):
        if Path(path).is_symlink():
            raise ValueError("shared root must not be a symlink")
        self.path = Path(path).resolve()
        self.identity = None
        self.identity = self.snapshot()["identity"]

    @classmethod
    def create(cls, path):
        path = Path(path)
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        (path / "lock").touch(mode=0o600, exist_ok=False)
        _save(
            path,
            {
                "kind": "shared-reservations-v1",
                "identity": secrets.token_hex(32),
                "envelopes": {},
                "recoveryEnvelopes": {},
                "reservations": {},
            },
        )
        return cls(path)

    @contextlib.contextmanager
    def _locked(self):
        if self.path.stat().st_mode & 0o077 or any(
            (self.path / name).is_symlink() for name in ("lock", "state.json")
        ):
            raise ValueError("private regular shared ledger required")
        with (self.path / "lock").open("r+") as stream:
            until = time.monotonic() + 15
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= until:
                        raise ValueError("shared reservation lock deadline") from None
                    time.sleep(0.01)
            with (self.path / "state.json").open("rb") as source:
                raw = source.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("bounded shared ledger exceeded")
            state = json.loads(raw)
            if state.get("kind") != "shared-reservations-v1" or self.identity not in (
                None,
                state.get("identity"),
            ):
                raise ValueError("shared ledger identity changed")
            _hash(state["identity"])
            for key, entry in state["envelopes"].items():
                _envelope(entry["envelope"])
                _budget(entry["allocated"])
                if digest(entry["envelope"]) != key:
                    raise ValueError("envelope binding changed")
                total = {
                    k: sum(
                        r["claim"]["budget"][k]
                        for r in state["reservations"].values()
                        if r["envelopeDigest"] == key
                    )
                    for k in DIMENSIONS
                }
                if total != entry["allocated"] or any(
                    total[k] > entry["envelope"]["limits"][k] for k in DIMENSIONS
                ):
                    raise ValueError("shared budget accounting changed")
            for key, entry in state.get("recoveryEnvelopes", {}).items():
                _envelope(entry["envelope"])
                _budget(entry["allocated"])
                if digest(entry["envelope"]) != key:
                    raise ValueError("recovery envelope binding changed")
                children = [
                    child
                    for row in state["reservations"].values()
                    for child in row.get("recoveryChildren", [])
                    if child.get("envelopeDigest") == key
                ]
                total = {k: sum(child["claim"]["budget"][k] for child in children) for k in DIMENSIONS}
                if total != entry["allocated"] or any(total[k] > entry["envelope"]["limits"][k] for k in DIMENSIONS):
                    raise ValueError("recovery envelope accounting changed")
            for row in state["reservations"].values():
                _claim(row["claim"])
                _number(row["deadline"])
                if (
                    row["envelopeDigest"] not in state["envelopes"]
                    or row["deadline"]
                    > state["envelopes"][row["envelopeDigest"]]["envelope"]["expiresAt"]
                ):
                    raise ValueError("reservation envelope changed")
                if "generation" in row:
                    _generation(row["generation"])
                if digest(row["claim"]) != row["claimDigest"] or row["state"] not in {
                    "held",
                    "closing",
                    "released",
                    "aborted-no-data",
                    "closed-after-escalation",
                    "closed-after-abandon",
                    "closed-after-recovery-child",
                    "closed-after-auth-recovery-child",
                }:
                    raise ValueError("reservation binding changed")
                children = row.get("recoveryChildren", [])
                if children and row["state"] not in {"held", "closed-after-recovery-child", "closed-after-auth-recovery-child"}:
                    raise ValueError("recovery child parent is not held")
                for child in children:
                    if child.get("claim", {}).get("kind") == AUTH_RECOVERY_CHILD_KIND:
                        _auth_recovery_child_claim(child["claim"])
                    else:
                        _recovery_child_claim(child["claim"])
                    if child.get("parentClaimDigest") != row["claimDigest"] or child.get("claimDigest") != digest(child["claim"]):
                        raise ValueError("recovery child parent binding changed")
                    if child.get("state") not in {"allocated", "settled"} or child.get("envelopeDigest") not in state.get("recoveryEnvelopes", {}):
                        raise ValueError("recovery child state changed")
                    if child.get("state") == "settled":
                        if not isinstance(child.get("receiptDigest"), str) or not 1 <= len(child["receiptDigest"]) <= 256:
                            raise ValueError("recovery settlement receipt changed")
                        _hash(child.get("finalGateDigest"))
                        if child.get("claim", {}).get("kind") == AUTH_RECOVERY_CHILD_KIND:
                            _hash(child.get("absenceProofDigest"))
                    _number(child.get("deadline"))
                    if child["deadline"] > child["claim"]["expiresAt"] or child["deadline"] > state["recoveryEnvelopes"][child["envelopeDigest"]]["envelope"]["expiresAt"]:
                        raise ValueError("recovery child deadline changed")
            yield state

    def _save(self, state):
        if len(json.dumps(state, allow_nan=False).encode()) > MAX_BYTES:
            raise ValueError("bounded shared ledger exceeded")
        _save(self.path, state)

    def snapshot(self):
        with self._locked() as state:
            return state

    def reserve(self, envelope, claim, gate_plan, *, generation=None, now=None):
        if now is not None:
            _number(now)
        _envelope(envelope)
        _claim(claim)
        if claim["campaignId"] not in CATALOGUED_CAMPAIGN_IDS:
            raise ValueError(f"uncatalogued campaign id: {claim['campaignId']}")
        if (
            "campaignId" in gate_plan
            and claim["campaignId"] != gate_plan["campaignId"]
        ):
            raise ValueError("claim campaign differs from Gate plan")
        if (
            (gate_plan.get("wallSeconds", 0) > 1200 or claim["durationSeconds"] > 1200)
            and (
                gate_plan.get("campaignId") != AUTH_REV3_CAMPAIGN_ID
                or claim["campaignId"] != AUTH_REV3_CAMPAIGN_ID
                or gate_plan.get("selector") != AUTH_REV3_SELECTOR
                or gate_plan.get("wallSeconds", 0) > AUTH_REV3_WALL_SECONDS
                or gate_plan.get("recoverySeconds", 0) < 300
                or claim["durationSeconds"] != gate_plan.get("wallSeconds")
            )
        ):
            raise ValueError("closed AUTH revision-3 wall reservation required")
        if generation is not None:
            _generation(generation)
        preparation = gate_plan.get("transport") == LIMITS_PREPARATION_TRANSPORT
        if preparation:
            validate_limits_preparation_plan(gate_plan)
            if (
                claim["campaignId"] != "FS-WRITE-LIMITS-03"
                or _gate_job(claim) != "limits"
                or claim["budget"] != {"requests": 6, "accounts": 0, "resources": 0, "costMicrousd": 600}
                or generation is None
                or {key: gate_plan.get(key) for key in GENERATION_FIELDS} != generation
                or claim["durationSeconds"] != gate_plan["wallSeconds"]
                or any(lock["mode"] != "READ" for lock in claim["locks"])
            ):
                raise ValueError("closed limits preparation reservation required")
        if (
            digest(gate_plan) != claim["gatePlanDigest"]
            or digest(gate_plan["nonce"]) != claim["nonceDigest"]
            or Path(claim["gatePath"]).exists()
        ):
            raise ValueError("fresh frozen Gate required")
        if (
            gate_plan.get("permissionDigest", envelope["permissionDigest"])
            != envelope["permissionDigest"]
        ):
            raise ValueError("Gate permission differs from shared envelope")
        recovery = sum(len(j["recovery"]) for j in gate_plan["jobs"].values()) + len(
            gate_plan.get("management", {}).get("recovery", [])
        )
        resources = {r for j in gate_plan["jobs"].values() for r in j["resources"]}
        if (
            claim["durationSeconds"] < gate_plan["wallSeconds"]
            or claim["budget"]["requests"]
            < gate_plan["observationRequests"]
            + recovery
            + gate_plan.get("coordinatorRequests", 0)
            or claim["budget"]["costMicrousd"] < gate_plan["costMicrousd"]
            or claim["budget"]["resources"] < len(resources)
        ):
            raise ValueError("Gate exceeds campaign sub-budget")
        for lock in claim["locks"]:
            if not any(
                _ancestor(_scope(scope), _scope(lock))
                and MODES[scope["mode"]] >= MODES[lock["mode"]]
                for scope in envelope["scopes"]
            ):
                raise ValueError("resource lock exceeds permission scope")
        key = digest(envelope)
        with self._locked() as state:
            decision_now = time.time() if now is None else now
            _number(decision_now)
            if preparation and (
                type(gate_plan.get("permissionExpiresAt")) not in (int, float)
                or not math.isfinite(gate_plan["permissionExpiresAt"])
                or not decision_now < gate_plan["permissionExpiresAt"] <= min(
                    envelope["expiresAt"], decision_now + claim["durationSeconds"]
                )
            ):
                raise ValueError("limits preparation deadline cannot reset")
            if (
                not envelope["issuedAt"] <= decision_now
                or decision_now + claim["durationSeconds"] > envelope["expiresAt"]
            ):
                raise ValueError("campaign outside permission window")
            for resource in resources:
                resource_scope = _resource_scope(resource)
                if not any(
                    _ancestor(_scope(lock), resource_scope)
                    and MODES[lock["mode"]] >= MODES["WRITE"]
                    for lock in claim["locks"]
                ):
                    raise ValueError("Gate resource lock is not covered")
            if any(
                entry["envelope"]["permissionDigest"] == envelope["permissionDigest"]
                and existing != key
                for existing, entry in state["envelopes"].items()
            ):
                raise ValueError("permission already bound to another envelope")
            rows = list(state["reservations"].values())
            if len(rows) >= MAX_RESERVATIONS or any(
                r["claim"]["nonceDigest"] == claim["nonceDigest"]
                or r["claim"]["gatePath"] == claim["gatePath"]
                for r in rows
            ):
                raise ValueError("reservation capacity or nonce/Gate reuse")
            active = [
                r
                for r in rows
                if (
                    r["state"] != "closed-after-auth-recovery-child"
                    and r["state"] not in {
                        "released",
                        "aborted-no-data",
                        "closed-after-escalation",
                        "closed-after-abandon",
                    }
                )
                or (
                    r["state"] == "closed-after-auth-recovery-child"
                    and not _auth_validated_close_row(r)
                )
            ]
            if any(
                conflicts(a, b)
                for r in active
                for a in r["claim"]["locks"]
                for b in claim["locks"]
            ):
                raise ValueError("production resource lock conflict")
            if (
                sum(r["envelopeDigest"] == key for r in active)
                >= envelope["concurrency"]
            ):
                raise ValueError("envelope concurrency exhausted")
            # The owner's US$10 is per observation task, and every earlier
            # reservation of the task counts whatever state it reached.
            task_budget_check(
                state, claim["campaignId"], claim["budget"]["costMicrousd"]
            )
            allocated = {
                k: sum(
                    r["claim"]["budget"][k] for r in rows if r["envelopeDigest"] == key
                )
                + claim["budget"][k]
                for k in DIMENSIONS
            }
            if any(allocated[k] > envelope["limits"][k] for k in DIMENSIONS):
                raise ValueError("envelope capacity exhausted")
            reservation = secrets.token_hex(32)
            ticket = {
                "ledgerPath": str(self.path),
                "ledgerIdentity": self.identity,
                "reservation": reservation,
                "claimDigest": digest(claim),
                "envelopeDigest": key,
            }
            state["envelopes"][key] = {"envelope": envelope, "allocated": allocated}
            row = {
                "claim": claim,
                "claimDigest": ticket["claimDigest"],
                "envelopeDigest": key,
                "state": "held",
                "deadline": decision_now + claim["durationSeconds"],
            }
            if generation is not None:
                # Bind the retirement path to this acquisition's own source
                # closure, so a later generation stays retirable without
                # editing canonical state by hand.
                row["generation"] = copy.deepcopy(generation)
            state["reservations"][reservation] = row
            self._save(state)
            return ticket

    def begin_auth_recovery_extension(
        self,
        parent_ticket,
        child_claim,
        new_envelope,
        canonical_child_gate_plan,
        *,
        source_binding,
        transport_binding,
        o7_binding,
        o8_binding,
        parent_evidence,
        now=None,
    ):
        """Persist the closed Auth packet05 lookup child before capability use.

        The lane owns source, transport, O7 and O8 authority. This Ledger method
        stores only their typed digests and performs no capability issuance or
        network action. The sole child operation is an exact custom-UID lookup.
        """
        _auth_recovery_child_claim(child_claim)
        _envelope(new_envelope)
        _auth_parent_evidence(parent_evidence)
        binding_digests = {
            "sourceBindingDigest": _auth_binding(source_binding, "auth-source-binding-v1"),
            "transportBindingDigest": _auth_binding(transport_binding, "auth-transport-binding-v1"),
            "o7BindingDigest": _auth_binding(o7_binding, "auth-o7-binding-v1"),
            "o8BindingDigest": _auth_binding(o8_binding, "auth-o8-binding-v1"),
        }
        if any(child_claim[key] != value for key, value in binding_digests.items()):
            raise ValueError("Auth recovery authority binding changed")
        if child_claim["manifestDigest"] != digest(canonical_child_gate_plan):
            raise ValueError("Auth recovery manifest binding changed")
        _auth_recovery_plan(canonical_child_gate_plan, child_claim)
        if now is not None:
            _number(now)
        with self._locked() as state:
            parent = self._row(state, parent_ticket)
            if parent["state"] != "held" or parent.get("inflight") is True:
                raise ValueError("held Auth parent without in-flight work required")
            claim = parent["claim"]
            if (
                claim["campaignId"] != AUTH_RECOVERY_CAMPAIGN
                or child_claim["parentClaimDigest"] != parent["claimDigest"]
                or child_claim["parentPlanDigest"] != claim["gatePlanDigest"]
                or child_claim["parentGateJob"] != _gate_job(claim)
                or child_claim["parentGateDigest"] != parent_evidence["gateDigest"]
                or child_claim["parentEvidenceDigest"] != parent_evidence["evidenceDigest"]
                or child_claim["nonceDigest"] == claim["nonceDigest"]
                or child_claim["gatePlanDigest"] == claim["gatePlanDigest"]
                or child_claim["permissionDigest"] == state["envelopes"][parent["envelopeDigest"]]["envelope"]["permissionDigest"]
                or child_claim["generation"] == parent.get("generation")
                or child_claim["ownedResources"] != [parent_evidence["resource"]]
            ):
                raise ValueError("Auth recovery child is not bound to held parent")
            if parent_evidence["gatePlanDigest"] != claim["gatePlanDigest"]:
                raise ValueError("Auth parent evidence Gate binding changed")
            parent_snapshot = {
                "state": parent["state"],
                "claim": copy.deepcopy(claim),
                "claimDigest": parent["claimDigest"],
                "envelopeDigest": parent["envelopeDigest"],
                "generation": copy.deepcopy(parent.get("generation")),
            }
            parent_gate_path = claim["gatePath"]
            parent_gate_job = _gate_job(claim)
        parent_gate = Gate(parent_gate_path, parent_gate_job).snapshot()
        projection = _auth_parent_projection(parent_gate, child_claim)
        if projection != parent_evidence:
            raise ValueError("Auth parent evidence differs from registered Gate")
        _auth_parent_responsibility_projection(parent_gate, child_claim)
        for pid in [parent_gate.get("coordinatorPid")] + [job.get("pid") for job in parent_gate.get("jobs", {}).values()]:
            if pid is None:
                continue
            if type(pid) is not int or pid <= 0:
                raise ValueError("Auth parent worker identity required")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise ValueError("Auth parent worker is still alive")
        decision_now = time.time() if now is None else now
        with self._locked() as state:
            parent = self._row(state, parent_ticket)
            claim = parent["claim"]
            if (
                parent["state"] != parent_snapshot["state"]
                or parent["claim"] != parent_snapshot["claim"]
                or parent["claimDigest"] != parent_snapshot["claimDigest"]
                or parent["envelopeDigest"] != parent_snapshot["envelopeDigest"]
                or parent.get("generation") != parent_snapshot["generation"]
            ):
                raise ValueError("parent changed during Auth recovery admission")
            child_digest = digest(child_claim)
            envelope_digest = digest(new_envelope)
            existing = parent.get("recoveryChildren", [])
            if existing:
                if len(existing) == 1 and existing[0].get("claimDigest") == child_digest and existing[0].get("envelopeDigest") == envelope_digest:
                    return copy.deepcopy(existing[0]["ticket"])
                raise ValueError("one Auth recovery child only")
            if Path(child_claim["gatePath"]).exists():
                raise ValueError("fresh Auth recovery Gate required")
            if any(
                child_claim["nonceDigest"] == row.get("claim", {}).get("nonceDigest")
                or any(
                    child_claim["nonceDigest"] == value.get("claim", {}).get("nonceDigest")
                    for value in row.get("recoveryChildren", [])
                )
                for row in state["reservations"].values()
            ):
                raise ValueError("Auth recovery nonce already reserved")
            if any(entry["envelope"].get("permissionDigest") == new_envelope["permissionDigest"] for entry in state["envelopes"].values()) or any(entry["envelope"].get("permissionDigest") == new_envelope["permissionDigest"] for entry in state.get("recoveryEnvelopes", {}).values()):
                raise ValueError("Auth recovery permission already spent")
            if child_claim["durationSeconds"] < canonical_child_gate_plan["wallSeconds"]:
                raise ValueError("Auth recovery duration below Gate wall")
            if child_claim["expiresAt"] < decision_now + child_claim["durationSeconds"]:
                raise ValueError("Auth recovery window is too short")
            if (
                new_envelope["permissionDigest"] != child_claim["permissionDigest"]
                or new_envelope["limits"]["requests"] < 1
                or new_envelope["limits"]["accounts"] < 1
                or new_envelope["limits"]["resources"] < 1
                or new_envelope["limits"]["costMicrousd"] < child_claim["budget"]["costMicrousd"]
                or not new_envelope["issuedAt"] <= decision_now < new_envelope["expiresAt"]
                or decision_now + child_claim["durationSeconds"] > new_envelope["expiresAt"]
            ):
                raise ValueError("Auth recovery envelope does not fund child")
            if any(
                not any(_ancestor(_scope(scope), _scope(lock)) and MODES[scope["mode"]] >= MODES[lock["mode"]] for scope in new_envelope["scopes"])
                for lock in child_claim["locks"]
            ):
                raise ValueError("Auth recovery lock exceeds permission scope")
            if any(
                not any(_ancestor(_scope(parent_lock), _scope(child_lock)) and MODES[parent_lock["mode"]] >= MODES[child_lock["mode"]] for parent_lock in claim["locks"])
                for child_lock in child_claim["locks"]
            ):
                raise ValueError("Auth recovery lock exceeds parent boundary")
            if not any(
                _ancestor(_scope(lock), _resource_scope(child_claim["ownedResources"][0])) and MODES[lock["mode"]] >= MODES["WRITE"]
                for lock in child_claim["locks"]
            ):
                raise ValueError("Auth recovery resource lock missing")
            task_budget_check(state, AUTH_RECOVERY_CAMPAIGN, child_claim["budget"]["costMicrousd"])
            child_reservation = secrets.token_hex(32)
            child_ticket = {
                "ledgerPath": str(self.path), "ledgerIdentity": self.identity,
                "reservation": child_reservation, "claimDigest": child_digest,
                "envelopeDigest": envelope_digest, "parentReservation": parent_ticket["reservation"],
            }
            state.setdefault("recoveryEnvelopes", {})[envelope_digest] = {
                "envelope": copy.deepcopy(new_envelope), "allocated": copy.deepcopy(child_claim["budget"]),
            }
            parent.setdefault("recoveryChildren", []).append({
                "reservation": child_reservation, "ticket": child_ticket,
                "claim": copy.deepcopy(child_claim), "claimDigest": child_digest,
                "parentClaimDigest": parent["claimDigest"], "envelopeDigest": envelope_digest,
                "state": "allocated", "deadline": decision_now + child_claim["durationSeconds"],
            })
            self._save(state)
            return copy.deepcopy(child_ticket)

    def bound_auth_recovery_claim(self, child_ticket):
        """Inspect one persisted Auth child without granting any capability."""
        if not isinstance(child_ticket, dict) or not isinstance(child_ticket.get("parentReservation"), str):
            raise ValueError("exact Auth recovery child ticket required")  # noqa: TRY004 -- refusal contract
        with self._locked() as state:
            parent = state["reservations"].get(child_ticket["parentReservation"])
            child = next((value for value in (parent or {}).get("recoveryChildren", []) if value.get("ticket") == child_ticket), None)
            if parent is None or child is None or child_ticket.get("ledgerPath") != str(self.path) or child_ticket.get("ledgerIdentity") != self.identity:
                raise ValueError("persisted Auth recovery child ticket required")
            if child["claim"].get("kind") != AUTH_RECOVERY_CHILD_KIND:
                raise ValueError("Auth recovery child kind changed")
            return {"ticket": copy.deepcopy(child["ticket"]), "childClaim": copy.deepcopy(child["claim"]),
                "newEnvelope": copy.deepcopy(state["recoveryEnvelopes"][child["envelopeDigest"]]["envelope"]),
                "parentClaim": copy.deepcopy(parent["claim"]), "parentIdentity": {"reservation": child_ticket["parentReservation"], "claimDigest": parent["claimDigest"]},
                "parentState": parent["state"], "childEnvelopeDigest": child["envelopeDigest"],
                "state": child["state"], "deadline": child["deadline"]}

    def settle_auth_recovery_child(self, child_ticket, *, absence_proof, receipt_digest, now=None):
        """Settle only a registered child Gate with a typed absent lookup."""
        if now is not None:
            _number(now)
        _hash(receipt_digest)
        bound = self.bound_auth_recovery_claim(child_ticket)
        child_claim = bound["childClaim"]
        settlement_snapshot = {
            "parentState": bound["parentState"],
            "parentClaim": bound["parentClaim"],
            "parentClaimDigest": bound["parentIdentity"]["claimDigest"],
            "childClaim": copy.deepcopy(child_claim),
            "childClaimDigest": digest(child_claim),
            "childEnvelopeDigest": bound["childEnvelopeDigest"],
            "childState": bound["state"],
        }
        gate = Gate(child_claim["gatePath"], child_claim["gateJob"]).snapshot()
        operation = gate["plan"]["jobs"][child_claim["gateJob"]]["recovery"][0]
        _auth_absence_proof(absence_proof, child_claim["ownedResources"][0], operation)
        _auth_recovery_gate(gate, child_claim, absence_proof)
        final_gate_digest = digest(gate)
        proof_digest = digest(absence_proof)
        with self._locked() as state:
            parent = state["reservations"].get(child_ticket["parentReservation"])
            child = next((value for value in (parent or {}).get("recoveryChildren", []) if value.get("ticket") == child_ticket), None)
            if (
                parent is None
                or child is None
                or parent.get("state") != settlement_snapshot["parentState"]
                or parent.get("claim") != settlement_snapshot["parentClaim"]
                or parent.get("claimDigest") != settlement_snapshot["parentClaimDigest"]
                or child.get("claim") != settlement_snapshot["childClaim"]
                or child.get("claimDigest") != settlement_snapshot["childClaimDigest"]
                or child.get("envelopeDigest") != settlement_snapshot["childEnvelopeDigest"]
            ):
                raise ValueError("Auth recovery child changed during settlement")
            if child.get("state") == "settled":
                if child.get("receiptDigest") != receipt_digest or child.get("absenceProofDigest") != proof_digest or child.get("finalGateDigest") != final_gate_digest:
                    raise ValueError("different Auth recovery settlement proof")
                return copy.deepcopy(child["ticket"])
            if child.get("state") != "allocated":
                raise ValueError("Auth recovery child is not allocatable")
            child["state"] = "settled"
            child["receiptDigest"] = receipt_digest
            child["absenceProofDigest"] = proof_digest
            child["finalGateDigest"] = final_gate_digest
            self._save(state)
            return copy.deepcopy(child["ticket"])

    def close_after_auth_recovery_child(self, parent_ticket, child_ticket, *, receipt_digest, now=None):
        """Close the held Auth parent only after the child proved typed absence."""
        if now is not None:
            _number(now)
        _hash(receipt_digest)
        if not isinstance(parent_ticket, dict) or not isinstance(child_ticket, dict):
            raise ValueError("exact Auth recovery close tickets required")  # noqa: TRY004 -- refusal contract
        with self._locked() as state:
            parent = self._row(state, parent_ticket)
            child = next((value for value in parent.get("recoveryChildren", []) if value.get("ticket") == child_ticket), None)
            if child is None or child_ticket.get("parentReservation") != parent_ticket.get("reservation"):
                raise ValueError("Auth recovery child is not nested under parent")
            if parent["state"] == "closed-after-auth-recovery-child":
                if (
                    parent.get("authRecoveryCloseReceiptDigest") != receipt_digest
                    or parent.get("authRecoveryCloseChildTicketDigest") != digest(child_ticket)
                ):
                    raise ValueError("different Auth recovery close")
                try:
                    _hash(parent.get("authRecoveryCloseResponsibilitiesDigest"))
                except ValueError:
                    raise ValueError("different Auth recovery close") from None
                return copy.deepcopy(parent_ticket)
            if parent["state"] != "held" or child.get("state") != "settled" or child.get("receiptDigest") != receipt_digest:
                raise ValueError("settled absent Auth child and held parent required")
            claim = copy.deepcopy(parent["claim"])
            child_claim = copy.deepcopy(child["claim"])
            close_snapshot = {
                "parentState": parent["state"],
                "parentClaim": copy.deepcopy(parent["claim"]),
                "parentClaimDigest": parent["claimDigest"],
                "parentEnvelopeDigest": parent["envelopeDigest"],
                "childClaim": copy.deepcopy(child_claim),
                "childClaimDigest": child["claimDigest"],
                "childEnvelopeDigest": child["envelopeDigest"],
                "childState": child["state"],
                "childReceiptDigest": child.get("receiptDigest"),
                "childProofDigest": child.get("absenceProofDigest"),
                "childFinalGateDigest": child.get("finalGateDigest"),
            }
            final_gate_digest = child.get("finalGateDigest")
            proof_digest = child.get("absenceProofDigest")
        parent_gate = Gate(claim["gatePath"], _gate_job(claim)).snapshot()
        evidence = _auth_parent_projection(parent_gate, child_claim)
        if evidence["evidenceDigest"] != child_claim["parentEvidenceDigest"] or evidence["gateDigest"] != child_claim["parentGateDigest"]:
            raise ValueError("Auth parent evidence changed during close")
        close_projection = _auth_parent_responsibility_projection(parent_gate, child_claim)
        for pid in [parent_gate.get("coordinatorPid")] + [job.get("pid") for job in parent_gate.get("jobs", {}).values()]:
            if pid is None:
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise ValueError("Auth parent worker is still alive")
        child_gate = Gate(child_claim["gatePath"], child_claim["gateJob"]).snapshot()
        operation = child_gate["plan"]["jobs"][child_claim["gateJob"]]["recovery"][0]
        body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
        proof = {"kind": AUTH_RECOVERY_ABSENCE_KIND, "resource": child_claim["ownedResources"][0], "status": 200,
            "bodyShape": body, "bodyDigest": digest(body), "responseDigest": digest(body), "eventIndex": 0,
            "requestDigest": digest(operation)}
        _auth_recovery_gate(child_gate, child_claim, proof)
        if digest(child_gate) != final_gate_digest or digest(proof) != proof_digest:
            raise ValueError("Auth recovery child terminal proof changed")
        with self._locked() as state:
            parent = self._row(state, parent_ticket)
            child = next((value for value in parent.get("recoveryChildren", []) if value.get("ticket") == child_ticket), None)
            if parent["state"] == "closed-after-auth-recovery-child":
                if (
                    parent.get("authRecoveryCloseReceiptDigest") != receipt_digest
                    or parent.get("authRecoveryCloseChildTicketDigest") != digest(child_ticket)
                    or parent.get("authRecoveryCloseChildClaimDigest") != close_snapshot["childClaimDigest"]
                    or parent.get("authRecoveryCloseResponsibilitiesDigest") != close_projection["projectionDigest"]
                    or parent.get("finalGateDigest") != close_snapshot["childFinalGateDigest"]
                ):
                    if close_snapshot["parentState"] == "held":
                        raise ValueError("Auth parent changed during close")
                    raise ValueError("different Auth recovery close")
                return copy.deepcopy(parent_ticket)
            if (
                parent.get("state") != close_snapshot["parentState"]
                or parent.get("claim") != close_snapshot["parentClaim"]
                or parent.get("claimDigest") != close_snapshot["parentClaimDigest"]
                or parent.get("envelopeDigest") != close_snapshot["parentEnvelopeDigest"]
                or child is None
                or child.get("claim") != close_snapshot["childClaim"]
                or child.get("claimDigest") != close_snapshot["childClaimDigest"]
                or child.get("envelopeDigest") != close_snapshot["childEnvelopeDigest"]
                or child.get("state") != close_snapshot["childState"]
                or child.get("receiptDigest") != close_snapshot["childReceiptDigest"]
                or child.get("absenceProofDigest") != close_snapshot["childProofDigest"]
                or child.get("finalGateDigest") != close_snapshot["childFinalGateDigest"]
            ):
                raise ValueError("Auth parent changed during close")
            parent["state"] = "closed-after-auth-recovery-child"
            parent["authRecoveryCloseReceiptDigest"] = receipt_digest
            parent["authRecoveryCloseChildTicketDigest"] = digest(child_ticket)
            parent["authRecoveryCloseChildClaimDigest"] = child["claimDigest"]
            parent["authRecoveryCloseResponsibilitiesDigest"] = close_projection["projectionDigest"]
            parent["finalGateDigest"] = final_gate_digest
            self._save(state)
            return copy.deepcopy(parent_ticket)

    def begin_recovery_extension(
        self,
        parent_ticket,
        child_claim,
        new_envelope,
        canonical_parent_plan,
        canonical_child_gate_plan,
        *,
        now=None,
        canonical_parent_inputs=None,
        parent_permission=None,
    ):
        """Persist one recovery child before an issuer or any wire activity.

        This is deliberately a Ledger-only transition.  It does not accept an
        O8 capability and therefore cannot consume one before a durable save.
        A later issuer must bind its capability to the returned child ticket.
        """
        if not isinstance(canonical_parent_inputs, dict) or not isinstance(parent_permission, dict):
            # The public admission API reports all malformed producer bindings as ValueError.
            raise ValueError("canonical parent producer inputs and permission required")  # noqa: TRY004
        actual_parent_plan = _compile_request_bytes_parent(canonical_parent_inputs)
        if digest(actual_parent_plan) != digest(canonical_parent_plan):
            raise ValueError("canonical parent compiler plan differs")
        _recovery_child_claim(child_claim)
        expected_case_id = actual_parent_plan.get("caseId")
        if child_claim.get("caseId") != expected_case_id:
            raise ValueError("recovery child case identity differs from parent")
        _envelope(new_envelope)
        if now is not None:
            _number(now)
        _validate_recovery_gate_plan(
            canonical_parent_plan, canonical_child_gate_plan, child_claim
        )
        child_envelope_digest = digest(new_envelope)
        child_digest = digest(child_claim)
        with self._locked() as state:
            initial_parent = self._row(state, parent_ticket)
            initial_claim_digest = initial_parent["claimDigest"]
            initial_claim = copy.deepcopy(initial_parent["claim"])
            initial_gate_path = initial_claim["gatePath"]
            initial_gate_job = _gate_job(initial_claim)
        parent_gate = Gate(initial_gate_path, initial_gate_job).snapshot()
        if canonical_parent_inputs is not None or parent_permission is not None:
            if not isinstance(canonical_parent_inputs, dict) or not isinstance(parent_permission, dict):
                raise ValueError("canonical parent producer inputs required")
            lane = Path(__file__).resolve().parent.parent / "fs-request-bytes-boundary"
            sys.path.insert(0, str(lane))
            try:
                import request_bytes_admission as request_admission
                expected_parent_gate = request_admission.gate_plan_for(canonical_parent_inputs, parent_permission)
            except (ImportError, KeyError, TypeError, ValueError) as error:
                raise ValueError("canonical parent producer refused inputs") from error
            if digest(expected_parent_gate) != digest(parent_gate.get("plan")):
                raise ValueError("registered parent Gate plan differs")
        if (
            digest(parent_gate.get("plan")) != initial_claim["gatePlanDigest"]
            or parent_gate.get("plan", {}).get("campaignId") != canonical_parent_plan.get("campaignId")
            or parent_gate.get("plan", {}).get("nonce") != canonical_parent_plan.get("nonce")
            or parent_gate.get("coordinatorInflight")
            or not parent_gate.get("events")
            or any(job.get("inflight") for job in parent_gate.get("jobs", {}).values())
        ):
            raise ValueError("parent Gate predecessor is not settled")
        parent_resources = sorted({resource for probe in canonical_parent_plan.get("probes", []) for resource in probe.get("resources", [])})
        registered_resources = sorted({resource for job in parent_gate.get("plan", {}).get("jobs", {}).values() for resource in job.get("resources", [])})
        if registered_resources != parent_resources:
            raise ValueError("registered parent resources differ")
        parent_operations = canonical_parent_plan.get("observation", []) + canonical_parent_plan.get("recovery", [])
        registered_operations = [operation for job in parent_gate.get("plan", {}).get("jobs", {}).values() for phase in ("observation", "recovery") for operation in job.get(phase, [])]
        operation_key = lambda operation: (operation.get("kind"), operation.get("method"), operation.get("path"), operation.get("resource"), operation.get("probe"))
        if sorted(map(operation_key, registered_operations), key=repr) != sorted(map(operation_key, parent_operations), key=repr):
            raise ValueError("registered parent operations differ")
        selected_probe = child_claim["selectedProbe"]
        selected_job = parent_gate.get("plan", {}).get("jobs", {}).get(initial_gate_job, {})
        creating_index = next(
            (index for index, operation in enumerate(selected_job.get("observation", []))
             if operation.get("probe") == selected_probe and operation.get("kind") == "conditional-create-commit"),
            None,
        )
        if creating_index is None:
            raise ValueError("selected parent create operation missing")
        expected_operation = selected_job["observation"][creating_index]
        if expected_operation.get("bodyRef") is not None:
            materialized = next(
                (
                    operation
                    for operation in actual_parent_plan.get("observation", [])
                    if operation.get("kind") == expected_operation.get("kind")
                    and operation.get("probe") == expected_operation.get("probe")
                    and operation.get("resource") == expected_operation.get("resource")
                ),
                None,
            )
            if not isinstance(materialized, dict) or not isinstance(materialized.get("body"), dict):
                raise ValueError("authoritative parent operation body missing")
            body = canonical_body_bytes(materialized["body"])
            reference = expected_operation["bodyRef"]
            if (
                len(body) != reference.get("bytes")
                or hashlib.sha256(body).hexdigest() != reference.get("sha256")
            ):
                raise ValueError("authoritative parent operation body reference differs")
            expected_operation = copy.deepcopy(materialized)
            expected_operation.pop("bodyRef", None)
        expected_event = next(
            (event for event in parent_gate.get("events", [])
             if event.get("phase") == "observation"
             and event.get("job") == initial_gate_job
             and event.get("index") == creating_index
             and event.get("requestDigest") == digest(expected_operation)),
            None,
        )
        if (
            not isinstance(expected_event, dict)
            or expected_event.get("completed") is not False
            or expected_event.get("creationOutcome") not in {"pending", "unknown"}
            or type(expected_event.get("ended")) not in (int, float)
            or unconfirmed_creates(parent_gate, initial_gate_job) != 1
        ):
            raise ValueError("selected parent create predecessor is not uncertain")
        for pid in [parent_gate.get("coordinatorPid")] + [job.get("pid") for job in parent_gate.get("jobs", {}).values()]:
            if pid is None:
                continue
            if type(pid) is not int or pid <= 0:
                raise ValueError("parent worker identity required")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise ValueError("parent worker is still alive")
        with self._locked() as state:
            parent = self._row(state, parent_ticket)
            if parent["state"] != "held" or parent.get("inflight") is True:
                raise ValueError("held parent without in-flight work required")
            claim = parent["claim"]
            if (
                parent_ticket.get("claimDigest") != parent["claimDigest"]
                or child_claim["parentClaimDigest"] != parent["claimDigest"]
                or child_claim["campaignId"] != claim["campaignId"]
                or claim["campaignId"] != "FS-LIMIT-API-REQUEST-BYTES"
                or claim["budget"]["requests"] != (108 if expected_case_id else 265)
                or claim["budget"]["costMicrousd"] != (123 if expected_case_id else 303)
                or child_claim["nonceDigest"] == claim["nonceDigest"]
                or child_claim["gatePlanDigest"] == claim["gatePlanDigest"]
                or child_claim["permissionDigest"] == state["envelopes"][parent["envelopeDigest"]]["envelope"]["permissionDigest"]
                or child_claim["generation"] == parent.get("generation")
            ):
                raise ValueError("recovery child is not bound to held parent")
            child_requests = RECOVERY_SENTINEL_REQUESTS if expected_case_id else RECOVERY_CHILD_REQUESTS
            child_cost = RECOVERY_SENTINEL_COST_MICROUSD if expected_case_id else RECOVERY_CHILD_COST_MICROUSD
            if child_claim["budget"]["requests"] != child_requests or child_claim["budget"]["costMicrousd"] != child_cost:
                raise ValueError("recovery child must reserve its canonical request allocation")
            if child_claim["durationSeconds"] < canonical_child_gate_plan["wallSeconds"]:
                raise ValueError("recovery duration below actual Gate wall")
            decision_now = time.time() if now is None else now
            if child_claim["expiresAt"] < decision_now + child_claim["durationSeconds"]:
                raise ValueError("recovery permission window is too short")
            if new_envelope["permissionDigest"] != child_claim["permissionDigest"] or new_envelope["limits"]["requests"] < child_requests or new_envelope["limits"]["costMicrousd"] < child_cost:
                raise ValueError("recovery envelope does not fund canonical child")
            if any(
                not any(
                    _ancestor(_scope(scope), _scope(lock))
                    and MODES[scope["mode"]] >= MODES[lock["mode"]]
                    for scope in new_envelope["scopes"]
                )
                for lock in child_claim["locks"]
            ):
                raise ValueError("recovery lock exceeds new permission scope")
            if any(
                not any(
                    _ancestor(_scope(parent_lock), _scope(child_lock))
                    and MODES[parent_lock["mode"]] >= MODES[child_lock["mode"]]
                    for parent_lock in claim["locks"]
                )
                for child_lock in child_claim["locks"]
            ):
                raise ValueError("recovery lock exceeds parent lock boundary")
            if any(
                not any(
                    _ancestor(_scope(lock), _resource_scope(resource))
                    and MODES[lock["mode"]] >= MODES["WRITE"]
                    for lock in child_claim["locks"]
                )
                or not any(
                    _ancestor(_scope(lock), _resource_scope(resource))
                    and MODES[lock["mode"]] >= MODES["WRITE"]
                    for lock in claim["locks"]
                )
                for resource in child_claim["ownedResources"]
            ):
                raise ValueError("recovery resource locks do not cover all resources")
            if not new_envelope["issuedAt"] <= decision_now < new_envelope["expiresAt"] or decision_now + child_claim["durationSeconds"] > new_envelope["expiresAt"] or child_claim["expiresAt"] > new_envelope["expiresAt"]:
                raise ValueError("recovery child outside permission window")
            if parent["claimDigest"] != initial_claim_digest or parent["claim"] != initial_claim:
                raise ValueError("parent reservation changed during Gate inspection")
            existing = parent.get("recoveryChildren", [])
            if existing:
                if len(existing) == 1 and existing[0].get("claimDigest") == child_digest and existing[0].get("envelopeDigest") == child_envelope_digest:
                    return copy.deepcopy(existing[0]["ticket"])
                raise ValueError("one recovery child only")
            if Path(child_claim["gatePath"]).exists():
                raise ValueError("fresh child Gate required")
            if any(child_claim["nonceDigest"] == row.get("claim", {}).get("nonceDigest") for row in state["reservations"].values()):
                raise ValueError("recovery nonce already reserved")
            if any(entry["envelope"].get("permissionDigest") == new_envelope["permissionDigest"] for entry in state["envelopes"].values()) or any(entry["envelope"].get("permissionDigest") == new_envelope["permissionDigest"] for entry in state.get("recoveryEnvelopes", {}).values()):
                raise ValueError("recovery permission already spent")
            task_budget_check(state, claim["campaignId"], child_cost)
            child_reservation = secrets.token_hex(32)
            child_ticket = {
                "ledgerPath": str(self.path),
                "ledgerIdentity": self.identity,
                "reservation": child_reservation,
                "claimDigest": child_digest,
                "envelopeDigest": child_envelope_digest,
                "parentReservation": parent_ticket["reservation"],
            }
            state.setdefault("recoveryEnvelopes", {})[child_envelope_digest] = {
                "envelope": copy.deepcopy(new_envelope),
                "allocated": copy.deepcopy(child_claim["budget"]),
            }
            child = {
                "reservation": child_reservation,
                "ticket": child_ticket,
                "claim": copy.deepcopy(child_claim),
                "claimDigest": child_digest,
                "parentClaimDigest": parent["claimDigest"],
                "envelopeDigest": child_envelope_digest,
                "state": "allocated",
                "deadline": decision_now + child_claim["durationSeconds"],
            }
            parent.setdefault("recoveryChildren", []).append(child)
            self._save(state)
            return copy.deepcopy(child_ticket)

    def _row(self, state, ticket):
        row = state["reservations"].get(ticket.get("reservation"))
        if row is None or ticket != {
            "ledgerPath": str(self.path),
            "ledgerIdentity": self.identity,
            "reservation": ticket.get("reservation"),
            "claimDigest": row["claimDigest"],
            "envelopeDigest": row["envelopeDigest"],
        }:
            raise ValueError("exact shared reservation ticket required")
        return row

    def bound_claim(self, ticket):
        with self._locked() as state:
            return self._row(state, ticket)["claim"]

    def bound_recovery_claim(self, child_ticket):
        """Read one persisted recovery child and its immutable parent binding.

        The child ticket must be the exact nested ticket written by
        ``begin_recovery_extension``. This is an inspection API: it does not
        apply an authorization deadline, consume capacity, or create a Gate.
        The returned object is detached from Ledger state and contains the
        child claim, its persisted recovery envelope, the parent claim and
        identity, plus the child state and deadline.
        """
        if not isinstance(child_ticket, dict) or set(child_ticket) != {
            "ledgerPath", "ledgerIdentity", "reservation", "claimDigest",
            "envelopeDigest", "parentReservation",
        }:
            raise ValueError("exact recovery child ticket required")
        if (
            child_ticket["ledgerPath"] != str(self.path)
            or child_ticket["ledgerIdentity"] != self.identity
            or not isinstance(child_ticket["reservation"], str)
            or not isinstance(child_ticket["parentReservation"], str)
        ):
            raise ValueError("recovery child ticket ledger binding changed")
        with self._locked() as state:
            parent = state["reservations"].get(child_ticket["parentReservation"])
            if parent is None:
                raise ValueError("recovery child parent reservation missing")
            child = next(
                (
                    value
                    for value in parent.get("recoveryChildren", [])
                    if value.get("reservation") == child_ticket["reservation"]
                ),
                None,
            )
            if child is None or child.get("ticket") != child_ticket:
                raise ValueError("exact persisted recovery child ticket required")
            if (
                child.get("claimDigest") != child_ticket["claimDigest"]
                or child.get("envelopeDigest") != child_ticket["envelopeDigest"]
                or child.get("envelopeDigest") not in state.get("recoveryEnvelopes", {})
            ):
                raise ValueError("recovery child ticket binding changed")
            envelope = state["recoveryEnvelopes"][child["envelopeDigest"]]["envelope"]
            parent_identity = {
                "ledgerPath": str(self.path),
                "ledgerIdentity": self.identity,
                "reservation": child_ticket["parentReservation"],
                "claimDigest": parent["claimDigest"],
                "envelopeDigest": parent["envelopeDigest"],
            }
            return copy.deepcopy(
                {
                    "ticket": child["ticket"],
                    "childClaim": child["claim"],
                    "newEnvelope": envelope,
                    "parentClaim": parent["claim"],
                    "parentIdentity": parent_identity,
                    "deadline": child["deadline"],
                    "state": child["state"],
                }
            )

    def settle_recovery_child(self, child_ticket, *, receipt_digest, canonical_parent_plan, now=None):
        """Settle one persisted child from its completed, registered Gate.

        ``receipt_digest`` is only a bounded correlation value; the terminal
        Gate journal and its compiler-bound plan are the authority. This
        transition never checks the wall-clock expiry and never changes the
        parent reservation.
        """
        if not isinstance(receipt_digest, str) or not 1 <= len(receipt_digest) <= 256:
            raise ValueError("bounded recovery receipt correlation required")
        if not isinstance(canonical_parent_plan, dict):
            raise ValueError("canonical parent compiler plan required")  # noqa: TRY004
        if not isinstance(child_ticket, dict) or set(child_ticket) != {
            "ledgerPath", "ledgerIdentity", "reservation", "claimDigest",
            "envelopeDigest", "parentReservation",
        }:
            raise ValueError("exact recovery child ticket required")
        if (
            child_ticket["ledgerPath"] != str(self.path)
            or child_ticket["ledgerIdentity"] != self.identity
            or not isinstance(child_ticket["reservation"], str)
            or not isinstance(child_ticket["parentReservation"], str)
        ):
            raise ValueError("recovery child ticket ledger binding changed")
        if now is not None:
            _number(now)
        with self._locked() as state:
            parent = state["reservations"].get(
                child_ticket.get("parentReservation")
                if isinstance(child_ticket, dict)
                else None
            )
            if parent is None:
                raise ValueError("recovery child parent reservation missing")
            child = next(
                (
                    value
                    for value in parent.get("recoveryChildren", [])
                    if value.get("ticket") == child_ticket
                ),
                None,
            )
            if child is None:
                raise ValueError("exact persisted recovery child ticket required")
            if child.get("state") == "settled":
                if child.get("receiptDigest") != receipt_digest:
                    raise ValueError("different recovery settlement receipt")
            elif child.get("state") != "allocated":
                raise ValueError("recovery child is not allocatable")
            claim = copy.deepcopy(child["claim"])
            child_digest = child["claimDigest"]
            gate_path = claim["gatePath"]
            expected_gate_digest = claim["gatePlanDigest"]
            envelope_digest = child["envelopeDigest"]
            parent_claim_digest = parent["claimDigest"]
            parent_snapshot = copy.deepcopy(parent["claim"])
            parent_plan_digest = claim["parentPlanDigest"]
        actual_parent_plan = _compile_request_bytes_parent({"plan": canonical_parent_plan})
        if digest(actual_parent_plan) != digest(canonical_parent_plan) or digest(actual_parent_plan) != parent_plan_digest:
            raise ValueError("canonical parent compiler plan differs")
        expected_fields = {
            write["update"]["name"]: digest(write["update"]["fields"])
            for operation in actual_parent_plan.get("observation", [])
            if isinstance(operation.get("body"), dict)
            for write in operation["body"].get("writes", [])
            if isinstance(write.get("update"), dict)
            and isinstance(write["update"].get("fields"), dict)
        }
        if str(Path(gate_path).resolve()) != gate_path:
            raise ValueError("registered recovery Gate path changed")
        gate = Gate(gate_path, RECOVERY_GATE_JOB).snapshot()
        if digest(gate.get("plan")) != expected_gate_digest or gate.get("planDigest") != expected_gate_digest:
            raise ValueError("registered recovery Gate plan differs")
        jobs = gate.get("jobs")
        job_name = RECOVERY_GATE_JOB
        job = jobs.get(job_name) if isinstance(jobs, dict) else None
        plan_job = gate["plan"].get("jobs", {}).get(job_name)
        child_requests = RECOVERY_SENTINEL_REQUESTS if claim.get("caseId") else RECOVERY_CHILD_REQUESTS
        child_absence_reads = RECOVERY_SENTINEL_ABSENCE_REQUESTS if claim.get("caseId") else RECOVERY_ABSENCE_REQUESTS
        if (
            not isinstance(job, dict)
            or not isinstance(plan_job, dict)
            or gate.get("coordinatorInflight")
            or gate.get("observation") != 0
            or gate.get("recovery") != gate.get("total")
            or type(gate.get("total")) is not int
            or not child_absence_reads <= gate.get("total") <= child_requests
            or gate.get("managementUsed") != []
            or job.get("complete") is not True
            or job.get("inflight")
            or job.get("recovery") != len(plan_job.get("recovery", []))
            or job.get("recovery") != child_requests
            or set(job.get("absent", [])) != set(job.get("resources", []))
            or len(job.get("absent", [])) != child_absence_reads
            or unconfirmed_creates(gate, job_name)
        ):
            raise ValueError("recovery Gate terminal evidence incomplete")
        _validate_recovery_terminal_slots(gate, job_name, expected_fields, claim)
        try:
            validate_absence_proofs(gate, job_name)
        except Exception as error:
            raise ValueError("recovery Gate typed absence evidence incomplete") from error
        final_gate_digest = digest(gate)
        with self._locked() as state:
            parent = state["reservations"].get(child_ticket.get("parentReservation"))
            child = next(
                (
                    value for value in (parent or {}).get("recoveryChildren", [])
                    if value.get("ticket") == child_ticket
                ),
                None,
            )
            if (
                parent is None
                or child is None
                or parent.get("claimDigest") != parent_claim_digest
                or parent.get("claim") != parent_snapshot
                or child.get("claimDigest") != child_digest
                or child.get("envelopeDigest") != envelope_digest
            ):
                raise ValueError("recovery child changed during Gate settlement")
            if child.get("state") == "settled":
                if child.get("receiptDigest") != receipt_digest or child.get("finalGateDigest") != final_gate_digest:
                    raise ValueError("different recovery settlement proof")
                return copy.deepcopy(child["ticket"])
            child["state"] = "settled"
            child["receiptDigest"] = receipt_digest
            child["finalGateDigest"] = final_gate_digest
            self._save(state)
            return copy.deepcopy(child["ticket"])

    def close_after_recovery_child(
        self,
        parent_ticket,
        child_ticket,
        *,
        receipt_digest,
        canonical_parent_plan,
        now=None,
    ):
        """Release only a held parent after its durable child has settled."""
        if now is not None:
            _number(now)
        if not isinstance(parent_ticket, dict) or not isinstance(child_ticket, dict):
            raise ValueError("exact recovery close tickets required")  # noqa: TRY004
        with self._locked() as state:
            parent = self._row(state, parent_ticket)
            child = next(
                (
                    value for value in parent.get("recoveryChildren", [])
                    if value.get("ticket") == child_ticket
                ),
                None,
            )
            if child is None or child_ticket.get("parentReservation") != parent_ticket.get("reservation"):
                raise ValueError("recovery child is not nested under parent")
            if parent["state"] not in {"held", "closed-after-recovery-child"} or child.get("state") != "settled":
                raise ValueError("settled recovery child and held parent required")
            parent_claim = copy.deepcopy(parent["claim"])
            parent_claim_digest = parent["claimDigest"]
            child_claim = copy.deepcopy(child["claim"])
            child_final_gate_digest = child.get("finalGateDigest")
        self.settle_recovery_child(
            child_ticket,
            receipt_digest=receipt_digest,
            canonical_parent_plan=canonical_parent_plan,
            now=now,
        )
        lane = Path(__file__).resolve().parent.parent / "fs-request-bytes-boundary"
        sys.path.insert(0, str(lane))
        actual_parent = _compile_request_bytes_parent({"plan": canonical_parent_plan})
        if digest(actual_parent) != digest(canonical_parent_plan) or digest(actual_parent) != child_claim["parentPlanDigest"]:
            raise ValueError("canonical parent compiler plan differs")
        parent_gate = Gate(parent_claim["gatePath"], _gate_job(parent_claim)).snapshot()
        if parent_gate.get("planDigest") != parent_claim["gatePlanDigest"] or parent_gate.get("coordinatorInflight") or any(job.get("inflight") for job in parent_gate.get("jobs", {}).values()):
            raise ValueError("original parent Gate is not frozen")
        if unconfirmed_creates(parent_gate, _gate_job(parent_claim)) != 1:
            raise ValueError("original parent create is not uncertain")
        if not any(
            event.get("job") == _gate_job(parent_claim)
            and event.get("phase") == "observation"
            and event.get("completed") is False
            and event.get("creationOutcome") in {"pending", "unknown"}
            for event in parent_gate.get("events", [])
        ):
            raise ValueError("original parent unknown create event missing")
        for pid in [parent_gate.get("coordinatorPid")] + [job.get("pid") for job in parent_gate.get("jobs", {}).values()]:
            if pid is not None:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                raise ValueError("original parent worker is still alive")
        with self._locked() as state:
            parent = self._row(state, parent_ticket)
            child = next((value for value in parent.get("recoveryChildren", []) if value.get("ticket") == child_ticket), None)
            if parent["state"] == "closed-after-recovery-child":
                if (
                    parent.get("recoveryCloseReceiptDigest") != receipt_digest
                    or parent.get("recoveryCloseChildTicketDigest") != digest(child_ticket)
                    or parent.get("recoveryCloseChildClaimDigest") != child["claimDigest"]
                ):
                    raise ValueError("different recovery child close")
                return copy.deepcopy(parent_ticket)
            if parent["state"] != "held" or parent["claimDigest"] != parent_claim_digest or parent["claim"] != parent_claim or child is None or child.get("state") != "settled" or child.get("finalGateDigest") != child_final_gate_digest:
                raise ValueError("recovery parent changed during close")
            parent["state"] = "closed-after-recovery-child"
            parent["recoveryCloseReceiptDigest"] = receipt_digest
            parent["recoveryCloseChildTicketDigest"] = digest(child_ticket)
            parent["recoveryCloseChildClaimDigest"] = child["claimDigest"]
            parent["finalGateDigest"] = child_final_gate_digest
            self._save(state)
            return copy.deepcopy(parent_ticket)

    def validate(self, ticket, *, now=None, duration=13):
        if now is not None:
            _number(now)
        if type(duration) is not int or duration < 1:
            raise ValueError("positive bounded operation required")
        with self._locked() as state:
            row = self._row(state, ticket)
            if row.get("recoveryChildren"):
                raise ValueError("recovery child must settle before parent validation")
            decision_now = time.time() if now is None else now
            _number(decision_now)
            if row["state"] != "held" or decision_now + duration > row["deadline"]:
                raise ValueError("shared reservation unavailable")
            return row["claimDigest"]

    def finish(self, ticket):
        # Close admission first; never hold ledger lock while waiting for Gate.
        with self._locked() as state:
            row = self._row(state, ticket)
            if row.get("recoveryChildren"):
                raise ValueError("recovery child must settle before parent close")
            if row["state"] != "held":
                raise ValueError("reservation is not held")
            row["state"] = "closing"
            claim = row["claim"]
            self._save(state)
        try:
            if str(Path(claim["gatePath"]).resolve()) != claim["gatePath"]:
                raise ValueError("registered Gate path changed")
            gate = Gate(claim["gatePath"], _gate_job(claim)).snapshot()
            if "gateJob" in claim and claim["gateJob"] not in gate["jobs"]:
                raise ValueError("registered Gate job is absent")
            if (
                digest(gate["plan"]) != claim["gatePlanDigest"]
                or gate["plan"].get("transport") == LIMITS_PREPARATION_TRANSPORT
                or gate["coordinatorInflight"]
                or any(
                    j["complete"] is not True
                    or j["inflight"]
                    or unconfirmed_creates(gate, job_name)
                    or set(j["absent"]) != set(j["resources"])
                    for job_name, j in gate["jobs"].items()
                )
                or gate["total"] > claim["budget"]["requests"]
                or gate["costMicrousd"] > claim["budget"]["costMicrousd"]
            ):
                raise ValueError("registered Gate cleanup/accounting incomplete")
            for job_name in gate["jobs"]:
                validate_absence_proofs(gate, job_name)
        except Exception:
            with self._locked() as state:
                self._row(state, ticket)["state"] = "held"
                self._save(state)
            raise
        with self._locked() as state:
            row = self._row(state, ticket)
            if row["state"] != "closing":
                raise ValueError("closing reservation changed")
            row["state"] = "released"
            row["finalGateDigest"] = digest(gate)
            self._save(state)

    @staticmethod
    def _read_bounded_json(path):
        path = Path(path)
        if not path.is_absolute() or str(path.resolve(strict=False)) != str(path):
            raise ValueError("bounded canonical evidence file required")
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as error:
            raise ValueError("bounded canonical evidence file required") from error
        try:
            initial = os.fstat(descriptor)
            if not stat.S_ISREG(initial.st_mode) or initial.st_size > MAX_BYTES:
                raise ValueError("bounded regular evidence file required")
            chunks = []
            remaining = MAX_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            final = os.fstat(descriptor)
            identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if not stat.S_ISREG(final.st_mode) or any(
                getattr(initial, key) != getattr(final, key) for key in identity
            ) or sum(map(len, chunks)) > MAX_BYTES:
                raise ValueError("bounded stable evidence file required")
            payload = b"".join(chunks)
        finally:
            os.close(descriptor)
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise ValueError("bounded evidence object required")
        return value

    def _configuration_gate(self, claim, record, receipt):
        gate_path = Path(claim["gatePath"])
        gate = self._read_bounded_json(gate_path / "state.json")
        collection = receipt.get("collection")
        plan_steps = {
            step.get("id"): step
            for step in gate.get("plan", {}).get("steps", [])
            if isinstance(step, dict)
        }
        receipt_steps = collection.get("steps") if isinstance(collection, dict) else None
        if (
            gate.get("planDigest") != claim["gatePlanDigest"]
            or digest(gate.get("plan")) != gate.get("planDigest")
            or gate.get("plan", {}).get("kind") != CONFIGURATION_GATE_PLAN_KIND
            or gate.get("plan", {}).get("campaignId") != CONFIGURATION_CAMPAIGN
            or gate.get("complete") is not True
            or gate.get("phase") != "recovery"
            or gate.get("inflight") is not False
            or not isinstance(gate.get("steps"), dict)
            or not gate["steps"]
            or set(gate["steps"]) != set(plan_steps)
            or not isinstance(receipt_steps, dict)
            or set(receipt_steps) != set(gate["steps"])
            or not isinstance(gate.get("reconciliation"), dict)
            or gate["reconciliation"].get("ok") is not True
            or collection.get("reconciliation") != gate["reconciliation"]
            or collection.get("stopPoint") is not None
            or collection.get("failure") is not None
            or collection.get("unrecovered") != []
            or set(collection.get("observedCases", []))
            != set(gate["plan"].get("executionOrder", []))
            or digest(gate) != record["gateDigest"]
            or receipt.get("gateDigest") != record["gateDigest"]
        ):
            raise ValueError("configuration restoration proof differs")
        for step_id, step in gate["steps"].items():
            if (
                not isinstance(step, dict)
                or step.get("restore") not in CONFIGURATION_FINISHED_STATES
            ):
                raise ValueError("configuration restoration incomplete")
            plan_step = plan_steps[step_id]
            receipt_step = receipt_steps[step_id]
            if (
                step.get("resource") != plan_step.get("resource")
                or not isinstance(receipt_step, dict)
                or any(
                    receipt_step.get(key) != step.get(key)
                    for key in ("restore", "preDigest", "postDigest", "verifyDigest")
                )
            ):
                raise ValueError("configuration terminal step proof differs")
            if step["restore"] == "restored" and any(
                not isinstance(step.get(key), str) or not step[key]
                for key in ("preDigest", "postDigest", "verifyDigest")
            ):
                raise ValueError("configuration before/after proof required")
        return gate

    @staticmethod
    def _limits_preparation_collection(receipt, gate):
        """Bind a closed public baseline packet to sanitized worker attestations."""
        packet = receipt.get("collection")
        fields = {
            "kind", "campaignId", "preparationId", "nonce", "permissionDigest", "sourceCommit",
            "sourceDigest", "manifestDigest", "ticketDigest", "claimDigest", "ownerIdentityDigest",
            "principalDigest", "issuedAt", "expiresAt", "slots", "evidence", "requestDigests",
            "chargedCalls", "costMicrousd", "completed", "failed", "failureClass", "project",
            "database", "authConfigDigest", "apiKey", "packetDigest",
        }
        if not isinstance(packet, dict) or set(packet) != fields:
            raise ValueError("closed sanitized preparation collection required")
        for key in ("permissionDigest", "sourceDigest", "manifestDigest", "ticketDigest", "claimDigest", "ownerIdentityDigest", "principalDigest", "authConfigDigest", "packetDigest"):
            _hash(packet[key])
        requests = packet["requestDigests"]
        if not isinstance(requests, list) or len(requests) != 6:
            raise ValueError("six preparation request digests required")
        for request_digest in requests:
            _hash(request_digest)
        _number(packet["issuedAt"])
        _number(packet["expiresAt"])
        bodies = {item["id"].removeprefix("observation:"): item["response"]["body"] for item in receipt["managementEvidence"]}
        if (
            packet["kind"] != "limits-03-baseline-preparation-v1"
            or packet["campaignId"] != "FS-WRITE-LIMITS-03"
            or packet["preparationId"] != gate["plan"]["nonce"] or packet["nonce"] != gate["plan"]["nonce"]
            or packet["permissionDigest"] != gate["plan"].get("permissionDigest")
            or packet["sourceCommit"] != receipt["generation"]["sourceCommit"]
            or packet["sourceDigest"] != receipt["generation"]["collectorSourceDigest"]
            or packet["ticketDigest"] != digest(receipt["ticket"])
            or packet["claimDigest"] != receipt["claimDigest"]
            or packet["principalDigest"] != bodies["oauth-tokeninfo"]["principalDigest"]
            or not packet["issuedAt"] < packet["expiresAt"]
            or packet["slots"] != gate["managementUsed"] or packet["evidence"] != gate["managementEvents"]
            or type(packet["chargedCalls"]) is not int or packet["chargedCalls"] != 6
            or type(packet["costMicrousd"]) is not int or packet["costMicrousd"] != 600
            or packet["completed"] is not True or packet["failed"] is not False or packet["failureClass"] is not None
            or packet["project"] != bodies["project"]["value"]
            or packet["database"] != bodies["database"]["value"]
            or packet["authConfigDigest"] != bodies["auth"]["responseDigest"]
            or packet["apiKey"] != bodies["key"]
            or packet["packetDigest"] != digest({key: value for key, value in packet.items() if key != "packetDigest"})
        ):
            raise ValueError("preparation collection differs from worker evidence")

    def finish_limits_preparation(self, ticket, record):
        """Release the exact six-read preparation after its coordinator exits.

        The immutable receipt and attached evidence bind the actual charged
        journal. No data absence or failure is invented, and no cost is refunded.
        """
        fields = {"kind", "ticket", "receiptPath", "receiptDigest", "gateDigest", "collectionDigest", "generation"}
        if (
            not isinstance(record, dict) or set(record) != fields
            or record["kind"] != "limits-03-baseline-preparation-release-v1"
            or record["ticket"] != ticket
        ):
            raise ValueError("exact limits preparation release record required")
        for key in ("receiptDigest", "gateDigest", "collectionDigest"):
            _hash(record[key])
        _generation(record["generation"])
        receipt = self._read_bounded_json(record["receiptPath"])
        if digest(receipt) != record["receiptDigest"]:
            raise ValueError("limits preparation receipt digest changed")
        if set(receipt) != {
            "kind", "ticket", "claimDigest", "planDigest", "gateDigest", "generation",
            "reservationStateAtPublication", "executionKind", "releaseEligible", "failure",
            "chargedCalls", "ownedResources", "collection", "managementEvidence",
        }:
            raise ValueError("closed sanitized preparation receipt required")
        with self._locked() as state:
            row = self._row(state, ticket)
            if row.get("recoveryChildren"):
                raise ValueError("preparation cannot own a recovery child")
            if row["state"] == "released":
                if row.get("releaseRecordDigest") != digest(record):
                    raise ValueError("different limits preparation release record")
                return copy.deepcopy(row)
            if row["state"] != "held":
                raise ValueError("limits preparation reservation is not held")
            claim = row["claim"]
            gate = self._bound_gate(claim, record, receipt)
            validate_limits_preparation_success(gate)
            generation = row.get("generation")
            if (
                claim["campaignId"] != "FS-WRITE-LIMITS-03"
                or _gate_job(claim) != "limits"
                or claim["budget"] != {"requests": 6, "accounts": 0, "resources": 0, "costMicrousd": 600}
                or gate["planDigest"] != claim["gatePlanDigest"]
                or digest(gate["plan"].get("nonce")) != claim["nonceDigest"]
                or generation is None or generation != record["generation"]
                or {key: gate["plan"].get(key) for key in GENERATION_FIELDS} != generation
                or receipt.get("generation") != generation
                or receipt.get("kind") != LIMITS_PREPARATION_RECEIPT
                or receipt.get("ticket") != ticket
                or receipt.get("claimDigest") != row["claimDigest"]
                or receipt.get("planDigest") != claim["gatePlanDigest"]
                or receipt.get("gateDigest") != record["gateDigest"]
                or receipt.get("reservationStateAtPublication") != "held"
                or receipt.get("executionKind") != "fixed-production-wire"
                or receipt.get("releaseEligible") is not True
                or "failure" not in receipt or receipt["failure"] is not None
                or receipt.get("chargedCalls") != 6 or receipt.get("ownedResources") != []
                or not isinstance(receipt.get("collection"), dict)
                or digest(receipt["collection"]) != record["collectionDigest"]
                or row.get("evidence") != {
                    "receiptSha256": record["receiptDigest"], "gateDigest": record["gateDigest"],
                    "collectionDigest": record["collectionDigest"], "ledgerIdentity": self.identity,
                }
                or gate["jobs"]["limits"].get("complete") is not True
                or Path(record["receiptPath"]) != Path(claim["gatePath"]).parent / "receipt.json"
                or gate["plan"]["permissionExpiresAt"] > row["deadline"]
            ):
                raise ValueError("limits preparation release binding changed")
            rows = receipt.get("managementEvidence")
            if not isinstance(rows, list) or len(rows) != 6:
                raise ValueError("six actual management receipts required")
            for item, event in zip(rows, gate["managementEvents"], strict=True):
                if (
                    not isinstance(item, dict) or set(item) != MANAGEMENT_ROW_FIELDS
                    or item["id"] != event["id"]
                    or not _management_receipt_valid(item.get("response"), event["id"].removeprefix("observation:"))
                    or item["responseDigest"] != digest(item["response"])
                    or item["responseDigest"] != event["responseDigest"]
                    or event["bodyDigest"] != digest(item["response"]["body"])
                    or any(item["response"].get(key) != event.get(key) for key in ("status", "complete", "workerReaped", "bodyKind"))
                ):
                    raise ValueError("limits preparation management receipt changed")
                validate_limits_preparation_response(event["id"].removeprefix("observation:"), item["response"])
            self._limits_preparation_collection(receipt, gate)
            for pid in (gate.get("coordinatorPid"), gate["jobs"]["limits"].get("pid")):
                if type(pid) is not int or pid <= 0:
                    raise ValueError("recorded preparation worker identity required")
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                raise ValueError("preparation worker exit not proven")
            row["state"] = "released"
            row["releaseRecordDigest"] = digest(record)
            row["finalGateDigest"] = record["gateDigest"]
            self._save(state)
            return copy.deepcopy(row)

    def finish_management_only(self, ticket, record):
        """Release a configuration-only reservation from its typed Gate proof.

        This is deliberately separate from ``finish``: no document resource or
        typed document absence is invented for a management-only campaign.
        """
        required = {
            "kind", "ticket", "receiptPath", "receiptDigest", "gateDigest",
            "collectionDigest", "generation",
        }
        if not isinstance(record, dict) or set(record) != required:
            raise ValueError("exact configuration release record required")
        if record["kind"] != CONFIGURATION_RELEASE_KIND or record["ticket"] != ticket:
            raise ValueError("configuration release record binding changed")
        _hash(record["receiptDigest"])
        _hash(record["gateDigest"])
        _hash(record["collectionDigest"])
        _generation(record["generation"])
        receipt_path = Path(record["receiptPath"])
        receipt = self._read_bounded_json(receipt_path)
        if digest(receipt) != record["receiptDigest"]:
            raise ValueError("configuration receipt digest changed")
        with self._locked() as state:
            row = self._row(state, ticket)
            if row.get("recoveryChildren"):
                raise ValueError("recovery child must settle before parent close")
            if row["state"] == "released":
                if row.get("releaseRecordDigest") != digest(record):
                    raise ValueError("different configuration release record")
                return copy.deepcopy(row)
            if row["state"] != "held":
                raise ValueError("configuration reservation is not held")
            claim = row["claim"]
            evidence = row.get("evidence")
            if (
                claim.get("campaignId") != CONFIGURATION_CAMPAIGN
                or claim.get("gatePlanDigest") != receipt.get("gatePlanDigest")
                or row.get("generation") != record["generation"]
                or row.get("generation") is None
                or receipt.get("generation") != row["generation"]
                or receipt.get("ticket") != ticket
                or receipt.get("claimDigest") != row["claimDigest"]
                or receipt.get("reservationStateAtPublication") != "held"
                or not isinstance(receipt.get("collection"), dict)
                or digest(receipt["collection"]) != record["collectionDigest"]
                or not isinstance(evidence, dict)
                or evidence.get("receiptSha256") != record["receiptDigest"]
                or evidence.get("gateDigest") != record["gateDigest"]
                or evidence.get("collectionDigest") != record["collectionDigest"]
                or evidence.get("ledgerIdentity") != self.identity
            ):
                raise ValueError("configuration release evidence is not attached")
            row["state"] = "closing"
            row["releaseRecordDigest"] = digest(record)
            self._save(state)
        try:
            gate = self._configuration_gate(claim, record, receipt)
        except Exception:
            with self._locked() as state:
                row = self._row(state, ticket)
                if row["state"] == "closing" and row.get("releaseRecordDigest") == digest(record):
                    row["state"] = "held"
                    row.pop("releaseRecordDigest", None)
                    self._save(state)
            raise
        with self._locked() as state:
            row = self._row(state, ticket)
            if row["state"] != "closing" or row.get("releaseRecordDigest") != digest(record):
                raise ValueError("configuration closing reservation changed")
            row["state"] = "released"
            row["finalGateDigest"] = digest(gate)
            self._save(state)
            return copy.deepcopy(row)
    def attach_evidence(self, ticket, receipt_sha256, gate_digest, collection_digest):
        """Anchor a run's observed bytes to its reservation before any terminal close.

        Today the Ledger row binds only what `reserve()` recorded at admission
        time; nothing ties the bytes a run actually produced to that row until
        a terminal transition reads them back, and a run whose terminal close
        never happens (a crash, an operator who stops short) leaves its
        observed evidence known only from the run directory. Call this right
        after the receipt is written, so the row itself is the anchor: it does
        not depend on the run directory surviving, and it does not require a
        terminal decision to have been made yet.

        A non-terminal transition: it never changes `row["state"]`. Refused on
        an unknown ticket (via `_row`), on a row that is not `held`, and on a
        second attach whose triple differs from the first; the same triple
        attached again is accepted as the idempotent republish of a receipt a
        caller already wrote.
        """
        for value in (receipt_sha256, gate_digest, collection_digest):
            _hash(value)
        evidence = {
            "receiptSha256": receipt_sha256,
            "gateDigest": gate_digest,
            "collectionDigest": collection_digest,
            # Pinned so the row identifies the Ledger it was observed under
            # even when read apart from the live Ledger object that wrote it.
            "ledgerIdentity": self.identity,
        }
        with self._locked() as state:
            row = self._row(state, ticket)
            if row["state"] != "held":
                raise ValueError("reservation is not held")
            existing = row.get("evidence")
            if existing is not None:
                if existing == evidence:
                    return
                raise ValueError("attached evidence differs")
            row["evidence"] = evidence
            self._save(state)

    def _attestation(self, attestation, *, ticket, claim, record, owned, now):
        """The owner's signed statement that the residue is gone. Not a no-data claim."""
        if (
            not isinstance(attestation, dict)
            or set(attestation) != ATTESTATION_FIELDS
            or attestation["kind"] != ATTESTATION_KIND
            or attestation["status"] != "attested"
            or attestation["campaignId"] != claim["campaignId"]
            or attestation["nonceDigest"] != claim["nonceDigest"]
            or attestation["claimDigest"] != ticket["claimDigest"]
            or attestation["ledgerRoot"] != str(self.path)
            or attestation["reservation"] != ticket["reservation"]
            or attestation["receiptDigest"] != record["receiptDigest"]
            or attestation["gateDigest"] != record["gateDigest"]
            or attestation["residueRemoved"] is not True
            or type(attestation["resourceCount"]) is not int
            or attestation["resourceCount"] != len(owned)
            or attestation["resourcesDigest"] != digest(owned)
            or not _owner_value(attestation["ownerIdentity"])
            or not _owner_value(attestation["recoveryOwner"])
            or attestation["executionHost"]
            != {
                "platform": platform.system().lower(),
                "machine": platform.machine(),
            }
        ):
            raise ValueError("bound owner escalation attestation required")
        _number(attestation["attestedAt"])
        _number(attestation["expiresAt"])
        if (
            not attestation["attestedAt"] <= now < attestation["expiresAt"]
            or attestation["expiresAt"] - attestation["attestedAt"]
            > MAX_ATTESTATION_SECONDS
        ):
            raise ValueError("fresh owner escalation attestation required")

    def _terminal_receipt(self, ticket, record, fields, kind, label):
        """The receipt and Gate an abandoned or escalated close is bound to."""
        if (
            not isinstance(record, dict)
            or set(record) != fields
            or record["kind"] != kind
            or record["ticket"] != ticket
        ):
            raise ValueError(f"exact {label} record required")
        for key in ("gateDigest", "receiptDigest"):
            _hash(record[key])
        receipt_path = Path(record["receiptPath"])
        if (
            str(receipt_path.resolve()) != record["receiptPath"]
            or receipt_path.is_symlink()
            or receipt_path.name != "receipt.json"
            or not receipt_path.is_file()
        ):
            raise ValueError("persisted canonical receipt required")
        with receipt_path.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("bounded receipt required")
        receipt = json.loads(raw)
        if digest(receipt) != record["receiptDigest"]:
            raise ValueError("receipt digest changed")
        return receipt

    def _bound_gate(self, claim, record, receipt, *, terminal=None):
        """The Gate this record binds, read from the reservation's registered path.

        The Ledger reads the Gate itself rather than trusting the caller's copy.
        That is strictly stronger, and it is also the only workable shape: a
        campaign whose plan embeds its request bodies has a Gate far larger than
        a bounded receipt can carry, so requiring the receipt to contain one
        would make every terminal exit unreachable for it. A receipt that does
        carry a copy must still agree with the record.
        """
        if str(Path(claim["gatePath"]).resolve()) != claim["gatePath"]:
            raise ValueError("registered Gate path changed")
        gate = Gate(claim["gatePath"], _gate_job(claim)).snapshot()
        if not _gate_plan_consistent(gate) or (
            digest(gate) != record["gateDigest"]
            # A no-data abort stops the Gate, so a run resumed after a crash
            # between the stop and this row's update finds it already terminal
            # under this very record. Nothing else may differ. No explicit
            # resume marker means there is no exception: two absent values
            # must not make a mismatched snapshot look bound to this record.
            and (terminal is None or gate.get("noDataAbort") != terminal)
        ):
            raise ValueError("registered Gate differs from the record")
        embedded = receipt.get("gate")
        if embedded is not None and digest(embedded) != record["gateDigest"]:
            raise ValueError("receipt Gate differs from the record")
        return gate

    def _terminal_row(self, state, ticket, record, *, digest_key, final):
        """Shared checks for a terminal close: job, state, receipt and workers."""
        row = self._row(state, ticket)
        if row.get("recoveryChildren"):
            raise ValueError("recovery child must settle before parent close")
        if row["state"] == final:
            if row.get(digest_key) != digest(record):
                raise ValueError(f"different terminal {final} record")
            return None
        if row["state"] not in {"held", "closing"}:
            raise ValueError("reservation unavailable for a terminal close")
        return row

    def _terminal_gate(self, row, ticket, receipt, record):
        """Resolve and bind the Gate for a terminal close, inside the ledger lock."""
        claim = row["claim"]
        gate = self._bound_gate(claim, record, receipt)
        if "gateJob" in claim and claim["gateJob"] not in gate.get("jobs", {}):
            raise ValueError("registered Gate job is absent")
        if _no_data_gate(gate):
            # The exits are disjoint by evidence, not merely by record shape.
            raise ValueError("no-data evidence must use the no-data abort")
        self._terminal_binding(row, ticket, receipt, gate, claim)
        return gate

    def _terminal_binding(self, row, ticket, receipt, gate, claim):
        if (
            receipt.get("ticket") != ticket
            or receipt.get("claimDigest") != row["claimDigest"]
            or receipt.get("planDigest") != claim["gatePlanDigest"]
            or gate.get("planDigest") != claim["gatePlanDigest"]
            or receipt.get("reservationStateAtPublication") != "held"
            or receipt.get("releaseEligible") is not False
        ):
            raise ValueError("receipt does not bind this held reservation")
        for pid in [gate.get("coordinatorPid")] + [
            job.get("pid") for job in gate["jobs"].values()
        ]:
            if type(pid) is not int or pid <= 0:
                raise ValueError("recorded worker identity required")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise ValueError("worker exit not proven")

    def close_after_abandon(self, ticket, record):
        """Retire a run that stopped early and then deleted everything it created.

        The Gate's own journal carries the typed absence for every document the
        run created, so nothing is left for an owner to attest to and this exit
        asks for no attestation. It is not a no-data claim: documents were
        written, and the record says only that none of them remain.

        A created document still present is refused here and stays with the
        owner-attested escalation exit, and a run that proved no creation belongs
        to the no-data abort, so the three are disjoint by evidence.
        """
        receipt = self._terminal_receipt(
            ticket, record, ABANDON_FIELDS, ABANDON_KIND, "abandoned cleanup close"
        )
        with self._locked() as state:
            row = self._terminal_row(
                state,
                ticket,
                record,
                digest_key="abandonRecordDigest",
                final="closed-after-abandon",
            )
            if row is None:
                return
            gate = self._terminal_gate(row, ticket, receipt, record)
            if abandoned_cleanup_complete(gate) is None:
                raise ValueError("a complete abandoned cleanup is required")
            row["state"] = "closed-after-abandon"
            row["abandonRecordDigest"] = digest(record)
            row["finalGateDigest"] = record["gateDigest"]
            self._save(state)

    def close_after_source_refusal(self, ticket, record):
        """Retire only the reviewed Auth pre-network refusal; never rewrite history."""
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "auth-credential-tokens"))
        import credential_source_refusal as refusal

        with self._locked() as state:
            receipt = self._terminal_receipt(
                ticket, record, refusal.FIELDS, refusal.KIND, "Auth source-refusal"
            )
            active = self._terminal_row(state, ticket, record,
                digest_key="sourceRefusalRecordDigest", final="closed-after-escalation")
            row = self._row(state, ticket)
            gate = self._terminal_gate(row, ticket, receipt, record)
            refusal.validate_resolution(record, receipt=receipt, gate=gate, row=row,
                now=time.time(), replay=active is None)
            if active is None:
                return
            row["state"] = "closed-after-escalation"
            row["resolutionDisposition"] = "source-proven-unsent"
            row["sourceRefusalRecordDigest"] = digest(record)
            row["finalGateDigest"] = record["gateDigest"]
            self._save(state)

    def close_after_escalation(self, ticket, record):
        """Retire a reservation whose run may have written, after the owner proves it did not persist.

        An uncertain stop, a Commit whose receipt was lost, can never be retired
        as no data: it may have been applied. Holding the row while that is
        unresolved is right, but before this there was no exit afterwards, so the
        row stayed active forever and kept its lock key and its whole allocation
        even once the owner had removed the residue by hand.

        This is deliberately not the no-data path and shares no evidence with it.
        A receipt whose Gate proves no data was written is refused here and must
        use `abort_no_data`; a receipt that does not is refused there. Neither
        can be mistaken for the other, and this transition never asserts that
        nothing was written, only that nothing remains.
        """
        receipt = self._terminal_receipt(
            ticket, record, ESCALATION_FIELDS, ESCALATION_KIND, "escalation close"
        )
        with self._locked() as state:
            row = self._terminal_row(
                state,
                ticket,
                record,
                digest_key="escalationRecordDigest",
                final="closed-after-escalation",
            )
            if row is None:
                return
            claim = row["claim"]
            gate = self._terminal_gate(row, ticket, receipt, record)
            if abandoned_cleanup_complete(gate) is not None:
                raise ValueError(
                    "a recoverable stop must use the abandoned cleanup close"
                )
            owned = _owned_resources(gate)
            absence = record["absence"]
            if (
                owned is None
                or not isinstance(absence, dict)
                or sorted(absence) != owned
                or any(
                    not isinstance(proof, dict)
                    or set(proof) != {"status", "body"}
                    or not typed_absence(proof["status"], proof["body"])
                    for proof in absence.values()
                )
            ):
                raise ValueError("every owned resource must be proven absent")
            self._attestation(
                record["attestation"],
                ticket=ticket,
                claim=claim,
                record=record,
                owned=owned,
                # Both the Ledger and the registered Gate may have waited for
                # a lock. Check freshness at the decision, not before either wait.
                now=time.time(),
            )
            row["state"] = "closed-after-escalation"
            row["escalationRecordDigest"] = digest(record)
            row["finalGateDigest"] = record["gateDigest"]
            self._save(state)

    def abort_no_data(self, ticket, record):
        """Retire a failed attempt only after persisted evidence proves no data dispatch."""
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "kind",
                "ticket",
                "planDigest",
                "gateDigest",
                "receiptPath",
                "receiptDigest",
                "collectorSourceDigest",
                "sourceCommit",
                "sourceDigests",
            }
            or record["kind"] != "shared-no-data-abort-v1"
            or record["ticket"] != ticket
        ):
            raise ValueError("exact no-data abort record required")
        for key in (
            "planDigest",
            "gateDigest",
            "receiptDigest",
            "collectorSourceDigest",
        ):
            _hash(record[key])
        claimed_generation = {key: record[key] for key in GENERATION_FIELDS}
        _generation(claimed_generation)
        receipt_path = Path(record["receiptPath"])
        if (
            str(receipt_path.resolve()) != record["receiptPath"]
            or receipt_path.is_symlink()
            or receipt_path.name != "receipt.json"
            or not receipt_path.is_file()
        ):
            raise ValueError("persisted canonical receipt required")
        with receipt_path.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("bounded receipt required")
        receipt = json.loads(raw)
        if digest(receipt) != record["receiptDigest"]:
            raise ValueError("receipt digest changed")
        with self._locked() as state:
            row = self._row(state, ticket)
            if row.get("recoveryChildren"):
                raise ValueError("recovery child must settle before parent close")
            # A reservation is retirable only by proving a source closure
            # identical to the one it was acquired under. Rows written before
            # the generation binding existed carry none and remain bound to the
            # legacy closure.
            recorded = row.get("generation")
            if claimed_generation != (
                LEGACY_COMMIT_GENERATION if recorded is None else recorded
            ):
                raise ValueError("acquisition source closure required")
            # The closure that retires a row is the one the ROW recorded, not
            # the one the aborting code is built from. Sources move on, and a
            # fix to this very file changes the current closure while the held
            # row keeps naming the closure its acquisition ran under. What the
            # caller must therefore present is that run's own receipt, which
            # recorded the generation at acquisition time.
            if recorded is not None and receipt.get("generation") != recorded:
                raise ValueError("receipt does not bind the recorded generation")
            if row["state"] == "aborted-no-data":
                if row.get("abortRecordDigest") != digest(record):
                    raise ValueError("different terminal abort record")
                return
            if row["state"] not in {"held", "closing"} or (
                row["state"] == "closing"
                and row.get("abortRecordDigest") != digest(record)
            ):
                raise ValueError("reservation unavailable for no-data abort")
            claim = row["claim"]
            # Read the Gate from the reservation's own registered path rather
            # than from the receipt's copy: stronger, and the only shape that
            # works for a campaign whose Gate is larger than a bounded receipt.
            gate_snapshot = self._bound_gate(
                claim,
                record,
                receipt,
                terminal={
                    "preGateDigest": record["gateDigest"],
                    "recordDigest": digest(record),
                },
            )
            if "gateJob" in claim and claim["gateJob"] not in gate_snapshot.get(
                "jobs", {}
            ):
                # The same check `finish` makes: a claim naming a job the Gate
                # never hosted is a binding error, not a retirement.
                raise ValueError("registered Gate job is absent")
            # The reserving plan's receipt kind selects the evidence contract.
            # A receipt of another kind, or of a kind with no contract, binds
            # nothing.
            schema = _no_data_schema(gate_snapshot)
            if gate_snapshot["plan"].get("transport") == LIMITS_PREPARATION_TRANSPORT:
                validate_limits_preparation_plan(gate_snapshot["plan"])
                self._terminal_binding(row, ticket, receipt, gate_snapshot, claim)
                if gate_snapshot.get("coordinatorInflight") is not False or any(
                    event.get("workerReaped") is not True
                    for event in gate_snapshot.get("managementEvents", [])
                ):
                    raise ValueError("preparation workers must be reaped before abort")
                rows = receipt.get("managementEvidence")
                if not isinstance(rows, list):
                    raise ValueError("sanitized preparation management evidence required")
                for item in rows:
                    if not isinstance(item, dict) or set(item) != MANAGEMENT_ROW_FIELDS or not isinstance(item.get("id"), str):
                        raise ValueError("sanitized preparation management row required")
                    validate_limits_preparation_response(item["id"].removeprefix("observation:"), item["response"])
            if (
                record["planDigest"] != claim["gatePlanDigest"]
                or gate_snapshot.get("planDigest") != claim["gatePlanDigest"]
                or receipt.get("kind") != _receipt_kind(gate_snapshot)
                or receipt.get("ticket") != ticket
                or receipt.get("claimDigest") != row["claimDigest"]
                or receipt.get("planDigest") != record["planDigest"]
                or receipt.get("reservationStateAtPublication") != "held"
                or receipt.get("executionKind") != "fixed-production-wire"
                or receipt.get("releaseEligible") is not False
                or not isinstance(receipt.get("failure"), str)
                or not receipt["failure"]
                or receipt.get("chargedCalls") != gate_snapshot.get("total")
                or (
                    receipt.get("gateDigest") is not None
                    and receipt["gateDigest"] != record["gateDigest"]
                )
                or schema is None
                or not (
                    _commit_no_data_receipt(receipt, gate_snapshot)
                    if schema == COMMIT_NO_DATA_SCHEMA
                    else _request_bytes_no_data_receipt(receipt, gate_snapshot)
                )
                or not _no_data_gate(gate_snapshot)
                or gate_snapshot["total"] > claim["budget"]["requests"]
                or gate_snapshot["costMicrousd"] > claim["budget"]["costMicrousd"]
                or gate_snapshot["plan"].get("collectorSourceDigest")
                != record["collectorSourceDigest"]
                or (
                    receipt.get("generation") is not None
                    and receipt["generation"] != claimed_generation
                )
                or str(receipt_path.parent / "gate") != claim["gatePath"]
            ):
                raise ValueError("receipt does not bind failed no-data attempt")
            if row["state"] == "held":
                row["state"] = "closing"
                row["abortRecordDigest"] = digest(record)
                self._save(state)
        gate = Gate(claim["gatePath"], _gate_job(claim))
        stopped = gate.abort_no_data(
            record["planDigest"], record["gateDigest"], digest(record)
        )
        expected = copy.deepcopy(gate_snapshot)
        expected["stopped"] = True
        for job in expected["jobs"].values():
            job["stopped"] = True
        expected["noDataAbort"] = {
            "preGateDigest": record["gateDigest"],
            "recordDigest": digest(record),
        }
        if stopped != expected:
            raise ValueError("terminal Gate differs from reviewed abort proof")
        final_digest = digest(stopped)
        if digest(gate.snapshot()) != final_digest:
            raise ValueError("terminal Gate snapshot changed")
        with self._locked() as state:
            row = self._row(state, ticket)
            if row["state"] != "closing" or row.get("abortRecordDigest") != digest(
                record
            ):
                raise ValueError("closing abort reservation changed")
            row["state"] = "aborted-no-data"
            row["finalGateDigest"] = final_digest
            self._save(state)
