"""One-host shared reservations underneath O7; never grants production permission.

Full campaign upper bounds remain allocated forever, including unused capacity.
Only locks/concurrency are released after the registered Gate proves cleanup.
The O7 caller must use one shared root and bind its identity into every campaign.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import math
import re
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import os
import platform
import stat

from broad_contract import digest
from shared_gate import (
    Gate,
    _save,
    abandoned_cleanup_complete,
    non_creating_dispatches,
    typed_absence,
    unconfirmed_creates,
    validate_absence_proofs,
)

DIMENSIONS = {"requests", "accounts", "resources", "costMicrousd"}
# The owner's US$10 is per production observation task, identified by the
# claim's campaignId, and never cumulative across the program. Every earlier
# reservation of the task counts whatever state it reached, because an
# allocation is never refunded.
TASK_CAP_MICROUSD = 10_000_000
TASK_BUDGET_REFUSAL = "task-budget-exceeded:"
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
RECOVERY_CHILD_FIELDS = {
    "kind", "version", "campaignId", "manifestDigest", "nonceDigest",
    "gatePath", "gatePlanDigest", "locks", "budget", "durationSeconds",
    "generation", "parentClaimDigest", "parentPlanDigest", "recoveryNonce",
    "selectedProbe", "resourceDigest", "ownedResources", "ownerIdentity",
    "recoveryOwner", "operationClass", "readCount", "inspectionCount",
    "absenceCount", "deleteCount", "tariffEstimateMicrousd", "expiresAt",
    "executionHost", "permissionDigest",
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


def _resource_scope(resource):
    if not isinstance(resource, str):
        raise TypeError("canonical Auth account resource required")
    parts = resource.split("/")
    if len(parts) > 2 and parts[0] == "projects" and parts[2] == "auth":
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
    ):
        raise ValueError("bounded duration required")
    path = value["gatePath"]
    if not isinstance(path, str) or str(Path(path).resolve()) != path:
        raise ValueError("absolute canonical Gate path required")


def _recovery_child_claim(value):
    if not isinstance(value, dict) or set(value) != RECOVERY_CHILD_FIELDS:
        raise ValueError("exact recovery child claim required")
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
        or value["readCount"] != RECOVERY_INSPECTION_REQUESTS + RECOVERY_ABSENCE_REQUESTS
        or value["inspectionCount"] != RECOVERY_INSPECTION_REQUESTS
        or value["absenceCount"] != RECOVERY_ABSENCE_REQUESTS
        or value["deleteCount"] != RECOVERY_DELETE_REQUESTS
        or value["tariffEstimateMicrousd"] != RECOVERY_TARIFF_ESTIMATE_MICROUSD
        or value["budget"]["resources"] != len(value["ownedResources"])
        or value["budget"] != {"requests": RECOVERY_CHILD_REQUESTS, "accounts": 0, "resources": value["budget"]["resources"], "costMicrousd": RECOVERY_CHILD_COST_MICROUSD}
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


def _validate_recovery_gate_plan(parent_plan, child_plan, child):
    if not isinstance(parent_plan, dict) or digest(parent_plan) != child["parentPlanDigest"]:
        raise ValueError("canonical parent plan binding changed")
    lane = Path(__file__).resolve().parent.parent / "fs-request-bytes-boundary"
    sys.path.insert(0, str(lane))
    try:
        import request_bytes_recovery_campaign as recovery_campaign
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
    if not isinstance(operations, list) or len(operations) != RECOVERY_CHILD_REQUESTS:
        raise ValueError("recovery operation count changed")
    kinds = [operation.get("kind") for operation in operations]
    if kinds.count("recovery-inspection-read") != RECOVERY_INSPECTION_REQUESTS or kinds.count("recovery-conditional-delete") != RECOVERY_DELETE_REQUESTS or kinds.count("recovery-absence-read") != RECOVERY_ABSENCE_REQUESTS:
        raise ValueError("recovery operation classes changed")
    if any(operation.get("versionFrom") != "recovery-inspection-read" for operation in operations if operation.get("kind") == "recovery-conditional-delete"):
        raise ValueError("version-bound delete inspection required")
    resources = sorted({operation.get("resource") for operation in operations})
    if digest(resources) != child["resourceDigest"] or resources != child["ownedResources"] or child["manifestDigest"] != digest(recovery):
        raise ValueError("recovery resources differ from canonical plan")


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
                }:
                    raise ValueError("reservation binding changed")
                children = row.get("recoveryChildren", [])
                if children and row["state"] != "held":
                    raise ValueError("recovery child parent is not held")
                for child in children:
                    _recovery_child_claim(child["claim"])
                    if child.get("parentClaimDigest") != row["claimDigest"] or child.get("claimDigest") != digest(child["claim"]):
                        raise ValueError("recovery child parent binding changed")
                    if child.get("state") != "allocated" or child.get("envelopeDigest") not in state.get("recoveryEnvelopes", {}):
                        raise ValueError("recovery child state changed")
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
        if generation is not None:
            _generation(generation)
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
                if r["state"]
                not in {
                    "released",
                    "aborted-no-data",
                    "closed-after-escalation",
                    "closed-after-abandon",
                }
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
        try:
            lane = Path(__file__).resolve().parent.parent / "fs-request-bytes-boundary"
            sys.path.insert(0, str(lane))
            import request_bytes_compiler as request_compiler
            actual_parent_plan = request_compiler.compile_request_bytes_plan(
                canonical_parent_inputs["plan"]["project"],
                canonical_parent_inputs["plan"]["database"],
                canonical_parent_inputs["plan"]["nonce"],
            )
        except (ImportError, KeyError, TypeError, ValueError) as error:
            raise ValueError("canonical parent compiler refused inputs") from error
        if digest(actual_parent_plan) != digest(canonical_parent_plan):
            raise ValueError("canonical parent compiler plan differs")
        _recovery_child_claim(child_claim)
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
                or claim["budget"]["requests"] != 265
                or claim["budget"]["costMicrousd"] != 303
                or child_claim["nonceDigest"] == claim["nonceDigest"]
                or child_claim["gatePlanDigest"] == claim["gatePlanDigest"]
                or child_claim["permissionDigest"] == state["envelopes"][parent["envelopeDigest"]]["envelope"]["permissionDigest"]
                or child_claim["generation"] == parent.get("generation")
            ):
                raise ValueError("recovery child is not bound to held parent")
            if child_claim["budget"]["requests"] != RECOVERY_CHILD_REQUESTS or child_claim["budget"]["costMicrousd"] != RECOVERY_CHILD_COST_MICROUSD:
                raise ValueError("recovery child must reserve all 85 requests")
            if child_claim["durationSeconds"] < canonical_child_gate_plan["wallSeconds"]:
                raise ValueError("recovery duration below actual Gate wall")
            decision_now = time.time() if now is None else now
            if child_claim["expiresAt"] < decision_now + child_claim["durationSeconds"]:
                raise ValueError("recovery permission window is too short")
            if new_envelope["permissionDigest"] != child_claim["permissionDigest"] or new_envelope["limits"]["requests"] < RECOVERY_CHILD_REQUESTS or new_envelope["limits"]["costMicrousd"] < RECOVERY_CHILD_COST_MICROUSD:
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
            task_budget_check(state, claim["campaignId"], RECOVERY_CHILD_COST_MICROUSD)
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
