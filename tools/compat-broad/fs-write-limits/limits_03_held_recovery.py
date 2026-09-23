"""Offline validation and planning for recovery of the historical held Limits-03 run.

This module does not send requests or mutate the shared Ledger. A returned
packet is deliberately non-authorizing and must pass the campaign's separate
Gate, O7/O8, budget, and owner-attestation checks before any execution.
"""

# ruff: noqa: TRY004 -- Fail-closed packet inputs use a stable refusal type.

from __future__ import annotations

import copy
import hashlib
import json
import math
import platform
import re
import sys
from pathlib import Path

HERE = __import__("pathlib").Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

import limits_03_preflight as preflight
import reservations
import shared_gate
from broad_contract import digest

CAMPAIGN = "FS-WRITE-LIMITS-03"
PACKET_KIND = "limits-03-held-recovery-plan-v1"
CHILD_KIND = "limits-03-held-recovery-child-v1"
CHILD_OPERATION_CLASS = "limits-03-held-absence-and-index-readback-v1"
RECOVERY_TASK_ID = "FS-WRITE-LIMITS-03-HELD-RECOVERY"
INDEX_READBACK_NAME = preflight.LIFECYCLE_FIELD
SOURCE_PATHS = {
    "tools/compat-broad/fs-write-limits/limits_03_admission.py": "limits_03_admission.py",
    "tools/compat-broad/fs-write-limits/limits_03_descriptor.py": "limits_03_descriptor.py",
    "tools/compat-broad/o8-core/o8_admission.py": "o8_admission.py",
    "tools/compat-broad/production-admission/reservations.py": "reservations.py",
    "tools/compat-broad/shared_gate.py": "shared_gate.py",
}
NONCE = re.compile(r"^[a-f0-9]{32}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
HEX40 = re.compile(r"^[a-f0-9]{40}$")
MAX_PACKET_SECONDS = 1800
REQUEST_LIMIT = 30
COST_LIMIT_MICROUSD = 3000
MAX_RESULT_BYTES = 2 * 1024 * 1024


def prepare_packet(
    receipt,
    gate,
    *,
    ticket,
    source_files,
    ledger_root,
    recovery_nonce,
    now,
):
    """Validate acquisition bindings and derive a fresh, GET-only recovery plan."""
    _finite_time(now, "packet time")
    if not isinstance(recovery_nonce, str) or not NONCE.fullmatch(recovery_nonce):
        raise ValueError("fresh recovery nonce required")
    if not isinstance(gate, dict) or not isinstance(receipt, dict):
        raise ValueError("historical receipt and Gate snapshot required")
    if not isinstance(ticket, dict) or receipt.get("ticket") != ticket:
        raise ValueError("historical receipt ticket differs")
    if recovery_nonce == gate.get("plan", {}).get("nonce"):
        raise ValueError("recovery nonce must differ from acquisition nonce")
    if not isinstance(ledger_root, str) or not ledger_root.startswith("/"):
        raise ValueError("absolute shared Ledger root required")
    if ticket.get("ledgerPath") != ledger_root:
        raise ValueError("ticket Ledger path differs")
    if set(ticket) != {
        "claimDigest",
        "envelopeDigest",
        "ledgerIdentity",
        "ledgerPath",
        "reservation",
    }:
        raise ValueError("exact historical reservation ticket required")
    for key in ("claimDigest", "envelopeDigest"):
        _require_hash(ticket.get(key), f"ticket {key}")
    for key in ("ledgerIdentity", "reservation"):
        if not _nonblank(ticket.get(key)):
            raise ValueError(f"ticket {key} required")

    plan = gate.get("plan")
    if (
        not isinstance(plan, dict)
        or digest(plan) != gate.get("planDigest")
        or plan.get("campaignId") != CAMPAIGN
        or plan.get("nonce") == recovery_nonce
        or plan.get("receiptKind") != "limits-03-acquisition-receipt-v1"
    ):
        raise ValueError("historical Limits-03 Gate plan binding required")
    if (
        receipt.get("kind") != "limits-03-acquisition-receipt-v1"
        or receipt.get("campaignId") != CAMPAIGN
        or receipt.get("claimDigest") != ticket["claimDigest"]
        or receipt.get("planDigest") != gate.get("planDigest")
        or receipt.get("gateDigest") != digest(gate)
        or receipt.get("reservationStateAtPublication") != "held"
        or receipt.get("releaseEligible") is not False
        or receipt.get("productionExecuted") is not False
        or not _nonblank(receipt.get("failure"))
    ):
        raise ValueError("historical held acquisition receipt binding required")

    generation = receipt.get("generation")
    _validate_source_generation(generation, plan, source_files)
    if gate.get("planDigest") != receipt.get("planDigest"):
        raise ValueError("historical Gate plan digest differs from receipt")

    jobs = plan.get("jobs")
    limits_job = jobs.get("limits") if isinstance(jobs, dict) else None
    resources = limits_job.get("resources") if isinstance(limits_job, dict) else None
    if (
        not isinstance(resources, list)
        or len(resources) != 29
        or any(
            not isinstance(name, str) or not name.startswith(_DOCUMENT_ROOT)
            for name in resources
        )
        or len(set(resources)) != 29
    ):
        raise ValueError("exact 29 historical owned document resources required")
    resources = sorted(resources)

    # This is the shared Ledger's own mutually exclusive predicate. Do not
    # replace it with a lane-local inference from receipt flags or counters.
    no_data_gate = reservations._no_data_gate(gate)
    if no_data_gate and not reservations._request_bytes_no_data_receipt(receipt, gate):
        raise ValueError("Ledger no-data predicate requires its exact receipt schema")
    ledger_action = "abort_no_data" if no_data_gate else "close_after_escalation"
    requests = [
        {
            "id": "index-readback",
            "method": "GET",
            "name": INDEX_READBACK_NAME,
            "operation": _get_operation(INDEX_READBACK_NAME),
        },
        *[
            {
                "id": f"resource-{index:02}",
                "method": "GET",
                "name": name,
                "operation": _get_operation(name),
            }
            for index, name in enumerate(resources, start=1)
        ],
    ]
    packet = {
        "kind": PACKET_KIND,
        "taskId": RECOVERY_TASK_ID,
        "campaignId": CAMPAIGN,
        "authorized": False,
        "admission": "NOT_AUTHORIZED",
        "recoveryNonce": recovery_nonce,
        "issuedAt": now,
        "expiresAt": now + MAX_PACKET_SECONDS,
        "ledgerRoot": ledger_root,
        "ticket": copy.deepcopy(ticket),
        "ticketDigest": digest(ticket),
        "reservation": ticket["reservation"],
        "claimNonceDigest": digest(plan["nonce"]),
        "receiptDigest": digest(receipt),
        "receiptGeneration": copy.deepcopy(generation),
        "indexBaselineProjection": copy.deepcopy(
            receipt.get("indexExemption", {})
            .get("precondition", {})
            .get("readback", {})
            .get("projection")
        ),
        "gateDigest": digest(gate),
        "planDigest": gate["planDigest"],
        "resourceCount": len(resources),
        "resourceDigest": digest(resources),
        "requestLimit": REQUEST_LIMIT,
        "costLimitMicrousd": COST_LIMIT_MICROUSD,
        "ledgerAction": ledger_action,
        "requests": requests,
    }
    packet["gatePlan"] = compile_gate_plan(packet)
    packet["packetDigest"] = digest(packet)
    return packet


def compile_gate_plan(packet):
    """Compile the nested child's canonical Shared Gate plan without I/O."""
    if not isinstance(packet, dict) or packet.get("kind") != PACKET_KIND:
        raise ValueError("held recovery packet required")
    requests = packet.get("requests")
    if (
        not isinstance(requests, list)
        or len(requests) != REQUEST_LIMIT
        or any(
            not isinstance(request, dict)
            or set(request) != {"id", "method", "name", "operation"}
            or request.get("method") != "GET"
            or request.get("operation") != _get_operation(request.get("name"))
            for request in requests
        )
        or requests[0].get("id") != "index-readback"
        or requests[0].get("name") != INDEX_READBACK_NAME
        or [request.get("name") for request in requests[1:]]
        != sorted({request.get("name") for request in requests[1:]})
        or len({request.get("name") for request in requests[1:]}) != 29
        or any(
            not isinstance(request.get("name"), str)
            or not request["name"].startswith(_DOCUMENT_ROOT)
            or request.get("id") != f"resource-{index:02}"
            for index, request in enumerate(requests[1:], start=1)
        )
        or packet.get("resourceCount") != 29
        or packet.get("resourceDigest")
        != digest([request["name"] for request in requests[1:]])
    ):
        raise ValueError("exact GET-only recovery requests required")
    projection = packet.get("indexBaselineProjection")
    expected_projection = _historical_index_projection(packet)
    if projection != expected_projection:
        raise ValueError("historical nx projection must be normalized and typed")
    operations = [request["operation"] for request in requests]
    schedule = [
        {"phase": "observation", "index": index, "seconds": 13, "creates": False}
        for index in range(len(operations))
    ]
    gate_plan = {
        "contract": "shared-local-v2",
        "campaignId": CAMPAIGN,
        "project": "fireemu-35fe6",
        "database": "(default)",
        "nonce": packet["recoveryNonce"],
        "transport": "limits-03-held-recovery-v1",
        "receiptKind": "limits-03-held-recovery-receipt-v1",
        "expectedIndexProjection": copy.deepcopy(expected_projection),
        "jobs": {
            "limits-03-held-recovery": {
                "resources": [request["name"] for request in requests[1:]],
                "observation": operations,
                "recovery": [],
                "schedule": schedule,
            }
        },
        "jobSlots": 1,
        "wallSeconds": 750,
        "recoverySeconds": 300,
        "observationRequests": REQUEST_LIMIT,
        "dataRequests": REQUEST_LIMIT,
        "managementRequests": 0,
        "recoveryRequests": 0,
        "intervalSeconds": 0.25,
        "requestSeconds": 13,
        "requestCostMicrousd": 100,
        "costMicrousd": COST_LIMIT_MICROUSD,
        "fixedCostMicrousd": 0,
        "coordinatorRequests": 0,
        "transportCeilingSeconds": 12,
    }
    observation_seconds = shared_gate._observation_time(
        gate_plan, shared_gate.request_seconds(gate_plan)
    )
    if observation_seconds > gate_plan["wallSeconds"] - gate_plan["recoverySeconds"]:
        raise ValueError(
            "recovery child Gate wall does not reserve all observation slots"
        )
    return gate_plan


def compile_child_claim(
    packet,
    *,
    envelope,
    gate_path,
    generation,
    owner_identity,
    recovery_owner,
    expires_at,
    source_binding,
    transport_binding,
    o7_binding,
    o8_binding,
    now,
):
    """Build a typed, non-authorizing nested-child claim from supplied refs.

    This compiler never creates permission or invokes the Ledger. Callers must
    supply already-issued authority bindings and an envelope; the shared Gate
    and Ledger remain responsible for admission and all persistent mutations.
    """
    _finite_time(now, "claim compilation time")
    _finite_time(expires_at, "child claim expiry")
    gate_plan = compile_gate_plan(packet)
    unsigned_packet = {key: value for key, value in packet.items() if key != "packetDigest"}
    if digest(unsigned_packet) != packet.get("packetDigest"):
        raise ValueError("recovery packet digest differs")
    if packet.get("authorized") is not False or packet.get("admission") != "NOT_AUTHORIZED":
        raise ValueError("offline recovery packet cannot grant authority")
    if not isinstance(gate_path, str) or not gate_path.startswith("/"):
        raise ValueError("absolute child Gate path required")
    if str(Path(gate_path).resolve()) != gate_path:
        raise ValueError("canonical child Gate path required")
    if generation == packet.get("receiptGeneration"):
        raise ValueError("child source generation must be fresh, not the held generation")
    reservations._generation(generation)
    if not reservations._owner_value(owner_identity) or not reservations._owner_value(recovery_owner):
        raise ValueError("owner and recovery owner identities required")
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"permissionDigest", "issuedAt", "expiresAt", "limits", "concurrency", "scopes"}
        or not isinstance(envelope.get("permissionDigest"), str)
        or not SHA256.fullmatch(envelope["permissionDigest"])
        or envelope.get("limits") != {"requests": 30, "accounts": 0, "resources": 29, "costMicrousd": 3000}
        or type(envelope.get("concurrency")) is not int
        or envelope["concurrency"] != 1
    ):
        raise ValueError("already-issued child permission envelope required")
    _finite_time(envelope["issuedAt"], "permission issue time")
    _finite_time(envelope["expiresAt"], "permission expiry")
    if not envelope["issuedAt"] <= now < envelope["expiresAt"]:
        raise ValueError("already-issued child permission envelope is not current")
    if type(envelope["expiresAt"]) not in (int, float) or expires_at > envelope["expiresAt"]:
        raise ValueError("child claim expiry exceeds supplied permission")
    if (
        not now + gate_plan["wallSeconds"] <= expires_at <= envelope["expiresAt"]
        or gate_plan["wallSeconds"] != 750
    ):
        raise ValueError("child claim must cover the exact 750-second Gate window")
    bindings = {
        "sourceBindingDigest": _binding_digest(source_binding, "limits-03-held-recovery-source-binding-v1"),
        "transportBindingDigest": _binding_digest(transport_binding, "limits-03-held-recovery-transport-binding-v1"),
        "o7BindingDigest": _binding_digest(o7_binding, "limits-03-held-recovery-o7-binding-v1"),
        "o8BindingDigest": _binding_digest(o8_binding, "limits-03-held-recovery-o8-binding-v1"),
    }
    plan_digest = digest(gate_plan)
    resources = [request["name"] for request in packet["requests"][1:]]
    locks = [
        {"key": "project/fireemu-35fe6/firestore/(default)/collectionGroups/nx/fields/*", "mode": "READ"},
        *[
            {"key": "/".join(reservations._resource_scope(resource)), "mode": "READ"}
            for resource in resources
        ],
    ]
    locks.sort(key=lambda lock: lock["key"])
    if envelope["scopes"] != locks:
        raise ValueError("permission scopes must exactly equal child READ locks")
    if Path(gate_path).exists():
        raise ValueError("child Gate path must be fresh and not exist")
    claim = {
        "kind": CHILD_KIND,
        "version": 1,
        "taskId": CAMPAIGN,
        "campaignId": CAMPAIGN,
        "manifestDigest": plan_digest,
        "nonceDigest": digest(packet["recoveryNonce"]),
        "gatePath": gate_path,
        "gateJob": "limits-03-held-recovery",
        "gatePlanDigest": plan_digest,
        "parentClaimDigest": packet["ticket"]["claimDigest"],
        "parentPlanDigest": packet["planDigest"],
        "parentGateDigest": packet["gateDigest"],
        "parentReceiptDigest": packet["receiptDigest"],
        "parentGateJob": "limits",
        "recoveryNonce": packet["recoveryNonce"],
        "resourceDigest": packet["resourceDigest"],
        "ownedResources": resources,
        "locks": locks,
        "budget": {"requests": 30, "accounts": 0, "resources": 29, "costMicrousd": 3000},
        "durationSeconds": gate_plan["wallSeconds"],
        "generation": copy.deepcopy(generation),
        "ownerIdentity": owner_identity,
        "recoveryOwner": recovery_owner,
        "operationClass": CHILD_OPERATION_CLASS,
        "readCount": 30,
        "inspectionCount": 1,
        "absenceCount": 29,
        "deleteCount": 0,
        "expiresAt": expires_at,
        "executionHost": {"platform": platform.system().lower(), "machine": platform.machine()},
        "permissionDigest": envelope["permissionDigest"],
        **bindings,
    }
    if digest(claim["ownedResources"]) != claim["resourceDigest"]:
        raise ValueError("child owned resources differ from parent-bound digest")
    if len({lock["key"] for lock in locks}) != 30:
        raise ValueError("child READ lock targets must be unique")
    return claim


def _binding_digest(binding, expected_kind):
    if not isinstance(binding, dict) or binding.get("kind") != expected_kind:
        raise ValueError(f"typed {expected_kind} reference required")
    supplied = binding.get("digest", binding.get("bindingDigest"))
    if supplied is None:
        return digest(binding)
    _require_hash(supplied, f"{expected_kind} digest")
    return supplied


def validate_results(packet, results):
    """Validate a retained synthetic or separately authorized result bundle."""
    if not isinstance(packet, dict) or packet.get("kind") != PACKET_KIND:
        raise ValueError("held recovery packet required")
    unsigned = {key: value for key, value in packet.items() if key != "packetDigest"}
    if digest(unsigned) != packet.get("packetDigest"):
        raise ValueError("recovery packet digest differs")
    if (
        packet.get("authorized") is not False
        or packet.get("admission") != "NOT_AUTHORIZED"
    ):
        raise ValueError("offline packet cannot grant execution authority")
    requests = packet.get("requests")
    if (
        not isinstance(requests, list)
        or len(requests) != REQUEST_LIMIT
        or any(request.get("method") != "GET" for request in requests)
        or len({request.get("id") for request in requests}) != REQUEST_LIMIT
    ):
        raise ValueError("exact GET-only 30-request packet required")
    if compile_gate_plan(packet) != packet.get("gatePlan"):
        raise ValueError("recovery child Gate plan differs from its compiler")
    if not isinstance(results, list) or len(results) != len(requests):
        raise ValueError("one fresh result per declared GET required")
    by_id = {result.get("id"): result for result in results if isinstance(result, dict)}
    if len(by_id) != len(results) or set(by_id) != {
        request["id"] for request in requests
    }:
        raise ValueError("result rows must exactly cover declared GETs")

    for request in requests:
        result = by_id[request["id"]]
        if set(result) != {
            "id",
            "requestDigest",
            "status",
            "complete",
            "workerReaped",
            "observedAt",
            "body",
        }:
            raise ValueError("closed typed GET result row required")
        try:
            result_size = len(json.dumps(result, allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError) as error:
            raise ValueError("finite JSON GET evidence required") from error
        if result_size > MAX_RESULT_BYTES:
            raise ValueError("bounded GET evidence required")
        if (
            result.get("requestDigest") != digest(request["operation"])
            or result.get("complete") is not True
            or result.get("workerReaped") is not True
        ):
            raise ValueError("complete Gate-bound GET result required")
        observed_at = result.get("observedAt")
        _finite_time(observed_at, "GET observation time")
        if not packet["issuedAt"] <= observed_at <= packet["expiresAt"]:
            raise ValueError("fresh GET evidence is outside the packet window")
        if request["id"] == "index-readback":
            if result.get("status") != 200:
                raise ValueError("fresh nx index readback must be HTTP 200")
            try:
                projection = preflight._field_readback(
                    result.get("body"), field=INDEX_READBACK_NAME
                )
            except (TypeError, ValueError) as error:
                raise ValueError("typed nx index readback required") from error
            expected = _historical_index_projection(packet)
            if projection != expected:
                raise ValueError(
                    "nx index readback differs from the held-run baseline; "
                    "a separately authorized conditional restore is required"
                )
        elif not reservations.typed_absence(result.get("status"), result.get("body")):
            raise ValueError("each owned document needs typed HTTP 404 NOT_FOUND")

    return {
        "packetDigest": packet["packetDigest"],
        "resultDigest": digest(results),
        "resourceDigest": packet["resourceDigest"],
        "resourceCount": 29,
        "resourcesAbsent": True,
        "indexReadbackRecorded": True,
        "closureReady": True,
        "ledgerAction": packet["ledgerAction"],
        "authorized": False,
    }


def validate_attestation(
    packet,
    results,
    attestation,
    *,
    owner_identity,
    recovery_owner,
    now,
):
    """Validate the shared Ledger's 17-field fresh owner attestation offline."""
    _finite_time(now, "attestation validation time")
    validate_results(packet, results)
    if (
        not isinstance(attestation, dict)
        or set(attestation) != reservations.ATTESTATION_FIELDS
        or attestation.get("kind") != reservations.ATTESTATION_KIND
        or attestation.get("status") != "attested"
        or attestation.get("campaignId") != CAMPAIGN
        or attestation.get("nonceDigest") != packet.get("claimNonceDigest")
        or attestation.get("claimDigest") != packet["ticket"].get("claimDigest")
        or attestation.get("ledgerRoot") != packet.get("ledgerRoot")
        or attestation.get("reservation") != packet.get("reservation")
        or attestation.get("receiptDigest") != packet.get("receiptDigest")
        or attestation.get("gateDigest") != packet.get("gateDigest")
        or attestation.get("residueRemoved") is not True
        or type(attestation.get("resourceCount")) is not int
        or attestation.get("resourceCount") != packet.get("resourceCount")
        or attestation.get("resourcesDigest") != packet.get("resourceDigest")
        or attestation.get("ownerIdentity") != owner_identity
        or attestation.get("recoveryOwner") != recovery_owner
        or not reservations._owner_value(owner_identity)
        or not reservations._owner_value(recovery_owner)
        or attestation.get("executionHost")
        != {"platform": platform.system().lower(), "machine": platform.machine()}
    ):
        raise ValueError("fresh owner attestation must bind the complete held recovery")
    attested_at = attestation.get("attestedAt")
    expires_at = attestation.get("expiresAt")
    _finite_time(attested_at, "attestation issue time")
    _finite_time(expires_at, "attestation expiry")
    if (
        not attested_at <= now < expires_at
        or expires_at - attested_at > reservations.MAX_ATTESTATION_SECONDS
    ):
        raise ValueError(
            "owner attestation is stale or exceeds the shared Ledger window"
        )
    return {"attestationDigest": digest(attestation), "fresh": True}


def _historical_index_projection(packet):
    # The original receipt is represented by its immutable digest, so its
    # expected baseline projection is carried explicitly in the packet inputs.
    projection = packet.get("indexBaselineProjection")
    if not isinstance(projection, dict):
        raise ValueError("historical nx index baseline projection required")
    if projection.get("name") != INDEX_READBACK_NAME:
        raise ValueError("historical nx index baseline name differs")
    if (
        set(projection) != {"name", "indexes", "usesAncestorConfig", "ancestorField"}
        or not isinstance(projection.get("indexes"), list)
        or type(projection.get("usesAncestorConfig")) is not bool
        or projection.get("ancestorField") != preflight.DEFAULT_ANCESTOR_FIELD
    ):
        raise ValueError("typed historical nx index baseline required")
    return projection


def _validate_source_generation(generation, plan, source_files):
    if (
        not isinstance(generation, dict)
        or set(generation) != {"sourceCommit", "collectorSourceDigest", "sourceDigests"}
        or not isinstance(source_files, dict)
        or set(source_files) != set(SOURCE_PATHS)
        or set(generation.get("sourceDigests", {})) != set(SOURCE_PATHS.values())
        or generation.get("collectorSourceDigest") != plan.get("collectorSourceDigest")
        or not isinstance(generation.get("sourceCommit"), str)
        or not HEX40.fullmatch(generation["sourceCommit"])
    ):
        raise ValueError("exact historical source generation required")
    for path, name in SOURCE_PATHS.items():
        content = source_files[path]
        expected = generation["sourceDigests"].get(name)
        _require_hash(expected, f"historical source digest for {name}")
        if (
            not isinstance(content, bytes)
            or hashlib.sha256(content).hexdigest() != expected
        ):
            raise ValueError(f"historical source bytes differ for {path}")
    _require_hash(generation.get("collectorSourceDigest"), "collector source digest")


def _require_hash(value, label):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _finite_time(value, label):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be a finite nonnegative timestamp")


def _nonblank(value):
    return isinstance(value, str) and bool(value.strip())


_DOCUMENT_ROOT = "projects/fireemu-35fe6/databases/(default)/documents/"


def _get_operation(name):
    if not isinstance(name, str) or not (
        name == INDEX_READBACK_NAME or name.startswith(_DOCUMENT_ROOT)
    ):
        raise ValueError("canonical Firestore GET resource required")
    return {
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + name,
        "body": None,
        "privileged": True,
    }
