from __future__ import annotations

import copy
import hashlib
import platform
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))

import limits_03_held_recovery as recovery
from broad_contract import digest

CAMPAIGN = "FS-WRITE-LIMITS-03"
ROOT_NAME = "projects/fireemu-35fe6/databases/(default)/documents"
INDEX_NAME = "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*"
COMMIT = "a" * 40
SOURCE_PATHS = recovery.SOURCE_PATHS


def fixture(*, recovery_count=1):
    resources = [f"{ROOT_NAME}/owned/doc-{index:02}" for index in range(29)]
    source_files = {
        path: f"source:{name}".encode() for path, name in SOURCE_PATHS.items()
    }
    source_digests = {
        name: hashlib.sha256(source_files[path]).hexdigest()
        for path, name in SOURCE_PATHS.items()
    }
    nonce = "b" * 32
    plan = {
        "campaignId": CAMPAIGN,
        "nonce": nonce,
        "collectorSourceDigest": "c" * 64,
        "receiptKind": "limits-03-acquisition-receipt-v1",
        "transport": "fixed-production-wire",
        "dataRequests": 176,
        "jobs": {"limits": {"resources": resources}},
    }
    gate = {
        "plan": plan,
        "planDigest": digest(plan),
        "total": 1 + recovery_count,
        "managementUsed": ["observation:one"],
        "observation": 1,
        "recovery": recovery_count,
        "events": [],
        "jobs": {
            "limits": {
                "observation": 0,
                "recovery": recovery_count,
                "owned": [],
                "creationProofs": {},
                "absent": [],
                "scheduleDone": 0,
            }
        },
    }
    ticket = {
        "claimDigest": "d" * 64,
        "envelopeDigest": "e" * 64,
        "ledgerIdentity": "fixture-ledger",
        "ledgerPath": "/private/ledger",
        "reservation": "reservation-fixture",
    }
    receipt = {
        "kind": "limits-03-acquisition-receipt-v1",
        "campaignId": CAMPAIGN,
        "ticket": ticket,
        "claimDigest": ticket["claimDigest"],
        "planDigest": digest(plan),
        "gateDigest": digest(gate),
        "reservationStateAtPublication": "held",
        "releaseEligible": False,
        "productionExecuted": False,
        "failure": "ValueError",
        "generation": {
            "sourceCommit": COMMIT,
            "collectorSourceDigest": plan["collectorSourceDigest"],
            "sourceDigests": source_digests,
        },
        "indexExemption": {
            "precondition": {
                "readback": {
                    "projection": {
                        "name": INDEX_NAME,
                        "indexes": [{"queryScope": "COLLECTION"}],
                        "usesAncestorConfig": True,
                        "ancestorField": "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*",
                    }
                }
            }
        },
    }
    return receipt, gate, ticket, source_files, resources


def test_builds_fresh_non_authorizing_get_only_packet_for_29_owned_resources():
    receipt, gate, ticket, source_files, resources = fixture()

    packet = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="f" * 32,
        now=1000,
    )

    assert packet["authorized"] is False
    assert packet["requestLimit"] == 30
    assert packet["costLimitMicrousd"] == 3000
    assert packet["ledgerAction"] == "close_after_escalation"
    assert len(packet["requests"]) == 30
    assert {key: packet["requests"][0][key] for key in ("id", "method", "name")} == {
        "id": "index-readback",
        "method": "GET",
        "name": INDEX_NAME,
    }
    assert [request["name"] for request in packet["requests"][1:]] == resources
    assert all(request["method"] == "GET" for request in packet["requests"])
    assert packet["resourceDigest"] == digest(resources)
    gate_plan = packet["gatePlan"]
    child_job = gate_plan["jobs"]["limits-03-held-recovery"]
    assert gate_plan["transport"] == "limits-03-held-recovery-v1"
    assert gate_plan["receiptKind"] == "limits-03-held-recovery-receipt-v1"
    assert gate_plan["project"] == "fireemu-35fe6"
    assert gate_plan["database"] == "(default)"
    assert gate_plan["jobSlots"] == 1
    assert gate_plan["dataRequests"] == 30
    assert gate_plan["managementRequests"] == 0
    assert gate_plan["recoveryRequests"] == 0
    assert gate_plan["expectedIndexProjection"] == packet["indexBaselineProjection"]
    assert child_job["resources"] == resources
    assert len(child_job["observation"]) == 30
    assert child_job["observation"][0]["path"] == "/v1/" + INDEX_NAME
    assert child_job["recovery"] == []
    assert all(not entry["creates"] for entry in child_job["schedule"])


def test_compiled_gate_plan_is_accepted_by_the_real_shared_gate(tmp_path):
    receipt, gate, ticket, source_files, _resources = fixture()
    packet = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="f" * 32,
        now=1000,
    )
    gate_path = tmp_path / "recovery-gate"

    recovery.shared_gate.create(gate_path, packet["gatePlan"])
    registered = recovery.shared_gate.Gate(
        gate_path, "limits-03-held-recovery"
    ).snapshot()

    assert registered["planDigest"] == digest(packet["gatePlan"])
    assert registered["total"] == 0
    assert registered["reservedRecovery"] == 0


def test_compiles_offline_nested_child_claim_from_already_issued_refs(tmp_path):
    receipt, gate, ticket, source_files, resources = fixture()
    packet = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="f" * 32,
        now=1000,
    )
    scopes = [
        {"key": "project/fireemu-35fe6/firestore/(default)/collectionGroups/nx/fields/*", "mode": "READ"},
        *[
            {"key": "/".join(recovery.reservations._resource_scope(resource)), "mode": "READ"}
            for resource in resources
        ],
    ]
    scopes.sort(key=lambda item: item["key"])
    envelope = {
        "permissionDigest": "1" * 64,
        "issuedAt": 900,
        "expiresAt": 1800,
        "limits": {"requests": 30, "accounts": 0, "resources": 29, "costMicrousd": 3000},
        "concurrency": 1,
        "scopes": scopes,
    }
    child_generation = copy.deepcopy(packet["receiptGeneration"])
    child_generation["sourceCommit"] = "2" * 40
    bindings = {
        key: {"kind": f"limits-03-held-recovery-{key}-binding-v1", "digest": value * 64}
        for key, value in (("source", "3"), ("transport", "4"), ("o7", "5"), ("o8", "6"))
    }

    claim = recovery.compile_child_claim(
        packet,
        envelope=envelope,
        gate_path=str(tmp_path / "fresh-gate"),
        generation=child_generation,
        owner_identity="owner@example.test",
        recovery_owner="recovery@example.test",
        expires_at=1750,
        source_binding=bindings["source"],
        transport_binding=bindings["transport"],
        o7_binding=bindings["o7"],
        o8_binding=bindings["o8"],
        now=1000,
    )

    assert claim["kind"] == "limits-03-held-recovery-child-v1"
    assert claim["campaignId"] == claim["taskId"] == CAMPAIGN
    assert claim["gatePlanDigest"] == claim["manifestDigest"] == digest(packet["gatePlan"])
    assert claim["parentClaimDigest"] == ticket["claimDigest"]
    assert claim["parentPlanDigest"] == packet["planDigest"]
    assert claim["parentGateDigest"] == packet["gateDigest"]
    assert claim["parentReceiptDigest"] == packet["receiptDigest"]
    assert claim["durationSeconds"] == 750
    assert claim["locks"] == scopes
    assert claim["ownedResources"] == resources
    assert claim["budget"] == envelope["limits"]
    assert claim["sourceBindingDigest"] == "3" * 64
    assert claim["transportBindingDigest"] == "4" * 64
    assert claim["o7BindingDigest"] == "5" * 64
    assert claim["o8BindingDigest"] == "6" * 64


def test_child_claim_refuses_missing_permission_scope_or_parent_generation(tmp_path):
    receipt, gate, ticket, source_files, resources = fixture()
    packet = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="f" * 32,
        now=1000,
    )
    scopes = [
        {"key": "project/fireemu-35fe6/firestore/(default)/collectionGroups/nx/fields/*", "mode": "READ"},
        *[
            {"key": "/".join(recovery.reservations._resource_scope(resource)), "mode": "READ"}
            for resource in resources
        ],
    ]
    scopes.sort(key=lambda item: item["key"])
    envelope = {
        "permissionDigest": "1" * 64,
        "issuedAt": 900,
        "expiresAt": 1800,
        "limits": {"requests": 30, "accounts": 0, "resources": 29, "costMicrousd": 3000},
        "concurrency": 1,
        "scopes": scopes,
    }
    child_generation = copy.deepcopy(packet["receiptGeneration"])
    child_generation["sourceCommit"] = "2" * 40
    bindings = {
        key: {"kind": f"limits-03-held-recovery-{key}-binding-v1", "digest": value * 64}
        for key, value in (("source", "3"), ("transport", "4"), ("o7", "5"), ("o8", "6"))
    }
    common = {
        "envelope": envelope,
        "gate_path": str(tmp_path / "fresh-gate"),
        "generation": child_generation,
        "owner_identity": "owner@example.test",
        "recovery_owner": "recovery@example.test",
        "expires_at": 1750,
        "source_binding": bindings["source"],
        "transport_binding": bindings["transport"],
        "o7_binding": bindings["o7"],
        "o8_binding": bindings["o8"],
        "now": 1000,
    }

    with pytest.raises(ValueError, match="permission scopes"):
        recovery.compile_child_claim(packet, **{**common, "envelope": {**envelope, "scopes": scopes[:-1]}})
    with pytest.raises(ValueError, match="source generation"):
        recovery.compile_child_claim(packet, **{**common, "generation": packet["receiptGeneration"]})

    tampered_packet = copy.deepcopy(packet)
    tampered_packet["parentGateDigest"] = "9" * 64
    with pytest.raises(ValueError, match="packet digest"):
        recovery.compile_child_claim(tampered_packet, **common)


def test_rejects_integer_instead_of_boolean_for_index_projection():
    receipt, gate, ticket, source_files, _resources = fixture()
    receipt["indexExemption"]["precondition"]["readback"]["projection"][
        "usesAncestorConfig"
    ] = 1

    with pytest.raises(ValueError, match="typed historical nx index baseline"):
        recovery.prepare_packet(
            receipt,
            gate,
            ticket=ticket,
            source_files=source_files,
            ledger_root=ticket["ledgerPath"],
            recovery_nonce="f" * 32,
            now=1000,
        )


def test_rejects_stale_nonce_ticket_mismatch_and_source_digest_drift():
    receipt, gate, ticket, source_files, _resources = fixture()
    for mutation in ("stale-nonce", "ticket", "source"):
        changed_receipt = copy.deepcopy(receipt)
        changed_ticket = copy.deepcopy(ticket)
        changed_sources = dict(source_files)
        nonce = "f" * 32
        if mutation == "stale-nonce":
            nonce = gate["plan"]["nonce"]
        elif mutation == "ticket":
            changed_ticket["claimDigest"] = "9" * 64
        else:
            changed_sources[next(iter(SOURCE_PATHS))] = b"changed-source"
        with pytest.raises(ValueError):
            recovery.prepare_packet(
                changed_receipt,
                gate,
                ticket=changed_ticket,
                source_files=changed_sources,
                ledger_root=ticket["ledgerPath"],
                recovery_nonce=nonce,
                now=1000,
            )


def test_ledger_predicate_selects_no_data_or_escalation_without_local_heuristic():
    receipt, gate, ticket, source_files, _resources = fixture(recovery_count=0)
    gate["plan"]["management"] = {
        "observation": [{"id": "project"}],
        "credentialIds": [],
    }
    gate["planDigest"] = digest(gate["plan"])
    response = {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": {"projectId": "fireemu-35fe6"},
    }
    response_digest = digest(response)
    gate.update(
        total=1,
        managementUsed=["observation:project"],
        managementEvents=[
            {
                "id": "observation:project",
                "status": 200,
                "completed": True,
                "responseDigest": response_digest,
                "bodyDigest": digest(response["body"]),
            }
        ],
        observation=1,
        recovery=0,
        events=[],
        jobs={
            "limits": {
                "observation": 0,
                "recovery": 0,
                "owned": [],
                "creationProofs": {},
                "absent": [],
                "scheduleDone": 0,
            }
        },
    )
    receipt.update(
        planDigest=gate["planDigest"],
        gateDigest=digest(gate),
        managementEvidence=[
            {
                "id": "observation:project",
                "response": response,
                "responseDigest": response_digest,
            }
        ],
        credentialEvidence=[],
        metadata=[],
        mayHaveCreated=False,
        preflightComplete=False,
        postflightComplete=False,
        routeDigest=digest([]),
        collection=None,
    )
    no_data = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="f" * 32,
        now=1000,
    )
    assert no_data["ledgerAction"] == "abort_no_data"

    gate["recovery"] = 1
    gate["total"] = 2
    gate["jobs"]["limits"]["recovery"] = 1
    receipt["gateDigest"] = digest(gate)
    receipt["managementEvidence"] = [
        {
            "id": "observation:project",
            "response": response,
            "responseDigest": response_digest,
        }
    ]
    with_recovery = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="0" * 32,
        now=1000,
    )
    assert with_recovery["ledgerAction"] == "close_after_escalation"


def test_requires_exactly_typed_absence_and_fresh_index_get_result():
    receipt, gate, ticket, source_files, _resources = fixture(recovery_count=1)
    packet = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="f" * 32,
        now=1000,
    )
    results = [
        {
            "id": request["id"],
            "requestDigest": digest(request["operation"]),
            "status": 200 if request["id"] == "index-readback" else 404,
            "complete": True,
            "workerReaped": True,
            "observedAt": 1001,
            "body": (
                {
                    "name": INDEX_NAME,
                    "indexConfig": {
                        "indexes": [{"queryScope": "COLLECTION"}],
                        "usesAncestorConfig": True,
                        "ancestorField": "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*",
                    },
                    "ttlConfig": {},
                }
                if request["id"] == "index-readback"
                else {"error": {"code": 404, "status": "NOT_FOUND"}}
            ),
        }
        for request in packet["requests"]
    ]

    proof = recovery.validate_results(packet, results)
    assert proof["resourcesAbsent"] is True
    assert proof["indexReadbackRecorded"] is True
    assert proof["closureReady"] is True

    changed = copy.deepcopy(results)
    changed[1]["body"] = {"error": {"code": 404, "status": "PERMISSION_DENIED"}}
    with pytest.raises(ValueError):
        recovery.validate_results(packet, changed)

    missing = results[:-1]
    with pytest.raises(ValueError):
        recovery.validate_results(packet, missing)


def test_index_mismatch_and_stale_result_block_parent_closure():
    receipt, gate, ticket, source_files, _resources = fixture(recovery_count=1)
    packet = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="f" * 32,
        now=1000,
    )
    results = [
        {
            "id": request["id"],
            "requestDigest": digest(request["operation"]),
            "status": 200 if request["id"] == "index-readback" else 404,
            "complete": True,
            "workerReaped": True,
            "observedAt": 1001,
            "body": (
                {"name": "wrong-resource", "indexConfig": {}}
                if request["id"] == "index-readback"
                else {"error": {"code": 404, "status": "NOT_FOUND"}}
            ),
        }
        for request in packet["requests"]
    ]
    with pytest.raises(ValueError, match="index readback"):
        recovery.validate_results(packet, results)

    stale = copy.deepcopy(results)
    stale[0]["body"] = {
        "name": INDEX_NAME,
        "indexConfig": {
            "indexes": [{"queryScope": "COLLECTION"}],
            "usesAncestorConfig": True,
            "ancestorField": "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*",
        },
        "ttlConfig": {},
    }
    stale[0]["observedAt"] = 999
    with pytest.raises(ValueError, match="fresh"):
        recovery.validate_results(packet, stale)


def test_fresh_owner_attestation_binds_ticket_receipt_gate_and_all_resources():
    receipt, gate, ticket, source_files, _resources = fixture(recovery_count=1)
    packet = recovery.prepare_packet(
        receipt,
        gate,
        ticket=ticket,
        source_files=source_files,
        ledger_root=ticket["ledgerPath"],
        recovery_nonce="f" * 32,
        now=1000,
    )
    results = [
        {
            "id": request["id"],
            "requestDigest": digest(request["operation"]),
            "status": 200 if request["id"] == "index-readback" else 404,
            "complete": True,
            "workerReaped": True,
            "observedAt": 1001,
            "body": (
                {
                    "name": INDEX_NAME,
                    "indexConfig": {
                        "indexes": [{"queryScope": "COLLECTION"}],
                        "usesAncestorConfig": True,
                        "ancestorField": "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*",
                    },
                    "ttlConfig": {},
                }
                if request["id"] == "index-readback"
                else {"error": {"code": 404, "status": "NOT_FOUND"}}
            ),
        }
        for request in packet["requests"]
    ]
    attestation = {
        "kind": "owner-escalation-attestation-v1",
        "status": "attested",
        "campaignId": CAMPAIGN,
        "nonceDigest": packet["claimNonceDigest"],
        "claimDigest": ticket["claimDigest"],
        "ledgerRoot": packet["ledgerRoot"],
        "reservation": ticket["reservation"],
        "receiptDigest": packet["receiptDigest"],
        "gateDigest": packet["gateDigest"],
        "ownerIdentity": "owner-fixture",
        "recoveryOwner": "recovery-fixture",
        "residueRemoved": True,
        "resourceCount": 29,
        "resourcesDigest": packet["resourceDigest"],
        "attestedAt": 1001,
        "expiresAt": 2000,
        "executionHost": {
            "platform": platform.system().lower(),
            "machine": platform.machine(),
        },
    }

    validated = recovery.validate_attestation(
        packet,
        results,
        attestation,
        owner_identity="owner-fixture",
        recovery_owner="recovery-fixture",
        now=1002,
    )
    assert validated == {"attestationDigest": digest(attestation), "fresh": True}

    changed = copy.deepcopy(attestation)
    changed["resourcesDigest"] = "0" * 64
    with pytest.raises(ValueError, match="attestation"):
        recovery.validate_attestation(
            packet,
            results,
            changed,
            owner_identity="owner-fixture",
            recovery_owner="recovery-fixture",
            now=1002,
        )
