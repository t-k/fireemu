# ruff: noqa: I001 -- reservations bootstraps the shared module path.
"""Real filesystem/process tests of bounded shared admission; no production I/O."""

import multiprocessing
import copy
import hashlib
import json
import os
import platform
import re
import sys
from types import SimpleNamespace
import threading
import time
from pathlib import Path
from urllib.parse import quote

import pytest
import reservations
from reservations import (
    CATALOGUED_CAMPAIGN_IDS,
    COMMIT_COLLECTOR_SOURCE_DIGEST,
    COMMIT_SOURCE_COMMIT,
    COMMIT_SOURCE_DIGESTS,
    Ledger,
    conflicts,
)
from broad_contract import digest
from shared_gate import (
    Gate,
    _save,
    abandoned_cleanup_complete,
    create,
    unconfirmed_creates,
)
from shared_production import ProductionGate
import shared_production


def envelope():
    return {
        "permissionDigest": "a" * 64,
        "issuedAt": 1000,
        "expiresAt": 10000,
        "limits": {
            "requests": 100,
            "accounts": 10,
            "resources": 10,
            "costMicrousd": 10000,
        },
        "concurrency": 4,
        "scopes": [{"key": "project/p", "mode": "EXCLUSIVE"}],
    }


def _legacy_projection_fixture(monkeypatch):
    nonce = "0123456789abcdef0123456789abcdef"
    resource = f"projects/fireemu-35fe6/auth/accounts/custom-{nonce}"
    operation = {
        "service": "auth", "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
        "body": {"token": "$binding:customToken", "returnSecureToken": True},
        "form": False, "owner": False, "kind": "custom-sign-in", "account": "custom",
        "binds": {"customUid": "localId"}, "resource": resource,
    }
    plan = {
        "campaignId": "AUTH-CREDENTIAL-TOKENS-01", "project": "fireemu-35fe6", "nonce": nonce,
        "jobs": {"auth-credential": {"observation": [operation], "recovery": []}},
    }
    event = {
        "job": "auth-credential", "phase": "observation", "index": 0,
        "requestDigest": digest(operation), "service": "auth", "method": "POST",
        "completed": True, "creationOutcome": "refused", "status": 200,
        "responseDigest": digest({"response": "opaque"}), "ended": 999.0,
        "authEvidence": {"kind": "custom-sign-in", "account": "custom", "status": 200, "creationOutcome": "refused"},
    }
    gate = {
        "plan": plan, "planDigest": digest(plan), "coordinatorInflight": False,
        "jobs": {"auth-credential": {"inflight": False, "authAccounts": {}, "creationProofs": {}}},
        "events": [event],
    }
    child = {
        "parentClaimDigest": "d" * 64, "parentPlanDigest": digest(plan),
        "parentGateJob": "auth-credential", "parentEventIndex": 0,
        "parentRequestDigest": digest(operation), "ownedResources": [resource],
        "generation": {"sourceCommit": "1" * 40},
    }
    monkeypatch.setattr(reservations, "AUTH_RECOVERY_LEGACY_SOURCE_COMMIT", "1" * 40)
    monkeypatch.setattr(reservations, "AUTH_RECOVERY_LEGACY_CLAIM_DIGEST", "d" * 64)
    monkeypatch.setattr(reservations, "AUTH_RECOVERY_LEGACY_PLAN_DIGEST", digest(plan))
    monkeypatch.setattr(reservations, "AUTH_RECOVERY_LEGACY_GATE_DIGEST", digest(gate))
    monkeypatch.setattr(reservations, "AUTH_RECOVERY_LEGACY_EVENT_INDEX", 0)
    return gate, child, event


def test_legacy_auth_parent_projection_is_independent_and_typed(monkeypatch):
    gate, child, event = _legacy_projection_fixture(monkeypatch)
    projection = reservations._auth_parent_projection(gate, child)
    assert projection["kind"] == reservations.AUTH_RECOVERY_LEGACY_PARENT_EVIDENCE_KIND
    assert projection["completed"] is True
    assert projection["creationOutcome"] == "refused"
    assert projection["eventDigest"] == digest(event)
    assert projection["responseDigest"] == event["responseDigest"]
    reservations._auth_parent_evidence(projection)


@pytest.mark.parametrize("mutation", ["status", "duplicate", "claim", "route", "ownership"])
def test_legacy_auth_parent_projection_refuses_tampered_tuple(monkeypatch, mutation):
    gate, child, event = _legacy_projection_fixture(monkeypatch)
    operation = gate["plan"]["jobs"]["auth-credential"]["observation"][0]
    if mutation == "status":
        event["status"] = 201
    elif mutation == "duplicate":
        gate["events"].append(copy.deepcopy(event))
    elif mutation == "claim":
        child["parentClaimDigest"] = "e" * 64
    elif mutation == "route":
        operation["path"] = "identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
    else:
        gate["jobs"]["auth-credential"]["authAccounts"] = {"custom": {"resource": operation["resource"]}}
    with pytest.raises(ValueError):
        reservations._auth_parent_projection(gate, child)


def _request_bytes_recovery_shape(tmp_path, *, sentinel):
    lane = Path(__file__).resolve().parent.parent / "fs-request-bytes-boundary"
    if str(lane) not in sys.path:
        sys.path.insert(0, str(lane))
    import request_bytes_compiler as compiler
    import request_bytes_recovery_campaign as recovery

    nonce = ("a" if sentinel else "b") * 32
    parent = (
        compiler.compile_request_bytes_sentinel_plan(
            "fireemu-35fe6", "(default)", nonce
        )
        if sentinel
        else compiler.compile_request_bytes_plan("fireemu-35fe6", "(default)", nonce)
    )
    selected_probe = "raw-16mib-over" if sentinel else "under"
    recovery_nonce = ("c" if sentinel else "d") * 32
    recovery_plan = recovery.compile_recovery_plan(
        parent, selected_probe=selected_probe, recovery_nonce=recovery_nonce
    )
    gate_plan = recovery.compile_gate_plan(
        parent,
        selected_probe=selected_probe,
        recovery_nonce=recovery_nonce,
        recovery_plan=recovery_plan,
    )
    operations = gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"]
    resources = sorted({operation["resource"] for operation in operations})
    reads = sum(operation["kind"] == "recovery-inspection-read" for operation in operations)
    deletes = sum(operation["kind"] == "recovery-conditional-delete" for operation in operations)
    absences = sum(operation["kind"] == "recovery-absence-read" for operation in operations)
    child = {
        "kind": reservations.RECOVERY_CHILD_KIND,
        "version": 2,
        "campaignId": "FS-LIMIT-API-REQUEST-BYTES",
        "manifestDigest": digest(recovery_plan),
        "nonceDigest": digest(recovery_nonce),
        "gatePath": str((tmp_path / "recovery-gate").resolve()),
        "gatePlanDigest": digest(gate_plan),
        "locks": [{"key": "project/fireemu-35fe6/firestore/(default)/documents/oracle", "mode": "WRITE"}],
        "budget": {"requests": len(operations), "accounts": 0, "resources": len(resources), "costMicrousd": len(operations)},
        "durationSeconds": 1200,
        "generation": {
            "sourceCommit": "1" * 40,
            "collectorSourceDigest": digest("sources"),
            "sourceDigests": {"source.py": digest("source")},
        },
        "parentClaimDigest": "2" * 64,
        "parentPlanDigest": digest(parent),
        "recoveryNonce": recovery_nonce,
        "selectedProbe": selected_probe,
        "resourceDigest": digest(resources),
        "ownedResources": resources,
        "ownerIdentity": "offline-owner",
        "recoveryOwner": "offline-recovery-owner",
        "operationClass": reservations.RECOVERY_OPERATION_CLASS,
        "readCount": reads + absences,
        "inspectionCount": reads,
        "absenceCount": absences,
        "deleteCount": deletes,
        "tariffEstimateMicrousd": recovery_plan["bounds"]["tariffEstimateMicrousd"],
        "expiresAt": time.time() + 2000,
        "executionHost": {"platform": platform.system().lower(), "machine": platform.machine()},
        "permissionDigest": "3" * 64,
    }
    if sentinel:
        child["caseId"] = compiler.RAW_16MIB_OVER_CASE_ID
    return parent, recovery_plan, gate_plan, child


def _uncertain_request_bytes_parent(gate_path, gate_plan, parent_plan):
    create(gate_path, gate_plan)
    gates = {name: Gate(gate_path, name) for name in gate_plan["jobs"]}
    coordinator = next(iter(gates.values()))
    for entry in gate_plan["management"]["observation"]:
        body = None
        if entry["id"] == "oauth-tokeninfo":
            body = {
                "kind": "request-byte-token-attestation-v1",
                "principalDigest": "0" * 64,
                "requiredScopeVerified": True,
                "identityMode": "subject",
                "identityVerified": True,
                "oauthClientVerified": True,
                "expiresInSeconds": 3600,
                "remainingSecondsAtVerification": 3600,
                "requiredSeconds": 1700,
                "complete": True,
                "workerReaped": True,
            }
        coordinator.management_dispatch(
            "observation",
            entry["id"],
            lambda _deadline, body=body: {
                "status": 200,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json" if body is not None else "empty",
                "body": body,
            },
        )
    for gate in gates.values():
        gate.claim()
    job_name = next(
        name
        for name, job in gate_plan["jobs"].items()
        if any(operation.get("kind") == "conditional-create-commit" for operation in job["observation"])
    )
    gate = gates[job_name]
    operations = gate.snapshot()["plan"]["jobs"][job_name]["observation"]
    source = {
        (operation["kind"], operation.get("probe"), operation.get("resource")): operation
        for operation in parent_plan["observation"]
    }
    for operation in operations:
        if operation.get("kind") == "conditional-create-commit":
            materialized = copy.deepcopy(operation)
            materialized.pop("bodyRef", None)
            original = source[(operation["kind"], operation.get("probe"), operation.get("resource"))]
            materialized["body"] = copy.deepcopy(original["body"])
            try:
                gate.dispatch(
                    materialized,
                    False,
                    lambda: (_ for _ in ()).throw(TimeoutError("uncertain commit")),
                )
            except TimeoutError:
                gate.abandon_observation("transport-deadline")
            return
        gate.dispatch(
            operation,
            False,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )


def _real_request_bytes_recovery_child(tmp_path, *, sentinel):
    lane = Path(__file__).resolve().parent.parent / "fs-request-bytes-boundary"
    if str(lane) not in sys.path:
        sys.path.insert(0, str(lane))
    import request_bytes_admission as parent_admission
    import request_bytes_compiler as compiler
    import request_bytes_descriptor as parent_descriptor
    import request_bytes_production as parent_production
    import request_bytes_recovery_campaign as recovery
    from test_request_bytes_admission import Admission, owner_permission

    fixture = Admission(tmp_path / "owner")
    case_id = compiler.RAW_16MIB_OVER_CASE_ID if sentinel else None
    nonce = ("e" if sentinel else "f") * 32
    fixture.plan = parent_descriptor.plan_compiler(nonce, case_id=case_id)
    fixture.execution_plan = parent_descriptor.execution_plan(fixture.plan)
    fixture.permission = owner_permission(
        fixture.plan,
        fixture.commit,
        hashlib.sha256(fixture.artifact_path.read_bytes()).hexdigest(),
        parent_descriptor.source_map(),
        fixture.baseline,
    )
    if case_id is not None:
        fixture.permission["caseId"] = case_id
        fixture.permission["gateReservationSeconds"]["upload"] = (
            parent_descriptor.transport_deadline_seconds(case_id)
        )
    fixture.permission_path.write_text(json.dumps(fixture.permission))
    fixture.inputs = parent_admission.freeze_inputs(
        fixture.permission_path,
        fixture.plan,
        source_root=fixture.source,
        artifact_path=fixture.artifact_path,
        baseline=fixture.baseline,
    )
    parent_plan = (
        compiler.compile_request_bytes_sentinel_plan(
            parent_descriptor.PROJECT, parent_descriptor.DATABASE, nonce
        )
        if sentinel
        else compiler.compile_request_bytes_plan(
            parent_descriptor.PROJECT, parent_descriptor.DATABASE, nonce
        )
    )
    parent_gate_plan = parent_admission.gate_plan_for(fixture.inputs, fixture.permission)
    parent_path = (tmp_path / "parent-gate").resolve()
    parent_claim = parent_admission.reservation_claim(
        fixture.inputs, gate_path=parent_path, gate_plan=parent_gate_plan
    )
    ledger = Ledger.create(tmp_path / "ledger")
    parent_ticket = ledger.reserve(
        parent_production._envelope(fixture.permission, parent_claim),
        parent_claim,
        parent_gate_plan,
        generation=parent_admission.abort_generation(fixture.inputs),
        now=time.time(),
    )
    process = multiprocessing.Process(
        target=_uncertain_request_bytes_parent,
        args=(str(parent_path), parent_gate_plan, parent_plan),
    )
    process.start()
    process.join(30)
    assert process.exitcode == 0

    recovery_nonce = ("a" if sentinel else "b") * 32
    selected_probe = "raw-16mib-over" if sentinel else "under"
    recovery_plan = recovery.compile_recovery_plan(
        parent_plan, selected_probe=selected_probe, recovery_nonce=recovery_nonce
    )
    gate_plan = recovery.compile_gate_plan(
        parent_plan,
        selected_probe=selected_probe,
        recovery_nonce=recovery_nonce,
        recovery_plan=recovery_plan,
    )
    resources = sorted(
        {
            operation["resource"]
            for operation in gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"]
        }
    )
    child_permission = {"kind": "offline-recovery-permission-v1", "nonce": recovery_nonce}
    child_generation = copy.deepcopy(parent_admission.abort_generation(fixture.inputs))
    child_generation["collectorSourceDigest"] = digest("distinct recovery source closure")
    child_generation["sourceDigests"]["recovery.py"] = digest("recovery source")
    request_count = len(gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"])
    inspection_count = sum(
        operation["kind"] == "recovery-inspection-read"
        for operation in gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"]
    )
    delete_count = sum(
        operation["kind"] == "recovery-conditional-delete"
        for operation in gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"]
    )
    absence_count = sum(
        operation["kind"] == "recovery-absence-read"
        for operation in gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"]
    )
    child_budget = {"requests": request_count, "accounts": 0, "resources": len(resources), "costMicrousd": request_count}
    child_claim = {
        "kind": reservations.RECOVERY_CHILD_KIND,
        "version": 2,
        "campaignId": parent_descriptor.CAMPAIGN,
        "manifestDigest": digest(recovery_plan),
        "nonceDigest": digest(recovery_nonce),
        "gatePath": str((tmp_path / "child-gate").resolve()),
        "gatePlanDigest": digest(gate_plan),
        "locks": parent_claim["locks"],
        "budget": child_budget,
        "durationSeconds": 1200,
        "generation": child_generation,
        "parentClaimDigest": parent_ticket["claimDigest"],
        "parentPlanDigest": digest(parent_plan),
        "recoveryNonce": recovery_nonce,
        "selectedProbe": selected_probe,
        "resourceDigest": digest(resources),
        "ownedResources": resources,
        "ownerIdentity": "offline-child-owner",
        "recoveryOwner": "offline-recovery-owner",
        "operationClass": reservations.RECOVERY_OPERATION_CLASS,
        "readCount": inspection_count + absence_count,
        "inspectionCount": inspection_count,
        "absenceCount": absence_count,
        "deleteCount": delete_count,
        "tariffEstimateMicrousd": recovery_plan["bounds"]["tariffEstimateMicrousd"],
        "expiresAt": time.time() + 1800,
        "executionHost": {"platform": platform.system().lower(), "machine": platform.machine()},
        "permissionDigest": digest(child_permission),
    }
    if case_id is not None:
        child_claim["caseId"] = case_id
    child_envelope = {
        "permissionDigest": digest(child_permission),
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 1800,
        "limits": child_budget,
        "concurrency": 1,
        "scopes": parent_claim["locks"],
    }
    child_ticket = ledger.begin_recovery_extension(
        parent_ticket,
        child_claim,
        child_envelope,
        parent_plan,
        gate_plan,
        now=time.time(),
        canonical_parent_inputs=fixture.inputs,
        parent_permission=fixture.permission,
    )
    return (
        ledger,
        parent_ticket,
        child_ticket,
        parent_plan,
        gate_plan,
        fixture.inputs,
        fixture.permission,
        child_claim,
        child_envelope,
    )


def _settle_absent_recovery_child(ledger, child_ticket, parent_plan, gate_plan):
    class ResponseBoundGate(Gate):
        def _recovery_capture(self, operation, status, body):
            capture = super()._recovery_capture(operation, status, body)
            capture["responseDigest"] = digest(body)
            return capture

    bound = ledger.bound_recovery_claim(child_ticket)
    gate_path = bound["childClaim"]["gatePath"]
    create(gate_path, gate_plan)
    gate = ResponseBoundGate(gate_path, reservations.RECOVERY_GATE_JOB)
    gate.claim()
    plan_job = gate.snapshot()["plan"]["jobs"][reservations.RECOVERY_GATE_JOB]
    for operation in plan_job["recovery"]:
        request = copy.deepcopy(operation)
        request.pop("versionFrom", None)
        gate.dispatch(
            request,
            True,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
    gate.finish()
    return ledger.settle_recovery_child(
        child_ticket,
        receipt_digest=digest("offline typed-absence receipt"),
        canonical_parent_plan=parent_plan,
    )


def test_sentinel_recovery_claim_reserves_canonical_sixty_operations(tmp_path):
    parent, _recovery_plan, gate_plan, child = _request_bytes_recovery_shape(
        tmp_path, sentinel=True
    )

    reservations._recovery_child_claim(child)
    reservations._validate_recovery_gate_plan(parent, gate_plan, child)
    assert len(gate_plan["jobs"][reservations.RECOVERY_GATE_JOB]["recovery"]) == 60
    assert (child["inspectionCount"], child["deleteCount"], child["absenceCount"]) == (20, 20, 20)
    assert len(child["ownedResources"]) == 20
    assert len(gate_plan["jobs"][reservations.RECOVERY_GATE_JOB]["schedule"]) == 60


@pytest.mark.parametrize("sentinel,expected", [(False, (85, 17, 17, 51)), (True, (60, 20, 20, 20))])
def test_real_ledger_admits_canonical_recovery_child_shape(tmp_path, sentinel, expected):
    (
        ledger,
        _parent_ticket,
        child_ticket,
        _parent_plan,
        gate_plan,
        _parent_inputs,
        _parent_permission,
        _child_claim,
        _child_envelope,
    ) = _real_request_bytes_recovery_child(tmp_path, sentinel=sentinel)

    claim = ledger.bound_recovery_claim(child_ticket)["childClaim"]
    assert (
        claim["budget"]["requests"],
        claim["inspectionCount"],
        claim["deleteCount"],
        claim["absenceCount"],
    ) == expected
    assert ("caseId" in claim) is sentinel
    assert len(gate_plan["jobs"][reservations.RECOVERY_GATE_JOB]["recovery"]) == expected[0]


@pytest.mark.parametrize("sentinel", [False, True])
def test_real_ledger_settles_recovery_only_after_typed_absence(tmp_path, sentinel):
    (
        ledger,
        parent_ticket,
        child_ticket,
        parent_plan,
        gate_plan,
        _parent_inputs,
        _parent_permission,
        child_claim,
        _child_envelope,
    ) = _real_request_bytes_recovery_child(tmp_path, sentinel=sentinel)
    child_operations = gate_plan["jobs"][reservations.RECOVERY_GATE_JOB]["recovery"]
    assert len(child_operations) == (60 if sentinel else 85)
    settled = _settle_absent_recovery_child(ledger, child_ticket, parent_plan, gate_plan)

    assert settled == child_ticket
    assert ledger.bound_recovery_claim(child_ticket)["state"] == "settled"
    assert ledger.snapshot()["reservations"][parent_ticket["reservation"]]["state"] == "held"
    gate = Gate(child_claim["gatePath"], reservations.RECOVERY_GATE_JOB).snapshot()
    assert sorted(gate["jobs"][reservations.RECOVERY_GATE_JOB]["absent"]) == child_claim["ownedResources"]


def test_real_ledger_refuses_wrong_sentinel_case_plan_count_and_cost_without_mutation(tmp_path):
    (
        ledger,
        parent_ticket,
        _child_ticket,
        parent_plan,
        gate_plan,
        parent_inputs,
        parent_permission,
        child_claim,
        child_envelope,
    ) = _real_request_bytes_recovery_child(tmp_path, sentinel=True)
    before = ledger.snapshot()
    wrong_parent = copy.deepcopy(parent_plan)
    wrong_parent["caseId"] = "FS-LIMIT-API-REQUEST-BYTES-RAW-16MIB-UNDER"
    candidates = []
    wrong_case = copy.deepcopy(child_claim)
    wrong_case["caseId"] = "FS-LIMIT-API-REQUEST-BYTES-RAW-16MIB-UNDER"
    wrong_count = copy.deepcopy(child_claim)
    wrong_count["absenceCount"] = 51
    candidates.append((wrong_count, parent_plan, gate_plan))
    wrong_cost = copy.deepcopy(child_claim)
    wrong_cost["budget"]["costMicrousd"] = 85
    candidates.append((wrong_cost, parent_plan, gate_plan))
    wrong_requests = copy.deepcopy(child_claim)
    wrong_requests["budget"]["requests"] = 85
    candidates.append((wrong_requests, parent_plan, gate_plan))
    candidates.extend(
        [
            (wrong_case, parent_plan, gate_plan),
            (child_claim, wrong_parent, gate_plan),
        ]
    )

    for candidate, candidate_parent, candidate_gate in candidates:
        with pytest.raises(ValueError):
            ledger.begin_recovery_extension(
                parent_ticket,
                candidate,
                child_envelope,
                candidate_parent,
                candidate_gate,
                now=time.time(),
                canonical_parent_inputs=parent_inputs,
                parent_permission=parent_permission,
            )
        assert ledger.snapshot() == before


def test_real_ledger_does_not_settle_child_without_typed_absence_reads(tmp_path):
    (
        ledger,
        _parent_ticket,
        child_ticket,
        parent_plan,
        gate_plan,
        _parent_inputs,
        _parent_permission,
        child_claim,
        _child_envelope,
    ) = _real_request_bytes_recovery_child(tmp_path, sentinel=True)
    create(child_claim["gatePath"], gate_plan)
    Gate(child_claim["gatePath"], reservations.RECOVERY_GATE_JOB).claim()
    before = ledger.snapshot()

    with pytest.raises(ValueError, match="terminal evidence|typed absence"):
        ledger.settle_recovery_child(
            child_ticket,
            receipt_digest=digest("unproven recovery receipt"),
            canonical_parent_plan=parent_plan,
        )

    assert ledger.snapshot() == before


def test_sentinel_allocation_adds_to_existing_task_spend_without_resetting_cap():
    state = {
        "reservations": {
            "historical": {
                "claim": {
                    "campaignId": "FS-LIMIT-API-REQUEST-BYTES",
                    "budget": {"costMicrousd": 606},
                },
                "recoveryChildren": [],
            }
        }
    }

    assert reservations.task_budget_check(
        state, "FS-LIMIT-API-REQUEST-BYTES", reservations.RECOVERY_SENTINEL_COST_MICROUSD
    ) == 666


@pytest.mark.parametrize("mutation", ["case", "requests", "cost", "counts"])
def test_sentinel_recovery_claim_rejects_wrong_case_or_allocation_without_mutation(
    tmp_path, mutation
):
    _parent, _recovery_plan, _gate_plan, child = _request_bytes_recovery_shape(
        tmp_path, sentinel=True
    )
    if mutation == "case":
        child["caseId"] = "FS-LIMIT-API-REQUEST-BYTES-RAW-16MIB-UNDER"
    elif mutation == "requests":
        child["budget"]["requests"] = 85
    elif mutation == "cost":
        child["budget"]["costMicrousd"] = 85
    else:
        child["absenceCount"] = 51
    before = copy.deepcopy(child)

    with pytest.raises(ValueError):
        reservations._recovery_child_claim(child)

    assert child == before


def preparation_response(slot):
    from batch_contract import DATABASE_PROJECTION

    project = {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
    projection = {
        "name": "projects/fireemu-35fe6/databases/(default)", "uid": "fixture-database-uid",
        "databaseEdition": "STANDARD", "type": "FIRESTORE_NATIVE", "locationId": "us-central1",
    }
    parent = "projects/592603257417/locations/global"
    values = {
        "project": project,
        "database": {"projection": projection, "projectionDigest": digest({**projection, "concurrencyMode": "PESSIMISTIC"}), "identityProjectionDigest": digest(projection), "responseDigest": digest({**projection, "concurrencyMode": "PESSIMISTIC"}), "contractDigest": digest(DATABASE_PROJECTION)},
        "auth": {"name": "projects/592603257417/config"},
        "key": {"parent": parent, "name": parent + "/keys/fixture-key-id"},
    }
    if slot == "refresh":
        body = {"kind": "limits-03-preparation-refresh-v1", "expiresInSeconds": 1200, "authorizedUserDigest": digest("authorized-user")}
    elif slot == "oauth-tokeninfo":
        body = token_attestation()
    else:
        body = {"kind": "limits-03-preparation-metadata-v1", "slot": slot, "responseDigest": digest(values[slot]), "value": values[slot]}
        if slot == "database":
            body["responseDigest"] = values[slot]["responseDigest"]
    return {"status": 200, "complete": True, "workerReaped": True, "bodyKind": "json", "body": body}


def _preparation_worker(gate_path, gate_plan, queue, fail=False):
    create(gate_path, gate_plan)
    gate = Gate(gate_path, "limits")
    gate.claim()
    rows = []
    for slot in gate_plan["management"]["observation"]:
        response = preparation_response(slot["id"])
        if fail and slot["id"] == "key":
            response = {"status": None, "complete": False, "workerReaped": True, "bodyKind": None, "body": None}
        gate.management_dispatch("observation", slot["id"], lambda _deadline, response=response: response)
        rows.append({"id": "observation:" + slot["id"], "response": response, "responseDigest": digest(response)})
    if not fail:
        gate.finish()
    queue.put(rows)


def preparation_reservation(tmp_path):
    from test_shared_gate import limits_preparation_plan

    value = limits_preparation_plan()
    value["permissionDigest"] = "a" * 64
    now = time.time()
    value["permissionExpiresAt"] = now + value["wallSeconds"]
    permission = envelope()
    permission.update(issuedAt=now - 1, expiresAt=now + 600)
    row = {
        "campaignId": "FS-WRITE-LIMITS-03", "manifestDigest": digest("prep"),
        "nonceDigest": digest(value["nonce"]), "gatePath": str((tmp_path / "run" / "gate").resolve()),
        "gatePlanDigest": digest(value), "locks": [{"key": "project/p/config", "mode": "READ"}],
        "budget": {"requests": 6, "accounts": 0, "resources": 0, "costMicrousd": 600},
        "durationSeconds": value["wallSeconds"],
    }
    generation = {key: value[key] for key in ("sourceCommit", "collectorSourceDigest", "sourceDigests")}
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(permission, row, value, generation=generation, now=now)
    return ledger, ticket, row, value, generation


def preparation_terminal(tmp_path, *, fail=False):
    ledger, ticket, row, value, generation = preparation_reservation(tmp_path)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    child = context.Process(target=_preparation_worker, args=(row["gatePath"], value, queue, fail))
    child.start()
    rows = queue.get(timeout=15)
    child.join(15)
    assert child.exitcode == 0
    queue.close()
    gate = Gate(row["gatePath"], "limits").snapshot()
    collection = {
        "kind": "limits-03-baseline-preparation-v1", "campaignId": "FS-WRITE-LIMITS-03",
        "preparationId": value["nonce"], "nonce": value["nonce"], "permissionDigest": value["permissionDigest"],
        "sourceCommit": generation["sourceCommit"], "sourceDigest": generation["collectorSourceDigest"],
        "manifestDigest": digest("approved-manifest"), "ticketDigest": digest(ticket), "claimDigest": ticket["claimDigest"],
        "ownerIdentityDigest": digest("owner"), "principalDigest": token_attestation()["principalDigest"],
        "issuedAt": time.time() - 300, "expiresAt": value["permissionExpiresAt"],
        "slots": gate["managementUsed"], "evidence": gate["managementEvents"],
        "requestDigests": [digest({"slot": slot}) for slot in value["management"]["observation"]],
        "chargedCalls": 6, "costMicrousd": 600, "completed": True, "failed": False, "failureClass": None,
        "project": preparation_response("project")["body"]["value"],
        "database": preparation_response("database")["body"]["value"],
        "authConfigDigest": preparation_response("auth")["body"]["responseDigest"],
        "apiKey": preparation_response("key")["body"],
    }
    collection["packetDigest"] = digest(collection)
    receipt = {
        "kind": value["receiptKind"], "ticket": ticket, "claimDigest": ticket["claimDigest"],
        "planDigest": digest(value), "gateDigest": digest(gate), "generation": generation,
        "reservationStateAtPublication": "held", "executionKind": "fixed-production-wire",
        "releaseEligible": True, "failure": None, "chargedCalls": 6, "ownedResources": [],
        "collection": collection, "managementEvidence": rows,
    }
    path = Path(row["gatePath"]).parent / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "limits-03-baseline-preparation-release-v1", "ticket": ticket,
        "receiptPath": str(path), "receiptDigest": digest(receipt),
        "gateDigest": digest(gate), "collectionDigest": digest(receipt["collection"]),
        "generation": generation,
    }
    return ledger, ticket, record


def test_limits_preparation_terminal_releases_real_exited_worker_and_keeps_cost(tmp_path):
    ledger, ticket, record = preparation_terminal(tmp_path)
    ledger.attach_evidence(ticket, record["receiptDigest"], record["gateDigest"], record["collectionDigest"])
    result = ledger.finish_limits_preparation(ticket, record)
    assert result["state"] == "released"
    assert ledger.finish_limits_preparation(ticket, record) == result
    state = ledger.snapshot()
    assert state["reservations"][ticket["reservation"]]["claim"]["budget"]["costMicrousd"] == 600
    assert state["envelopes"][ticket["envelopeDigest"]]["allocated"]["costMicrousd"] == 600


@pytest.mark.parametrize("target", ["refresh", "oauth-tokeninfo", "project", "database", "auth", "key", "project-value", "database-projection", "auth-value", "key-value", "collection", "collection-project", "collection-database", "collection-event", "receipt"])
def test_limits_preparation_refuses_rebound_secret_fields_without_release(tmp_path, target):
    ledger, ticket, record = preparation_terminal(tmp_path)
    gate = Gate(ledger.bound_claim(ticket)["gatePath"], "limits")
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    with gate.locked() as state:
        if target == "receipt":
            destination = receipt
        elif target.startswith("collection"):
            destination = receipt["collection"]
            if target == "collection-project":
                destination = destination["project"]
            elif target == "collection-database":
                destination = destination["database"]["projection"]
            elif target == "collection-event":
                destination = destination["evidence"][0]
                state["managementEvents"][0]["access_token"] = "SECRET"
        else:
            slot = target.split("-", 1)[0] if target.endswith(("-value", "-projection")) else target
            index = next(index for index, row in enumerate(receipt["managementEvidence"]) if row["id"] == "observation:" + slot)
            item = receipt["managementEvidence"][index]
            destination = item["response"]["body"]
            if target.endswith("-value"):
                destination = destination["value"]
            elif target == "database-projection":
                destination = destination["value"]["projection"]
        destination["access_token"] = "SECRET"
        if not target.startswith("collection") and target != "receipt":
            item["responseDigest"] = digest(item["response"])
            state["managementEvents"][index]["responseDigest"] = item["responseDigest"]
            state["managementEvents"][index]["bodyDigest"] = digest(item["response"]["body"])
            receipt["collection"]["evidence"] = state["managementEvents"]
        _save(gate.path, state)
    receipt["gateDigest"] = digest(state)
    receipt["collection"]["packetDigest"] = digest({key: value for key, value in receipt["collection"].items() if key != "packetDigest"})
    path.write_text(json.dumps(receipt))
    record.update(receiptDigest=digest(receipt), gateDigest=digest(state), collectionDigest=digest(receipt["collection"]))
    ledger.attach_evidence(ticket, record["receiptDigest"], record["gateDigest"], record["collectionDigest"])
    before = ledger.snapshot()
    before_gate = gate.snapshot()
    with pytest.raises(ValueError):
        ledger.finish_limits_preparation(ticket, record)
    assert ledger.snapshot() == before
    assert gate.snapshot() == before_gate


def test_limits_preparation_dispatch_never_persists_raw_refresh_response(tmp_path):
    ledger, ticket, row, value, _generation = preparation_reservation(tmp_path)
    create(row["gatePath"], value)
    gate = Gate(row["gatePath"], "limits")
    gate.claim()
    response = preparation_response("refresh")
    response["body"]["access_token"] = "SECRET"
    with pytest.raises(ValueError, match="sanitized refresh"):
        gate.management_dispatch("observation", "refresh", lambda _deadline: response)
    state = gate.snapshot()
    assert state["total"] == 1
    assert state["managementEvents"][0]["completed"] is False
    assert "SECRET" not in (gate.path / "state.json").read_text()
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_limits_preparation_cannot_use_generic_finish(tmp_path):
    ledger, ticket, _record = preparation_terminal(tmp_path)
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("fault", [
    "live-worker", "unknown-worker", "unreaped", "partial", "http-error",
    "inflight", "data", "resource", "cost", "generation", "nonce", "deadline",
    "response", "receipt-kind", "unattached", "wrong-collection", "wrong-ticket", "late-event",
])
def test_limits_preparation_terminal_refusal_preserves_reservation(tmp_path, fault):
    ledger, ticket, record = preparation_terminal(tmp_path)
    row = ledger.bound_claim(ticket)
    gate = Gate(row["gatePath"], "limits")
    with gate.locked() as state:
        if fault == "live-worker":
            state["coordinatorPid"] = os.getpid()
        elif fault == "unknown-worker":
            state["coordinatorPid"] = None
        elif fault == "unreaped":
            state["managementEvents"][-1]["workerReaped"] = False
        elif fault == "partial":
            state["managementUsed"].pop()
            state["managementEvents"].pop()
        elif fault == "http-error":
            state["managementEvents"][-1]["status"] = 500
        elif fault == "inflight":
            state["coordinatorInflight"] = True
        elif fault == "data":
            state["events"].append({"phase": "observation"})
        elif fault == "resource":
            state["jobs"]["limits"]["owned"] = ["forged"]
        elif fault == "cost":
            state["costMicrousd"] = 500
        elif fault == "nonce":
            state["plan"]["nonce"] = "9" * 32
            state["planDigest"] = digest(state["plan"])
        elif fault == "deadline":
            state["plan"]["permissionExpiresAt"] += 100
            state["planDigest"] = digest(state["plan"])
        elif fault == "late-event":
            state["managementEvents"][-1]["ended"] = state["managementEvents"][-1]["deadline"] + 1
        _save(gate.path, state)
    record["gateDigest"] = digest(state)
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    receipt["gateDigest"] = record["gateDigest"]
    if fault == "generation":
        record["generation"]["collectorSourceDigest"] = "f" * 64
        receipt["generation"] = record["generation"]
    elif fault == "response":
        receipt["managementEvidence"][-1]["response"]["body"] = {"forged": True}
        receipt["managementEvidence"][-1]["responseDigest"] = digest(receipt["managementEvidence"][-1]["response"])
    elif fault == "receipt-kind":
        receipt["kind"] = "limits-03-production-receipt-v1"
    elif fault == "wrong-collection":
        receipt["collection"] = {"forged": True}
    elif fault == "wrong-ticket":
        receipt["ticket"] = {**ticket, "reservation": "0" * 64}
    path.write_text(json.dumps(receipt))
    record["receiptDigest"] = digest(receipt)
    if fault != "unattached":
        ledger.attach_evidence(ticket, record["receiptDigest"], record["gateDigest"], record["collectionDigest"])
    before = ledger.snapshot()
    before_gate = (gate.path / "state.json").read_bytes()
    with pytest.raises(ValueError):
        ledger.finish_limits_preparation(ticket, record)
    assert ledger.snapshot() == before
    assert (gate.path / "state.json").read_bytes() == before_gate


def preparation_failure_terminal(tmp_path):
    ledger, ticket, release_record = preparation_terminal(tmp_path, fail=True)
    row = ledger.bound_claim(ticket)
    gate = Gate(row["gatePath"], "limits").snapshot()
    path = Path(release_record["receiptPath"])
    old_receipt = json.loads(path.read_text())
    responses = [(item["id"], item["response"]) for item in old_receipt["managementEvidence"]]
    receipt = request_bytes_receipt(
        gate, ticket, row["gatePlanDigest"], responses,
        kind="limits-03-baseline-preparation-receipt-v1",
        generation=release_record["generation"], failure="WorkerTimeout",
        credentialEvidence=[response["body"] for identity, response in responses if identity == "observation:oauth-tokeninfo"],
    )
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1", "ticket": ticket,
        "planDigest": row["gatePlanDigest"], "gateDigest": digest(gate),
        "receiptPath": str(path), "receiptDigest": digest(receipt), **release_record["generation"],
    }
    return ledger, ticket, record


def test_limits_preparation_real_failure_uses_truthful_no_data_abort(tmp_path):
    ledger, ticket, record = preparation_failure_terminal(tmp_path)
    ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "aborted-no-data"
    assert ledger.snapshot()["envelopes"][ticket["envelopeDigest"]]["allocated"]["costMicrousd"] == 600


@pytest.mark.parametrize("fault", ["unreaped", "live-worker", "missing-worker", "false-failure"])
def test_limits_preparation_failed_unknown_worker_retains_held_state(tmp_path, fault):
    ledger, ticket, record = preparation_failure_terminal(tmp_path)
    gate = Gate(ledger.bound_claim(ticket)["gatePath"], "limits")
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    with gate.locked() as state:
        if fault == "unreaped":
            state["coordinatorInflight"] = True
            state["managementEvents"][-1]["workerReaped"] = False
            item = receipt["managementEvidence"][-1]
            item["response"]["workerReaped"] = False
            item["responseDigest"] = digest(item["response"])
            state["managementEvents"][-1]["responseDigest"] = item["responseDigest"]
        elif fault == "live-worker":
            state["coordinatorPid"] = os.getpid()
        elif fault == "missing-worker":
            state["coordinatorPid"] = None
        else:
            receipt["failure"] = None
        _save(gate.path, state)
    receipt["gateDigest"] = digest(state)
    record["gateDigest"] = digest(state)
    record["receiptDigest"] = digest(receipt)
    path.write_text(json.dumps(receipt))
    before = ledger.snapshot()
    gate_before = gate.snapshot()
    with pytest.raises(ValueError):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot() == before
    assert gate.snapshot() == gate_before


@pytest.mark.parametrize("fault", ["campaign", "resources", "requests", "generation", "lock", "deadline", "slot"])
def test_limits_preparation_reservation_is_exact_and_atomic(tmp_path, fault):
    _ledger, _ticket, row, value, generation = preparation_reservation(tmp_path)
    fresh = Ledger.create(tmp_path / "fresh-ledger")
    permission = envelope()
    permission.update(issuedAt=time.time() - 1, expiresAt=time.time() + 600)
    if fault == "campaign":
        row["campaignId"] = "FS-DATA-WRITE-LIMITS-02"
    elif fault == "resources":
        row["budget"]["resources"] = 1
    elif fault == "requests":
        row["budget"]["requests"] = 7
    elif fault == "generation":
        generation["sourceCommit"] = "f" * 40
    elif fault == "lock":
        row["locks"][0]["mode"] = "WRITE"
    elif fault == "deadline":
        value["permissionExpiresAt"] += 600
    elif fault == "slot":
        value["management"]["observation"][-1]["id"] = "apply"
    row["gatePlanDigest"] = digest(value)
    before = fresh.snapshot()
    with pytest.raises(ValueError):
        fresh.reserve(permission, row, value, generation=generation)
    assert fresh.snapshot() == before


def test_limits_preparation_released_nonce_cannot_be_reused(tmp_path):
    ledger, ticket, record = preparation_terminal(tmp_path)
    ledger.attach_evidence(ticket, record["receiptDigest"], record["gateDigest"], record["collectionDigest"])
    ledger.finish_limits_preparation(ticket, record)
    row = ledger.bound_claim(ticket)
    value = Gate(row["gatePath"], "limits").snapshot()["plan"]
    row["gatePath"] = str((tmp_path / "replayed-gate").resolve())
    permission = envelope()
    permission.update(issuedAt=time.time() - 1, expiresAt=time.time() + 600, permissionDigest="e" * 64)
    value["permissionDigest"] = permission["permissionDigest"]
    row["gatePlanDigest"] = digest(value)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="reuse"):
        ledger.reserve(permission, row, value, generation=record["generation"])
    assert ledger.snapshot() == before


def test_limits_preparation_and_final_observation_share_one_dollar_cap(tmp_path):
    ledger, ticket, record = preparation_terminal(tmp_path)
    ledger.attach_evidence(ticket, record["receiptDigest"], record["gateDigest"], record["collectionDigest"])
    ledger.finish_limits_preparation(ticket, record)
    final_plan = plan("b")
    final_claim = claim(tmp_path, "b")
    final_claim["campaignId"] = "FS-WRITE-LIMITS-03"
    final_claim["budget"]["costMicrousd"] = 999_401
    permission = envelope()
    permission["permissionDigest"] = "e" * 64
    permission["limits"]["costMicrousd"] = 2_000_000
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="task-budget-exceeded"):
        ledger.reserve(permission, final_claim, final_plan, now=1100)
    assert ledger.snapshot() == before
    final_claim["budget"]["costMicrousd"] = 999_400
    ledger.reserve(permission, final_claim, final_plan, now=1100)
    retry_plan = plan("c")
    retry_claim = claim(tmp_path, "c")
    retry_claim["campaignId"] = "FS-WRITE-LIMITS-03"
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="task-budget-exceeded"):
        ledger.reserve(permission, retry_claim, retry_plan, now=1100)
    assert ledger.snapshot() == before
    from reservations import task_budget_check
    with pytest.raises(ValueError, match="task-budget-exceeded"):
        task_budget_check(before, "FS-WRITE-LIMITS-03", 1)


def plan(label="a"):
    operation = {
        "service": "firestore",
        "method": "GET",
        "path": f"/v1/projects/p/databases/(default)/documents/owned/{label}",
        "body": None,
        "privileged": True,
    }
    return {
        "contract": "shared-local-v2",
        "nonce": digest(label)[:32],
        "wallSeconds": 100,
        "recoverySeconds": 40,
        "intervalSeconds": 0.25,
        "observationRequests": 0,
        "requestCostMicrousd": 1,
        "costMicrousd": 10,
        "jobs": {
            "limits": {
                "observation": [],
                "recovery": [operation],
                "resources": [operation["path"].removeprefix("/v1/")],
            }
        },
    }


# Fixture labels stand for catalogued tasks: `reserve` refuses any other id.
TASKS = {
    "a": "FS-DATA-WRITE-LIMITS-02",
    "b": "FS-DATA-WRITE-COMMIT-TRANSFORMS-03",
    "c": "FS-LIMIT-API-REQUEST-BYTES",
}


def claim(tmp_path, label, locks=None):
    owned = {
        "key": f"project/p/firestore/(default)/documents/owned/{label}",
        "mode": "WRITE",
    }
    locks = list(locks or [])
    if owned not in locks:
        locks.append(owned)
    return {
        "campaignId": TASKS[label],
        "manifestDigest": digest(label),
        "nonceDigest": digest(plan(label)["nonce"]),
        "gatePath": str((tmp_path / label).resolve()),
        "gatePlanDigest": digest(plan(label)),
        "locks": locks,
        "budget": {"requests": 2, "accounts": 0, "resources": 1, "costMicrousd": 10},
        "durationSeconds": 100,
    }


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (("project/p/config", "READ"), ("project/p/config/policy", "READ"), False),
        (("project/p/config", "WRITE"), ("project/p/config/policy", "READ"), True),
        (("project/p/config", "READ"), ("project/p/config/policy", "WRITE"), True),
        (("project/p/data/a/*", "EXCLUSIVE"), ("project/p/data/a/doc", "READ"), True),
        (("project/p/data/a", "WRITE"), ("project/p/data/ab", "WRITE"), False),
        (("project/p/data/a", "WRITE"), ("project/q/data/a", "WRITE"), False),
    ],
)
def test_segment_aware_lock_conflicts(left, right, expected):
    assert (
        conflicts(
            {"key": left[0], "mode": left[1]}, {"key": right[0], "mode": right[1]}
        )
        is expected
    )


def test_auth_config_resource_maps_to_exact_write_leaf():
    assert reservations._resource_scope("projects/p/auth/config") == (
        "project",
        "p",
        "auth",
        "config",
    )


@pytest.mark.parametrize(
    "resource",
    [
        "projects/p/auth",
        "projects/p/auth/config/extra",
        "projects//auth/config",
        "projects/./auth/config",
        "projects/../auth/config",
        "projects/p/auth/config/",
        "projects/p/authentication/config",
        "projects/p/auth/unknown",
    ],
)
def test_unknown_or_malformed_auth_resource_refused(resource):
    with pytest.raises(ValueError):
        reservations._resource_scope(resource)


def test_auth_config_scope_preserves_auth_account_and_firestore_boundaries():
    config = reservations._resource_scope("projects/p/auth/config")
    account = reservations._resource_scope("projects/p/auth/accounts/user-1")
    other_project_config = reservations._resource_scope("projects/q/auth/config")
    firestore = reservations._resource_scope(
        "projects/p/databases/(default)/documents/owned/user-1"
    )

    assert account == ("project", "p", "auth", "accounts", "user-1")
    assert firestore == (
        "project",
        "p",
        "firestore",
        "(default)",
        "documents",
        "owned",
        "user-1",
    )
    config_lock = {"key": "/".join(config), "mode": "WRITE"}
    account_lock = {"key": "/".join(account), "mode": "WRITE"}
    other_project_lock = {"key": "/".join(other_project_config), "mode": "WRITE"}
    firestore_lock = {"key": "/".join(firestore), "mode": "WRITE"}
    auth_ancestor = {"key": "project/p/auth", "mode": "WRITE"}

    assert not conflicts(config_lock, account_lock)
    assert not conflicts(config_lock, other_project_lock)
    assert not conflicts(config_lock, firestore_lock)
    assert conflicts(auth_ancestor, config_lock)
    assert conflicts(auth_ancestor, account_lock)


@pytest.mark.parametrize(
    "key",
    [
        "project/p//data",
        "project/p/../data",
        "project/p/data%2Fa",
        "project/p/*/a",
        "/project/p/data",
        "project/p/data/",
    ],
)
def test_ambiguous_scope_refused_without_mutation(tmp_path, key):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(),
            claim(tmp_path, "a", [{"key": key, "mode": "READ"}]),
            plan(),
            now=1100,
        )
    assert ledger.snapshot() == before


def test_atomic_capacity_and_cross_envelope_conflicts(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a", [{"key": "project/p/config", "mode": "WRITE"}])
    ledger.reserve(envelope(), first, plan(), now=1100)
    before = ledger.snapshot()
    other = envelope()
    other["permissionDigest"] = "b" * 64
    with pytest.raises(ValueError):
        ledger.reserve(
            other,
            claim(tmp_path, "b", [{"key": "project/p/config/policy", "mode": "READ"}]),
            plan("b"),
            now=1100,
        )
    assert ledger.snapshot() == before
    too_large = claim(tmp_path, "c")
    too_large["budget"]["accounts"] = 11
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), too_large, plan("c"), now=1100)
    assert ledger.snapshot() == before


def test_expiry_never_releases_locks_and_nonce_is_never_reused(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    with pytest.raises(ValueError):
        ledger.validate(ticket, now=1201)
    second = claim(tmp_path, "b", first["locks"])
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), second, plan("b"), now=1201)
    second["locks"] = [
        {"key": "project/p/data/b", "mode": "WRITE"},
        {
            "key": "project/p/firestore/(default)/documents/owned/a",
            "mode": "WRITE",
        },
    ]
    second["nonceDigest"] = first["nonceDigest"]
    second["gatePlanDigest"] = first["gatePlanDigest"]
    with pytest.raises(ValueError, match="reuse"):
        ledger.reserve(envelope(), second, plan("a"), now=1201)


def test_cleanup_releases_scope_but_never_returns_budget(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    operation = plan()["jobs"]["limits"]["recovery"][0]
    gate.dispatch(
        operation, True, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    gate.finish()
    ledger.finish(ticket)
    state = ledger.snapshot()
    assert state["envelopes"][digest(envelope())]["allocated"] == first["budget"]
    with pytest.raises(ValueError):
        ledger.validate(ticket, now=1110)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    ledger.reserve(
        envelope(), claim(tmp_path, "b", first["locks"]), plan("b"), now=1110
    )


def _stopped_pid():
    child = multiprocessing.get_context("spawn").Process(target=time.sleep, args=(0,))
    child.start()
    pid = child.pid
    child.join(timeout=10)
    assert child.exitcode == 0
    return pid


def generation(label="9"):
    """A source closure of a later generation than the recorded legacy one."""
    return {
        "sourceCommit": digest(f"commit-{label}")[:40],
        "collectorSourceDigest": digest(f"collector-{label}"),
        "sourceDigests": {
            name: digest(f"{name}-{label}") for name in COMMIT_SOURCE_DIGESTS
        },
    }


# The preflight the production adapter actually issues: two credential slots,
# then four privileged metadata GETs.
CREDENTIAL_SLOTS = ("oauth-refresh", "oauth-tokeninfo")
PREFLIGHT = ("project", "database", "auth", "key")


def _no_data_attempt(
    tmp_path, source_generation=None, stop=2, mode="decision", kind=None
):
    """One failed attempt that stopped at preflight slot `stop` with no data sent.

    `mode` is "decision" when the request was sent and its evidence appended
    before the baseline comparison failed, and "transport" when the slot was
    consumed but no evidence could be appended.
    """
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    frozen = plan()
    frozen["collectorSourceDigest"] = (
        COMMIT_COLLECTOR_SOURCE_DIGEST
        if source_generation is None
        else source_generation["collectorSourceDigest"]
    )
    frozen["observationRequests"] = 17
    frozen["management"] = {
        "observation": [
            {"id": name, "timeout": 13, "duration": 12}
            for name in (*CREDENTIAL_SLOTS, *PREFLIGHT)
        ],
        "recovery": [],
    }
    if kind is not None:
        frozen["receiptKind"] = kind
    used = [f"observation:{name}" for name in (*CREDENTIAL_SLOTS, *PREFLIGHT[:stop])]
    observed = PREFLIGHT[: stop if mode == "decision" else stop - 1]
    first["gatePlanDigest"] = digest(frozen)
    first["budget"]["requests"] = 27
    ticket = ledger.reserve(
        envelope(), first, frozen, generation=source_generation, now=1100
    )
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], "limits")
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        state["jobs"]["limits"]["pid"] = state["coordinatorPid"]
        state["total"] = len(used)
        state["observation"] = len(used)
        state["costMicrousd"] = len(used)
        state["managementUsed"] = used
        state["managementEvents"] = [
            {"id": item, "started": index, "durationReserved": 12}
            for index, item in enumerate(state["managementUsed"])
        ]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt = {
        "kind": "commit-acquisition-receipt-v2" if kind is None else kind,
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "claimDigest": ticket["claimDigest"],
        "gate": snapshot,
        "chargedCalls": len(used),
        "collection": None,
        "productionExecuted": False,
        "failure": "ValueError",
        "releaseEligible": False,
        "reservationStateAtPublication": "held",
        "executionKind": "fixed-production-wire",
        "metadata": [{"id": f"observation:{name}", "status": 200} for name in observed],
        "credentialEvidence": [
            {
                "slot": "refresh",
                "workerReaped": True,
                "complete": True,
                "verified": True,
                "status": 200,
            },
            {
                "slot": "tokeninfo",
                "workerReaped": True,
                "complete": True,
                "verified": True,
                "status": 200,
            },
        ],
    }
    if source_generation is not None:
        # A receipt written before the generation binding existed carries none,
        # which is what the legacy branch of this helper reproduces.
        receipt["generation"] = source_generation
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": frozen["collectorSourceDigest"],
        "sourceCommit": COMMIT_SOURCE_COMMIT
        if source_generation is None
        else source_generation["sourceCommit"],
        "sourceDigests": COMMIT_SOURCE_DIGESTS
        if source_generation is None
        else source_generation["sourceDigests"],
    }
    return ledger, gate, ticket, record


def test_no_data_abort_releases_only_lock_and_keeps_budget_and_nonce(tmp_path):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    ledger.abort_no_data(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert row["abortRecordDigest"] == digest(record)
    assert gate.snapshot()["stopped"] is True
    with pytest.raises(ValueError):
        gate.dispatch(plan()["jobs"]["limits"]["recovery"][0], True, lambda: None)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        gate.claim()
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        gate.coordinator_call(0, lambda: None)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        gate.stop(environment=True)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        gate.finish()
    assert row["finalGateDigest"] == digest(gate.snapshot())
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["envelopes"][digest(envelope())]["allocated"]
        == row["claim"]["budget"]
    )
    ledger.reserve(
        envelope(),
        claim(tmp_path, "b", claim(tmp_path, "a")["locks"]),
        plan("b"),
        now=1110,
    )
    reuse = claim(tmp_path, "a")
    reuse["gatePath"] = str((tmp_path / "other-gate").resolve())
    with pytest.raises(ValueError, match="reuse"):
        ledger.reserve(envelope(), reuse, plan(), now=1110)


@pytest.mark.parametrize("stop", [1, 2, 3, 4])
@pytest.mark.parametrize("mode", ["decision", "transport"])
def test_no_data_abort_accepts_every_preflight_stop_point(tmp_path, stop, mode):
    """Any preflight gate can stop an attempt, and all four are retirable.

    The evidence contract used to admit exactly one stop point, which left an
    attempt that reached the auth or API-key gate with no documented retirement.
    """
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, stop=stop, mode=mode)
    ledger.abort_no_data(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert gate.snapshot()["stopped"] is True


@pytest.mark.parametrize(
    "ids",
    [
        ["observation:database"],
        ["observation:database", "observation:project"],
        ["observation:project", "observation:auth"],
        ["observation:project", "observation:database", "observation:key"],
        [
            "observation:project",
            "observation:database",
            "observation:auth",
            "observation:key",
        ],
        [],
    ],
    ids=[
        "wrong-first",
        "reordered",
        "skips-database",
        "skips-auth",
        "too-many",
        "none",
    ],
)
def test_no_data_abort_refuses_metadata_that_is_not_a_preflight_prefix(tmp_path, ids):
    """Only a prefix of the declared preflight sequence proves where it stopped."""
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path, stop=3)
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    receipt["metadata"] = [{"id": name, "status": 200} for name in ids]
    path.write_text(json.dumps(receipt))
    record = {**record, "receiptDigest": digest(receipt)}
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


@pytest.mark.parametrize(
    "damage",
    [
        {"gate": {"total": 6}},
        {"gate": {"observation": 4}},
        {"gate": {"recovery": 1}},
        {"job": {"observation": 1}},
        {"job": {"recovery": 1}},
        {"job": {"owned": ["projects/p/databases/(default)/documents/owned/a"]}},
        {"job": {"creationProofs": {"a": {"name": "a"}}}},
        {"job": {"absent": ["a"]}},
    ],
    ids=[
        "charged-more-than-used",
        "observation-count",
        "recovery-count",
        "job-observation",
        "job-recovery",
        "job-owned",
        "job-creation-proof",
        "job-absent",
    ],
)
def test_no_data_abort_refuses_a_receipt_that_shows_dispatched_data(tmp_path, damage):
    """The contract must say "no data left this run", not merely "it stopped early"."""
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, stop=3)
    with gate.locked() as state:
        state.update(damage.get("gate", {}))
        for job in state["jobs"].values():
            job.update(damage.get("job", {}))
        _save(gate.path, state)
    snapshot = gate.snapshot()
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    receipt["gate"] = snapshot
    if "total" in damage.get("gate", {}):
        receipt["chargedCalls"] = snapshot["total"]
    path.write_text(json.dumps(receipt))
    record = {
        **record,
        "receiptDigest": digest(receipt),
        "gateDigest": digest(snapshot),
    }
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_no_data_abort_requires_the_receipt_to_bind_the_recorded_generation(tmp_path):
    """A row that recorded a generation is retired only by a receipt naming it."""
    source = generation("later")
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path, source, stop=3)
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    del receipt["generation"]
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="recorded generation"):
        ledger.abort_no_data(ticket, {**record, "receiptDigest": digest(receipt)})
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_no_data_abort_retires_a_reservation_of_a_later_generation(tmp_path):
    later = generation()
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, later)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["generation"] == (
        later
    )
    ledger.abort_no_data(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert row["abortRecordDigest"] == digest(record)
    assert gate.snapshot()["stopped"] is True
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )


def test_no_data_abort_refuses_a_receipt_naming_another_generation(tmp_path):
    """A receipt that records a closure must record the one being proven."""
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, generation())
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["generation"] = generation("10")
    receipt_path.write_text(json.dumps(receipt))
    record = {**record, "receiptDigest": digest(receipt)}
    with pytest.raises(ValueError, match="recorded generation"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    assert gate.snapshot()["stopped"] is False


def test_no_data_abort_refuses_a_generation_the_reservation_never_recorded(tmp_path):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, generation())
    other = generation("10")
    for field, value in (
        ("sourceCommit", other["sourceCommit"]),
        ("sourceDigests", other["sourceDigests"]),
        ("sourceCommit", COMMIT_SOURCE_COMMIT),
        ("sourceDigests", COMMIT_SOURCE_DIGESTS),
    ):
        with pytest.raises(ValueError, match="source closure"):
            ledger.abort_no_data(ticket, {**record, field: value})
        assert (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
        )
    assert gate.snapshot()["stopped"] is False


def test_no_data_abort_of_a_reservation_without_a_generation_stays_on_the_legacy_one(
    tmp_path,
):
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path)
    assert "generation" not in ledger.snapshot()["reservations"][ticket["reservation"]]
    later = generation()
    with pytest.raises(ValueError, match="source closure"):
        ledger.abort_no_data(ticket, {**record, "sourceCommit": later["sourceCommit"]})
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )


@pytest.mark.parametrize(
    "damage",
    [
        {"sourceCommit": "not-a-commit"},
        {"sourceCommit": "A" * 40},
        {"collectorSourceDigest": "0" * 63},
        {"sourceDigests": {}},
        {"sourceDigests": {"shared_gate.py": "0" * 63}},
        {"sourceDigests": {"../shared_gate.py": "0" * 64}},
        {"sourceDigests": ["shared_gate.py"]},
        {"extra": "field"},
    ],
)
def test_reserve_refuses_a_malformed_generation_without_mutation(tmp_path, damage):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(),
            claim(tmp_path, "a"),
            plan(),
            generation={**generation(), **damage},
            now=1100,
        )
    assert ledger.snapshot() == before


def test_recorded_generation_is_revalidated_when_the_ledger_is_read(tmp_path):
    ledger, _gate, ticket, _record = _no_data_attempt(tmp_path, generation())
    state = json.loads((ledger.path / "state.json").read_text())
    state["reservations"][ticket["reservation"]]["generation"]["sourceCommit"] = "0"
    (ledger.path / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="frozen source commit"):
        ledger.snapshot()


@pytest.mark.parametrize(
    "damage",
    [
        "event",
        "counter",
        "inflight",
        "owned",
        "proof",
        "live-worker",
        "management",
        "cost",
    ],
)
def test_no_data_abort_rejects_positive_or_uncertain_data(tmp_path, damage):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    with gate.locked() as state:
        job = state["jobs"]["limits"]
        if damage == "event":
            state["events"].append({"completed": False})
        elif damage == "counter":
            job["observation"] = 1
        elif damage == "inflight":
            job["inflight"] = True
        elif damage == "owned":
            job["owned"].append(job["resources"][0])
        elif damage == "proof":
            job["creationProofs"][job["resources"][0]] = {}
        elif damage == "management":
            state["managementEvents"].pop()
        elif damage == "cost":
            state["costMicrousd"] += 1
        else:
            job["pid"] = os.getpid()
        _save(gate.path, state)
    with pytest.raises(ValueError):
        ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        != "aborted-no-data"
    )


@pytest.mark.parametrize(
    "damage", ["receipt", "ticket", "source", "gate", "missing-gate"]
)
def test_no_data_abort_rejects_changed_binding(tmp_path, damage):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    record = dict(record)
    if damage == "receipt":
        Path(record["receiptPath"]).write_text("{}")
    elif damage == "ticket":
        record["ticket"] = {**ticket, "reservation": "0" * 64}
    elif damage == "source":
        record["collectorSourceDigest"] = "0" * 64
    elif damage == "gate":
        record["gateDigest"] = "0" * 64
    else:
        (gate.path / "state.json").unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        != "aborted-no-data"
    )


@pytest.mark.parametrize("gate_stopped", [False, True])
def test_no_data_abort_recovers_closing_crash(tmp_path, gate_stopped):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    with ledger._locked() as state:
        row = ledger._row(state, ticket)
        row["state"] = "closing"
        row["abortRecordDigest"] = digest(record)
        ledger._save(state)
    if gate_stopped:
        gate.abort_no_data(record["planDigest"], record["gateDigest"], digest(record))
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )


def test_no_data_abort_rejects_tampered_gate_after_stop(tmp_path):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    with ledger._locked() as state:
        row = ledger._row(state, ticket)
        row["state"] = "closing"
        row["abortRecordDigest"] = digest(record)
        ledger._save(state)
    gate.abort_no_data(record["planDigest"], record["gateDigest"], digest(record))
    with gate.locked() as state:
        state["jobs"]["limits"]["owned"].append(state["jobs"]["limits"]["resources"][0])
        _save(gate.path, state)
    # Caught on the evidence read from the Gate itself, before any Gate call.
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "closing"
    )


@pytest.mark.parametrize("missing", ["coordinator", "job", "both", "malformed"])
def test_no_data_abort_requires_recorded_worker_identity(tmp_path, missing):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    with gate.locked() as state:
        if missing in {"coordinator", "both"}:
            state["coordinatorPid"] = None
        if missing in {"job", "both"}:
            state["jobs"]["limits"]["pid"] = None
        if missing == "malformed":
            state["jobs"]["limits"]["pid"] = "not-a-pid"
        _save(gate.path, state)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["gate"] = gate.snapshot()
    receipt_path.write_text(json.dumps(receipt))
    record["gateDigest"] = digest(receipt["gate"])
    record["receiptDigest"] = digest(receipt)
    with pytest.raises(ValueError, match="worker identity"):
        ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "closing"
    )


def test_terminal_abort_rejects_recovery_management_without_gate_mutation(
    tmp_path, monkeypatch
):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    ledger.abort_no_data(ticket, record)
    frozen = gate.snapshot()
    worker_pid = frozen["coordinatorPid"]
    monkeypatch.setattr(shared_production.os, "getpid", lambda: worker_pid)
    production_gate = ProductionGate(gate.path, "limits")
    coordinator = SimpleNamespace(budget=SimpleNamespace(recovery=True))
    with pytest.raises(ValueError, match="management stopped"):
        production_gate.manage(coordinator, "project", lambda: "accepted")
    assert gate.snapshot() == frozen
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["finalGateDigest"] == digest(frozen)


def contender(root, barrier, queue, label):
    ledger = Ledger(Path(root) / "ledger")
    request = claim(Path(root), label, [{"key": "project/p/shared", "mode": "WRITE"}])
    barrier.wait(timeout=10)
    try:
        ledger.reserve(envelope(), request, plan(label), now=1100)
        queue.put("accepted")
    except ValueError:
        queue.put("refused")


def test_two_processes_cannot_both_reserve_conflicting_scope(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ctx = multiprocessing.get_context("spawn")
    barrier, queue = ctx.Barrier(2), ctx.Queue()
    children = [
        ctx.Process(target=contender, args=(str(tmp_path), barrier, queue, label))
        for label in ("a", "b")
    ]
    try:
        for child in children:
            child.start()
        for child in children:
            child.join(timeout=15)
            assert child.exitcode == 0
        assert sorted([queue.get(timeout=2), queue.get(timeout=2)]) == [
            "accepted",
            "refused",
        ]
        assert len(ledger.snapshot()["reservations"]) == 1
        assert (
            ledger.snapshot()["envelopes"][digest(envelope())]["allocated"]["requests"]
            == 2
        )
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
        queue.close()
        queue.join_thread()


def test_same_permission_cannot_multiply_its_envelope(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    before = ledger.snapshot()
    changed = envelope()
    changed["limits"]["requests"] += 100
    with pytest.raises(ValueError, match="another envelope"):
        ledger.reserve(changed, claim(tmp_path, "b"), plan("b"), now=1100)
    assert ledger.snapshot() == before


def test_readers_share_scope_but_concurrency_still_bounds_admission(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    policy = envelope()
    policy["concurrency"] = 2
    locks = [{"key": "project/p/config", "mode": "READ"}]
    ledger.reserve(policy, claim(tmp_path, "a", locks), plan(), now=1100)
    ledger.reserve(policy, claim(tmp_path, "b", locks), plan("b"), now=1100)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="concurrency"):
        ledger.reserve(policy, claim(tmp_path, "c"), plan("c"), now=1100)
    assert ledger.snapshot() == before


def test_ticket_cannot_move_to_copied_or_missing_ledger(tmp_path):
    import shutil

    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    shutil.copytree(tmp_path / "ledger", tmp_path / "copy")
    with pytest.raises(ValueError, match="ticket"):
        Ledger(tmp_path / "copy").validate(ticket, now=1100)
    with pytest.raises(FileNotFoundError):
        Ledger(tmp_path / "missing")
    (tmp_path / "alias").symlink_to(tmp_path / "ledger", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        Ledger(tmp_path / "alias")


def test_attach_evidence_anchors_a_running_reservations_observed_bytes(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    receipt_sha256, gate_digest, collection_digest = digest("r"), digest("g"), digest("c")
    ledger.attach_evidence(ticket, receipt_sha256, gate_digest, collection_digest)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "held"
    assert row["evidence"] == {
        "receiptSha256": receipt_sha256,
        "gateDigest": gate_digest,
        "collectionDigest": collection_digest,
        "ledgerIdentity": ledger.identity,
    }
    # The same triple attached again (a retried publish) is idempotent.
    before = ledger.snapshot()
    ledger.attach_evidence(ticket, receipt_sha256, gate_digest, collection_digest)
    assert ledger.snapshot() == before


def test_attach_evidence_refuses_a_second_attach_with_different_digests(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    ledger.attach_evidence(ticket, digest("r"), digest("g"), digest("c"))
    before = ledger.snapshot()
    for changed in (
        (digest("other"), digest("g"), digest("c")),
        (digest("r"), digest("other"), digest("c")),
        (digest("r"), digest("g"), digest("other")),
    ):
        with pytest.raises(ValueError, match="attached evidence differs"):
            ledger.attach_evidence(ticket, *changed)
    assert ledger.snapshot() == before


def test_attach_evidence_refuses_an_unknown_ticket(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    forged = {**ticket, "reservation": "0" * 64}
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="exact shared reservation ticket required"):
        ledger.attach_evidence(forged, digest("r"), digest("g"), digest("c"))
    assert ledger.snapshot() == before


@pytest.mark.parametrize("malformed", ["", "not-hex", "a" * 63, "A" * 64, None])
def test_attach_evidence_requires_bounded_sha256_digests(tmp_path, malformed):
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    for triple in (
        (malformed, digest("g"), digest("c")),
        (digest("r"), malformed, digest("c")),
        (digest("r"), digest("g"), malformed),
    ):
        with pytest.raises(ValueError, match="SHA-256"):
            ledger.attach_evidence(ticket, *triple)
    assert "evidence" not in ledger.snapshot()["reservations"][ticket["reservation"]]


def test_attach_evidence_refuses_once_the_reservation_is_no_longer_held(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    c = claim(tmp_path, "a")
    frozen = plan()
    ticket = ledger.reserve(envelope(), c, frozen, now=1100)
    create(Path(c["gatePath"]), frozen)
    gate = Gate(c["gatePath"], "limits")
    gate.claim()
    for operation in frozen["jobs"]["limits"]["recovery"]:
        gate.dispatch(
            operation, True, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        )
    gate.finish()
    ledger.finish(ticket)
    with pytest.raises(ValueError, match="reservation is not held"):
        ledger.attach_evidence(ticket, digest("r"), digest("g"), digest("c"))


def interrupted_worker(root, connection):
    ledger = Ledger(Path(root) / "ledger")
    request = claim(Path(root), "a")
    ticket = ledger.reserve(envelope(), request, plan(), now=1100)
    create(Path(request["gatePath"]), plan())
    gate = Gate(request["gatePath"], "limits")
    gate.claim()

    def interrupted():
        connection.send(ticket)
        connection.close()
        raise SystemExit(23)

    gate.dispatch(plan()["jobs"]["limits"]["recovery"][0], True, interrupted)


def test_exited_worker_keeps_uncertain_gate_and_shared_ownership(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    child = ctx.Process(target=interrupted_worker, args=(str(tmp_path), sender))
    try:
        child.start()
        sender.close()
        assert receiver.poll(10)
        ticket = receiver.recv()
        child.join(timeout=10)
        assert child.exitcode == 23
        gate = Gate(tmp_path / "a", "limits").snapshot()
        assert gate["total"] == 1
        assert gate["jobs"]["limits"]["inflight"] is True
        with pytest.raises(ValueError, match="cleanup"):
            ledger.finish(ticket)
        row = ledger.snapshot()["reservations"][ticket["reservation"]]
        assert row["state"] == "held"
        with pytest.raises(ValueError, match="conflict"):
            ledger.reserve(
                envelope(),
                claim(tmp_path, "b", row["claim"]["locks"]),
                plan("b"),
                now=5000,
            )
    finally:
        receiver.close()
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)


def test_closing_refuses_dispatch_without_gate_ledger_lock_inversion(tmp_path):
    import threading
    import time

    ledger = Ledger.create(tmp_path / "ledger")
    request = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), request, plan(), now=1100)
    create(Path(request["gatePath"]), plan())
    gate = Gate(request["gatePath"], "limits")
    gate.claim()
    gate.dispatch(
        plan()["jobs"]["limits"]["recovery"][0],
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    gate.finish()
    errors = []

    def finish():
        try:
            ledger.finish(ticket)
        except Exception as error:  # noqa: BLE001 -- Preserve thread failures for assertions.
            errors.append(error)

    worker = threading.Thread(target=finish, daemon=True)
    with gate.locked():
        worker.start()
        until = time.monotonic() + 5
        while (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
            != "closing"
        ):
            assert time.monotonic() < until
            time.sleep(0.01)
        with pytest.raises(ValueError, match="unavailable"):
            ledger.validate(ticket, now=1110)
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert errors == []
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
    )


def test_production_gate_cannot_borrow_another_permission_budget(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    frozen = plan()
    frozen["permissionDigest"] = "b" * 64
    request = claim(tmp_path, "a")
    request["gatePlanDigest"] = digest(frozen)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="permission differs"):
        ledger.reserve(envelope(), request, frozen, now=1100)
    assert ledger.snapshot() == before


def test_validate_samples_default_clock_after_waiting_for_ledger_lock(tmp_path):
    now = time.time()
    policy = envelope()
    policy.update(issuedAt=now - 1, expiresAt=now + 4.5)
    request = claim(tmp_path, "a")
    short_plan = plan()
    short_plan["wallSeconds"] = 3
    short_plan["recoverySeconds"] = 0.5
    request["gatePlanDigest"] = digest(short_plan)
    request["durationSeconds"] = 3
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(policy, request, short_plan, now=now)
    entered = threading.Event()
    errors = []

    def validate():
        entered.set()
        try:
            ledger.validate(ticket, duration=1)
        except ValueError as error:
            assert "unavailable" in str(error)
            errors.append(error)
        else:
            errors.append(
                AssertionError("validate accepted after the reservation deadline")
            )

    with ledger._locked():
        worker = threading.Thread(target=validate, daemon=True)
        worker.start()
        assert entered.wait(2)
        time.sleep(2.2)
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert errors and isinstance(errors[0], ValueError)


def test_reserve_samples_default_clock_after_waiting_for_ledger_lock(tmp_path):
    now = time.time()
    policy = envelope()
    policy.update(issuedAt=now - 1, expiresAt=now + 3.5)
    request = claim(tmp_path, "a")
    short_plan = plan()
    short_plan["wallSeconds"] = 3
    short_plan["recoverySeconds"] = 0.5
    request["gatePlanDigest"] = digest(short_plan)
    request["durationSeconds"] = 3
    ledger = Ledger.create(tmp_path / "ledger")
    entered = threading.Event()
    errors = []

    def reserve():
        entered.set()
        try:
            ledger.reserve(policy, request, short_plan)
        except ValueError as error:
            errors.append(error)

    with ledger._locked():
        worker = threading.Thread(target=reserve, daemon=True)
        worker.start()
        assert entered.wait(2)
        time.sleep(3.2)
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert any("permission window" in str(error) for error in errors)
    assert ledger.snapshot()["reservations"] == {}


@pytest.mark.parametrize(
    "locks",
    [
        [],
        [{"key": "project/p/firestore/(default)/documents/other", "mode": "WRITE"}],
        [{"key": "project/p/firestore/(default)/documents/owned/a", "mode": "READ"}],
        [{"key": "project/q/firestore/(default)/documents/owned/a", "mode": "WRITE"}],
    ],
)
def test_gate_firestore_resources_require_covering_write_lock(tmp_path, locks):
    ledger = Ledger.create(tmp_path / "ledger")
    request = claim(tmp_path, "a", locks)
    request["locks"] = locks
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), request, plan(), now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("covered", [True, False])
def test_gate_resource_lock_prevents_same_document_escape(tmp_path, covered):
    ledger = Ledger.create(tmp_path / "ledger")
    ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    before = ledger.snapshot()
    other_plan = plan("b")
    other_plan["jobs"]["limits"]["recovery"][0]["path"] = plan()["jobs"]["limits"][
        "recovery"
    ][0]["path"]
    other_plan["jobs"]["limits"]["resources"] = [
        other_plan["jobs"]["limits"]["recovery"][0]["path"].removeprefix("/v1/")
    ]
    request = claim(
        tmp_path,
        "b",
        [
            {"key": "project/p/data/alternate", "mode": "WRITE"},
            {
                "key": "project/p/firestore/(default)/documents/owned/*",
                "mode": "WRITE",
            },
        ],
    )
    if not covered:
        request["locks"] = claim(tmp_path, "b")["locks"]
    request["gatePlanDigest"] = digest(other_plan)
    request["nonceDigest"] = digest(other_plan["nonce"])
    with pytest.raises(ValueError, match="conflict" if covered else "not covered"):
        ledger.reserve(envelope(), request, other_plan, now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize(
    "body",
    [
        {"nonJson": "<html>not found</html>"},
        {"error": {"code": 404, "status": "PERMISSION_DENIED"}},
        {"error": {"code": "404", "status": "NOT_FOUND"}},
        {"error": {"code": 404.0, "status": "NOT_FOUND"}},
    ],
)
def test_untyped_absence_never_releases_shared_ownership(tmp_path, body):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    operation = plan()["jobs"]["limits"]["recovery"][0]
    with pytest.raises(ValueError, match="typed.*absence"):
        gate.dispatch(operation, True, lambda: (404, body))
    with pytest.raises(ValueError):
        gate.finish()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(), claim(tmp_path, "b", first["locks"]), plan("b"), now=1110
        )


def test_absent_boolean_cannot_replace_bound_cleanup_evidence(tmp_path):
    from shared_gate import _save

    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    with gate.locked() as state:
        job = state["jobs"]["limits"]
        job.update(complete=True, absent=list(job["resources"]), recovery=1)
        _save(gate.path, state)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


@pytest.mark.parametrize(
    "field,value",
    [
        ("requestDigest", "wrong-resource"),
        ("responseDigest", "wrong-body"),
        ("completed", False),
        ("phase", "observation"),
    ],
)
def test_absence_release_checks_request_response_and_completion(tmp_path, field, value):
    from shared_gate import _save

    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    operation = plan()["jobs"]["limits"]["recovery"][0]
    gate.dispatch(
        operation, True, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    gate.finish()
    with gate.locked() as state:
        state["events"][0][field] = value
        _save(gate.path, state)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_a_claim_may_name_the_gate_job_it_reserved(tmp_path):
    """The reservation addresses the Gate by the job its own campaign declared."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = {**claim(tmp_path, "a"), "gateJob": "limits"}
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    assert ledger.bound_claim(ticket)["gateJob"] == "limits"
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    gate.dispatch(
        plan()["jobs"]["limits"]["recovery"][0],
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    gate.finish()
    ledger.finish(ticket)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
    )


def test_a_named_gate_job_must_exist_in_the_reserved_gate(tmp_path):
    """A claim that names a job the Gate never hosted is a binding error."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = {**claim(tmp_path, "a"), "gateJob": "probe-1"}
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    gate.dispatch(
        plan()["jobs"]["limits"]["recovery"][0],
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    gate.finish()
    with pytest.raises(ValueError, match="registered Gate job"):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


@pytest.mark.parametrize("name", ["", "a/b", "a b", 7, None, "x" * 65])
def test_a_malformed_gate_job_name_is_refused_without_mutation(tmp_path, name):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(), {**claim(tmp_path, "a"), "gateJob": name}, plan(), now=1100
        )
    assert ledger.snapshot() == before


def test_a_claim_key_outside_the_closed_set_is_still_refused(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="closed campaign claim"):
        ledger.reserve(
            envelope(), {**claim(tmp_path, "a"), "gateSlot": "limits"}, plan(), now=1100
        )
    assert ledger.snapshot() == before


# A second campaign shape: three probes, an interleaved schedule, one bearer
# credential slot and its own preflight gates and receipt kind. Synthetic, and
# deliberately unlike the Commit lane in every one of those dimensions.
CAMPAIGN_CREDENTIALS = ("bearer-issue",)
CAMPAIGN_PREFLIGHT = ("project", "database", "owned-scope")
CAMPAIGN_PROBES = ("p1", "p2", "p3")
CAMPAIGN_RECEIPT_KIND = "request-bytes-acquisition-receipt-v1"


def token_attestation():
    """The public body the request-byte lane publishes for a verified token."""
    return {
        "kind": "request-byte-token-attestation-v1",
        "principalDigest": digest("principal"),
        "requiredScopeVerified": True,
        "identityMode": "subject",
        "identityVerified": True,
        "oauthClientVerified": True,
        "expiresInSeconds": 3600,
        "remainingSecondsAtVerification": 3599.0,
        "requiredSeconds": 600,
        "complete": True,
        "workerReaped": True,
    }


def management_response(identity, *, complete=True, transport=True):
    """One bounded management receipt as the Gate charges and digests it."""
    if not transport:
        return {
            "status": None,
            "complete": False,
            "workerReaped": True,
            "bodyKind": None,
            "body": None,
        }
    slot = identity.split(":", 1)[1]
    if slot in CAMPAIGN_CREDENTIALS:
        body = token_attestation() if complete else None
    else:
        body = {
            "kind": "request-byte-metadata-attestation-v1",
            "slot": slot,
            "bodyDigest": digest(slot),
            "baselineVerified": complete,
        }
    return {
        "status": 200,
        "complete": complete,
        "workerReaped": True,
        "bodyKind": "json",
        "body": body,
    }


def charge_management(state, responses):
    """Record charged management slots on a Gate state the way `management_dispatch` does."""
    state["managementUsed"] = [identity for identity, _ in responses]
    state["managementEvents"] = [
        {
            "id": identity,
            "started": index,
            "durationReserved": 12,
            "status": response["status"],
            "complete": response["complete"],
            "workerReaped": response["workerReaped"],
            "bodyKind": response["bodyKind"],
            "responseDigest": digest(response),
            "bodyDigest": digest(response["body"]),
            "completed": bool(response["complete"] and response["workerReaped"]),
        }
        for index, (identity, response) in enumerate(responses)
    ]
    state["total"] += len(responses)
    state["observation"] += len(responses)
    state["costMicrousd"] += len(responses)


def request_bytes_receipt(snapshot, ticket, plan_digest, responses, **overrides):
    """A receipt in the shape `request_bytes_production.execute` persists."""
    rows = [
        {"id": identity, "response": response, "responseDigest": digest(response)}
        for identity, response in responses
    ]
    credentials = [
        response["body"]
        for identity, response in responses
        if identity.split(":", 1)[1] in CAMPAIGN_CREDENTIALS
        and response["complete"] is True
    ]
    routes = [
        {
            "id": f"observation:{index:03d}",
            "route": "/v1/"
            + snapshot["plan"]["jobs"][event["job"]]["observation"][event["index"]][
                "path"
            ].removeprefix("/v1/"),
            "status": event.get("status") if event.get("completed") else None,
            "responseDigest": event.get("responseDigest", digest(None))
            if event.get("completed")
            else digest({"failure": event.get("failure")}),
        }
        for index, event in enumerate(snapshot["events"])
    ]
    receipt = {
        "kind": CAMPAIGN_RECEIPT_KIND,
        "ticket": ticket,
        "planDigest": plan_digest,
        "claimDigest": ticket["claimDigest"],
        "gateDigest": digest(snapshot),
        "chargedCalls": snapshot["total"],
        "collection": None
        if not routes
        else {"rowCount": len(routes), "recoveryRowCount": 0, "completed": False},
        "productionExecuted": bool(routes),
        "mayHaveCreated": False,
        "preflightComplete": len(responses)
        == len(CAMPAIGN_CREDENTIALS) + len(CAMPAIGN_PREFLIGHT),
        "postflightComplete": False,
        "failure": "ValueError",
        "releaseEligible": False,
        "reservationStateAtPublication": "held",
        "executionKind": "fixed-production-wire",
        "metadata": routes,
        "routeDigest": digest(routes),
        "managementEvidence": rows,
        "credentialEvidence": credentials,
    }
    receipt.update(overrides)
    return receipt


def campaign_plan(tmp_path, kind=CAMPAIGN_RECEIPT_KIND):
    op = lambda key: {
        "service": "firestore",
        "path": "/v1/" + key,
        "body": None,
        "method": "GET",
        "privileged": True,
        "form": False,
    }
    owned = {
        probe: f"projects/p/databases/(default)/documents/owned/a/probe/{probe}"
        for probe in CAMPAIGN_PROBES
    }
    jobs = {
        probe: {
            "resources": [owned[probe]],
            "observation": [op(owned[probe]), op(owned[probe])],
            "recovery": [op(owned[probe]), op(owned[probe])],
            "schedule": [
                {"phase": "observation", "index": 0},
                {"phase": "recovery", "index": 0},
                {"phase": "observation", "index": 1},
                {"phase": "recovery", "index": 1},
            ],
        }
        for probe in CAMPAIGN_PROBES
    }
    return {
        "contract": "shared-local-v1",
        "nonce": plan("a")["nonce"],
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": 12,
        "costMicrousd": 5000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": 2,
        "jobSlots": 3,
        "receiptKind": kind,
        "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
        "management": {
            "observation": [
                {"id": name, "timeout": 13, "duration": 12}
                for name in (*CAMPAIGN_CREDENTIALS, *CAMPAIGN_PREFLIGHT)
            ],
            "recovery": [],
            "credentialIds": list(CAMPAIGN_CREDENTIALS),
            "credentialSlots": ["bearer"],
        },
        "jobs": jobs,
    }


def _campaign_attempt(
    tmp_path, *, stop=1, mode="decision", dispatched=False, kind=CAMPAIGN_RECEIPT_KIND
):
    """A failed attempt by the three-probe campaign, stopped at preflight `stop`."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    first["gateJob"] = CAMPAIGN_PROBES[0]
    frozen = campaign_plan(tmp_path, kind)
    first["gatePlanDigest"] = digest(frozen)
    first["budget"] = {
        "requests": 60,
        "accounts": 1,
        "resources": 3,
        "costMicrousd": 9000,
    }
    first["durationSeconds"] = 600
    ticket = ledger.reserve(envelope(), first, frozen, now=1100)
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], CAMPAIGN_PROBES[0])
    used = [
        f"observation:{name}"
        for name in (*CAMPAIGN_CREDENTIALS, *CAMPAIGN_PREFLIGHT[:stop])
    ]
    # A slot is charged before its evidence is appended: a "decision" stop is
    # a slot whose transport answered and whose baseline comparison failed, a
    # "transport" stop is a slot the worker never answered.
    responses = [
        (
            identity,
            management_response(
                identity,
                complete=index < len(used) - 1,
                transport=mode == "decision" or index < len(used) - 1,
            ),
        )
        for index, identity in enumerate(used)
    ]
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        for probe in CAMPAIGN_PROBES:
            state["jobs"][probe]["pid"] = state["coordinatorPid"]
        charge_management(state, responses)
        if dispatched:
            # The transport-deadline stop: a probe Commit was sent and its
            # outcome is unknown, so no evidence can prove that no data exists.
            state["jobs"][CAMPAIGN_PROBES[0]]["observation"] = 1
            state["jobs"][CAMPAIGN_PROBES[0]]["scheduleDone"] = 1
            state["total"] += 1
            state["observation"] += 1
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt = request_bytes_receipt(
        snapshot, ticket, first["gatePlanDigest"], responses, gate=snapshot, kind=kind
    )
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": frozen["collectorSourceDigest"],
        "sourceCommit": COMMIT_SOURCE_COMMIT,
        "sourceDigests": COMMIT_SOURCE_DIGESTS,
    }
    return ledger, gate, ticket, record


@pytest.mark.parametrize("stop", [1, 2, 3])
@pytest.mark.parametrize("mode", ["decision", "transport"])
def test_every_preflight_stop_of_a_second_campaign_is_retirable(tmp_path, stop, mode):
    """The evidence contract follows the Gate plan, not the Commit lane's slots."""
    ledger, gate, ticket, record = _campaign_attempt(tmp_path, stop=stop, mode=mode)
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )
    assert gate.snapshot()["stopped"] is True
    assert all(job["stopped"] for job in gate.snapshot()["jobs"].values())


def test_a_transport_deadline_stop_is_never_retirable_as_no_data(tmp_path):
    """A dispatched probe Commit may have been applied, whatever the receipt says."""
    ledger, gate, ticket, record = _campaign_attempt(tmp_path, dispatched=True)
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    assert gate.snapshot()["stopped"] is False


def test_a_second_campaign_receipt_must_carry_its_own_declared_kind(tmp_path):
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["kind"] = "commit-acquisition-receipt-v2"
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, {**record, "receiptDigest": digest(receipt)})
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_a_second_campaign_credential_slot_set_is_its_own(tmp_path):
    """Commit-shaped credential items do not satisfy the request-byte contract."""
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["credentialEvidence"] = [
        {
            "slot": slot,
            "workerReaped": True,
            "complete": True,
            "verified": True,
            "status": 200,
        }
        for slot in ("refresh", "tokeninfo")
    ]
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, {**record, "receiptDigest": digest(receipt)})
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_management_outside_the_declared_campaign_prefix_is_refused(tmp_path):
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path, stop=2)
    gate = Gate(Path(record["receiptPath"]).parent / "gate", CAMPAIGN_PROBES[0])
    responses = [
        (identity, management_response(identity))
        for identity in ("observation:bearer-issue", "observation:owned-scope")
    ]
    with gate.locked() as state:
        state["total"] = state["observation"] = state["costMicrousd"] = 0
        charge_management(state, responses)
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt_path = Path(record["receiptPath"])
    receipt = request_bytes_receipt(
        snapshot, ticket, record["planDigest"], responses, gate=snapshot
    )
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(
            ticket,
            {
                **record,
                "gateDigest": digest(snapshot),
                "receiptDigest": digest(receipt),
            },
        )
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


# A third campaign shape: no credential acquisition, no metadata preflight, and
# probe slots that read before they write. Its stop points are real no-data
# stops even though data requests were sent.
READONLY_RECEIPT_KIND = "request-bytes-acquisition-receipt-v1"


def readonly_plan(creates=False, kind=READONLY_RECEIPT_KIND):
    owned = "projects/p/databases/(default)/documents/owned/a/probe/u01"
    op = {
        "service": "firestore",
        "path": "/v1/" + owned,
        "body": None,
        "method": "GET",
        "privileged": True,
        "form": False,
    }
    return {
        "contract": "shared-local-v1",
        "nonce": plan("a")["nonce"],
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": 3,
        "costMicrousd": 5000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": 2,
        "jobSlots": 1,
        "receiptKind": kind,
        "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
        "management": {
            "observation": [],
            "recovery": [],
            "credentialIds": [],
            "credentialSlots": [],
        },
        "jobs": {
            "probe": {
                "resources": [owned],
                "observation": [dict(op), dict(op), dict(op)],
                "recovery": [dict(op)],
                "schedule": [
                    {"phase": "observation", "index": 0, "creates": creates},
                    {"phase": "observation", "index": 1, "creates": creates},
                    {"phase": "observation", "index": 2, "creates": creates},
                    {"phase": "recovery", "index": 0},
                ],
            }
        },
    }


def _readonly_attempt(
    tmp_path, *, dispatched=0, creates=False, kind=READONLY_RECEIPT_KIND
):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    first["gateJob"] = "probe"
    frozen = readonly_plan(creates, kind)
    first["gatePlanDigest"] = digest(frozen)
    first["budget"] = {
        "requests": 60,
        "accounts": 1,
        "resources": 1,
        "costMicrousd": 9000,
    }
    first["durationSeconds"] = 600
    ticket = ledger.reserve(envelope(), first, frozen, now=1100)
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], "probe")
    gate.claim()
    for index in range(dispatched):
        gate.dispatch(
            frozen["jobs"]["probe"]["observation"][index],
            False,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        state["jobs"]["probe"]["pid"] = state["coordinatorPid"]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt = request_bytes_receipt(
        snapshot, ticket, first["gatePlanDigest"], [], gate=snapshot, kind=kind
    )
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": frozen["collectorSourceDigest"],
        "sourceCommit": COMMIT_SOURCE_COMMIT,
        "sourceDigests": COMMIT_SOURCE_DIGESTS,
    }
    return ledger, gate, ticket, record


def test_the_txn_expiry_kind_is_held_to_the_commit_contract_by_name(tmp_path):
    """A lane that projects onto the Commit vocabulary is mapped, not guessed."""
    ledger, gate, ticket, record = _no_data_attempt(
        tmp_path, kind="txn-expiry-acquisition-receipt-v1"
    )
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )
    assert gate.snapshot()["stopped"] is True


def test_the_partition_cursor_kind_is_held_to_the_commit_contract_by_name(tmp_path):
    """The partition/cursor lane's receipt projects onto the Commit vocabulary."""
    ledger, gate, ticket, record = _no_data_attempt(
        tmp_path, kind="partition-cursor-acquisition-receipt-v1"
    )
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )
    assert gate.snapshot()["stopped"] is True


@pytest.mark.parametrize(
    "kind",
    [
        "limits-03-acquisition-receipt-v1",
        "auth-credential-acquisition-receipt-v1",
    ],
)
def test_a_lane_that_reuses_the_request_byte_preflight_is_held_to_its_contract(
    tmp_path, kind
):
    """limits-03 and auth-credential load request_bytes_preflight.py at runtime
    for their credential attestation, so their receipts are held to the same
    row-by-row Gate-bound contract, not the looser Commit shape."""
    ledger, gate, ticket, record = _campaign_attempt(tmp_path, kind=kind)
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )
    assert gate.snapshot()["stopped"] is True


@pytest.mark.parametrize(
    "kind",
    [
        "limits-03-acquisition-receipt-v1",
        "auth-credential-acquisition-receipt-v1",
    ],
)
def test_the_commit_shape_is_refused_under_a_request_byte_preflight_kind(
    tmp_path, kind
):
    """A Commit-shaped receipt does not satisfy a lane bound to the row-by-row
    contract just because both are "no data" shapes."""
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path, kind=kind)
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_a_receipt_kind_outside_the_closed_schema_map_has_no_retirement(tmp_path):
    """An unfamiliar receipt shape is refused, never read as a known one."""
    ledger, gate, ticket, record = _readonly_attempt(tmp_path, kind="other-receipt-v9")
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    assert gate.snapshot()["stopped"] is False


def test_the_commit_shape_is_refused_under_the_request_bytes_kind_and_back(tmp_path):
    """The reserving plan's receipt kind selects the contract; shapes do not mix."""
    ledger, _gate, ticket, record = _readonly_attempt(tmp_path)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    # The Commit lane's contract would accept this: no management, no routes,
    # nothing executed. The request-byte contract needs its own fields.
    for key in ("managementEvidence", "mayHaveCreated", "routeDigest"):
        receipt.pop(key)
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, {**record, "receiptDigest": digest(receipt)})
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path / "commit")
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    # And a request-byte-shaped receipt under the Commit kind is refused too.
    receipt.update(managementEvidence=[], mayHaveCreated=False, credentialEvidence=[])
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, {**record, "receiptDigest": digest(receipt)})


def test_a_stop_before_the_schedule_starts_is_retirable(tmp_path):
    """A campaign with no preflight slots still has a stop point at zero."""
    ledger, gate, ticket, record = _readonly_attempt(tmp_path)
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )
    assert gate.snapshot()["stopped"] is True


@pytest.mark.parametrize("dispatched", [1, 2, 3])
def test_a_stop_after_only_non_creating_slots_is_retirable(tmp_path, dispatched):
    """Ownership reads create nothing, so a stop during them leaves no residue."""
    ledger, gate, ticket, record = _readonly_attempt(tmp_path, dispatched=dispatched)
    assert gate.snapshot()["jobs"]["probe"]["observation"] == dispatched
    ledger.abort_no_data(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert gate.snapshot()["stopped"] is True


@pytest.mark.parametrize("dispatched", [1, 2])
def test_a_stop_after_a_slot_that_may_create_is_never_retirable(tmp_path, dispatched):
    """A slot the plan did not declare non-creating may have written a document."""
    ledger, gate, ticket, record = _readonly_attempt(
        tmp_path, dispatched=dispatched, creates=True
    )
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    assert gate.snapshot()["stopped"] is False


def test_an_abort_refuses_a_gate_job_the_claim_did_not_reserve(tmp_path):
    """abort_no_data checks the named job exists, exactly as finish does."""
    ledger, _gate, ticket, record = _readonly_attempt(tmp_path)
    with ledger._locked() as state:
        ledger._row(state, ticket)["claim"]["gateJob"] = "probe-absent"
        row = ledger._row(state, ticket)
        row["claimDigest"] = digest(row["claim"])
        ledger._save(state)
    ticket = {
        **ticket,
        "claimDigest": digest(
            ledger.snapshot()["reservations"][ticket["reservation"]]["claim"]
        ),
    }
    with pytest.raises(ValueError, match="registered Gate job"):
        ledger.abort_no_data(ticket, {**record, "ticket": ticket})


def test_a_rewritten_gate_copy_cannot_speak_for_the_registered_gate(tmp_path):
    """The retirement contract is read from the Gate itself, not from a copy."""
    ledger, _gate, ticket, record = _readonly_attempt(tmp_path)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["gate"]["plan"]["receiptKind"] = "commit-acquisition-receipt-v2"
    receipt_path.write_text(json.dumps(receipt))
    # The Ledger reads the Gate itself, so a rewritten copy cannot speak for it.
    with pytest.raises(ValueError, match="registered Gate differs"):
        ledger.abort_no_data(
            ticket,
            {
                **record,
                "gateDigest": digest(receipt["gate"]),
                "receiptDigest": digest(receipt),
            },
        )
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


# An uncertain stop: a probe Commit was dispatched and its outcome is unknown.
# Such a row is correctly refused by the no-data path, and before the escalation
# exit existed it stayed held and active forever, holding its lock key and its
# whole allocation even after the owner had removed the residue by hand.
ESCALATION_KIND = "shared-owner-escalation-close-v1"


def _typed_absence():
    return {"status": 404, "body": {"error": {"code": 404, "status": "NOT_FOUND"}}}


def _escalation_record(ledger, ticket, record, *, resources=None, attest=None):
    """An owner attestation plus typed absence for every owned resource."""
    import platform

    receipt = json.loads(Path(record["receiptPath"]).read_text())
    owned = sorted(
        name
        for job in receipt["gate"]["plan"]["jobs"].values()
        for name in job["resources"]
    )
    claim = ledger.bound_claim(ticket)
    now = time.time()
    attestation = {
        "kind": "owner-escalation-attestation-v1",
        "status": "attested",
        "campaignId": claim["campaignId"],
        "nonceDigest": claim["nonceDigest"],
        "claimDigest": ticket["claimDigest"],
        "ledgerRoot": str(ledger.path),
        "reservation": ticket["reservation"],
        "receiptDigest": record["receiptDigest"],
        "gateDigest": record["gateDigest"],
        "ownerIdentity": "t-k",
        "recoveryOwner": "t-k",
        "residueRemoved": True,
        "resourceCount": len(owned),
        "resourcesDigest": digest(owned),
        "attestedAt": now - 1,
        "expiresAt": now + 3600,
        "executionHost": {
            "platform": platform.system().lower(),
            "machine": platform.machine(),
        },
    }
    attestation.update(attest or {})
    return {
        "kind": ESCALATION_KIND,
        "ticket": ticket,
        "gateDigest": record["gateDigest"],
        "receiptPath": record["receiptPath"],
        "receiptDigest": record["receiptDigest"],
        "attestation": attestation,
        "absence": {
            name: _typed_absence()
            for name in (owned if resources is None else resources)
        },
    }


def test_an_escalated_stop_closes_and_stops_being_active(tmp_path):
    """The row reaches a terminal state and releases its lock key, nothing more."""
    ledger, gate, ticket, record = _campaign_attempt(tmp_path, dispatched=True)
    with pytest.raises(ValueError):
        ledger.abort_no_data(ticket, record)
    escalation = _escalation_record(ledger, ticket, record)
    ledger.close_after_escalation(ticket, escalation)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "closed-after-escalation"
    assert row["escalationRecordDigest"] == digest(escalation)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    # The allocation is never refunded, only the conflict lock is freed.
    envelope_row = ledger.snapshot()["envelopes"][digest(envelope())]
    assert envelope_row["allocated"] == row["claim"]["budget"]
    reuse = claim(tmp_path, "b", row["claim"]["locks"])
    reuse["gatePath"] = str((tmp_path / "second-gate").resolve())
    ledger.reserve(envelope(), reuse, plan("b"), now=1110)
    ledger.close_after_escalation(ticket, escalation)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-escalation"
    )


def test_an_escalated_close_refuses_without_a_bound_owner_attestation(tmp_path):
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path, dispatched=True)
    base = _escalation_record(ledger, ticket, record)
    for damage in (
        {"status": "pending"},
        {"kind": "other-attestation-v1"},
        {"campaignId": "another-campaign"},
        {"nonceDigest": "0" * 64},
        {"claimDigest": "0" * 64},
        {"reservation": "0" * 64},
        {"receiptDigest": "0" * 64},
        {"gateDigest": "0" * 64},
        {"ledgerRoot": "/nonexistent/ledger"},
        {"residueRemoved": False},
        {"resourceCount": 99},
        {"resourcesDigest": "0" * 64},
        {"ownerIdentity": "<<ROOT: who>>"},
        {"recoveryOwner": ""},
        {"attestedAt": time.time() + 600},
        {"expiresAt": time.time() - 1},
        {"executionHost": {"platform": "other", "machine": "other"}},
    ):
        with pytest.raises(ValueError):
            ledger.close_after_escalation(
                ticket, _escalation_record(ledger, ticket, record, attest=damage)
            )
        assert (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
        )
    escalation = dict(base)
    del escalation["attestation"]
    with pytest.raises(ValueError, match="escalation close record"):
        ledger.close_after_escalation(ticket, escalation)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_an_escalated_close_refuses_a_resource_not_proven_absent(tmp_path):
    """Every owned resource, not merely the ones the owner chose to read back."""
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path, dispatched=True)
    receipt = json.loads(Path(record["receiptPath"]).read_text())
    owned = sorted(
        name
        for job in receipt["gate"]["plan"]["jobs"].values()
        for name in job["resources"]
    )
    with pytest.raises(ValueError, match="absent"):
        ledger.close_after_escalation(
            ticket, _escalation_record(ledger, ticket, record, resources=owned[:-1])
        )
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    escalation = _escalation_record(ledger, ticket, record)
    escalation["absence"][owned[0]] = {"status": 200, "body": {"name": owned[0]}}
    with pytest.raises(ValueError, match="absent"):
        ledger.close_after_escalation(ticket, escalation)
    escalation["absence"][owned[0]] = {"status": 404, "body": {"error": {"code": 500}}}
    with pytest.raises(ValueError, match="absent"):
        ledger.close_after_escalation(ticket, escalation)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_the_escalation_exit_and_the_no_data_abort_are_mutually_exclusive(tmp_path):
    """Neither path can be reached with the other's evidence."""
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path, stop=1)
    escalation = _escalation_record(ledger, ticket, record)
    with pytest.raises(ValueError, match="no-data"):
        ledger.close_after_escalation(ticket, escalation)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )

    other, _gate, other_ticket, other_record = _campaign_attempt(
        tmp_path / "second", dispatched=True
    )
    with pytest.raises(ValueError, match="no-data abort record"):
        other.abort_no_data(
            other_ticket, _escalation_record(other, other_ticket, other_record)
        )
    with pytest.raises(ValueError):
        other.close_after_escalation(other_ticket, other_record)
    assert (
        other.snapshot()["reservations"][other_ticket["reservation"]]["state"] == "held"
    )


def abandoned_plan():
    """A scheduled probe whose observation can stop before it creates anything."""
    owned = "projects/p/databases/(default)/documents/owned/a/probe/u01"
    read = {
        "kind": "ownership-read",
        "resource": owned,
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + owned,
        "body": None,
        "privileged": True,
        "form": False,
    }
    return {
        "contract": "shared-local-v1",
        "nonce": plan("a")["nonce"],
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": 2,
        "costMicrousd": 5000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": 2,
        "jobSlots": 1,
        "receiptKind": READONLY_RECEIPT_KIND,
        "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
        "management": {
            "observation": [],
            "recovery": [],
            "credentialIds": [],
            "credentialSlots": [],
        },
        "jobs": {
            "probe": {
                "resources": [owned],
                "observation": [dict(read), dict(read)],
                "recovery": [dict(read)],
                "schedule": [
                    {"phase": "observation", "index": 0, "creates": False},
                    {"phase": "observation", "index": 1, "creates": False},
                    {"phase": "recovery", "index": 0, "creates": False},
                ],
            }
        },
    }


def test_a_stop_before_any_create_retires_as_no_data(tmp_path):
    """An abandoned observation that wrote nothing is still a no-data stop."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    first["gateJob"] = "probe"
    frozen = abandoned_plan()
    first["gatePlanDigest"] = digest(frozen)
    first["budget"] = {
        "requests": 60,
        "accounts": 1,
        "resources": 1,
        "costMicrousd": 9000,
    }
    first["durationSeconds"] = 600
    ticket = ledger.reserve(envelope(), first, frozen, now=1100)
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], "probe")
    gate.claim()
    gate.abandon_observation("transport-deadline")
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        state["jobs"]["probe"]["pid"] = state["coordinatorPid"]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    assert snapshot["jobs"]["probe"]["stopReason"] == "transport-deadline"
    receipt = request_bytes_receipt(
        snapshot,
        ticket,
        first["gatePlanDigest"],
        [],
        gate=snapshot,
        failure="TimeoutError",
    )
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": frozen["collectorSourceDigest"],
        "sourceCommit": COMMIT_SOURCE_COMMIT,
        "sourceDigests": COMMIT_SOURCE_DIGESTS,
    }
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )


ABANDON_KIND = "shared-abandoned-cleanup-close-v1"
CREATED_VERSION = "2026-09-19T00:00:00.000000Z"


def abandoned_cleanup_plan():
    """One probe that creates a document, stops early, then cleans up."""
    owned = "projects/p/databases/(default)/documents/owned/a/probe/u01"
    fields = {"blob": {"stringValue": "x"}}
    commit = {
        "service": "firestore",
        "method": "POST",
        "path": "/v1/projects/p/databases/(default)/documents:commit",
        "body": {
            "writes": [
                {
                    "update": {"name": owned, "fields": fields},
                    "currentDocument": {"exists": False},
                }
            ]
        },
        "privileged": True,
        "form": False,
    }
    read = {
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + owned,
        "body": None,
        "privileged": True,
        "form": False,
    }
    delete = {
        **read,
        "method": "DELETE",
        "versionFrom": 0,
    }
    return (
        owned,
        fields,
        {
            "contract": "shared-local-v1",
            "nonce": plan("a")["nonce"],
            "wallSeconds": 600,
            "recoverySeconds": 300,
            "observationRequests": 2,
            "costMicrousd": 5000,
            "requestCostMicrousd": 1,
            "intervalSeconds": 0.25,
            "requestSeconds": 2,
            "jobSlots": 1,
            "receiptKind": READONLY_RECEIPT_KIND,
            "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
            "management": {
                "observation": [],
                "recovery": [],
                "credentialIds": [],
                "credentialSlots": [],
            },
            "jobs": {
                "probe": {
                    "resources": [owned],
                    "observation": [commit, dict(read)],
                    "recovery": [dict(read), delete, dict(read)],
                    "schedule": [
                        {"phase": "observation", "index": 0},
                        {"phase": "observation", "index": 1, "creates": False},
                        {"phase": "recovery", "index": 0, "creates": False},
                        {"phase": "recovery", "index": 1, "creates": False},
                        {"phase": "recovery", "index": 2, "creates": False},
                    ],
                }
            },
        },
    )


def _abandoned_cleanup(
    tmp_path, *, absent=True, abandon=True, cleanup=True, lost=False, steps=3
):
    owned, fields, frozen = abandoned_cleanup_plan()
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    first["gateJob"] = "probe"
    first["gatePlanDigest"] = digest(frozen)
    first["budget"] = {
        "requests": 60,
        "accounts": 1,
        "resources": 1,
        "costMicrousd": 9000,
    }
    first["durationSeconds"] = 600
    ticket = ledger.reserve(envelope(), first, frozen, now=1100)
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], "probe")
    gate.claim()
    probe = frozen["jobs"]["probe"]

    def commit():
        if lost:
            raise TimeoutError("transport deadline")
        return (
            200,
            {
                "writeResults": [{"updateTime": CREATED_VERSION}],
                "commitTime": CREATED_VERSION,
            },
        )

    if lost:
        with pytest.raises(TimeoutError):
            gate.dispatch(probe["observation"][0], False, commit)
    else:
        gate.dispatch(probe["observation"][0], False, commit)
    if abandon:
        gate.abandon_observation("transport-deadline")
    if cleanup and steps >= 1:
        gate.dispatch(
            probe["recovery"][0],
            True,
            lambda: (
                200,
                {"name": owned, "fields": fields, "updateTime": CREATED_VERSION},
            ),
        )
    if cleanup and steps >= 2:
        deleted = dict(probe["recovery"][1])
        del deleted["versionFrom"]
        deleted["path"] += "?currentDocument.updateTime=" + quote(
            CREATED_VERSION, safe=""
        )
        gate.dispatch(deleted, True, lambda: (200, {}))
    if cleanup and steps >= 3:
        gate.dispatch(
            probe["recovery"][2],
            True,
            lambda: (
                (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
                if absent
                else (
                    200,
                    {"name": owned, "fields": fields, "updateTime": CREATED_VERSION},
                )
            ),
        )
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        state["jobs"]["probe"]["pid"] = state["coordinatorPid"]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt = {
        "kind": READONLY_RECEIPT_KIND,
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "claimDigest": ticket["claimDigest"],
        "gate": snapshot,
        "chargedCalls": snapshot["total"],
        "collection": None,
        "productionExecuted": True,
        "failure": "TimeoutError",
        "releaseEligible": False,
        "reservationStateAtPublication": "held",
        "executionKind": "fixed-production-wire",
        "metadata": [],
        "credentialEvidence": [],
    }
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": ABANDON_KIND,
        "ticket": ticket,
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
    }
    return ledger, gate, ticket, record


def test_an_abandoned_run_that_cleaned_up_retires_without_an_attestation(tmp_path):
    """The Gate's own journal proves absence, so no owner statement is needed."""
    ledger, gate, ticket, record = _abandoned_cleanup(tmp_path)
    escalation = _escalation_record(
        ledger, ticket, {**record, "kind": "shared-no-data-abort-v1"}
    )
    with pytest.raises(ValueError, match="recoverable"):
        ledger.close_after_escalation(ticket, escalation)
    ledger.close_after_abandon(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "closed-after-abandon"
    assert row["abandonRecordDigest"] == digest(record)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    reuse = claim(tmp_path, "b", row["claim"]["locks"])
    reuse["gatePath"] = str((tmp_path / "second-gate").resolve())
    ledger.reserve(envelope(), reuse, plan("b"), now=1110)
    ledger.close_after_abandon(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-abandon"
    )


def test_abandoned_cleanup_accepts_mixed_normal_and_stopped_jobs_after_reload(
    tmp_path,
):
    """A normal terminal job must not require a stop marker for its sibling."""
    _ledger, gate, _ticket, _record = _abandoned_cleanup(tmp_path)
    state = gate.snapshot()
    abandoned = state["jobs"]["probe"]
    normal = {
        "resources": [],
        "pid": None,
        "stopped": False,
        "inflight": False,
        "observation": 1,
        "recovery": 1,
        "owned": [],
        "creationProofs": {},
        "absent": [],
        "captures": {},
        "complete": True,
    }
    state["plan"]["jobs"]["normal"] = {
        "observation": [{"id": "normal-observation"}],
        "recovery": [{"id": "normal-recovery"}],
        "resources": [],
        "schedule": [
            {"phase": "observation", "index": 0, "creates": False},
            {"phase": "recovery", "index": 0, "creates": False},
        ],
    }
    normal["scheduleDone"] = 2
    state["jobs"]["normal"] = normal
    state_path = gate.path / "state.json"
    state_path.write_text(json.dumps(state))

    reloaded = json.loads(state_path.read_text())
    assert abandoned_cleanup_complete(reloaded) == sorted(abandoned["creationProofs"])

    abandoned["stopReason"] = None
    abandoned["complete"] = True
    state_path.write_text(json.dumps(state))
    assert abandoned_cleanup_complete(json.loads(state_path.read_text())) is None


def test_a_created_document_still_present_keeps_the_escalation_exit(tmp_path):
    """One document left behind is exactly what the owner has to attest to."""
    ledger, _gate, ticket, record = _abandoned_cleanup(tmp_path, absent=False)
    with pytest.raises(ValueError, match="abandoned cleanup"):
        ledger.close_after_abandon(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    escalation = _escalation_record(
        ledger, ticket, {**record, "kind": "shared-no-data-abort-v1"}
    )
    ledger.close_after_escalation(ticket, escalation)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-escalation"
    )


def test_an_incomplete_or_unabandoned_cleanup_is_refused(tmp_path):
    ledger, _gate, ticket, record = _abandoned_cleanup(tmp_path, cleanup=False)
    with pytest.raises(ValueError, match="abandoned cleanup"):
        ledger.close_after_abandon(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    other, _gate, other_ticket, other_record = _abandoned_cleanup(
        tmp_path / "second", abandon=False, cleanup=False
    )
    with pytest.raises(ValueError, match="abandoned cleanup"):
        other.close_after_abandon(other_ticket, other_record)
    assert (
        other.snapshot()["reservations"][other_ticket["reservation"]]["state"] == "held"
    )


def test_a_dispatched_commit_with_no_answer_is_never_closed_as_abandoned(tmp_path):
    """Uncreated means no write was sent, not that no proof came back."""
    ledger, gate, ticket, record = _abandoned_cleanup(
        tmp_path, lost=True, cleanup=False
    )
    assert unconfirmed_creates(gate.snapshot(), "probe") == 1
    with pytest.raises(ValueError, match="abandoned cleanup"):
        ledger.close_after_abandon(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    escalation = _escalation_record(
        ledger, ticket, {**record, "kind": "shared-no-data-abort-v1"}
    )
    ledger.close_after_escalation(ticket, escalation)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-escalation"
    )


def test_a_partial_recovery_is_never_closed_as_abandoned(tmp_path):
    """Deleted is not the same as proven absent, and only the proof retires it."""
    ledger, gate, ticket, record = _abandoned_cleanup(tmp_path, steps=2)
    job = gate.snapshot()["jobs"]["probe"]
    assert job["recovery"] == 2
    assert job["absent"] == []
    with pytest.raises(ValueError, match="abandoned cleanup"):
        ledger.close_after_abandon(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_a_receipt_need_not_carry_the_gate_it_binds(tmp_path):
    """A campaign whose Gate exceeds the receipt bound must still be able to retire.

    The request-byte Gate embeds its three ten-mebibyte request bodies, so its
    state is about twice the Ledger's bounded-receipt limit. A receipt that had
    to carry a copy could not be read at all, and every terminal exit would be
    unreachable for that campaign.
    """
    ledger, gate, ticket, record = _abandoned_cleanup(tmp_path)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    del receipt["gate"]
    receipt_path.write_text(json.dumps(receipt))
    record = {**record, "receiptDigest": digest(receipt)}
    assert digest(gate.snapshot()) == record["gateDigest"]
    ledger.close_after_abandon(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-abandon"
    )


@pytest.mark.parametrize(
    "campaign_id",
    ["a", digest("nonce")[:32], "FS-WRITE-TXN-PRECEDENCE-01-V9", "limits"],
    ids=["label", "nonce-shaped", "versioned", "lane-nickname"],
)
def test_reserve_refuses_a_campaign_id_outside_the_catalogue(tmp_path, campaign_id):
    """A renamed task would earn itself a fresh US$10; only catalogued ids reserve."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["campaignId"] = campaign_id
    before = (tmp_path / "ledger" / "state.json").read_bytes()
    with pytest.raises(ValueError, match="uncatalogued campaign id"):
        ledger.reserve(envelope(), first, plan("a"), now=1100)
    assert (tmp_path / "ledger" / "state.json").read_bytes() == before


def test_every_lane_descriptor_campaign_id_is_catalogued():
    """The catalogue is a closed literal; the lanes' declared ids must be in it.

    Read from source text rather than imported, so this module never pulls a
    lane's import graph into the shared Ledger's own test run.
    """
    root = Path(__file__).resolve().parents[1]
    for relative, name in (
        ("fs-commit-transform-limits/commit_acquisition.py", "CAMPAIGN_ID"),
        ("fs-config-lifecycle/surface_matrix.py", "CASE_ID"),
        ("fs-request-bytes-boundary/request_bytes_compiler.py", "CAMPAIGN"),
        ("fs-write-limits/compiler.py", "CAMPAIGN"),
        ("fs-write-limits/compiler_03.py", "CAMPAIGN"),
        ("fs-query-in-boundary/query_in_compiler.py", "CAMPAIGN"),
        ("fs-query-partition-cursor/partition_cursor_case.py", "CAMPAIGN"),
        ("fs-write-txn/txn_expiry_cases.py", "CAMPAIGN"),
        ("auth-action-codes/action_codes_plan.py", "CAMPAIGN_ID"),
        ("auth-credential-tokens/credential_cases.py", "CAMPAIGN_ID"),
        ("auth-totp-enroll/mfa_cases.py", "CAMPAIGN_ID"),
        ("auth-totp-enroll/totp_plan.py", "CAMPAIGN_ID"),
        ("fs-rules-publication/o5_rules_case.py", "CAMPAIGN"),
        ("fs-rules-publication/o5_user_token_case.py", "CAMPAIGN"),
    ):
        source = (root / relative).read_text()
        match = re.search(rf'^{name} = "([^"]+)"$', source, re.MULTILINE)
        assert match, relative
        assert match.group(1) in CATALOGUED_CAMPAIGN_IDS, (relative, match.group(1))
