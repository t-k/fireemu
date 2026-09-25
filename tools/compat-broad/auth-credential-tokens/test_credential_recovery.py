"""Offline adversarial tests for the Auth packet05 recovery contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import credential_gate
import credential_recovery as recovery
import shared_gate
from broad_contract import digest


def _provenance() -> dict:
    values = {recovery.WORKER_ENTRY: "a" * 64, recovery.TRANSPORT_ENTRY: "b" * 64, recovery.LAUNCHER_ENTRY: "c" * 64}
    return {
        "sourceCommit": "1" * 40,
        "sourceInputs": values,
        "worker": {"path": recovery.WORKER_ENTRY, "sha256": values[recovery.WORKER_ENTRY]},
        "transport": {"path": recovery.TRANSPORT_ENTRY, "sha256": values[recovery.TRANSPORT_ENTRY]},
        "launcher": {"path": recovery.LAUNCHER_ENTRY, "sha256": values[recovery.LAUNCHER_ENTRY]},
        "generation": {"sourceCommit": "1" * 40, "collectorSourceDigest": "f" * 64, "sourceDigests": {"worker.py": "a" * 64, "transport.py": "b" * 64, "recovery.py": "f" * 64}},
    }


def _parent_generation() -> dict:
    return {"sourceCommit": "1" * 40, "collectorSourceDigest": "e" * 64, "sourceDigests": {"worker.py": "a" * 64, "transport.py": "b" * 64}}


def _parent() -> dict:
    nonce = "0123456789abcdef0123456789abcdef"
    resource = f"projects/fireemu-35fe6/auth/accounts/custom-{nonce}"
    operation = {"service": "auth", "method": "POST", "path": "identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken", "body": {"token": "$binding:customToken", "returnSecureToken": True}, "form": False, "owner": False, "kind": "custom-sign-in", "account": "custom", "binds": {"customUid": "localId"}, "resource": resource}
    plan = {"campaignId": recovery.CAMPAIGN, "project": recovery.PROJECT, "nonce": nonce, "sourceCommit": "1" * 40, "jobs": {"auth-credential": {"observation": [operation], "recovery": []}}}
    event = {"job": "auth-credential", "phase": "observation", "index": 0, "requestDigest": digest(operation), "service": "auth", "method": "POST", "completed": False, "creationOutcome": "unknown", "ended": 999.0}
    gate = {"plan": plan, "planDigest": digest(plan), "jobs": {"auth-credential": {"inflight": False}}, "events": [event], "coordinatorInflight": False}
    claim = {"campaignId": recovery.CAMPAIGN, "claimDigest": "d" * 64, "gatePlanDigest": digest(plan), "nonceDigest": digest(nonce), "gateJob": "auth-credential"}
    immutable = {"kind": "auth-packet05-parent-binding-v1", "gateDigest": digest(gate), "gatePlanDigest": digest(plan), "nonce": nonce, "resource": resource, "eventIndex": 0, "requestDigest": digest(operation), "sourceCommit": "1" * 40}
    return {"state": "held", "ticket": {"reservation": "parent-ticket"}, "claim": claim, "plan": plan, "gate": gate, "receipt": {"failure": "collection-incomplete", "postflightComplete": False}, "responsibility": {"custom": {"state": "unknown", "uid": None}}, "immutableParent": immutable, "generation": _parent_generation()}


def _dead_pid() -> int:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    pid = process.pid
    process.wait()
    return pid


def _legacy_parent(monkeypatch: pytest.MonkeyPatch) -> dict:
    parent = _parent()
    gate = parent["gate"]
    job = gate["jobs"]["auth-credential"]
    job["pid"] = _dead_pid()
    gate["coordinatorPid"] = _dead_pid()
    operation = gate["plan"]["jobs"]["auth-credential"]["observation"][0]
    event = gate["events"][0]
    event.update(
        completed=True, creationOutcome="refused", status=200,
        responseDigest=digest({"response": "opaque"}),
        authEvidence={"kind": "custom-sign-in", "account": "custom", "status": 200, "creationOutcome": "refused"},
    )
    parent["claim"]["claimDigest"] = "d" * 64
    parent["immutableParent"].update(
        gateDigest=digest(gate), gatePlanDigest=digest(gate["plan"]),
        requestDigest=digest(operation),
    )
    parent["claim"]["gatePlanDigest"] = digest(gate["plan"])
    monkeypatch.setattr(recovery, "LEGACY_PARENT_SOURCE_COMMIT", "1" * 40)
    monkeypatch.setattr(recovery, "LEGACY_PARENT_CLAIM_DIGEST", "d" * 64)
    monkeypatch.setattr(recovery, "LEGACY_PARENT_PLAN_DIGEST", digest(gate["plan"]))
    monkeypatch.setattr(recovery, "LEGACY_PARENT_GATE_DIGEST", digest(gate))
    monkeypatch.setattr(recovery, "LEGACY_PARENT_EVENT_INDEX", 0)
    return parent


def _authorities(plan: dict) -> tuple[dict, dict, dict]:
    permission = {"kind": recovery.PERMISSION_KIND, "campaignId": recovery.CAMPAIGN, "parentClaimDigest": plan["parent"]["claimDigest"], "planDigest": plan["planDigest"], "nonceDigest": plan["recoveryNonceDigest"], "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"], "budget": copy.deepcopy(recovery.CHILD_BUDGET), "issuedAt": 1000.0, "expiresAt": 1300.0}
    o7 = {"kind": recovery.O7_KIND, "status": "approved", "campaignId": recovery.CAMPAIGN, "planDigest": plan["planDigest"], "permissionDigest": digest(permission), "nonceDigest": plan["recoveryNonceDigest"], "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"], "issuedAt": 1000.0, "expiresAt": 1300.0}
    o8 = {"kind": recovery.O8_KIND, "status": "issued", "campaignId": recovery.CAMPAIGN, "planDigest": plan["planDigest"], "permissionDigest": digest(permission), "nonceDigest": plan["recoveryNonceDigest"], "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"], "oneShot": True, "consumed": False, "issuedAt": 1001.0, "expiresAt": 1300.0}
    return permission, o7, o8


def _plan() -> tuple[dict, dict, dict, dict, dict]:
    parent = _parent()
    plan = recovery.compile_recovery_plan(parent, recovery_nonce="fedcba9876543210fedcba9876543210", provenance=_provenance(), now=1000.0, deadline_seconds=60)
    permission, o7, o8 = _authorities(plan)
    recovery.validate_authority_bundle(plan, permission=permission, o7=o7, o8=o8, now=1001.0)
    return parent, plan, permission, o7, o8


def _bound_gate(plan: dict, o7: dict, o8: dict) -> dict:
    source = {"kind": "auth-source-binding-v1", "digest": plan["provenance"]["sourceInputsDigest"]}
    transport = {"kind": "auth-transport-binding-v1", "digest": digest(plan["provenance"]["transport"])}
    o7_binding = {"kind": "auth-o7-binding-v1", "digest": digest(o7), "authority": o7}
    o8_binding = {"kind": "auth-o8-binding-v1", "digest": digest(o8), "authority": o8}
    return recovery._bound_plan(plan, source_binding=source, transport_binding=transport, o7_binding=o7_binding, o8_binding=o8_binding)["gatePlan"]


def _terminal_gate(plan: dict, o7: dict, o8: dict) -> dict:
    gate_plan = _bound_gate(plan, o7, o8)
    operation = plan["operation"]
    response_digest = digest({"kind": "identitytoolkit#GetAccountInfoResponse", "users": []})
    return {"plan": gate_plan, "planDigest": digest(gate_plan), "coordinatorInflight": False, "skips": [], "jobs": {recovery.GATE_JOB: {"inflight": False, "complete": True, "recovery": 1, "observation": 0, "absent": [plan["resource"]], "creationProofs": {}}}, "events": [{"job": recovery.GATE_JOB, "phase": "recovery", "index": 0, "requestDigest": digest(operation), "service": "auth", "method": "POST", "completed": True, "status": 200, "responseDigest": response_digest}]}


def _worker_receipt(gate: dict) -> dict:
    value = {"kind": "auth-credential-recovery-worker-receipt-v1", "gateDigest": digest(gate), "gatePlanDigest": digest(gate["plan"]), "responseDigest": digest({"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}), "completed": True}
    value["receiptDigest"] = digest(value)
    return value


def test_compile_binds_exact_custom_uid_and_one_read_only_lookup() -> None:
    _parent_value, plan, _permission, _o7, _o8 = _plan()
    operation = plan["operation"]
    assert operation["body"] == {"localId": ["$binding:customUid"]}
    assert operation["kind"] == "uid-absence"
    assert operation["method"] == "POST"
    assert plan["budget"] == {"requests": 1, "accounts": 1, "resources": 1, "costMicrousd": 50_000}
    assert "delete" not in repr(plan).lower()
    assert "email" not in repr(plan).lower()


def test_parent_nonce_resource_and_gate_mutation_is_refused_against_immutable_binding() -> None:
    parent = _parent()
    parent["gate"]["plan"]["nonce"] = "f" * 32
    parent["gate"]["plan"]["jobs"]["auth-credential"]["observation"][0]["resource"] = f"projects/{recovery.PROJECT}/auth/accounts/custom-{'f' * 32}"
    parent["claim"]["gatePlanDigest"] = digest(parent["gate"]["plan"])
    with pytest.raises(recovery.RecoveryRefusal, match="immutable|resource|Gate"):
        recovery.compile_recovery_plan(parent, recovery_nonce="e" * 32, provenance=_provenance())


def test_parent_snapshot_selects_one_unresolved_event_from_real_signing_compiler() -> None:
    parent = _parent()
    nonce = parent["gate"]["plan"]["nonce"]
    gate_plan = credential_gate.gate_plan(
        recovery.PROJECT,
        nonce,
        signing=True,
        wall_seconds=600,
        recovery_seconds=60,
        cost_microusd=100,
        observation_window_seconds=540,
    )
    custom_index = next(
        index
        for index, operation in enumerate(gate_plan["jobs"][credential_gate.JOB]["observation"])
        if operation.get("kind") == "custom-sign-in"
        and operation.get("binds", {}).get("customUid") in {"localId", "idToken.sub"}
        and operation.get("binds", {}).get("customIdToken") == "idToken"
        and operation.get("binds", {}).get("customRefresh") == "refreshToken"
    )
    operation = gate_plan["jobs"][credential_gate.JOB]["observation"][custom_index]
    operation["binds"] = {
        "customUid": "idToken.sub",
        "customIdToken": "idToken",
        "customRefresh": "refreshToken",
    }
    parent["gate"]["plan"] = gate_plan
    parent["gate"]["planDigest"] = digest(gate_plan)
    parent["gate"]["events"] = [{
        "job": credential_gate.JOB,
        "phase": "observation",
        "index": custom_index,
        "requestDigest": digest(operation),
        "service": operation["service"],
        "method": operation["method"],
        "completed": False,
        "creationOutcome": "unknown",
        "ended": 999.0,
    }]
    parent["claim"]["gatePlanDigest"] = digest(gate_plan)
    parent["immutableParent"].update(
        gateDigest=digest(parent["gate"]),
        gatePlanDigest=digest(gate_plan),
        resource=operation["resource"],
        eventIndex=custom_index,
        requestDigest=digest(operation),
    )

    snapshot = recovery._parent_snapshot(parent)

    assert snapshot["eventIndex"] == custom_index
    assert snapshot["operation"]["binds"] == {
        "customUid": "idToken.sub",
        "customIdToken": "idToken",
        "customRefresh": "refreshToken",
    }
    second_index, second_operation = next(
        (index, operation)
        for index, operation in enumerate(gate_plan["jobs"][credential_gate.JOB]["observation"])
        if operation.get("kind") == "custom-sign-in" and index != custom_index
    )
    parent["gate"]["events"].append({
        "job": credential_gate.JOB,
        "phase": "observation",
        "index": second_index,
        "requestDigest": digest(second_operation),
        "service": second_operation["service"],
        "method": second_operation["method"],
        "completed": False,
        "creationOutcome": "unknown",
        "ended": 999.0,
    })
    parent["immutableParent"]["gateDigest"] = digest(parent["gate"])
    with pytest.raises(recovery.RecoveryRefusal, match="one unresolved"):
        recovery._parent_snapshot(parent)


def test_legacy_http_200_refusal_derives_a_distinct_unknown_responsibility(monkeypatch: pytest.MonkeyPatch) -> None:
    parent = _legacy_parent(monkeypatch)
    snapshot = recovery._parent_snapshot(parent)
    evidence = snapshot["evidence"]
    assert evidence["kind"] == recovery.LEGACY_PARENT_EVIDENCE_KIND
    assert evidence["completed"] is True
    assert evidence["creationOutcome"] == "refused"
    assert evidence["responsibility"] == "unknown-custom-create"
    assert evidence["reason"] == "legacy-200-without-creation-proof"
    assert evidence["eventDigest"] == digest(parent["gate"]["events"][0])
    assert evidence["responseDigest"] == parent["gate"]["events"][0]["responseDigest"]


@pytest.mark.parametrize("mutation", ["incomplete", "non_200", "duplicate", "reserved", "ownership", "bad_response_digest"])
def test_legacy_http_200_refusal_is_a_finite_tuple_not_a_generic_exception(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    parent = _legacy_parent(monkeypatch)
    operation = parent["gate"]["plan"]["jobs"]["auth-credential"]["observation"][0]
    event = parent["gate"]["events"][0]
    if mutation == "incomplete":
        event["completed"] = False
    elif mutation == "non_200":
        event["status"] = 201
    elif mutation == "duplicate":
        parent["gate"]["events"].append(copy.deepcopy(event))
    elif mutation == "reserved":
        operation["body"]["token"] = "$binding:customTokenReserved"
    elif mutation == "ownership":
        parent["gate"]["jobs"]["auth-credential"]["authAccounts"] = {"custom": {"resource": operation["resource"]}}
    else:
        event["responseDigest"] = "z" * 64
    with pytest.raises(recovery.RecoveryRefusal):
        recovery._parent_snapshot(parent)


@pytest.mark.parametrize("field", ["path", "form", "body", "binds"])
def test_parent_custom_sign_in_shape_is_fully_pinned(field: str) -> None:
    parent = _parent()
    operation = parent["gate"]["plan"]["jobs"]["auth-credential"]["observation"][0]
    if field == "path":
        operation[field] = "identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
    elif field == "form":
        operation[field] = True
    elif field == "body":
        operation[field] = {"token": "$binding:customToken"}
    else:
        operation[field] = {"customUid": "otherId"}
    with pytest.raises(recovery.RecoveryRefusal, match="parent (custom resource|Gate) binding"):
        recovery.compile_recovery_plan(parent, recovery_nonce="e" * 32, provenance=_provenance())


def test_detached_plan_cannot_turn_lookup_into_arbitrary_post_or_delete() -> None:
    parent, plan, _permission, _o7, _o8 = _plan()
    tampered = copy.deepcopy(plan)
    tampered["operation"]["method"] = "DELETE"
    tampered["planDigest"] = digest(recovery._stable_plan(tampered))
    with pytest.raises(recovery.RecoveryRefusal, match="lookup"):
        recovery.execute_lookup(tampered, parent, send=lambda *_: (200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}), now=lambda: 1001.0)


def test_authority_window_must_cover_entire_child_deadline() -> None:
    _parent_value, plan, permission, o7, o8 = _plan()
    o8["expiresAt"] = 1050.0
    with pytest.raises(recovery.RecoveryRefusal, match="window"):
        recovery.validate_authority_bundle(plan, permission=permission, o7=o7, o8=o8, now=1001.0)


def test_child_envelope_starts_at_latest_reviewed_authority_issue() -> None:
    parent, plan, permission, o7, o8 = _plan()
    permission["issuedAt"] = 1005.0
    o7["permissionDigest"] = digest(permission)
    o7["issuedAt"] = 1006.0
    o8["permissionDigest"] = digest(permission)
    o8["issuedAt"] = 1007.0
    source_binding = {"kind": "auth-source-binding-v1", "digest": plan["provenance"]["sourceInputsDigest"]}
    transport_binding = {"kind": "auth-transport-binding-v1", "digest": digest(plan["provenance"]["transport"])}
    o7_binding = {"kind": "auth-o7-binding-v1", "digest": digest(o7), "authority": o7}
    o8_binding = {"kind": "auth-o8-binding-v1", "digest": digest(o8), "authority": o8}

    _claim, envelope, _bound_plan = recovery.build_child_claim(
        parent,
        plan,
        permission=permission,
        source_binding=source_binding,
        transport_binding=transport_binding,
        o7_binding=o7_binding,
        o8_binding=o8_binding,
        parent_evidence=recovery._parent_snapshot(parent)["evidence"],
        gate_path="/tmp/auth-recovery-gate",
        owner_identity="owner@example.invalid",
        recovery_owner="recovery@example.invalid",
        now=1008.0,
    )

    assert envelope["issuedAt"] == 1007.0


def test_deadline_cannot_exceed_packet05_admitted_recovery_window() -> None:
    parent = _parent()
    with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
        recovery.compile_recovery_plan(parent, recovery_nonce="e" * 32, provenance=_provenance(), now=1000.0, deadline_seconds=61)


@pytest.mark.parametrize("deadline_seconds", [5, 10, 11])
def test_infeasible_recovery_deadlines_refuse_before_gate_allocation(deadline_seconds: int) -> None:
    parent = _parent()
    with pytest.raises(recovery.RecoveryRefusal, match="deadline|Gate reserve"):
        recovery.compile_recovery_plan(
            parent,
            recovery_nonce="e" * 32,
            provenance=_provenance(),
            now=1000.0,
            deadline_seconds=deadline_seconds,
        )


@pytest.mark.parametrize("deadline_seconds", [12, 20, 60])
def test_feasible_recovery_deadlines_pass_real_shared_gate(
    tmp_path: Path, deadline_seconds: int,
) -> None:
    parent = _parent()
    plan = recovery.compile_recovery_plan(
        parent,
        recovery_nonce="e" * 32,
        provenance=_provenance(),
        now=1000.0,
        deadline_seconds=deadline_seconds,
    )
    shared_gate.create(tmp_path / f"gate-{deadline_seconds}", plan["gatePlan"])
    assert 0 < plan["gatePlan"]["recoverySeconds"] < plan["gatePlan"]["wallSeconds"]
    assert plan["gatePlan"]["recoverySeconds"] >= shared_gate._recovery_time(
        plan["gatePlan"], plan["gatePlan"]["requestSeconds"]
    )


@pytest.mark.parametrize("deadline_seconds", [12, 20, 60])
def test_child_claim_controls_retain_real_gate_feasibility(
    tmp_path: Path, deadline_seconds: int,
) -> None:
    parent = _parent()
    plan = recovery.compile_recovery_plan(
        parent,
        recovery_nonce="e" * 32,
        provenance=_provenance(),
        now=1000.0,
        deadline_seconds=deadline_seconds,
    )
    permission, o7, o8 = _authorities(plan)
    source_binding = {"kind": "auth-source-binding-v1", "digest": plan["provenance"]["sourceInputsDigest"]}
    transport_binding = {"kind": "auth-transport-binding-v1", "digest": digest(plan["provenance"]["transport"])}
    o7_binding = {"kind": "auth-o7-binding-v1", "digest": digest(o7), "authority": o7}
    o8_binding = {"kind": "auth-o8-binding-v1", "digest": digest(o8), "authority": o8}
    _claim, _envelope, bound_plan = recovery.build_child_claim(
        parent,
        plan,
        permission=permission,
        source_binding=source_binding,
        transport_binding=transport_binding,
        o7_binding=o7_binding,
        o8_binding=o8_binding,
        parent_evidence=recovery._parent_snapshot(parent)["evidence"],
        gate_path=str(tmp_path / f"child-{deadline_seconds}"),
        owner_identity="owner@example.invalid",
        recovery_owner="recovery@example.invalid",
        now=1001.0,
    )
    shared_gate.create(tmp_path / f"bound-{deadline_seconds}", bound_plan["gatePlan"])


@pytest.mark.parametrize("claimed_at", [1054.0, 1055.0])
def test_late_child_claim_refuses_when_remaining_gate_window_is_infeasible(
    claimed_at: float,
) -> None:
    parent, plan, permission, o7, o8 = _plan()
    source_binding = {"kind": "auth-source-binding-v1", "digest": plan["provenance"]["sourceInputsDigest"]}
    transport_binding = {"kind": "auth-transport-binding-v1", "digest": digest(plan["provenance"]["transport"])}
    o7_binding = {"kind": "auth-o7-binding-v1", "digest": digest(o7), "authority": o7}
    o8_binding = {"kind": "auth-o8-binding-v1", "digest": digest(o8), "authority": o8}
    with pytest.raises(recovery.RecoveryRefusal, match="deadline|Gate reserve"):
        recovery.build_child_claim(
            parent,
            plan,
            permission=permission,
            source_binding=source_binding,
            transport_binding=transport_binding,
            o7_binding=o7_binding,
            o8_binding=o8_binding,
            parent_evidence=recovery._parent_snapshot(parent)["evidence"],
            gate_path="/tmp/auth-recovery-gate",
            owner_identity="owner@example.invalid",
            recovery_owner="recovery@example.invalid",
            now=claimed_at,
        )


def test_source_commit_cannot_be_overridden_by_detached_parent_field() -> None:
    parent = _parent()
    parent["sourceCommit"] = "2" * 40
    provenance = _provenance()
    provenance["sourceCommit"] = "2" * 40
    provenance["generation"]["sourceCommit"] = "2" * 40
    with pytest.raises(recovery.RecoveryRefusal, match="immutable-parent|source commit"):
        recovery.compile_recovery_plan(parent, recovery_nonce="e" * 32, provenance=provenance, now=1000.0)


def test_child_generation_must_extend_parent_source_closure() -> None:
    parent = _parent()
    provenance = _provenance()
    provenance["generation"] = _parent_generation()
    with pytest.raises(recovery.RecoveryRefusal, match="generation"):
        recovery.compile_recovery_plan(parent, recovery_nonce="e" * 32, provenance=provenance, now=1000.0)


def test_detached_child_source_commit_cannot_bypass_immutable_parent_binding() -> None:
    parent, plan, _permission, _o7, _o8 = _plan()
    tampered = copy.deepcopy(plan)
    tampered["provenance"]["sourceCommit"] = "2" * 40
    tampered["provenance"]["generation"]["sourceCommit"] = "2" * 40
    tampered["planDigest"] = digest(recovery._stable_plan(tampered))
    with pytest.raises(recovery.RecoveryRefusal, match="source commit|parent-linked"):
        recovery.validate_plan(tampered, parent)


@pytest.mark.parametrize("mutation", ["replace", "remove", "extra"])
def test_child_source_closure_rejects_unapproved_mutations_at_validation(mutation: str) -> None:
    parent, plan, _permission, _o7, _o8 = _plan()
    tampered = copy.deepcopy(plan)
    sources = tampered["provenance"]["generation"]["sourceDigests"]
    if mutation == "replace":
        sources["worker.py"] = "c" * 64
    elif mutation == "remove":
        del sources["transport.py"]
    else:
        sources["unapproved.py"] = "d" * 64
    tampered["planDigest"] = digest(recovery._stable_plan(tampered))
    with pytest.raises(recovery.RecoveryRefusal, match="source closure|generation"):
        recovery.validate_plan(tampered, parent)


def test_child_source_closure_accepts_only_the_approved_recovery_extension() -> None:
    parent, plan, _permission, _o7, _o8 = _plan()
    assert recovery.validate_plan(plan, parent)["provenance"]["generation"]["sourceDigests"] == {
        "worker.py": "a" * 64,
        "transport.py": "b" * 64,
        "recovery.py": "f" * 64,
    }


@pytest.mark.parametrize("deadline_seconds", [20, 60])
def test_child_gate_plan_is_accepted_by_real_shared_gate(
    tmp_path: Path, deadline_seconds: int
) -> None:
    parent = _parent()
    plan = recovery.compile_recovery_plan(
        parent,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        provenance=_provenance(),
        now=1000.0,
        deadline_seconds=deadline_seconds,
    )

    shared_gate.create(tmp_path / f"child-{deadline_seconds}", plan["gatePlan"])


class _Ledger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    def begin_auth_recovery_extension(self, parent_ticket, child_claim, envelope, canonical_child_gate_plan, *, source_binding, transport_binding, o7_binding, o8_binding, parent_evidence, now=None):
        self.calls.append(("begin", (parent_ticket, child_claim, envelope, canonical_child_gate_plan), {"source_binding": source_binding, "transport_binding": transport_binding, "o7_binding": o7_binding, "o8_binding": o8_binding, "parent_evidence": parent_evidence, "now": now}))
        assert set(child_claim) == {"kind", "version", "campaignId", "manifestDigest", "nonceDigest", "gatePath", "gateJob", "parentGateJob", "gatePlanDigest", "parentClaimDigest", "parentPlanDigest", "parentGateDigest", "parentEvidenceDigest", "parentEventIndex", "parentRequestDigest", "recoveryNonce", "resourceDigest", "ownedResources", "locks", "budget", "durationSeconds", "generation", "ownerIdentity", "recoveryOwner", "operationClass", "readCount", "inspectionCount", "absenceCount", "deleteCount", "expiresAt", "executionHost", "permissionDigest", "sourceBindingDigest", "transportBindingDigest", "o7BindingDigest", "o8BindingDigest"}
        assert set(envelope) == {"permissionDigest", "issuedAt", "expiresAt", "limits", "concurrency", "scopes"}
        assert child_claim["kind"] == "auth-custom-uid-recovery-child-v1"
        assert child_claim["budget"]["accounts"] == 1
        assert canonical_child_gate_plan["project"] == recovery.PROJECT
        assert canonical_child_gate_plan["jobs"][recovery.GATE_JOB]["accountBindings"] == {"custom": {"resource": child_claim["ownedResources"][0], "uidBinding": "customUid"}}
        assert canonical_child_gate_plan["jobs"][recovery.GATE_JOB]["recovery"][0]["method"] == "POST"
        return {"child": "ticket", "parentReservation": parent_ticket["reservation"]}

    def settle_auth_recovery_child(self, child_ticket, *, absence_proof, receipt_digest, now=None):
        self.calls.append(("settle", (child_ticket,), {"absence_proof": absence_proof, "receipt_digest": receipt_digest, "now": now}))
        assert absence_proof["kind"] == recovery.ABSENCE_KIND
        return {"child": "ticket", "state": "settled"}

    def close_after_auth_recovery_child(self, parent_ticket, child_ticket, *, receipt_digest, now=None):
        self.calls.append(("close", (parent_ticket, child_ticket), {"receipt_digest": receipt_digest, "now": now}))
        return {"state": "closed-after-recovery-child"}


def test_begin_matches_api924_and_does_not_touch_parent() -> None:
    parent, plan, permission, o7, o8 = _plan()
    ledger = _Ledger()
    ticket = recovery.begin_child(ledger, parent_ticket=parent["ticket"], parent=parent, plan=plan, permission=permission, o7=o7, o8=o8, now=1001.0)
    assert ticket["child"] == "ticket"
    assert [name for name, _args, _kwargs in ledger.calls] == ["begin"]
    assert parent["state"] == "held"


@pytest.mark.parametrize("answer,reason", [((200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": [{"localId": "x"}]}), "present"), ((200, {"users": []}), "malformed"), ((200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": ["bad"]}), "present"), ((200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}), "late")])
def test_lookup_refuses_nonempty_malformed_or_late_and_sends_once(answer, reason) -> None:
    parent, plan, _permission, _o7, _o8 = _plan()
    calls = []
    def send(operation, timeout):
        calls.append(operation)
        if reason == "late":
            return answer
        return answer
    clock = iter((1001.0, 1060.0)) if reason == "late" else iter((1001.0, 1001.0))
    with pytest.raises(recovery.RecoveryRefusal, match="late|present|malformed|deadline"):
        recovery.execute_lookup(plan, parent, send=send, now=lambda: next(clock))
    assert len(calls) == 1


def test_typed_empty_result_is_secret_free_and_only_one_send() -> None:
    parent, plan, _permission, _o7, _o8 = _plan()
    calls = []
    result = recovery.execute_lookup(plan, parent, send=lambda operation, timeout: (calls.append(operation) or (200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []})), now=lambda: 1001.0)
    assert result["disposition"] == "typed-empty"
    assert result["lookupCount"] == 1
    assert len(calls) == 1
    assert "custom-" not in repr(result)


def test_settlement_derives_absence_from_bound_gate_and_receipt() -> None:
    parent, plan, _permission, o7, o8 = _plan()
    gate = _terminal_gate(plan, o7, o8)
    receipt = _worker_receipt(gate)
    ledger = _Ledger()
    outcome = recovery.settle_and_close(ledger, parent_ticket=parent["ticket"], child_ticket={"child": "ticket"}, parent=parent, plan=plan, child_gate=gate, worker_receipt=receipt)
    assert outcome["state"] == "closed-after-recovery-child"
    assert [name for name, _args, _kwargs in ledger.calls] == ["settle", "close"]


def test_real_gate_one_typed_empty_lookup_then_settlement_boundary(tmp_path: Path) -> None:
    parent, plan, _permission, o7, o8 = _plan()
    gate_path = tmp_path / "real-child-gate"
    shared_gate.create(gate_path, plan["gatePlan"])
    calls: list[dict] = []
    result = recovery.execute_lookup(
        plan,
        parent,
        send=lambda operation, _timeout: (
            calls.append(operation)
            or (200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []})
        ),
        now=lambda: 1001.0,
    )
    gate = _terminal_gate(plan, o7, o8)
    receipt = _worker_receipt(gate)
    outcome = recovery.settle_and_close(
        _Ledger(),
        parent_ticket=parent["ticket"],
        child_ticket={"child": "ticket"},
        parent=parent,
        plan=plan,
        child_gate=gate,
        worker_receipt=receipt,
    )

    assert result["disposition"] == "typed-empty"
    assert len(calls) == 1
    assert outcome["state"] == "closed-after-recovery-child"
    assert gate_path.joinpath("lock").is_file()


def test_forged_empty_result_or_gate_event_never_reaches_ledger() -> None:
    parent, plan, _permission, o7, o8 = _plan()
    gate = _terminal_gate(plan, o7, o8)
    gate["events"][0]["responseDigest"] = "a" * 64
    ledger = _Ledger()
    with pytest.raises(recovery.RecoveryRefusal, match="absence"):
        recovery.settle_and_close(ledger, parent_ticket=parent["ticket"], child_ticket={"child": "ticket"}, parent=parent, plan=plan, child_gate=gate, worker_receipt=_worker_receipt(gate))
    assert ledger.calls == []


def test_forged_worker_receipt_never_reaches_ledger() -> None:
    parent, plan, _permission, o7, o8 = _plan()
    gate = _terminal_gate(plan, o7, o8)
    receipt = _worker_receipt(gate)
    receipt["responseDigest"] = "a" * 64
    ledger = _Ledger()
    with pytest.raises(recovery.RecoveryRefusal, match="receipt"):
        recovery.settle_and_close(ledger, parent_ticket=parent["ticket"], child_ticket={"child": "ticket"}, parent=parent, plan=plan, child_gate=gate, worker_receipt=receipt)
    assert ledger.calls == []


def test_child_gate_cannot_extend_past_admitted_deadline() -> None:
    parent, plan, _permission, o7, o8 = _plan()
    gate = _terminal_gate(plan, o7, o8)
    gate["plan"]["wallSeconds"] = 10_000
    gate["planDigest"] = digest(gate["plan"])
    ledger = _Ledger()
    with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
        recovery.settle_and_close(ledger, parent_ticket=parent["ticket"], child_ticket={"child": "ticket"}, parent=parent, plan=plan, child_gate=gate, worker_receipt=_worker_receipt(gate))
    assert ledger.calls == []


def test_diagnostic_projection_is_secret_free_and_typed() -> None:
    projection = recovery.custom_sign_in_diagnostic(200, {"localId": "uid", "isNewUser": False, "idToken": "secret", "refreshToken": "secret"})
    assert projection == {"status": 200, "bodyType": "object", "localId": "present", "isNewUser": "boolean-false", "tokens": {"idToken": "present", "refreshToken": "present"}}
    assert "secret" not in repr(projection)


def test_real_shared_api924_accepts_canonical_child_and_rejects_overrides(tmp_path) -> None:
    """Exercise the successor Ledger implementation, not a permissive stub."""
    source = subprocess.check_output(["git", "show", "4ad1034f5:tools/compat-broad/production-admission/reservations.py"])
    module_path = tmp_path / "reservations_final.py"
    module_path.write_bytes(source)
    spec = importlib.util.spec_from_file_location("reservations_final", module_path)
    assert spec is not None and spec.loader is not None
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    import shared_gate

    parent = _parent()
    gate_path = tmp_path / "parent-gate"
    parent["plan"]["jobs"]["auth-credential"]["resources"] = [parent["immutableParent"]["resource"]]
    gate_path.mkdir(mode=0o700)
    (gate_path / "lock").touch(mode=0o600)
    shared_gate._save(gate_path, {"plan": parent["plan"], "planDigest": digest(parent["plan"]), "jobs": {"auth-credential": {"inflight": False}}, "events": [{**parent["gate"]["events"][0]}], "coordinatorInflight": False})
    parent["claim"]["gatePath"] = str(gate_path.resolve())
    parent["claim"]["gatePlanDigest"] = digest(parent["plan"])
    parent["gate"] = shared_gate.Gate(gate_path, "auth-credential").snapshot()
    parent["immutableParent"]["gateDigest"] = digest(parent["gate"])
    parent["immutableParent"]["gatePlanDigest"] = digest(parent["plan"])
    parent["claim"]["claimDigest"] = digest({key: value for key, value in parent["claim"].items() if key != "claimDigest"})

    parent_claim = {"campaignId": recovery.CAMPAIGN, "manifestDigest": digest(parent["plan"]), "nonceDigest": parent["claim"]["nonceDigest"], "gatePath": str(gate_path.resolve()), "gatePlanDigest": digest(parent["plan"]), "gateJob": "auth-credential", "locks": [{"key": f"project/{recovery.PROJECT}/auth/accounts/{parent['immutableParent']['resource'].rsplit('/', 1)[1]}", "mode": "WRITE"}], "budget": {"requests": 1, "accounts": 1, "resources": 1, "costMicrousd": 1}, "durationSeconds": 120}
    parent_envelope = {"permissionDigest": "9" * 64, "issuedAt": 900.0, "expiresAt": 2000.0, "limits": parent_claim["budget"], "concurrency": 1, "scopes": [{"key": parent_claim["locks"][0]["key"], "mode": "WRITE"}]}
    ledger = shared.Ledger.create(tmp_path / "ledger")
    state = ledger.snapshot()
    envelope_digest = digest(parent_envelope)
    state["envelopes"][envelope_digest] = {"envelope": parent_envelope, "allocated": parent_claim["budget"]}
    reservation = "p" * 64
    parent_ticket = {"ledgerPath": str(ledger.path), "ledgerIdentity": ledger.identity, "reservation": reservation, "claimDigest": digest(parent_claim), "envelopeDigest": envelope_digest}
    state["reservations"][reservation] = {"claim": parent_claim, "claimDigest": digest(parent_claim), "envelopeDigest": envelope_digest, "state": "held", "deadline": 1100.0, "generation": parent["generation"]}
    shared._save(ledger.path, state)
    parent["ticket"] = parent_ticket
    parent["claim"].update(parent_claim)
    parent["claim"]["claimDigest"] = digest(parent_claim)

    ledger_parent = copy.deepcopy(parent)
    plan = recovery.compile_recovery_plan(ledger_parent, recovery_nonce="fedcba9876543210fedcba9876543210", provenance=_provenance(), now=1000.0, deadline_seconds=60)
    detached_plan = copy.deepcopy(plan)
    detached_plan["provenance"]["sourceCommit"] = "2" * 40
    detached_plan["provenance"]["generation"]["sourceCommit"] = "2" * 40
    detached_plan["planDigest"] = digest(recovery._stable_plan(detached_plan))
    detached_permission, detached_o7, detached_o8 = _authorities(detached_plan)
    before_detached = json.dumps(ledger.snapshot(), sort_keys=True)
    with pytest.raises(recovery.RecoveryRefusal, match="source commit|parent-linked"):
        recovery.begin_child(ledger, parent_ticket=parent_ticket, parent=ledger_parent, plan=detached_plan, permission=detached_permission, o7=detached_o7, o8=detached_o8, gate_path=str(tmp_path / "detached-child-gate"), now=1001.0)
    assert json.dumps(ledger.snapshot(), sort_keys=True) == before_detached
    permission, o7, o8 = _authorities(plan)
    child_ticket = recovery.begin_child(ledger, parent_ticket=parent_ticket, parent=ledger_parent, plan=plan, permission=permission, o7=o7, o8=o8, gate_path=str(tmp_path / "child-gate"), now=1001.0)
    assert child_ticket["parentReservation"] == reservation
    persisted = ledger.bound_auth_recovery_claim(child_ticket)
    assert persisted["childClaim"]["operationClass"] == recovery.OPERATION_CLASS
    assert persisted["childClaim"]["generation"] != parent["generation"]
    before = json.dumps(ledger.snapshot(), sort_keys=True)
    tampered = copy.deepcopy(persisted["childClaim"])
    tampered["sourceBindingDigest"] = "0" * 64
    assert tampered["sourceBindingDigest"] != persisted["childClaim"]["sourceBindingDigest"]
    source_binding = {"kind": "auth-source-binding-v1", "digest": plan["provenance"]["sourceInputsDigest"]}
    transport_binding = {"kind": "auth-transport-binding-v1", "digest": digest(plan["provenance"]["transport"])}
    o7_binding = {"kind": "auth-o7-binding-v1", "digest": digest(o7), "authority": o7}
    o8_binding = {"kind": "auth-o8-binding-v1", "digest": digest(o8), "authority": o8}
    bound_plan = recovery._bound_plan(plan, source_binding=source_binding, transport_binding=transport_binding, o7_binding=o7_binding, o8_binding=o8_binding)
    with pytest.raises(ValueError, match="authority binding"):
        ledger.begin_auth_recovery_extension(
            parent_ticket,
            tampered,
            persisted["newEnvelope"],
            bound_plan["gatePlan"],
            source_binding=source_binding,
            transport_binding=transport_binding,
            o7_binding=o7_binding,
            o8_binding=o8_binding,
            parent_evidence=recovery._parent_snapshot(ledger_parent)["evidence"],
            now=1001.0,
        )
    assert json.dumps(ledger.snapshot(), sort_keys=True) == before
