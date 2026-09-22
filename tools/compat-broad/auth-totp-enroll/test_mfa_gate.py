"""The Gate facade: the frozen plan is what the shared Gate creates and the walk sends."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import reservations
import shared_gate

import mfa_gate
from mfa_cases import owned_accounts

NONCE = "e" * 32


def plan(wall=1200, recovery=300):
    import time

    value = mfa_gate.gate_plan(
        NONCE, wall_seconds=wall, recovery_seconds=recovery, cost_microusd=100_006
    )
    value["permissionExpiresAt"] = time.time() + 7200
    return value


def test_the_frozen_plan_is_created_by_the_shared_gate_at_its_wall_cap(tmp_path):
    value = plan()
    mfa_gate.create(tmp_path / "gate", value)
    gate = mfa_gate.MfaGate(tmp_path / "gate")
    snapshot = gate.snapshot()
    job = snapshot["plan"]["jobs"][mfa_gate.JOB]
    assert len(job["observation"]) == 93
    assert len(job["recovery"]) == 42
    assert job["resources"] == [
        mfa_gate.account_resource("fireemu-35fe6", NONCE, role)
        for role in mfa_gate.ROLE_ORDER
    ]
    assert job["accountBindings"] == {
        role: {
            "resource": mfa_gate.account_resource("fireemu-35fe6", NONCE, role),
            "uidBinding": f"{mfa_gate._camel(role)}Uid",
        }
        for role in mfa_gate.ROLE_ORDER
    }
    for phase in ("observation", "recovery"):
        for operation in job[phase]:
            if operation.get("account") is not None:
                assert operation["resource"] == job["accountBindings"][operation["account"]]["resource"]
                assert operation["uidBinding"] == job["accountBindings"][operation["account"]]["uidBinding"]
    assert snapshot["plan"]["accountResources"] == [
        f"projects/fireemu-35fe6/auth/accounts/o2-mfa-{role}-{NONCE}"
        for role in mfa_gate.ROLE_ORDER
    ]
    assert set(mfa_gate.ROLE_ORDER) == set(owned_accounts())
    assert snapshot["plan"]["configResource"] == "projects/fireemu-35fe6/auth/config"
    # Only the base Gate's own non-creating recipes are declared non-creating.
    declared = [entry for entry in job["schedule"] if entry.get("creates") is False]
    assert all(
        job["observation"][entry["index"]]["kind"] in ("sign-in", "lookup")
        for entry in declared
    )
    assert declared


def test_the_selected_gate_plan_has_one_account_and_the_three_case_closure():
    value = mfa_gate.gate_plan(
        NONCE,
        wall_seconds=1200,
        recovery_seconds=300,
        cost_microusd=100_006,
        selector="pending-age-300-v1",
    )
    job = value["jobs"][mfa_gate.JOB]
    assert value["selector"] == "pending-age-300-v1"
    assert value["plannedAccounts"] == ["pending-age-300"]
    assert len(job["observation"]) == 11
    assert len(job["recovery"]) == 4
    assert len(job["accountBindings"]) == 1
    assert all(
        operation.get("account") == "pending-age-300"
        for operation in (*job["observation"], *job["recovery"])
    )


def test_the_plan_above_the_wall_cap_is_refused_by_the_shared_gate(tmp_path):
    with pytest.raises(ValueError, match="invalid shared allocation"):
        mfa_gate.create(tmp_path / "gate", plan(wall=2700, recovery=300))


def test_the_ledger_refuses_the_auth_resources_by_name():
    for name in (
        *mfa_gate.route_resources("fireemu-35fe6"),
        mfa_gate.account_resource("fireemu-35fe6", NONCE, "pending-control"),
        mfa_gate.config_resource("fireemu-35fe6"),
    ):
        with pytest.raises(ValueError, match="canonical Firestore resource required"):
            reservations._firestore_resource_scope(name)
    assert shared_gate.typed_absence(200, {"users": []}) is False


def test_each_mfa_signup_extracts_its_declared_camel_uid_binding(tmp_path):
    value = plan()
    signup = next(
        operation
        for operation in value["jobs"][mfa_gate.JOB]["observation"]
        if operation["kind"] == "sign-up" and operation["account"] == "pending-control"
    )
    signup["binds"]["pendingControlUid"] = "idToken"
    with pytest.raises(ValueError, match="signup UID binding differs"):
        mfa_gate.create(tmp_path / "gate", value)


def test_mfa_foreign_resource_and_uid_binding_are_refused_before_creation(tmp_path):
    value = plan()
    recovery = value["jobs"][mfa_gate.JOB]["recovery"][0]
    recovery["resource"] = mfa_gate.account_resource(
        "fireemu-35fe6", NONCE, "pending-age-2"
    )
    with pytest.raises(ValueError, match="resource binding differs"):
        mfa_gate.create(tmp_path / "foreign-resource", value)

    value = plan()
    value["jobs"][mfa_gate.JOB]["recovery"][0]["uidBinding"] = "pendingAge2Uid"
    with pytest.raises(ValueError, match="UID binding differs"):
        mfa_gate.create(tmp_path / "foreign-binding", value)


def test_cleanup_authorization_rejects_cross_role_uid_collision(tmp_path):
    value = plan()
    job_name = mfa_gate.JOB
    observation = value["jobs"][job_name]["observation"]
    first = next(
        (index, operation)
        for index, operation in enumerate(observation)
        if operation["kind"] == "sign-up" and operation["account"] == "pending-control"
    )
    second = next(
        (index, operation)
        for index, operation in enumerate(observation)
        if operation["kind"] == "sign-up" and operation["account"] == "pending-age-300"
    )
    events = [
        {
            "job": job_name,
            "phase": "observation",
            "index": index,
            "requestDigest": shared_gate.digest(operation),
            "completed": True,
            "creationOutcome": "created",
            "authEvidence": {"account": operation["account"], "creationOutcome": "created"},
        }
        for index, operation in (first, second)
    ]
    state = {"plan": value, "events": events}
    job = {
        "authAccounts": {
            "pending-control": {"uid": "same-uid", "createEvent": 0, "resource": first[1]["resource"]},
            "pending-age-300": {"uid": "same-uid", "createEvent": 1, "resource": second[1]["resource"]},
        }
    }
    delete = next(
        operation
        for operation in value["jobs"][job_name]["recovery"]
        if operation["kind"] == "delete" and operation["account"] == "pending-control"
    )
    assert shared_gate._auth_creation_ownership(state, job, delete) is False


def test_no_binding_value_is_in_the_plan_and_every_placeholder_is_declared():
    value = plan()
    names = set()
    for phase in ("observation", "recovery"):
        for operation in value["jobs"][mfa_gate.JOB][phase]:
            stack = [operation["body"]]
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
                elif isinstance(item, str) and item.startswith("$binding:"):
                    names.add(item.removeprefix("$binding:"))
    observed = {
        name
        for phase in ("observation", "recovery")
        for operation in value["jobs"][mfa_gate.JOB][phase]
        for name in operation["binds"]
    }
    unbound = names - observed - set(mfa_gate.MINTED_BINDINGS)
    assert unbound == set()
    assert "password" in names and "totpSignIn" in names


def test_the_facade_refuses_a_request_outside_its_slot_and_a_skip_of_a_creating_slot(
    tmp_path,
):
    mfa_gate.create(tmp_path / "gate", plan())
    gate = mfa_gate.MfaGate(tmp_path / "gate")
    gate.claim()
    with pytest.raises(ValueError, match="outside closed scenario"):
        gate.dispatch_runtime(
            "/v1/accounts:lookup",
            {"idToken": "x"},
            owner=False,
            recovery=False,
            send=lambda: (200, {}),
        )
    with pytest.raises(ValueError, match="can be skipped"):
        gate.skip_planned("not a finalize")


# --- admission properties, each with a test that fails if the check is removed -------


def _claimed_gate(tmp_path):
    mfa_gate.create(tmp_path / "gate", plan())
    gate = mfa_gate.MfaGate(tmp_path / "gate")
    gate.claim()
    return gate


def _preflight(gate):
    """Charge the four observation management slots so data dispatch is admitted."""
    attestation = {
        "kind": "request-byte-token-attestation-v1",
        "principalDigest": "a" * 64,
        "requiredScopeVerified": True,
        "identityMode": "subject",
        "identityVerified": True,
        "oauthClientVerified": True,
        "expiresInSeconds": 3599,
        "remainingSecondsAtVerification": 3599.0,
        "requiredSeconds": 240.0,
        "complete": True,
        "workerReaped": True,
    }
    for slot in mfa_gate.MANAGEMENT_OBSERVATION_IDS:
        body = attestation if slot == "oauth-tokeninfo" else {"name": "x"}
        gate.management_dispatch(
            "observation",
            slot,
            lambda _deadline, body=body: {
                "status": 200,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": body,
            },
        )


def _sign_up(gate, uid="uid-1"):
    return gate.dispatch_runtime(
        "/v1/accounts:signUp",
        {
            "email": f"o2-mfa-pending-control-{NONCE}@example.com",
            "password": "Aa9!x" * 4,
            "returnSecureToken": True,
        },
        owner=False,
        recovery=False,
        send=lambda: (
            200,
            {
                "localId": uid,
                "idToken": "idt-" + uid,
                "email": f"o2-mfa-pending-control-{NONCE}@example.com",
            },
        ),
    )


def test_a_value_the_run_did_not_observe_is_refused_at_dispatch(tmp_path):
    gate = _claimed_gate(tmp_path)
    _preflight(gate)
    _sign_up(gate)
    # The next slot is the admin update carrying `$binding:pendingControlUid`.
    with pytest.raises(ValueError, match="runtime binding differs"):
        gate.dispatch_runtime(
            "/v1/projects/fireemu-35fe6/accounts:update",
            {"localId": "some-other-uid", "emailVerified": True},
            owner=True,
            recovery=False,
            send=lambda: (200, {}),
        )
    snapshot = gate.snapshot()
    assert snapshot["jobs"][mfa_gate.JOB]["observation"] == 1
    gate.dispatch_runtime(
        "/v1/projects/fireemu-35fe6/accounts:update",
        {"localId": "uid-1", "emailVerified": True},
        owner=True,
        recovery=False,
        send=lambda: (200, {"localId": "uid-1"}),
    )


def test_a_minted_value_is_pinned_on_first_use(tmp_path):
    gate = _claimed_gate(tmp_path)
    _preflight(gate)
    _sign_up(gate)
    gate.dispatch_runtime(
        "/v1/projects/fireemu-35fe6/accounts:update",
        {"localId": "uid-1", "emailVerified": True},
        owner=True,
        recovery=False,
        send=lambda: (200, {}),
    )
    # The sign-in carries the minted password, which must equal the signup's.
    with pytest.raises(ValueError, match="runtime binding differs"):
        gate.dispatch_runtime(
            "/v1/accounts:signInWithPassword",
            {
                "email": f"o2-mfa-pending-control-{NONCE}@example.com",
                "password": "other",
                "returnSecureToken": True,
            },
            owner=False,
            recovery=False,
            send=lambda: (200, {}),
        )


def test_a_changed_account_identity_is_refused(tmp_path):
    gate = _claimed_gate(tmp_path)
    operation = mfa_gate.observation_operations(NONCE)[0]
    state = {"jobs": {mfa_gate.JOB: {"authAccounts": {}}}, "events": [{}]}
    gate._record_auth_response(
        state,
        operation,
        False,
        state["events"][0],
        200,
        {"localId": "uid-1", "idToken": "t1"},
    )
    assert (
        state["jobs"][mfa_gate.JOB]["authAccounts"]["pending-control"]["uid"] == "uid-1"
    )
    state["events"].append({})
    with pytest.raises(ValueError, match="identity binding is immutable"):
        gate._record_auth_response(
            state,
            operation,
            False,
            state["events"][1],
            200,
            {"localId": "uid-2", "idToken": "t2"},
        )


def test_acknowledged_signup_records_uid_for_shared_cleanup_ownership(tmp_path):
    gate = _claimed_gate(tmp_path)
    _preflight(gate)
    _sign_up(gate, uid="uid-ack")
    snapshot = gate.snapshot()
    record = snapshot["jobs"][mfa_gate.JOB]["authAccounts"]["pending-control"]
    creation = snapshot["events"][record["createEvent"]]
    assert creation["authEvidence"]["uid"] == "uid-ack"
    delete = next(
        operation
        for operation in snapshot["plan"]["jobs"][mfa_gate.JOB]["recovery"]
        if operation["kind"] == "delete" and operation["account"] == "pending-control"
    )
    assert shared_gate._auth_creation_ownership(
        snapshot, snapshot["jobs"][mfa_gate.JOB], delete
    ) is True


def test_cleanup_of_an_account_the_run_never_created_is_refused(tmp_path):
    gate = _claimed_gate(tmp_path)
    delete = next(
        operation
        for operation in mfa_gate.recovery_operations(NONCE)
        if operation["kind"] == "delete"
    )
    state = {
        "jobs": {mfa_gate.JOB: {"authAccounts": {}, "resources": [], "absent": []}},
        "events": [{}],
    }
    with pytest.raises(ValueError, match="never created"):
        gate._record_auth_response(
            state,
            delete,
            True,
            {"responseDigest": "x"},
            200,
            {"kind": "identitytoolkit#DeleteAccountResponse"},
        )


def test_an_unsettled_signup_is_neither_skipped_nor_settled_twice(tmp_path):
    gate = _claimed_gate(tmp_path)
    _preflight(gate)

    def lost():
        raise ValueError("answer lost")

    with pytest.raises(ValueError, match="answer lost"):
        gate.dispatch_runtime(
            "/v1/accounts:signUp",
            {
                "email": f"o2-mfa-pending-control-{NONCE}@example.com",
                "password": "Aa9!x" * 4,
                "returnSecureToken": True,
            },
            owner=False,
            recovery=False,
            send=lost,
        )
    assert gate.unsettled_accounts() == ["pending-control"]
    gate.abandon_observation("test")
    # Its cleanup slots are neither sent nor skipped until a readback settles it.
    assert gate.drain_recovery() == 0
    assert gate.snapshot()["jobs"][mfa_gate.JOB]["recovery"] == 0
    with pytest.raises(ValueError, match="outside closed scenario"):
        gate.dispatch_runtime(
            "/v1/projects/fireemu-35fe6/accounts:delete",
            {"localId": "uid-9"},
            owner=True,
            recovery=True,
            send=lambda: (200, {}),
        )
    assert gate.unsettled_accounts() == ["pending-control"]
    with pytest.raises(ValueError, match="direct account settlement"):
        gate.settle_creation("pending-control", "uid-9", evidence={})


def test_address_reconciliation_accepts_typed_presence_and_kind_only_absence(tmp_path):
    gate = _claimed_gate(tmp_path)
    operation = next(
        item
        for item in mfa_gate.recovery_operations(NONCE)
        if item["kind"] == "address-reconcile" and item["account"] == "pending-control"
    )
    email = operation["body"]["email"][0]
    assert gate._reconcile_uid(
        operation,
        200,
        {"kind": "identitytoolkit#GetAccountInfoResponse", "users": [{"email": email, "localId": "uid-1"}]},
    ) == {"uid": "uid-1", "ownership": "email-only-unproven"}
    assert gate._reconcile_uid(
        operation, 200, {"kind": "identitytoolkit#GetAccountInfoResponse"}
    ) is None
    assert gate._reconcile_uid(operation, 200, {"users": []}) is None
    for body in ({}, {"kind": "wrong", "users": []}):
        with pytest.raises(ValueError):
            gate._reconcile_uid(operation, 200, body)


def test_email_only_presence_is_held_without_adoption_or_cleanup(tmp_path):
    gate = _claimed_gate(tmp_path)
    operation = next(
        item
        for item in mfa_gate.recovery_operations(NONCE)
        if item["kind"] == "address-reconcile" and item["account"] == "pending-control"
    )
    signup = next(
        item
        for item in mfa_gate.observation_operations(NONCE)
        if item["kind"] == "sign-up" and item["account"] == "pending-control"
    )
    with gate.locked() as state:
        state["events"] = [
            {
                "job": mfa_gate.JOB,
                "phase": "observation",
                "index": mfa_gate.observation_operations(NONCE).index(signup),
                "creationOutcome": "unknown",
                "settlementOutcome": None,
            },
            {
                "job": mfa_gate.JOB,
                "phase": "recovery",
                "index": mfa_gate.recovery_operations(NONCE).index(operation),
                "completed": True,
                "authEvidence": {
                    "account": "pending-control",
                    "uid": "foreign-uid",
                    "ownership": "email-only-unproven",
                    "responseDigest": "a" * 64,
                },
            },
        ]
        mfa_gate._save(gate.path, state)
    settled = gate.settle_reconciled_creation("pending-control")
    assert settled == {
        "role": "pending-control",
        "uid": "foreign-uid",
        "adopted": False,
        "held": True,
    }
    snapshot = gate.snapshot()
    assert snapshot["jobs"][mfa_gate.JOB].get("authAccounts", {}) == {}
    assert gate.unsettled_accounts() == ["pending-control"]


def test_adoption_requires_the_recorded_processes_to_be_gone(tmp_path, monkeypatch):
    import os

    gate = _claimed_gate(tmp_path)
    real = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real + 100_000)
    with pytest.raises(ValueError, match="still alive"):
        gate.adopt()
    monkeypatch.setattr(mfa_gate, "_process_alive", lambda pid: False)
    record = gate.adopt()
    assert record["from"] == [real, real] and record["to"] == real + 100_000
    snapshot = gate.snapshot()
    assert (
        snapshot["coordinatorPid"]
        == snapshot["jobs"][mfa_gate.JOB]["pid"]
        == real + 100_000
    )
    assert snapshot["adoptions"] == [record]
