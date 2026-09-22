"""Bounded tests for the Rules production bridge seam."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace as Namespace

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "o8-core"))
sys.path.insert(0, str(HERE.parent / "production-admission"))
sys.path.insert(0, str(HERE))

import o5_user_token_case as case
import o5_user_token_production_bridge as bridge
import o5_user_token_descriptor as descriptor
import shared_gate
from o5_user_token_collector import open_ownership_journal
from o5_user_token_campaign import validate_production_packet
from broad_contract import digest
from reservations import Ledger


def _plan():
    return case.compile_case("fireemu-35fe6", "(default)", "a" * 32, "tenant-test")


def _owned_account_gate(tmp_path):
    plan = descriptor.gate_plan(
        _plan(), permission_expires_at=time.time() + 900
    )
    path = tmp_path / "gate"
    shared_gate.create(path, plan)
    gate = shared_gate.Gate(path, "rules-management")
    gate.claim()
    effect = {
        "subject": "account/owner-a",
        "proof": {
            "kind": "account",
            "accountRef": "owner-a",
            "tenantId": None,
            "uid": "uid-owner",
        },
    }
    receipt = {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": {
            "kind": "rules-management-proof-v1",
            "responseDigest": "0" * 64,
            "effects": [effect],
        },
    }
    gate.management_dispatch(
        "observation", "setup/account/owner-a/signup", lambda _deadline: receipt
    )
    gate.cancel_management_observation()
    return gate, receipt


def _prefix_digest(gate):
    snapshot = gate.snapshot()
    return digest(
        {"used": snapshot["managementUsed"], "skipped": snapshot["managementSkipped"]}
    )


def test_initial_packet_uses_admin_and_api_key_without_preexisting_users(tmp_path):
    plan = _plan()
    path = tmp_path / "gate"
    shared_gate.create(path, descriptor.gate_plan(plan))
    result = validate_production_packet(
        plan,
        approval={"status": "approved"},
        permission={"campaignId": plan["campaignId"], "planDigest": plan["planDigest"]},
        capability_inputs={"plan": plan, "planDigest": digest(plan)},
        credentials={"administrator": "fixture-admin", "api-key": "fixture-key"},
        account_bindings={},
        identity_proofs={},
        gate=shared_gate.Gate(path, "rules-management"),
        ledger=Ledger.create(tmp_path / "ledger"),
        ticket={},
    )
    assert result["requestUpperBound"] == 144


def test_shared_inventory_preserves_authoritative_gate_status(tmp_path):
    plan = _plan()
    path = tmp_path / "gate"
    shared_gate.create(path, descriptor.gate_plan(plan))
    gate = shared_gate.Gate(path, "rules-management")
    ownership = {}
    before = gate.snapshot()
    bridge.refresh_ownership(gate, ownership)
    assert len(ownership) == 21
    assert all(state["status"] == "not-attempted" for state in ownership.values())
    assert gate.snapshot() == before


@pytest.mark.parametrize(
    "subject",
    ["document/owned-a", "account/other-b", "account/foreign"],
)
def test_gate_rejects_forged_or_not_yet_owned_recovery_holds(tmp_path, subject):
    gate, _receipt = _owned_account_gate(tmp_path)
    state = gate.snapshot()
    state["rulesRecoveryHeld"] = {
        subject: {"kind": "identity-proof-unavailable-v1", "failure": "ValueError"}
    }
    shared_gate._save(gate.path, state)
    with pytest.raises(ValueError, match="held recovery"):
        gate.snapshot()


def test_gate_rejects_hold_after_account_recovery_read(tmp_path):
    gate, receipt = _owned_account_gate(tmp_path)
    target = "cleanup/account/owner-a/read"
    for slot in gate.snapshot()["plan"]["management"]["recovery"]:
        if slot["id"] == target:
            break
        before = gate.snapshot()
        gate.skip_management_recovery(
            slot["id"],
            expected_plan_digest=before["planDigest"],
            expected_prefix_digest=_prefix_digest(gate),
        )
    gate.management_dispatch("recovery", target, lambda _deadline: receipt)
    before = gate.snapshot()
    with pytest.raises(ValueError, match="already entered recovery"):
        gate.hold_management_recovery(
            "account/owner-a",
            expected_plan_digest=before["planDigest"],
            expected_prefix_digest=_prefix_digest(gate),
            failure="ValueError",
        )


def test_worker_timeout_uses_the_compiled_slot_bound():
    assert bridge.worker_timeout({"kind": "rules-lifecycle"}, None) == 12.0
    assert bridge.worker_timeout({"kind": "observation"}, None) == 2.0
    assert bridge.worker_timeout({"phase": "recovery"}, None) == 2.0


def test_worker_timeout_refuses_expired_deadline():
    with pytest.raises(TimeoutError, match="deadline"):
        bridge.worker_timeout({"kind": "observation"}, 0.0)


def test_data_denial_projects_only_exact_remote_atomic_commit_evidence():
    plan = _plan()
    row = next(row for row in plan["observation"] if row["method"] == "commit")
    raw = {
        "httpStatus": 403,
        "complete": True,
        "workerReaped": True,
        "responseDigest": "a" * 64,
        "effects": [],
        "refusal": {
            "kind": "atomic-commit-permission-denied-v1",
            "canonicalRowDigest": digest(row),
            "principalRef": row["principal"],
            "operation": "Commit",
            "code": 7,
            "restErrorCode": 403,
            "status": "PERMISSION_DENIED",
        },
    }
    receipt = bridge.data_gate_receipt(plan, row["index"], raw)
    assert receipt["status"] == 403
    assert receipt["body"]["effects"] == []
    assert receipt["body"]["refusal"] == {
        "kind": "rules-atomic-commit-refusal-v1",
        "slotId": f"data/{row['index']}",
        "rowDigest": digest(row),
        "principal": row["principal"],
        "operation": "Commit",
        "restCode": 403,
        "status": "PERMISSION_DENIED",
        "canonicalCode": 7,
    }
    raw["refusal"]["canonicalRowDigest"] = "b" * 64
    with pytest.raises(ValueError, match="refusal"):
        bridge.data_gate_receipt(plan, row["index"], raw)


def test_rules_receipt_preserves_real_status_and_keeps_rest_body_outside_gate():
    raw = {
        "httpStatus": 404,
        "complete": True,
        "workerReaped": True,
        "endpoint": "127.0.0.1:17400",
        "wireSequence": 22,
        "error": {"code": 404},
    }
    operation = {
        "kind": "rules-lifecycle",
        "managementPhase": "recovery",
        "managementSlot": "delete-a-absence",
        "action": "get",
        "rulesetName": "projects/fireemu-35fe6/rulesets/issued-a",
    }
    receipt = bridge.rules_gate_receipt(_plan(), operation, raw)
    assert receipt["status"] == 404
    assert receipt["body"]["effects"] == [
        {
            "subject": "ruleset/a",
            "proof": {"kind": "absence", "resource": operation["rulesetName"]},
        }
    ]
    assert receipt.response_body == {"error": {"code": 404}}
    assert "error" not in receipt["body"]
    assert receipt.endpoint == raw["endpoint"]
    assert receipt.wire_sequence == 22


@pytest.mark.parametrize("missing", ["httpStatus", "complete", "workerReaped"])
def test_rules_receipt_never_defaults_missing_wire_facts(missing):
    raw = {
        "httpStatus": 200,
        "complete": True,
        "workerReaped": True,
        "endpoint": "127.0.0.1:17400",
        "wireSequence": 1,
        "name": "projects/fireemu-35fe6/releases/cloud.firestore",
        "rulesetName": "projects/fireemu-35fe6/rulesets/baseline",
    }
    raw.pop(missing)
    operation = {
        "kind": "rules-lifecycle",
        "managementPhase": "observation",
        "managementSlot": "baseline-release-get",
        "action": "release-get",
    }
    with pytest.raises(ValueError, match="wire"):
        bridge.rules_gate_receipt(_plan(), operation, raw)


def test_setup_refuses_failed_durable_journal_before_gate_or_worker(tmp_path):
    plan = _plan()
    gate_path = tmp_path / "gate"
    shared_gate.create(gate_path, descriptor.gate_plan(plan))
    gate = shared_gate.Gate(gate_path, "rules-management")
    journal = open_ownership_journal(
        tmp_path, run_id="journal-failure", plan_digest=plan["planDigest"]
    )
    before = gate.snapshot()
    with pytest.raises(ValueError, match="journal"):
        bridge.run_bound_setup(
            plan=plan,
            gate=gate,
            credentials={},
            setup_secrets={},
            account_bindings={},
            capability=None,
            fixture_origin=None,
            binding=b"",
            binding_digest="",
            journal=journal,
            ownership={},
        )
    assert gate.snapshot() == before


def test_bridge_binds_compiler_accounting_144():
    plan = _plan()
    accounting = bridge.validate_compiled_accounting(plan)
    assert accounting["requestUpperBound"] == 144
    assert accounting["rulesRequests"] == 23
    assert accounting["recoveryRequests"] == 63


@pytest.mark.parametrize(
    "mutation",
    ["observationRequests", "rulesRequests", "recoveryRequests", "requestUpperBound"],
)
def test_bridge_rejects_accounting_drift_without_wire(mutation):
    plan = _plan()
    original = bridge.campaign_budget
    bridge.campaign_budget = lambda _plan: {**original(plan), mutation: 1}
    try:
        with pytest.raises(ValueError, match="accounting"):
            bridge.validate_compiled_accounting(plan)
    finally:
        bridge.campaign_budget = original


def test_bound_execute_rejects_missing_capability_before_transport():
    plan = _plan()
    with pytest.raises(ValueError, match="capability"):
        bridge.bound_execute(
            plan,
            credentials={},
            frozen_inputs={"sourceInputs": {}},
            account_bindings={},
            identity_proofs={},
            capability=None,
        )


def test_bound_execute_rejects_expired_deadline_before_worker():
    plan = _plan()
    with pytest.raises(ValueError, match="worker source|capability"):
        bridge.bound_execute(
            plan,
            credentials={},
            frozen_inputs={"sourceInputs": {}},
            account_bindings={},
            identity_proofs={},
            capability=object(),
        )


@pytest.mark.parametrize(
    ("failure", "journal_failure"),
    [
        ("identity", False),
        ("transport", False),
        ("session", False),
        ("collector", False),
        ("identity", True),
    ],
)
def test_post_setup_failures_recover_owned_resources_and_preserve_outcome(
    tmp_path, monkeypatch, failure, journal_failure
):
    """Every post-side-effect boundary must enter the shared recovery path."""
    plan = {"campaignId": bridge.CAMPAIGN, "nonce": "a" * 32, "planDigest": "plan"}
    frozen_gate = {"kind": "frozen-gate"}
    state = {
        "planDigest": digest(frozen_gate),
        "jobs": {"rules-management": {"pid": os.getpid()}},
        "managementEvents": [],
    }
    released = []
    gate = Namespace(
        path=tmp_path / "gate",
        job="rules-management",
        snapshot=lambda: state,
        claim=lambda: None,
        finish=lambda: released.append(True),
    )
    journal = Namespace(
        path=tmp_path / "journal",
        failures=[],
        close=lambda: setattr(journal, "closed", True),
        closed=False,
    )

    def record(*args, **kwargs):
        if journal_failure:
            journal.failures.append("journal-record:OSError")

    journal.record = record
    ownership = {"owned-account-A": {"phase": "acknowledged"}}
    recovery = {
        "cleanupComplete": journal_failure,
        "held": ["owned-account-A"],
        "recoveryFailure": "ValueError",
    }
    recovery_calls = []

    def setup(**kwargs):
        kwargs["ownership"].update(ownership)
        return [{"id": str(index)} for index in range(19)]

    def proofs(*args, **kwargs):
        if failure == "identity":
            raise ValueError("injected-identity-proof-failure")
        return {
            "owner-a": Namespace(
                uid="owned-uid",
                token="private-fixture",
                provider="password",
                tenant=None,
                claims_digest="claims",
                auth_time=1,
            )
        }

    def execute(*args, **kwargs):
        if failure == "transport":
            raise ValueError("injected-transport-binding-failure")
        return lambda *inner_args, **inner_kwargs: None

    def session(**kwargs):
        if failure == "session":
            raise ValueError("injected-management-session-failure")
        return object()

    def collect(*args, **kwargs):
        if failure == "collector":
            raise ValueError("injected-collector-startup-failure")
        return {"recordingComplete": True, "cleanup": {"cleanupComplete": True}}

    def recover(**kwargs):
        recovery_calls.append(kwargs)
        return recovery

    monkeypatch.setattr(bridge, "validate_compiled_accounting", lambda plan: None)
    monkeypatch.setattr(bridge, "gate_plan", lambda *args, **kwargs: frozen_gate)
    monkeypatch.setattr(bridge, "verify_worker_binding", lambda *args: None)
    monkeypatch.setattr(bridge, "open_ownership_journal", lambda *args, **kwargs: journal)
    monkeypatch.setattr(bridge, "start_context", lambda *args, **kwargs: object())
    monkeypatch.setattr(bridge, "run_bound_setup", setup)
    monkeypatch.setattr(bridge, "setup_identity_proofs", proofs)
    monkeypatch.setattr(bridge, "bound_execute", execute)
    monkeypatch.setattr(
        bridge,
        "collection_dispatch",
        lambda *args, **kwargs: lambda *inner_args, **inner_kwargs: None,
    )
    monkeypatch.setattr(bridge, "refresh_ownership", lambda *args, **kwargs: None)
    monkeypatch.setattr(bridge, "management_session", session)
    monkeypatch.setattr(bridge, "collector", collect)
    monkeypatch.setattr(bridge, "recover_setup_failure", recover)

    with pytest.raises(ValueError, match=failure) as caught:
        bridge.run_bound_collection(
            plan=plan,
            gate=gate,
            ledger=Namespace(finish=lambda ticket: released.append(True)),
            ticket={"id": "ticket"},
            frozen_inputs={},
            acquisition={"environment": {"kind": "local-fireemu"}},
            run_id="run",
            setup_secrets={},
            capability=object(),
            account_bindings={},
            credentials={},
            fixture_origin=None,
            binding=b"worker",
            binding_digest="digest",
            journal_path=tmp_path / "journal",
        )

    assert len(recovery_calls) == 1
    assert recovery_calls[0]["ownership"] == ownership
    assert caught.value.failure_stage in {
        "identity-proof",
        "transport",
        "management-session",
        "collector-startup",
    }
    if journal_failure:
        assert caught.value.recovery_outcome["cleanupComplete"] is False
        assert caught.value.recovery_outcome["journalFailures"] == [
            "journal-record:OSError"
        ]
    else:
        assert caught.value.recovery_outcome == recovery
    assert journal.closed is True
    assert released == []


def test_recovery_keeps_confirmed_documents_when_one_identity_proof_fails(monkeypatch):
    plan = {
        "ownedResources": ["document-a"],
        "ownedAccounts": [
            {"ref": "account-good", "tenant": None},
            {"ref": "account-bad", "tenant": None},
        ],
    }
    ownership = {
        "document-a": {"phase": "acknowledged"},
        "account-good": {"phase": "acknowledged"},
        "account-bad": {"phase": "acknowledged"},
    }
    gate = Namespace(snapshot=lambda: {"coordinatorInflight": False})
    context = Namespace(attempted=["account-bad"])
    proof = Namespace(
        uid="uid-good",
        provider="password",
        tenant=None,
        claims_digest="claims",
        auth_time=1,
    )
    proof_calls = []
    recovered_plan = []

    def proofs(_plan, _gate, handoffs, **kwargs):
        ref = next(iter(handoffs))
        proof_calls.append(ref)
        if ref == "account-bad":
            raise ValueError("injected-proof-failure")
        return {ref: proof}

    monkeypatch.setattr(bridge, "refresh_ownership", lambda _gate, _ownership: None)
    monkeypatch.setattr(bridge, "setup_identity_proofs", proofs)
    monkeypatch.setattr(bridge, "make_recovery_transport", lambda *args, **kwargs: object())
    monkeypatch.setattr(bridge, "collection_dispatch", lambda *args, **kwargs: object())

    def recover(recovery_plan, *args, **kwargs):
        recovered_plan.append(recovery_plan)
        return {"cleanupComplete": True, "held": []}

    monkeypatch.setattr(bridge, "recover_owned", recover)
    monkeypatch.setattr(bridge, "skip_unused_recovery", lambda _gate: None)

    result = bridge.recover_setup_failure(
        plan=plan,
        gate=gate,
        context=context,
        ownership=ownership,
        identity_handoffs={"account-good": object(), "account-bad": object()},
        credentials={"administrator": "fixture"},
        frozen_inputs={},
        capability=object(),
        fixture_origin=None,
        binding=b"worker",
        binding_digest="digest",
    )

    assert proof_calls == ["account-good", "account-bad"]
    assert recovered_plan[0]["ownedResources"] == ["document-a"]
    assert [account["ref"] for account in recovered_plan[0]["ownedAccounts"]] == [
        "account-good",
        "account-bad",
    ]
    assert result["cleanupComplete"] is False
    assert result["held"] == ["account-bad"]
    assert result["unrecoveredAttempted"] == ["account-bad"]
    assert result["proofFailures"] == {"account-bad": "ValueError"}


def test_recovery_uses_gate_held_disposition_before_selecting_accounts(monkeypatch):
    plan = {
        "ownedResources": ["document-a"],
        "ownedAccounts": [
            {"ref": "account-bad", "tenant": None},
            {"ref": "account-good", "tenant": None},
        ],
    }
    ownership = {
        "document-a": {"phase": "acknowledged"},
        "account-bad": {"phase": "acknowledged"},
        "account-good": {"phase": "acknowledged"},
    }
    state = {
        "coordinatorInflight": False,
        "plan": {"management": {"recovery": [{"id": "cleanup/account/bad/read"}]}},
        "managementAbort": {"version": "rules-cancel-v1"},
        "managementUsed": [],
        "managementSkipped": [],
        "planDigest": "plan",
    }
    held_calls = []

    def hold(subject, **kwargs):
        held_calls.append((subject, kwargs))

    gate = Namespace(snapshot=lambda: state, hold_management_recovery=hold)
    context = Namespace(attempted=["account-bad"])
    proof = Namespace(
        uid="uid-good",
        provider="password",
        tenant=None,
        claims_digest="claims",
        auth_time=1,
    )
    recovered_plan = []

    def proofs(_plan, _gate, handoffs, **kwargs):
        ref = next(iter(handoffs))
        if ref == "account-bad":
            raise ValueError("injected-proof-failure")
        return {ref: proof}

    def recover(recovery_plan, *args, **kwargs):
        recovered_plan.append(recovery_plan)
        return {"cleanupComplete": True, "held": []}

    monkeypatch.setattr(bridge, "refresh_ownership", lambda _gate, _ownership: None)
    monkeypatch.setattr(bridge, "setup_identity_proofs", proofs)
    monkeypatch.setattr(bridge, "make_recovery_transport", lambda *args, **kwargs: object())
    monkeypatch.setattr(bridge, "collection_dispatch", lambda *args, **kwargs: object())
    monkeypatch.setattr(bridge, "recover_owned", recover)
    monkeypatch.setattr(bridge, "skip_unused_recovery", lambda _gate: None)

    result = bridge.recover_setup_failure(
        plan=plan,
        gate=gate,
        context=context,
        ownership=ownership,
        identity_handoffs={"account-bad": object(), "account-good": object()},
        credentials={"administrator": "fixture"},
        frozen_inputs={},
        capability=object(),
        fixture_origin=None,
        binding=b"worker",
        binding_digest="digest",
    )

    assert held_calls[0][0] == "account/account-bad"
    assert [account["ref"] for account in recovered_plan[0]["ownedAccounts"]] == [
        "account-good"
    ]
    assert result["held"] == ["account-bad"]
    assert result["unrecoveredAttempted"] == ["account-bad"]
