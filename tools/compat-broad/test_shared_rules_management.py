"""Canonical Rules management scheduling using real private Gate state."""

import sys
import time
import json
from pathlib import Path

import pytest

import shared_gate
from shared_gate import Gate, create

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "fs-rules-publication"))
sys.path.insert(0, str(HERE / "o8-core"))
import o5_user_token_case as case
import o5_user_token_descriptor as descriptor


def rules_plan():
    compiled = case.compile_case("fireemu-35fe6", "(default)", "a" * 32, "tenant-test")
    value = descriptor.gate_plan(compiled, permission_expires_at=time.time() + 900)
    value["jobs"]["rules-management"]["resources"] = []
    return value


def test_canonical_rules_empty_data_gate_reserves_all_management_time(tmp_path):
    value = rules_plan()
    assert shared_gate._observation_time(value, 8) == 289.75
    create(tmp_path / "gate", value)
    state = Gate(tmp_path / "gate", "rules-management").snapshot()
    assert state["reservedRecovery"] == 73
    assert state["plan"]["costMicrousd"] == 144
    assert state["jobs"]["rules-management"]["resources"] == []


@pytest.mark.parametrize("fault", ["source", "contract", "effect", "dependency", "data-principal", "observation-time", "recovery-time"])
def test_rules_plan_drift_refused_before_gate_creation(tmp_path, fault):
    value = rules_plan()
    if fault == "source":
        value["rulesCompilerSources"]["o5_user_token_case.py"] = "0" * 64
    elif fault == "contract":
        value["rulesManagementContract"]["subjects"].pop()
    elif fault == "effect":
        value["management"]["observation"][0]["effects"] = []
    elif fault == "dependency":
        value["management"]["recovery"][0]["dependency"]["subject"] = "account/owner-a"
    elif fault == "data-principal":
        value["planDigest"] = "0" * 64
    elif fault == "observation-time":
        value["wallSeconds"] = 580
    else:
        value["recoverySeconds"] = 260
    with pytest.raises(ValueError):
        create(tmp_path / "gate", value)
    assert not (tmp_path / "gate").exists()


def test_unattempted_rules_cancel_and_skip_are_uncharged_and_terminal(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    gate.cancel_management_observation()
    for slot in gate.snapshot()["plan"]["management"]["recovery"]:
        before = gate.snapshot()
        gate.skip_management_recovery(slot["id"], expected_plan_digest=before["planDigest"],
                                      expected_prefix_digest=shared_gate.digest({"used": before["managementUsed"], "skipped": before["managementSkipped"]}))
        after = gate.snapshot()
        assert after["total"] == after["costMicrousd"] == 0
        assert after["reservedRecovery"] == before["reservedRecovery"] - 1
    gate.finish()
    assert gate.snapshot()["jobs"]["rules-management"]["complete"] is True


def test_rules_finish_cannot_bypass_incomplete_management(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    before = gate.snapshot()
    with pytest.raises(ValueError):
        gate.finish()
    assert gate.snapshot() == before


def response(effects=(), *, status=200, complete=True, reaped=True):
    return {"status": status, "complete": complete, "workerReaped": reaped,
            "bodyKind": "json", "body": {"kind": "rules-management-proof-v1", "responseDigest": "f" * 64, "effects": list(effects)}}


def skip_next(gate, slot):
    before = gate.snapshot()
    return gate.skip_management_recovery(slot, expected_plan_digest=before["planDigest"], expected_prefix_digest=shared_gate.digest({"used": before["managementUsed"], "skipped": before["managementSkipped"]}))


def first_creation(gate):
    state = gate.snapshot()
    slot = state["plan"]["management"]["observation"][0]
    subject_id = slot["effects"][0]["subject"]
    subject = next(item for item in state["plan"]["rulesManagementContract"]["subjects"] if item["id"] == subject_id)
    if subject["kind"] == "document":
        proof = {"kind": "document", "name": subject["resource"], "fieldsDigest": "e" * 64, "updateTime": "2026-09-22T00:00:00Z"}
    else:
        proof = {"kind": "account", "accountRef": subject["resource"], "tenantId": None, "uid": "real-response-uid"}
    return slot, subject, {"subject": subject_id, "proof": proof}


def test_partial_creation_typed_absence_releases_without_delete_or_refund(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    slot, subject, effect = first_creation(gate)
    gate.management_dispatch("observation", slot["id"], lambda deadline: response([effect]))
    gate.cancel_management_observation()
    for recovery in gate.snapshot()["plan"]["management"]["recovery"]:
        if recovery["dependency"] == {"subject": subject["id"], "step": "read"}:
            gate.management_dispatch("recovery", recovery["id"], lambda deadline: response([{"subject": subject["id"], "proof": {"kind": "absence", "resource": subject["resource"]}}], status=404))
        else:
            skip_next(gate, recovery["id"])
    gate.finish()
    final = gate.snapshot()
    assert final["total"] == final["costMicrousd"] == 2
    assert final["reservedRecovery"] == 0
    assert len(final["managementEvents"]) == 2


@pytest.mark.parametrize("fault", ["out-of-order", "wrong-plan", "wrong-prefix", "wire-for-unattempted", "forged-complete"])
def test_rules_negative_paths_leave_state_unchanged(tmp_path, fault):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    gate.cancel_management_observation()
    before = gate.snapshot()
    slots = before["plan"]["management"]["recovery"]
    if fault == "forged-complete":
        forged = json.loads(json.dumps(before))
        forged["jobs"]["rules-management"]["complete"] = True
        shared_gate._save(gate.path, forged)
        raw = (gate.path / "state.json").read_bytes()
        with pytest.raises(ValueError):
            Gate(gate.path, "rules-management").snapshot()
        assert (gate.path / "state.json").read_bytes() == raw
        return
    with pytest.raises(ValueError):
        if fault == "wire-for-unattempted":
            gate.management_dispatch("recovery", slots[0]["id"], lambda deadline: pytest.fail("must not invoke wire"))
        else:
            gate.skip_management_recovery(slots[int(fault == "out-of-order")]["id"], expected_plan_digest="0" * 64 if fault == "wrong-plan" else before["planDigest"], expected_prefix_digest="0" * 64 if fault == "wrong-prefix" else shared_gate.digest({"used": before["managementUsed"], "skipped": before["managementSkipped"]}))
    assert gate.snapshot() == before


def test_unknown_worker_refuses_cancel_and_retains_charged_call(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    slot, _, _ = first_creation(gate)
    gate.management_dispatch("observation", slot["id"], lambda deadline: response(complete=False, reaped=False))
    before = gate.snapshot()
    with pytest.raises(ValueError):
        gate.cancel_management_observation()
    assert gate.snapshot() == before
    assert before["total"] == before["costMicrousd"] == 1
