"""Focused management-observation abort tests for the durable shared Gate."""

import multiprocessing as mp
import os
import time

import pytest

import shared_gate
from shared_gate import Gate, create
from test_shared_management_gate import receipt
from test_shared_gate import plan as base_plan


def management_abort_plan():
    value = base_plan()
    value["observationRequests"] = 3
    value["costMicrousd"] = 1200
    value["permissionExpiresAt"] = time.time() + 600
    value["management"] = {
        "dispatchKind": "closed-v1",
        "observation": [
            {"id": "first", "timeout": 13},
            {"id": "uncertain", "timeout": 13},
            {"id": "last", "timeout": 11},
        ],
        "recovery": [
            {"id": "restore", "timeout": 13},
            {"id": "restore-final", "timeout": 13},
        ],
    }
    return value


def make_gate(tmp_path):
    value = management_abort_plan()
    path = tmp_path / "gate"
    create(path, value)
    return Gate(path, "a")


def cancellation_gate(tmp_path):
    value = management_abort_plan()
    value["management"]["observation"] = [
        {"id": "credential", "lifecycle": "preflight", "timeout": 13},
        {"id": "apply-slot", "lifecycle": "apply", "timeout": 13},
        {"id": "poll-slot", "lifecycle": "poll", "timeout": 13},
        {"id": "readback-slot", "lifecycle": "readback", "timeout": 13},
        {"id": "after-slot", "lifecycle": "after", "timeout": 11},
    ]
    value["observationRequests"] = len(value["management"]["observation"])
    path = tmp_path / "cancellation-gate"
    create(path, value)
    return Gate(path, "a")


def reaped_unknown():
    return {
        "status": None,
        "complete": False,
        "workerReaped": True,
        "bodyKind": None,
        "body": None,
    }


def test_reaped_management_failure_skips_only_obs_suffix_and_allows_restore(
    tmp_path,
):
    gate = make_gate(tmp_path)
    gate.claim()
    gate.management_dispatch("observation", "first", lambda _deadline: receipt())
    gate.management_dispatch(
        "observation", "uncertain", lambda _deadline: reaped_unknown()
    )
    before = gate.snapshot()

    after = gate.abort_management_observation()

    assert after["managementUsed"] == [
        "observation:first",
        "observation:uncertain",
    ]
    assert after["managementSkipped"] == [
        {
            "id": "observation:last",
            "phase": "observation",
            "index": 2,
            "reason": "management-not-run",
        }
    ]
    assert after["total"] == before["total"] == 2
    assert after["costMicrousd"] == before["costMicrousd"]
    assert after["managementAbort"]["applyOutcome"] == "may-have-landed"
    assert after["managementAbort"]["recoveryPrerequisite"] is True
    assert after["jobs"]["a"]["pid"] == after["coordinatorPid"]
    assert after["jobs"]["a"]["complete"] is False

    restored = gate.management_dispatch(
        "recovery", "restore", lambda _deadline: receipt()
    )
    assert restored["complete"] is True
    assert gate.abort_management_observation()["total"] == 3
    gate.management_dispatch(
        "recovery", "restore-final", lambda _deadline: receipt()
    )
    assert gate.abort_management_observation()["total"] == 4
    state = gate.snapshot()
    assert state["managementUsed"][-2:] == [
        "recovery:restore",
        "recovery:restore-final",
    ]
    assert state["managementSkipped"][0]["id"] == "observation:last"
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()

    context = mp.get_context("spawn")
    result = context.Queue()
    child = context.Process(target=_child_abort, args=(gate.path, result))
    child.start()
    child.join(10)
    assert child.exitcode == 0
    assert result.get(timeout=2) == "management abort coordinator ownership mismatch"


@pytest.mark.parametrize("kind", ["inflight", "data-cursor", "claimed-cursor", "foreign-pid"])
def test_abort_refuses_when_state_is_not_pre_data(tmp_path, kind):
    gate = make_gate(tmp_path)
    if kind in ("claimed-cursor", "foreign-pid"):
        gate.claim()
    gate.management_dispatch("observation", "first", lambda _deadline: receipt())
    before = gate.snapshot()
    with gate.locked() as state:
        if kind == "inflight":
            state["coordinatorInflight"] = True
        elif kind in ("data-cursor", "claimed-cursor"):
            state["jobs"]["a"]["observation"] = 1
        else:
            state["jobs"]["a"]["pid"] = os.getpid() + 100000
        shared_gate._save(gate.path, state)
    changed = gate.snapshot()
    with pytest.raises(ValueError):
        gate.abort_management_observation()
    assert gate.snapshot() == changed
    assert before != changed


def test_abort_cross_checks_optional_bindings_against_internal_state(tmp_path):
    gate = make_gate(tmp_path)
    gate.management_dispatch(
        "observation", "first", lambda _deadline: reaped_unknown()
    )
    with pytest.raises(ValueError, match="binding"):
        gate.abort_management_observation(expected_plan_digest="forged")
    assert gate.snapshot().get("managementAbort") is None


def test_unreaped_management_failure_remains_uncertain(tmp_path):
    gate = make_gate(tmp_path)
    failed = {
        "status": None,
        "complete": False,
        "workerReaped": False,
        "bodyKind": None,
        "body": None,
    }
    with pytest.raises(ValueError, match="receipt"):
        gate.management_dispatch("observation", "first", lambda _deadline: failed)
    before = gate.snapshot()
    with pytest.raises(ValueError, match="uncertain"):
        gate.abort_management_observation()
    assert gate.snapshot() == before


def test_forged_abort_marker_is_rejected_without_state_repair(tmp_path):
    gate = make_gate(tmp_path)
    gate.management_dispatch(
        "observation", "first", lambda _deadline: reaped_unknown()
    )
    gate.abort_management_observation()
    before = gate.snapshot()
    with gate.locked() as state:
        state["managementAbort"]["postGateDigest"] = "forged"
        shared_gate._save(gate.path, state)
    forged = gate.snapshot()
    with pytest.raises(ValueError, match="forged"):
        gate.abort_management_observation()
    assert gate.snapshot() == forged
    assert before != forged


def test_changed_pre_gate_digest_is_rejected_without_state_repair(tmp_path):
    gate = make_gate(tmp_path)
    gate.management_dispatch(
        "observation", "first", lambda _deadline: reaped_unknown()
    )
    gate.abort_management_observation()
    with gate.locked() as state:
        state["managementAbort"]["preGateDigest"] = "forged"
        shared_gate._save(gate.path, state)
    forged = gate.snapshot()
    with pytest.raises(ValueError, match="forged"):
        gate.abort_management_observation()
    assert gate.snapshot() == forged


def _child_abort(path, result):
    try:
        Gate(path, "a").abort_management_observation()
    except ValueError as error:
        result.put(str(error))
    else:
        result.put("accepted")


def _child_cancel(path, result):
    try:
        Gate(path, "a").cancel_management_observation()
    except ValueError as error:
        result.put(str(error))
    else:
        result.put("accepted")


def test_restarted_coordinator_cannot_apply_transition(tmp_path):
    gate = make_gate(tmp_path)
    gate.management_dispatch(
        "observation", "first", lambda _deadline: reaped_unknown()
    )
    before = gate.snapshot()
    context = mp.get_context("spawn")
    result = context.Queue()
    child = context.Process(target=_child_abort, args=(gate.path, result))
    child.start()
    child.join(10)
    assert child.exitcode == 0
    assert result.get(timeout=2) == "management abort coordinator ownership mismatch"
    assert gate.snapshot() == before


def test_coordinator_cancel_preserves_completed_apply_and_skips_remaining_observation(
    tmp_path,
):
    gate = cancellation_gate(tmp_path)
    gate.claim()
    gate.management_dispatch(
        "observation", "credential", lambda _deadline: receipt()
    )
    first = gate.management_dispatch(
        "observation", "apply-slot", lambda _deadline: receipt()
    )
    second = gate.management_dispatch(
        "observation", "poll-slot", lambda _deadline: receipt()
    )
    gate.management_dispatch(
        "observation", "readback-slot", lambda _deadline: receipt()
    )

    after = gate.cancel_management_observation()

    assert first["complete"] is True
    assert second["complete"] is True
    assert after["managementUsed"] == [
        "observation:credential",
        "observation:apply-slot",
        "observation:poll-slot",
        "observation:readback-slot",
    ]
    assert after["managementSkipped"] == [
        {
            "id": "observation:after-slot",
            "phase": "observation",
            "index": 4,
            "reason": "management-not-run",
        }
    ]
    assert after["managementAbort"]["applyOutcome"] == "coordinator-cancelled"
    assert after["managementAbort"]["recoveryPrerequisite"] is True
    assert after["managementEvents"][1]["status"] == first["status"]
    assert after["managementEvents"][2]["responseDigest"]
    assert after["jobs"]["a"]["complete"] is False
    assert gate.cancel_management_observation() == after

    restored = gate.management_dispatch(
        "recovery", "restore", lambda _deadline: receipt()
    )
    assert restored["complete"] is True


def test_coordinator_cancel_before_declared_apply_is_unchanged(tmp_path):
    gate = cancellation_gate(tmp_path)
    gate.management_dispatch(
        "observation", "credential", lambda _deadline: receipt()
    )
    before = gate.snapshot()
    with pytest.raises(ValueError, match="declared apply"):
        gate.cancel_management_observation()
    assert gate.snapshot() == before


def test_coordinator_cancel_rejects_unreaped_or_foreign_data_state_unchanged(tmp_path):
    gate = cancellation_gate(tmp_path)
    gate.claim()
    gate.management_dispatch(
        "observation", "credential", lambda _deadline: receipt()
    )
    gate.management_dispatch(
        "observation", "apply-slot", lambda _deadline: receipt()
    )
    before = gate.snapshot()
    with gate.locked() as state:
        state["managementEvents"][1]["workerReaped"] = False
        shared_gate._save(gate.path, state)
    forged = gate.snapshot()
    with pytest.raises(ValueError, match="admissible"):
        gate.cancel_management_observation()
    assert gate.snapshot() == forged

    with gate.locked() as state:
        state["managementEvents"][1]["workerReaped"] = True
        state["jobs"]["a"]["pid"] = os.getpid() + 100000
        shared_gate._save(gate.path, state)
    foreign = gate.snapshot()
    with pytest.raises(ValueError, match="admissible"):
        gate.cancel_management_observation()
    assert gate.snapshot() == foreign
    assert before != forged


def test_coordinator_cancel_accepts_reaped_semantic_error_and_preserves_receipt(
    tmp_path,
):
    gate = cancellation_gate(tmp_path)
    gate.claim()
    response = gate.management_dispatch(
        "observation", "credential", lambda _deadline: receipt()
    )
    gate.management_dispatch(
        "observation", "apply-slot", lambda _deadline: receipt(400)
    )
    gate.management_dispatch(
        "observation", "poll-slot", lambda _deadline: receipt()
    )
    gate.management_dispatch(
        "observation", "readback-slot", lambda _deadline: receipt()
    )

    state = gate.cancel_management_observation()

    assert response["status"] == 200
    assert state["managementEvents"][1]["status"] == 400
    assert state["managementEvents"][1]["completed"] is True
    assert state["managementEvents"][1]["workerReaped"] is True


def test_coordinator_cancel_rejects_foreign_coordinator_without_state_change(tmp_path):
    gate = make_gate(tmp_path)
    gate.management_dispatch("observation", "first", lambda _deadline: receipt())
    before = gate.snapshot()
    context = mp.get_context("spawn")
    result = context.Queue()
    child = context.Process(target=_child_cancel, args=(gate.path, result))
    child.start()
    child.join(10)
    assert child.exitcode == 0
    assert result.get(timeout=2) == "management abort coordinator ownership mismatch"
    assert gate.snapshot() == before
