"""Focused management-observation abort tests for the durable shared Gate."""

import multiprocessing as mp
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
    assert after["jobs"]["a"]["complete"] is False

    restored = gate.management_dispatch(
        "recovery", "restore", lambda _deadline: receipt()
    )
    assert restored["complete"] is True
    gate.management_dispatch(
        "recovery", "restore-final", lambda _deadline: receipt()
    )
    state = gate.snapshot()
    assert state["managementUsed"][-2:] == [
        "recovery:restore",
        "recovery:restore-final",
    ]
    assert state["managementSkipped"][0]["id"] == "observation:last"
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()


@pytest.mark.parametrize("kind", ["inflight", "data-cursor"])
def test_abort_refuses_when_state_is_not_pre_data(tmp_path, kind):
    gate = make_gate(tmp_path)
    gate.management_dispatch("observation", "first", lambda _deadline: receipt())
    before = gate.snapshot()
    with gate.locked() as state:
        if kind == "inflight":
            state["coordinatorInflight"] = True
        else:
            state["jobs"]["a"]["observation"] = 1
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
