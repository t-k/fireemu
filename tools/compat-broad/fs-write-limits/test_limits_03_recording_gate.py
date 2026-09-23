"""Real-Gate integration regressions for limits-03 publication failures.

Uses both existing campaign parts, the real Gate and test_campaign_03.Responder.
The service/clock remain synthetic; this file never authorizes production I/O.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import collector_03
import shared_gate
from expectations_03 import pending_rows
from test_campaign_03 import Responder, plan_for


@pytest.fixture(params=("A", "B"))
def scenario(request, tmp_path, monkeypatch):
    clock = [10_000.0]
    monkeypatch.setattr(shared_gate, "time", SimpleNamespace(
        monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    ))
    plan = plan_for(part=request.param)
    shared_gate.create(tmp_path / "gate", plan["localGatePlan"])
    gate = shared_gate.Gate(tmp_path / "gate", "limits")
    gate.claim()
    responder = Responder()
    first_write = next(
        i for i, op in enumerate(plan["requests"])
        if op["kind"] in {"batch-write", "create-only-patch"}
    )
    calls = []

    def wire(operation, recovery, index, request_index):
        calls.append((recovery, index, operation["method"]))
        return responder(operation, recovery, index, request_index)

    return SimpleNamespace(plan=plan, gate=gate, responder=responder, first_write=first_write,
                           wire=wire, calls=calls, output=tmp_path / "collection")


def run(scenario, **kwargs):
    return collector_03.collect(
        scenario.gate, scenario.plan, scenario.output, scenario.wire,
        excused=pending_rows(scenario.plan), **kwargs,
    )


def fail_sidecar(monkeypatch, name):
    original = collector_03.save
    hits = []

    def failing(path, value):
        if path.name == name:
            hits.append(name)
            raise OSError("injected collection sidecar failure")
        return original(path, value)

    monkeypatch.setattr(collector_03, "save", failing)
    return hits


def test_limits03_control_completes_with_real_gate(scenario):
    result = run(scenario)
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["collectionComplete"] is True
    assert scenario.responder.documents == {}
    assert scenario.gate.snapshot()["jobs"]["limits"]["complete"] is True


@pytest.mark.parametrize("location", ["write-wire", "write-row", "recovery-wire", "recovery-row"])
def test_limits03_sidecar_failure_preserves_real_gate_cleanup(scenario, monkeypatch, location):
    names = {
        "write-wire": f"observation-{scenario.first_write:02d}-wire.json",
        "write-row": f"observation-{scenario.first_write:02d}.json",
        "recovery-wire": "cleanup-00-wire.json",
        "recovery-row": "cleanup-00.json",
    }
    hits = fail_sidecar(monkeypatch, names[location])
    result = run(scenario)
    assert hits == [names[location]]
    assert result["collectionComplete"] is False
    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is True
    assert scenario.responder.documents == {}
    assert scenario.gate.snapshot()["jobs"]["limits"]["complete"] is True
    assert any(recovery for recovery, _, _ in scenario.calls)
    if location.startswith("write"):
        assert len(result["rows"]) == scenario.first_write + 1
        assert not any(not recovery and index > scenario.first_write for recovery, index, _ in scenario.calls)
        assert result["rows"][-1]["complete"] is True
        assert result["rows"][-1]["status"] == 200
        assert result["rows"][-1].get("dispatchFailure") is None


def test_limits03_all_cleanup_sidecars_can_fail_without_starving_recovery(scenario, monkeypatch):
    original = collector_03.save

    def failing(path, value):
        if path.name.startswith("cleanup-"):
            raise OSError("injected cleanup volume failure")
        return original(path, value)

    monkeypatch.setattr(collector_03, "save", failing)
    result = run(scenario)
    assert scenario.responder.documents == {}
    assert result["recordingComplete"] is False
    assert result["collectionComplete"] is False
    assert result["cleanupComplete"] is True
    assert len(result["cleanup"]) == len(scenario.plan["localGatePlan"]["jobs"]["limits"]["recovery"])


def test_limits03_failed_abandon_never_calls_recovery_credential_hook(scenario, monkeypatch):
    fail_sidecar(monkeypatch, f"observation-{scenario.first_write:02d}.json")

    def refused(reason):
        raise OSError("injected abandonment journal failure")

    monkeypatch.setattr(scenario.gate, "abandon_observation", refused)
    callbacks = []
    result = run(scenario, before_recovery=lambda: callbacks.append(True))
    assert callbacks == []
    assert not any(recovery for recovery, _, _ in scenario.calls)
    assert scenario.responder.documents
    assert result["collectionComplete"] is False and result["cleanupComplete"] is False


def test_limits03_gate_journal_failure_is_not_swallowed_as_a_sidecar_failure(scenario, monkeypatch):
    original = shared_gate._save

    def failed_ack(path, state):
        if any(event.get("index") == scenario.first_write and event.get("completed") is True
               and event.get("phase") == "observation" for event in state["events"]):
            raise OSError("injected central Gate journal failure")
        return original(path, state)

    monkeypatch.setattr(shared_gate, "_save", failed_ack)
    result = run(scenario)
    assert scenario.responder.documents
    assert result["cleanupComplete"] is False
    assert result["collectionComplete"] is False
    assert scenario.gate.snapshot()["jobs"]["limits"]["inflight"] is True
    assert not any(recovery for recovery, _, _ in scenario.calls)


def test_limits03_lost_write_acknowledgement_does_not_gain_delete_authority(scenario):
    original = scenario.wire

    def lost(operation, recovery, index, request_index):
        result = original(operation, recovery, index, request_index)
        if not recovery and index == scenario.first_write:
            raise TimeoutError("injected lost write acknowledgement")
        return result

    scenario.wire = lost
    result = run(scenario)
    assert scenario.responder.documents
    assert result["cleanupComplete"] is False and result["collectionComplete"] is False
    assert not any(recovery and method == "DELETE" for recovery, _, method in scenario.calls)


def test_limits03_final_publication_failure_occurs_after_recovery(scenario, monkeypatch):
    fail_sidecar(monkeypatch, "collection.json")
    with pytest.raises(OSError, match="injected collection"):
        run(scenario)
    assert scenario.responder.documents == {}
    assert scenario.gate.snapshot()["jobs"]["limits"]["complete"] is True
