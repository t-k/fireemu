"""Publication failures never grant success or starve unrelated typed cleanup."""
from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

import collector
import shared_gate
from compiler import compile_limits_plan


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    clock = [10_000.0]
    monkeypatch.setattr(shared_gate, "time", SimpleNamespace(
        monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    ))
    plan = compile_limits_plan("demo-limits", "(default)", "a" * 32)
    shared_gate.create(tmp_path / "gate", plan["localGatePlan"])
    gate = shared_gate.Gate(tmp_path / "gate", "limits")
    gate.claim()
    live, calls = {}, []
    negative = {doc["resource"] for key, doc in plan["documents"].items()
                if key.startswith("over-")}

    def wire(operation, recovery, index, request_index):
        calls.append((recovery, index, copy.deepcopy(operation)))
        name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        method = operation["method"]
        if method == "PATCH":
            if name in negative:
                return {"complete": True, "status": 400, "failure": None,
                        "body": {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}}
            live[name] = {**copy.deepcopy(operation["body"]),
                          "updateTime": "2026-09-19T00:00:00Z"}
        elif method == "DELETE":
            assert "currentDocument.updateTime=" in operation["path"]
            del live[name]
            return {"complete": True, "status": 200, "failure": None, "body": {}}
        if name in live:
            return {"complete": True, "status": 200, "failure": None,
                    "body": copy.deepcopy(live[name])}
        return {"complete": True, "status": 404, "failure": None,
                "body": {"error": {"code": 404, "status": "NOT_FOUND"}}}

    return plan, gate, live, calls, wire, tmp_path / "collection"


def test_control_run_is_complete(scenario):
    plan, gate, live, calls, wire, output = scenario
    result = collector.collect(gate, plan, output, wire)
    assert result["collectionComplete"] is True
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert live == {}
    assert len(calls) == 26


@pytest.mark.parametrize("failed_file", [
    "observation-06-wire.json", "observation-06.json",
    "cleanup-00-wire.json", "cleanup-00.json",
    "cleanup-01-wire.json", "cleanup-01.json",
    "cleanup-11-wire.json", "cleanup-11.json",
])
def test_recording_failure_does_not_abort_typed_recovery(scenario, monkeypatch, failed_file):
    plan, gate, live, calls, wire, output = scenario
    original = collector.save
    hit = []

    def failing(path, value):
        if path.name == failed_file:
            hit.append(path.name)
            raise OSError("injected-publication-error")
        return original(path, value)

    monkeypatch.setattr(collector, "save", failing)
    result = collector.collect(gate, plan, output, wire)
    assert hit == [failed_file]
    assert result["collectionComplete"] is False
    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is True
    assert result["infrastructureFailures"]
    assert live == {}
    assert any(recovery and index == 11 for recovery, index, _ in calls)
    assert gate.snapshot()["jobs"]["limits"]["complete"] is True
    if failed_file.startswith("observation"):
        assert not any(not recovery and index > 6 for recovery, index, _ in calls)


def test_all_sidecar_writes_failing_still_recover_acknowledged_resources(scenario, monkeypatch):
    plan, gate, live, calls, wire, output = scenario
    original = collector.save

    def failing(path, value):
        if path.name.startswith("cleanup-"):
            raise OSError("disk-unavailable")
        return original(path, value)

    monkeypatch.setattr(collector, "save", failing)
    result = collector.collect(gate, plan, output, wire)
    assert live == {}
    assert result["collectionComplete"] is False
    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is True
    assert len(result["cleanup"]) == 12


def test_final_publication_failure_happens_after_cleanup(scenario, monkeypatch):
    plan, gate, live, calls, wire, output = scenario
    original = collector.save

    def failing(path, value):
        if path.name == "collection.json":
            raise OSError("final-publication-failure")
        return original(path, value)

    monkeypatch.setattr(collector, "save", failing)
    with pytest.raises(OSError, match="final-publication-failure"):
        collector.collect(gate, plan, output, wire)
    assert live == {}
    assert gate.snapshot()["jobs"]["limits"]["complete"] is True


def test_stop_record_failure_still_uses_gate_for_recovery(scenario, monkeypatch):
    plan, gate, live, calls, wire, output = scenario
    monkeypatch.setattr(gate, "stop", lambda: (_ for _ in ()).throw(OSError("stop-write")))
    result = collector.collect(gate, plan, output, wire)
    assert live == {}
    assert result["collectionComplete"] is False
    assert result["cleanupComplete"] is True
    assert any(failure["phase"] == "stop" for failure in result["infrastructureFailures"])


def test_lost_creation_response_is_never_settled_by_publication_fix(scenario):
    plan, gate, live, calls, wire, output = scenario

    def lost(operation, recovery, index, request_index):
        value = wire(operation, recovery, index, request_index)
        if not recovery and index == 6:
            raise TimeoutError("lost-acknowledgement")
        return value

    result = collector.collect(gate, plan, output, lost)
    uncertain = plan["documents"]["exact-nested-boundary"]["resource"]
    assert uncertain in live
    assert result["cleanupComplete"] is False
    assert result["collectionComplete"] is False
    assert gate.snapshot()["jobs"]["limits"]["complete"] is False
    assert not any(op["method"] == "DELETE" and uncertain in op["path"] for _, _, op in calls)


def test_failed_stop_cannot_trigger_recovery_credential_callback(scenario, monkeypatch):
    plan, gate, live, calls, wire, output = scenario
    monkeypatch.setattr(gate, "stop", lambda: (_ for _ in ()).throw(OSError("stop-write")))
    credential_calls = []
    result = collector.collect(gate, plan, output, wire,
                               before_recovery=lambda: credential_calls.append(True))
    assert credential_calls == []
    assert not any(recovery for recovery, _, _ in calls)
    assert result["collectionComplete"] is False and result["cleanupComplete"] is False
    assert live


def test_gate_journal_failure_is_not_a_sidecar_failure_and_is_never_bypassed(scenario, monkeypatch):
    plan, gate, live, calls, wire, output = scenario
    original = shared_gate._save
    def failed_gate_ack(path, state):
        if any(event.get("index") == 4 and event.get("completed") is True
               and event.get("phase") == "observation" for event in state["events"]):
            raise OSError("central-gate-journal")
        return original(path, state)
    monkeypatch.setattr(shared_gate, "_save", failed_gate_ack)
    result = collector.collect(gate, plan, output, wire)
    assert live
    assert result["cleanupComplete"] is False
    assert result["collectionComplete"] is False
    assert gate.snapshot()["jobs"]["limits"]["inflight"] is True
    assert not any(recovery for recovery, _, _ in calls)
