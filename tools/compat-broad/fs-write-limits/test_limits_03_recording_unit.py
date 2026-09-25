"""Collector fault-injection unit tests; Gate, plan and service are test doubles.

These tests isolate callback/publication ordering. The companion Gate tests run
against the real compiler and Gate. Neither suite performs production I/O.
"""
from __future__ import annotations

import copy
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import quote, unquote

import collector_03 as collector
import pytest

VERSION = "2026-09-23T00:00:00Z"
ABSENT = {"error": {"code": 404, "status": "NOT_FOUND"}}


def is_absent(status, body):
    return type(status) is int and status == 404 and body == ABSENT


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def resolve_recovery(operation, rows):
    operation = copy.deepcopy(operation)
    if "versionFrom" in operation:
        index = operation.pop("versionFrom")
        version = (rows[index].get("body") or {}).get("updateTime")
        if version is not None:
            operation["path"] += "?currentDocument.updateTime=" + quote(version, safe="")
    return operation


class GateDouble:
    """Small callback-order fixture, deliberately not the shared Gate implementation."""

    def __init__(self, plan):
        self.plan = copy.deepcopy(plan["localGatePlan"])
        self.job = self.plan["jobs"]["limits"]
        self.events = []
        self.observed = self.recovered = 0
        self.proofs = {}
        self.absent = set()
        self.uncertain = False
        self.stopped = False
        self.complete = False
        self.fail_transition = False
        self.fail_ack = False

    def snapshot(self):
        return {
            "plan": copy.deepcopy(self.plan),
            "events": copy.deepcopy(self.events),
            "jobs": {"limits": {"complete": self.complete, "inflight": self.uncertain}},
        }

    def dispatch(self, operation, recovery, send):
        if self.uncertain:
            raise ValueError("uncertain operation remains held")
        if recovery and not self.stopped and "schedule" in self.job:
            raise ValueError("observation phase was not abandoned")
        if not recovery and self.stopped:
            raise ValueError("observation stopped")
        index = self.recovered if recovery else self.observed
        self.events.append(("dispatch", recovery, index))
        name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        if recovery and operation["method"] == "DELETE" and name not in self.proofs:
            if name not in self.absent:
                raise ValueError("no creation ownership")
            self.recovered += 1
            return None, {"skipped": "absent-or-unavailable-cleanup-read"}
        self.uncertain = True
        status, body = send()
        if not recovery and operation["method"] == "POST":
            if self.fail_ack:
                raise OSError("injected central journal failure")
            if status == 200:
                for write, item in zip(operation["body"]["writes"], body["writeResults"], strict=True):
                    if "update" in write and "updateTime" in item:
                        self.proofs[write["update"]["name"]] = item["updateTime"]
        if recovery and is_absent(status, body):
            self.absent.add(name)
        self.events.append(("ack", recovery, index, status))
        self.uncertain = False
        if recovery:
            self.recovered += 1
        else:
            self.observed += 1
        return status, body

    def stop(self):
        self.events.append(("stop",))
        if self.fail_transition:
            raise OSError("injected stop failure")
        self.stopped = True

    def abandon_observation(self, reason):
        self.events.append(("abandon", reason))
        if self.fail_transition or self.uncertain:
            raise OSError("injected abandon failure")
        self.stopped = True

    def finish(self):
        self.events.append(("finish",))
        if (self.uncertain or self.recovered != len(self.job["recovery"])
                or self.absent != set(self.job["resources"])):
            raise ValueError("recovery incomplete")
        self.complete = True


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    # Only collector sequencing is tested here. Production dispatch authorization
    # and compiler validation are explicitly replaced, never claimed as exercised.
    names = [f"projects/demo-limits/databases/(default)/documents/unit/{x}" for x in ("a", "b")]
    docs = {name: {"name": name, "fields": {"v": {"integerValue": "1"}}} for name in names}

    def op(method, path, body=None, **extra):
        return {"method": method, "path": path, "body": body, **extra}

    observe = [op("GET", "/v1/" + name) for name in names]
    observe.append(op("POST", "/v1/projects/demo-limits/databases/(default)/documents:batchWrite", {
        "writes": [{"update": docs[names[0]], "currentDocument": {"exists": False}},
                   {}, {"update": docs[names[1]], "currentDocument": {"exists": False}}],
    }))
    observe.extend(op("GET", "/v1/" + name) for name in names)
    recovery = []
    for name in names:
        index = len(recovery)
        recovery += [op("GET", "/v1/" + name),
                     op("DELETE", "/v1/" + name, versionFrom=index),
                     op("GET", "/v1/" + name)]
    plan = {"localGatePlan": {"jobs": {"limits": {
        "resources": names, "observation": observe, "recovery": recovery,
        # Presence controls the collector branch; this is NOT a real Gate schedule.
        "schedule": "unit-fixture",
    }}}, "requests": copy.deepcopy(observe + recovery)}
    gate = GateDouble(plan)
    live, calls = {}, []

    def wire(operation, recovery, index, request_index):
        calls.append((recovery, index, copy.deepcopy(operation)))
        name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        method = operation["method"]
        if method == "POST":
            for n, doc in docs.items():
                assert n not in live
                live[n] = {**copy.deepcopy(doc), "updateTime": VERSION}
            return {"complete": True, "failure": None, "status": 200, "body": {
                "status": [{}, {"code": 3}, {}],
                "writeResults": [{"updateTime": VERSION}, {}, {"updateTime": VERSION}],
            }}
        if method == "DELETE":
            assert name in gate.proofs, "a sidecar never supplies creation ownership"
            query = operation["path"].split("?", 1)[1]
            assert unquote(query.split("=", 1)[1]) == live[name]["updateTime"]
            del live[name]
            return {"complete": True, "failure": None, "status": 200, "body": {}}
        return {"complete": True, "failure": None,
                "status": 200 if name in live else 404,
                "body": copy.deepcopy(live.get(name, ABSENT))}

    def save(path, entry):
        # A real file is written for every successful publication in this fixture.
        path.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")

    monkeypatch.setattr(collector, "resolve_body", lambda op, body: copy.deepcopy(op))
    monkeypatch.setattr(collector, "preflight_count", lambda plan: 2)
    monkeypatch.setattr(collector, "writes_safe", lambda rows, plan, **kw: (
        len(rows) >= 2 and all(is_absent(r.get("status"), r.get("body")) for r in rows[:2])
    ))
    monkeypatch.setattr(collector, "evaluate_rows", lambda rows, plan, **kw: [])
    monkeypatch.setattr(collector, "digest", digest)
    monkeypatch.setattr(collector, "typed_absence", is_absent)
    monkeypatch.setattr(collector, "resolve_recovery", resolve_recovery)
    monkeypatch.setattr(collector, "save", save)
    return SimpleNamespace(plan=plan, gate=gate, live=live, calls=calls, wire=wire,
                           output=tmp_path / "collection", saved=save)


def collect(scenario, **kwargs):
    return collector.collect(scenario.gate, scenario.plan, scenario.output, scenario.wire, **kwargs)


def fail_file(scenario, monkeypatch, failed):
    hits = []

    def save(path, entry):
        if path.name == failed:
            hits.append(path.name)
            raise OSError("injected disk error")
        scenario.saved(path, entry)

    monkeypatch.setattr(collector, "save", save)
    return hits


@pytest.mark.parametrize("scheduled", [False, True])
def test_normal_collection_is_unchanged(scenario, scheduled):
    if not scheduled:
        scenario.plan["localGatePlan"]["jobs"]["limits"].pop("schedule")
        scenario.gate.job.pop("schedule")
    result = collect(scenario)
    assert result["collectionComplete"] is True
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["infrastructureFailures"] == []
    assert len(result["rows"]) == 5 and len(result["cleanup"]) == 6
    assert len(scenario.calls) == 11 and scenario.live == {}
    assert scenario.gate.complete


@pytest.mark.parametrize("failed", [
    "observation-02-wire.json", "observation-02.json",
    "cleanup-00-wire.json", "cleanup-00.json",
    "cleanup-01-wire.json", "cleanup-01.json",
    "cleanup-05-wire.json", "cleanup-05.json",
])
def test_publication_failure_keeps_ack_and_recovery(scenario, monkeypatch, failed):
    hits = fail_file(scenario, monkeypatch, failed)
    result = collect(scenario)
    assert hits == [failed]
    assert result["collectionComplete"] is False
    assert result["recordingComplete"] is False
    assert result["cleanupComplete"] is True
    assert result["recordingFailures"][0]["file"] == failed
    assert scenario.live == {} and scenario.gate.complete
    assert len(result["cleanup"]) == 6
    assert not any(row.get("dispatchFailure") for row in result["rows"] + result["cleanup"])
    assert any(e[:3] == ("ack", False, 2) for e in scenario.gate.events)
    if failed.startswith("observation"):
        assert len(result["rows"]) == 3
        assert not any(not recovery and index > 2 for recovery, index, _ in scenario.calls)
        assert any(e[0] == "abandon" for e in scenario.gate.events)


def test_persistent_recovery_sidecar_failure_does_not_starve_later_resources(scenario, monkeypatch):
    def fail_cleanup(path, entry):
        if path.name.startswith("cleanup-"):
            raise OSError("disk unavailable")
        scenario.saved(path, entry)
    monkeypatch.setattr(collector, "save", fail_cleanup)
    result = collect(scenario)
    assert result["recordingComplete"] is False
    assert result["collectionComplete"] is False
    assert result["cleanupComplete"] is True
    assert len(result["recordingFailures"]) == 12
    assert len(result["cleanup"]) == 6 and scenario.live == {}


def test_final_publication_failure_is_after_recovery(scenario, monkeypatch):
    fail_file(scenario, monkeypatch, "collection.json")
    with pytest.raises(OSError, match="injected disk"):
        collect(scenario)
    assert scenario.live == {} and scenario.gate.complete


@pytest.mark.parametrize("phase", ["stop", "abandon"])
def test_transition_failure_never_acquires_recovery_credentials(scenario, monkeypatch, phase):
    scenario.gate.fail_transition = True
    if phase == "abandon":
        fail_file(scenario, monkeypatch, "observation-02.json")
    acquired = []
    result = collect(scenario, before_recovery=lambda: acquired.append(True))
    assert acquired == []
    assert not any(recovery for recovery, _, _ in scenario.calls)
    assert scenario.live and not scenario.gate.complete
    assert result["cleanupComplete"] is False and result["collectionComplete"] is False
    assert any(f["phase"] == phase for f in result["infrastructureFailures"])


def test_unscheduled_stop_failure_uses_only_gate_admitted_recovery(scenario):
    scenario.plan["localGatePlan"]["jobs"]["limits"].pop("schedule")
    scenario.gate.job.pop("schedule")
    scenario.gate.fail_transition = True
    result = collect(scenario)
    assert result["collectionComplete"] is False
    assert result["cleanupComplete"] is True
    assert scenario.live == {}
    assert any(f["phase"] == "stop" for f in result["infrastructureFailures"])


def test_callback_failure_keeps_responsibility(scenario):
    def refused():
        raise PermissionError("no recovery credentials")
    result = collect(scenario, before_recovery=refused)
    assert scenario.live and not scenario.gate.complete
    assert not any(recovery for recovery, _, _ in scenario.calls)
    assert result["cleanupComplete"] is False and result["collectionComplete"] is False


@pytest.mark.parametrize("failure", ["lost-response", "gate-journal"])
def test_uncertain_dispatch_is_not_repaired_by_sidecar_handling(scenario, failure):
    if failure == "gate-journal":
        scenario.gate.fail_ack = True
    else:
        original = scenario.wire
        def lost(operation, recovery, index, request_index):
            result = original(operation, recovery, index, request_index)
            if not recovery and index == 2:
                raise TimeoutError("lost response")
            return result
        scenario.wire = lost
    result = collect(scenario)
    assert scenario.live and scenario.gate.uncertain and not scenario.gate.complete
    assert not any(recovery for recovery, _, _ in scenario.calls)
    assert result["cleanupComplete"] is False and result["collectionComplete"] is False
    assert any(r.get("dispatchFailure") for r in result["rows"])


def test_failure_in_first_preflight_does_not_send_batch(scenario, monkeypatch):
    fail_file(scenario, monkeypatch, "observation-00-wire.json")
    result = collect(scenario)
    assert len(result["rows"]) == 1
    assert not any(op["method"] == "POST" for _, _, op in scenario.calls)
    assert result["recordingComplete"] is False and result["collectionComplete"] is False
    assert scenario.live == {}


def test_recording_fault_does_not_overwrite_semantic_response(scenario, monkeypatch):
    fail_file(scenario, monkeypatch, "observation-02-wire.json")
    result = collect(scenario)
    row = result["rows"][-1]
    assert row["status"] == 200
    assert row["body"]["status"] == [{}, {"code": 3}, {}]
    assert row["complete"] is True
    assert row["recordingFailure"] == "OSError"


def test_false_gate_binding_sends_nothing(scenario):
    scenario.gate.plan["jobs"]["limits"]["resources"] = []
    with pytest.raises(ValueError, match="binding differs"):
        collect(scenario)
    assert not scenario.calls and not scenario.output.exists()


def test_gate_refusal_is_not_a_successful_missing_wire(scenario, monkeypatch):
    def refused(*args):
        raise ValueError("admission refused")
    monkeypatch.setattr(scenario.gate, "dispatch", refused)
    result = collect(scenario)
    assert not scenario.calls
    assert result["collectionComplete"] is False and result["cleanupComplete"] is False
    assert all(r.get("dispatchFailure") for r in result["rows"] + result["cleanup"])
