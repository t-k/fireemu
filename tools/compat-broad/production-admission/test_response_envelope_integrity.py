"""Contradictory Firestore replies cannot create or retire destructive authority.

Real file-backed Gate and Ledger; deterministic clock and injected wire replies.
No credentials, Firebase, or network. Do not count these as native API tests.
"""
from __future__ import annotations

import copy
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
from urllib.parse import quote

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import shared_gate
from broad_contract import digest
from reservations import Ledger
from shared_gate import Gate, create, typed_absence, unconfirmed_creates

ROOT = "projects/demo-envelope/databases/(default)/documents"
RESOURCE = ROOT + "/owned/one"
VERSION = "2026-09-19T00:00:00.000000Z"
FIELDS = {"_sharedOwner": {"referenceValue": RESOURCE}, "n": {"integerValue": "1"}}
DOCUMENT = {"name": RESOURCE, "fields": FIELDS, "updateTime": VERSION}
ABSENT = {"error": {"code": 404, "status": "NOT_FOUND"}}
REFUSED = {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}
EXTRAS = [
    ("name", RESOURCE), ("fields", FIELDS), ("updateTime", VERSION),
    ("writeResults", [{"updateTime": VERSION}]), ("status", [{}]),
    ("document", DOCUMENT), ("result", None), ("futureEnvelopeField", {}),
]


@pytest.fixture(autouse=True)
def local_only(monkeypatch):
    clock = [1000.0]

    def sleep(seconds):
        assert seconds >= 0
        clock[0] += seconds

    monkeypatch.setattr(shared_gate, "time", SimpleNamespace(
        monotonic=lambda: clock[0], sleep=sleep))

    def denied(*_args, **_kwargs):
        raise AssertionError("network forbidden in Gate envelope tests")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)


def request(surface):
    common = {"service": "firestore", "body": None, "privileged": True}
    if surface == "patch":
        return {**common, "method": "PATCH", "path": "/v1/" + RESOURCE +
                "?currentDocument.exists=false", "body": {"fields": copy.deepcopy(FIELDS)}}
    return {**common, "method": "POST", "path": "/v1/" + ROOT + ":" + surface,
            "body": {"writes": [{"update": {"name": RESOURCE, "fields": copy.deepcopy(FIELDS)},
                                 "currentDocument": {"exists": False}}]}}


def reply(surface):
    if surface == "patch":
        return copy.deepcopy(DOCUMENT)
    return {"writeResults": [{"updateTime": VERSION}],
            **({"status": [{}]} if surface == "batchWrite" else {"commitTime": VERSION})}


def plan(surface, scheduled):
    read = {"service": "firestore", "method": "GET", "path": "/v1/" + RESOURCE,
            "body": None, "privileged": True}
    recovery = [read, {**read, "method": "DELETE", "versionFrom": 0}, copy.deepcopy(read)]
    job = {"resources": [RESOURCE], "observation": [request(surface)], "recovery": recovery}
    if scheduled:
        job["schedule"] = [{"phase": "observation", "index": 0, "creates": True},
                           *[{"phase": "recovery", "index": i, "creates": False} for i in range(3)]]
    return {"contract": "shared-local-v2", "nonce": "a" * 32, "jobs": {"limits": job},
            "wallSeconds": 200, "recoverySeconds": 100, "requestSeconds": 1,
            "observationRequests": 1, "requestCostMicrousd": 1,
            "costMicrousd": 10, "intervalSeconds": 0.25}


def start(tmp_path, surface, scheduled):
    frozen = plan(surface, scheduled)
    ledger = Ledger.create(tmp_path / "ledger")
    claim = {"campaignId": "FS-DATA-WRITE-LIMITS-02", "manifestDigest": digest("offline"),
             "nonceDigest": digest(frozen["nonce"]), "gatePath": str(tmp_path / "gate"),
             "gatePlanDigest": digest(frozen),
             "locks": [{"key": "project/demo-envelope/firestore/(default)/documents/owned", "mode": "WRITE"}],
             "budget": {"requests": 4, "accounts": 0, "resources": 1, "costMicrousd": 10},
             "durationSeconds": 200}
    envelope = {"permissionDigest": "b" * 64, "issuedAt": 1000, "expiresAt": 10000,
                "limits": {"requests": 40, "accounts": 0, "resources": 10, "costMicrousd": 100},
                "concurrency": 4, "scopes": [{"key": "project/demo-envelope", "mode": "EXCLUSIVE"}]}
    ticket = ledger.reserve(envelope, claim, frozen, now=1100)
    create(tmp_path / "gate", frozen)
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    return gate, ledger, ticket, claim, envelope, frozen


def recover(gate, frozen, *, owned, first=None, final=None):
    results = [(200, copy.deepcopy(DOCUMENT)) if owned else (404, copy.deepcopy(ABSENT)),
               (200, {}), (404, copy.deepcopy(ABSENT))]
    if first is not None:
        results[0] = first
    if final is not None:
        results[2] = final
    for i, declared in enumerate(frozen["jobs"]["limits"]["recovery"]):
        op = copy.deepcopy(declared)
        source = op.pop("versionFrom", None)
        if source is not None and owned:
            op["path"] += "?currentDocument.updateTime=" + quote(VERSION, safe="")
        try:
            gate.dispatch(op, True, lambda i=i: copy.deepcopy(results[i]))
        except ValueError:
            # Continue the fixed recovery sequence, never invent a new slot.
            pass


def held(ledger, ticket, claim, envelope):
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot() == before
    assert before["reservations"][ticket["reservation"]]["state"] == "held"
    assert before["envelopes"][digest(envelope)]["allocated"] == claim["budget"]
    # A later run cannot evade the held resource lock using a different nonce.
    frozen = plan("patch", False)
    frozen["nonce"] = "c" * 32
    other = {**claim, "gatePath": claim["gatePath"] + "-next", "nonceDigest": digest(frozen["nonce"]),
             "gatePlanDigest": digest(frozen)}
    with pytest.raises(ValueError, match="lock conflict"):
        ledger.reserve(envelope, other, frozen, now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("status,body", [(404, ABSENT), (400, REFUSED)])
@pytest.mark.parametrize("key,value", EXTRAS)
def test_error_plus_success_or_unknown_envelope_never_proves_absence_or_refusal(status, body, key, value):
    body = {**copy.deepcopy(body), key: copy.deepcopy(value)}
    if status == 404:
        assert typed_absence(status, body) is False
    else:
        assert shared_gate._creation_outcome(request("patch"), status, body, []) == "unknown"


@pytest.mark.parametrize("status,body", [(404, ABSENT), (400, REFUSED)])
@pytest.mark.parametrize("diagnostic", [{}, {"message": "fixture error"},
    {"details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "metadata": {"name": RESOURCE}}]},
    {"message": "fixture", "errors": [{"domain": "global", "reason": "fixture"}]}])
def test_diagnostics_inside_a_typed_error_remain_usable(status, body, diagnostic):
    body = copy.deepcopy(body)
    body["error"].update(diagnostic)
    if status == 404:
        assert typed_absence(status, body) is True
    else:
        assert shared_gate._creation_outcome(request("patch"), status, body, []) == "refused"


@pytest.mark.parametrize("surface", ["patch", "commit", "batchWrite"])
@pytest.mark.parametrize("error", [None, False, {}, {"code": 403, "status": "PERMISSION_DENIED"}])
def test_success_with_an_error_field_never_grants_creation_proofs(surface, error):
    body = {**reply(surface), "error": error}
    with pytest.raises(ValueError, match="success response contains an API error"):
        shared_gate._creation_proofs(request(surface), 200, body, {"resources": [RESOURCE]}, plan(surface, False))
    # Defense for a caller holding an otherwise valid success proof.
    valid = shared_gate._creation_proofs(request(surface), 200, reply(surface),
                                        {"resources": [RESOURCE]}, plan(surface, False))
    assert shared_gate._creation_outcome(request(surface), 200, body, valid) == "unknown"


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("surface", ["patch", "commit", "batchWrite"])
@pytest.mark.parametrize("mode", ["normal", "typed-refusal", "error-in-success", "success-in-refusal", "success-in-absence"])
def test_gate_ledger_retirement_requires_unambiguous_envelopes(tmp_path, surface, scheduled, mode):
    gate, ledger, ticket, claim, envelope, frozen = start(tmp_path, surface, scheduled)
    body, status = reply(surface), 200
    if mode in {"typed-refusal", "success-in-refusal"}:
        body, status = copy.deepcopy(REFUSED), 400
        if mode == "success-in-refusal":
            body.update(reply(surface))
    if mode == "error-in-success":
        body["error"] = {"code": 403, "status": "PERMISSION_DENIED"}
        with pytest.raises(ValueError):
            gate.dispatch(frozen["jobs"]["limits"]["observation"][0], False, lambda: (status, body))
    else:
        gate.dispatch(frozen["jobs"]["limits"]["observation"][0], False, lambda: (status, body))
    final = (404, {**ABSENT, **DOCUMENT}) if mode == "success-in-absence" else None
    recover(gate, frozen, owned=mode in {"normal", "success-in-absence"}, final=final)
    if mode in {"normal", "typed-refusal"}:
        gate.finish()
        ledger.finish(ticket)
        state = ledger.snapshot()
        assert state["reservations"][ticket["reservation"]]["state"] == "released"
        assert state["envelopes"][digest(envelope)]["allocated"] == claim["budget"]
    else:
        with pytest.raises(ValueError):
            gate.finish()
        held(ledger, ticket, claim, envelope)
        state = gate.snapshot()
        if mode in {"error-in-success", "success-in-refusal"}:
            assert unconfirmed_creates(state, "limits") == 1
            assert state["jobs"]["limits"]["creationProofs"] == {}
            assert not any(e["method"] == "DELETE" for e in state["events"])
        else:
            assert RESOURCE not in state["jobs"]["limits"]["absenceProofs"]


@pytest.mark.parametrize("scheduled", [False, True])
def test_ledger_revalidates_a_conflicting_absence_even_when_gate_complete_is_set(tmp_path, scheduled):
    gate, ledger, ticket, claim, envelope, frozen = start(tmp_path, "patch", scheduled)
    gate.dispatch(frozen["jobs"]["limits"]["observation"][0], False, lambda: (200, copy.deepcopy(DOCUMENT)))
    recover(gate, frozen, owned=True)
    gate.finish()
    with gate.locked() as state:
        # Recompute the checksum too: the failure must be semantic, not just a digest mismatch.
        contradictory = {**copy.deepcopy(ABSENT), "name": RESOURCE}
        state["jobs"]["limits"]["absenceProofs"][RESOURCE]["body"] = contradictory
        state["events"][-1]["responseDigest"] = digest(contradictory)
        shared_gate._save(gate.path, state)
    held(ledger, ticket, claim, envelope)


@pytest.mark.parametrize("scheduled", [False, True])
def test_recovery_read_with_error_cannot_supply_a_delete_capture(tmp_path, scheduled):
    gate, ledger, ticket, claim, envelope, frozen = start(tmp_path, "patch", scheduled)
    gate.dispatch(frozen["jobs"]["limits"]["observation"][0], False, lambda: (200, copy.deepcopy(DOCUMENT)))
    contaminated = {**copy.deepcopy(DOCUMENT), "error": {"code": 403, "status": "PERMISSION_DENIED"}}
    with pytest.raises(ValueError, match="readback identity/body mismatch"):
        gate.dispatch(frozen["jobs"]["limits"]["recovery"][0], True, lambda: (200, contaminated))
    assert "0" not in gate.snapshot()["jobs"]["limits"]["captures"]
    delete = copy.deepcopy(frozen["jobs"]["limits"]["recovery"][1])
    delete.pop("versionFrom")
    calls = []
    gate.dispatch(delete, True, lambda: calls.append("delete") or (200, {}))
    assert calls == []
    held(ledger, ticket, claim, envelope)
