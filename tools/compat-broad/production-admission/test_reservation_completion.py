# ruff: noqa: I001 -- reservations bootstraps the shared module path.
"""Gate/Ledger completion boundaries using real journals, locks and exited workers.

All API results are explicit fixtures. No Firebase request or credential is used.
"""

import contextlib
import copy
import json
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest

import reservations  # Bootstraps the sibling shared-module path.
import broad_contract
import shared_gate
from broad_contract import digest
from reservations import Ledger
from shared_gate import Gate, _save, create, unconfirmed_creates

ROOT = "projects/p/databases/(default)/documents"
NAMES = [ROOT + "/owned/a", ROOT + "/owned/b"]
VERSION = "2026-09-19T00:00:00.000000Z"
ABSENT = {"error": {"code": 404, "status": "NOT_FOUND"}}


def op(method, path, body=None, **extra):
    return dict(service="firestore", method=method, path=path, body=body,
                privileged=True, **extra)


def fields(name):
    return {"_sharedOwner": {"referenceValue": name}}


def make_plan(*, batch=False, scheduled=False):
    names = NAMES if batch else NAMES[:1]
    write = (
        op("POST", "/v1/" + ROOT + ":batchWrite", {"writes": [
            {"update": {"name": name, "fields": fields(name)},
             "currentDocument": {"exists": False}} for name in names]})
        if batch else
        op("PATCH", "/v1/" + names[0] + "?currentDocument.exists=false",
           {"fields": fields(names[0])})
    )
    recovery = []
    for name in names:
        read = op("GET", "/v1/" + name)
        index = len(recovery)
        recovery.extend([read, op("DELETE", "/v1/" + name, versionFrom=index), read])
    job = {"observation": [write], "recovery": recovery, "resources": list(names)}
    if scheduled:
        job["schedule"] = [dict(phase="observation", index=0, creates=True)] + [
            dict(phase="recovery", index=i, creates=False) for i in range(len(recovery))]
    return {"contract": "shared-local-v2", "nonce": "f" * 32,
            "wallSeconds": 200, "recoverySeconds": 100,
            "observationRequests": 1, "requestCostMicrousd": 1,
            "costMicrousd": 100, "intervalSeconds": 0.25,
            "jobs": {"limits": job}}


def envelope():
    return {"permissionDigest": "a" * 64, "issuedAt": 1000, "expiresAt": 10000,
            "limits": dict(requests=100, accounts=0, resources=10, costMicrousd=10000),
            "concurrency": 4, "scopes": [{"key": "project/p", "mode": "EXCLUSIVE"}]}


def make_claim(path, plan):
    return {"campaignId": "FS-DATA-WRITE-LIMITS-02", "manifestDigest": digest("fixture"),
            "nonceDigest": digest(plan["nonce"]), "gatePath": str(path.resolve()),
            "gatePlanDigest": digest(plan),
            "locks": [{"key": "project/p/firestore/(default)/documents/owned", "mode": "WRITE"}],
            "budget": dict(requests=20, accounts=0,
                           resources=len(plan["jobs"]["limits"]["resources"]), costMicrousd=100),
            "durationSeconds": 200}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network is forbidden in completion tests")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def fast_gate(monkeypatch):
    now = [1000.0]
    def sleep(seconds):
        now[0] += seconds
    monkeypatch.setattr(shared_gate, "time", SimpleNamespace(
        monotonic=lambda: now[0], sleep=sleep))


def reserve(tmp_path, plan):
    ledger = Ledger.create(tmp_path / "ledger")
    claim = make_claim(tmp_path / "run" / "gate", plan)
    ticket = ledger.reserve(envelope(), claim, plan, now=1100)
    return ledger, ticket, claim


# The worker is an actual child process; both coordinatorPid and job pid are
# therefore checked by the actual os.kill(pid, 0) guard after it has been reaped.
# Only wire outcomes and the Gate's rate clock are simulated.
WORKER = r'''
import json, socket, sys
from pathlib import Path
from types import SimpleNamespace
import shared_gate
from shared_gate import Gate, create
from urllib.parse import quote

def blocked(*args, **kwargs):
    raise AssertionError('worker network forbidden')
socket.create_connection = socket.getaddrinfo = blocked
socket.socket.connect = socket.socket.connect_ex = blocked
clock = [1000.0]
def sleep(seconds):
    clock[0] += seconds
shared_gate.time = SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep)
root = Path(sys.argv[1])
plan = json.loads((root / 'plan.json').read_text())
mode = sys.argv[2]
create(root / 'gate', plan)
gate = Gate(root / 'gate', 'limits')
gate.claim()
job = plan['jobs']['limits']
name = job['resources'][0]
version = '2026-09-19T00:00:00.000000Z'
absence = {'error': {'code': 404, 'status': 'NOT_FOUND'}}
if mode == 'uncertain':
    def timeout():
        raise TimeoutError('fixture: write response lost')
    try:
        gate.dispatch(job['observation'][0], False, timeout)
    except TimeoutError:
        pass
elif mode == 'abandoned':
    body = {'name': name, 'fields': job['observation'][0]['body']['fields'], 'updateTime': version}
    gate.dispatch(job['observation'][0], False, lambda: (200, body))
    gate.abandon_observation('offline-fixture-stop')
    gate.dispatch(job['recovery'][0], True, lambda: (200, body))
    delete = dict(job['recovery'][1])
    delete.pop('versionFrom')
    delete['path'] += '?currentDocument.updateTime=' + quote(version, safe='')
    gate.dispatch(delete, True, lambda: (200, {}))
    gate.dispatch(job['recovery'][2], True, lambda: (404, absence))
else:
    raise AssertionError('unknown offline worker mode')
'''


def ended_run(tmp_path, mode="uncertain"):
    plan = make_plan(scheduled=mode == "abandoned")
    ledger, ticket, claim = reserve(tmp_path, plan)
    run = Path(claim["gatePath"]).parent
    run.mkdir(mode=0o700, parents=True)
    (run / "plan.json").write_text(json.dumps(plan))
    search = [Path(module.__file__).resolve().parent
              for module in (shared_gate, reservations, broad_contract)]
    env = {"PYTHONPATH": os.pathsep.join(map(str, search)),
           "PYTHONHASHSEED": "0", "LANG": "C.UTF-8", "HOME": str(run)}
    result = subprocess.run([sys.executable, "-c", WORKER, str(run), mode],
                            env=env, capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    gate = Gate(claim["gatePath"], "limits")
    snapshot = gate.snapshot()
    with pytest.raises(ProcessLookupError):
        os.kill(snapshot["coordinatorPid"], 0)
    receipt = {"ticket": ticket, "claimDigest": ticket["claimDigest"],
               "planDigest": claim["gatePlanDigest"],
               "reservationStateAtPublication": "held", "releaseEligible": False,
               "productionExecuted": False, "executionKind": "offline-fixture"}
    receipt_path = run / "receipt.json"
    receipt_path.write_text(json.dumps(receipt))
    record = {"kind": (reservations.ESCALATION_KIND if mode == "uncertain"
                       else reservations.ABANDON_KIND),
              "ticket": ticket, "gateDigest": digest(snapshot),
              "receiptPath": str(receipt_path.resolve()), "receiptDigest": digest(receipt)}
    if mode == "uncertain":
        record["absence"] = {name: {"status": 404, "body": copy.deepcopy(ABSENT)}
                             for name in snapshot["jobs"]["limits"]["resources"]}
        record["attestation"] = {
            "kind": reservations.ATTESTATION_KIND, "status": "attested",
            "campaignId": claim["campaignId"], "nonceDigest": claim["nonceDigest"],
            "claimDigest": ticket["claimDigest"], "ledgerRoot": str(ledger.path),
            "reservation": ticket["reservation"], "receiptDigest": record["receiptDigest"],
            "gateDigest": record["gateDigest"], "ownerIdentity": "offline-fixture-owner",
            "recoveryOwner": "offline-fixture-recovery", "residueRemoved": True,
            "resourceCount": 1, "resourcesDigest": digest(NAMES[:1]),
            "attestedAt": 1100, "expiresAt": 1200,
            "executionHost": {"platform": platform.system().lower(), "machine": platform.machine()}}
    return ledger, ticket, claim, gate, record


def fixed_wall(monkeypatch, now=1150):
    clock = SimpleNamespace(now=now)
    monkeypatch.setattr(reservations, "time", SimpleNamespace(
        time=lambda: clock.now, monotonic=time.monotonic, sleep=time.sleep))
    return clock


def assert_held(ledger, ticket, before=None):
    current = ledger.snapshot()
    assert current["reservations"][ticket["reservation"]]["state"] == "held"
    if before is not None:
        assert current == before


def test_management_finalizer_rejects_untyped_release_document_without_mutation(tmp_path):
    plan = make_plan()
    ledger, ticket, _ = reserve(tmp_path, plan)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="exact configuration release record"):
        ledger.finish_management_only(ticket, {"kind": "fake-owned-document-release"})
    assert ledger.snapshot() == before


@pytest.mark.parametrize("mode", ["uncertain", "abandoned"])
@pytest.mark.parametrize("embedded", [False, True])
@pytest.mark.parametrize("drift", ["event", "clock", "stopped"])
def test_terminal_close_refuses_changed_gate(tmp_path, monkeypatch, mode, embedded, drift):
    ledger, ticket, claim, gate, record = ended_run(tmp_path, mode)
    fixed_wall(monkeypatch)
    if embedded:
        path = Path(record["receiptPath"])
        receipt = json.loads(path.read_text())
        receipt["gate"] = gate.snapshot()
        path.write_text(json.dumps(receipt))
        record["receiptDigest"] = digest(receipt)
        if mode == "uncertain":
            record["attestation"]["receiptDigest"] = record["receiptDigest"]
    with gate.locked() as state:
        if drift == "event":
            state["events"][0]["ended"] += 0.01
        elif drift == "clock":
            state["lastSent"] += 0.01
        else:
            state["stopped"] = not state["stopped"]
        _save(gate.path, state)
    before = ledger.snapshot()
    close = ledger.close_after_escalation if mode == "uncertain" else ledger.close_after_abandon
    with pytest.raises(ValueError, match="registered Gate differs"):
        close(ticket, record)
    assert_held(ledger, ticket, before)


@pytest.mark.parametrize("mode", ["uncertain", "abandoned"])
def test_bound_terminal_close_is_idempotent_and_preserves_budget(tmp_path, monkeypatch, mode):
    ledger, ticket, claim, gate, record = ended_run(tmp_path, mode)
    clock = fixed_wall(monkeypatch)
    close = ledger.close_after_escalation if mode == "uncertain" else ledger.close_after_abandon
    close(ticket, record)
    expected = "closed-after-escalation" if mode == "uncertain" else "closed-after-abandon"
    snapshot = ledger.snapshot()
    row = snapshot["reservations"][ticket["reservation"]]
    assert row["state"] == expected
    assert row["finalGateDigest"] == record["gateDigest"] == digest(gate.snapshot())
    assert snapshot["envelopes"][ticket["envelopeDigest"]]["allocated"] == claim["budget"]
    clock.now = 1300  # A repeat of the same terminal record is not new admission.
    close(ticket, record)
    assert ledger.snapshot() == snapshot
    with pytest.raises(ValueError, match="unavailable"):
        ledger.validate(ticket, now=1150)


@pytest.mark.parametrize("wait_at", ["ledger", "gate"])
@pytest.mark.parametrize("wall_after,refused", [(1199.99, False), (1200, True),
                                             (1200.01, True), (1099, True)])
def test_attestation_uses_time_after_both_locks(tmp_path, monkeypatch, wait_at, wall_after, refused):
    ledger, ticket, _, gate, record = ended_run(tmp_path)
    clock = fixed_wall(monkeypatch)
    before = ledger.snapshot()
    visits = []
    if wait_at == "ledger":
        original = ledger._locked
        @contextlib.contextmanager
        def delayed():
            with original() as state:
                clock.now = wall_after
                visits.append("ledger")
                yield state
        monkeypatch.setattr(ledger, "_locked", delayed)
    else:
        original = Gate.locked
        @contextlib.contextmanager
        def delayed(self):
            with original(self) as state:
                if self.path == gate.path:
                    clock.now = wall_after
                    visits.append("gate")
                yield state
        monkeypatch.setattr(Gate, "locked", delayed)
    if refused:
        with pytest.raises(ValueError, match="fresh owner escalation attestation"):
            ledger.close_after_escalation(ticket, record)
        assert_held(ledger, ticket, before)
    else:
        ledger.close_after_escalation(ticket, record)
        assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "closed-after-escalation"
    assert visits


@pytest.mark.parametrize("bad_count", [True, 1.0, "1", None, 0, 2])
def test_attested_resource_count_requires_exact_integer(tmp_path, monkeypatch, bad_count):
    ledger, ticket, _, _, record = ended_run(tmp_path)
    fixed_wall(monkeypatch)
    record["attestation"]["resourceCount"] = bad_count
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="bound owner escalation attestation"):
        ledger.close_after_escalation(ticket, record)
    assert_held(ledger, ticket, before)


@pytest.mark.parametrize("marker", ["missing", "null", "wrong"])
def test_no_data_resume_exception_requires_explicit_marker(tmp_path, marker):
    ledger, _, claim, gate, record = ended_run(tmp_path)
    with gate.locked() as state:
        if marker == "null":
            state["noDataAbort"] = None
        elif marker == "wrong":
            state["noDataAbort"] = {"preGateDigest": "a" * 64, "recordDigest": "b" * 64}
        state["lastSent"] += 1
        _save(gate.path, state)
    receipt = json.loads(Path(record["receiptPath"]).read_text())
    with pytest.raises(ValueError, match="registered Gate differs"):
        ledger._bound_gate(claim, record, receipt)


def test_explicit_matching_no_data_resume_marker_remains_supported(tmp_path):
    ledger, _, claim, gate, record = ended_run(tmp_path)
    marker = {"preGateDigest": record["gateDigest"], "recordDigest": digest(record)}
    with gate.locked() as state:
        state["noDataAbort"] = marker
        state["stopped"] = True
        _save(gate.path, state)
    receipt = json.loads(Path(record["receiptPath"]).read_text())
    assert ledger._bound_gate(claim, record, receipt, terminal=marker) == gate.snapshot()
    with pytest.raises(ValueError):
        ledger._bound_gate(claim, record, receipt,
                           terminal={**marker, "recordDigest": "0" * 64})


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("status_code", [0, 3, 4, 13, 14])
def test_batch_outcome_is_preserved_through_ledger_finish(tmp_path, fast_gate, scheduled, status_code):
    plan = make_plan(batch=True, scheduled=scheduled)
    ledger, ticket, claim = reserve(tmp_path, plan)
    create(Path(claim["gatePath"]), plan)
    gate = Gate(claim["gatePath"], "limits")
    gate.claim()
    job = plan["jobs"]["limits"]
    body = {"status": [{}, {"code": status_code}],
            "writeResults": [{"updateTime": VERSION}, {"updateTime": VERSION} if status_code == 0 else {}]}
    gate.dispatch(job["observation"][0], False, lambda: (200, body))
    for index, name in enumerate(NAMES):
        recovery = job["recovery"][index * 3: index * 3 + 3]
        if index == 0 or status_code == 0:
            document = {"name": name, "fields": fields(name), "updateTime": VERSION}
            gate.dispatch(recovery[0], True, lambda document=document: (200, document))
            delete = dict(recovery[1])
            delete.pop("versionFrom")
            delete["path"] += "?currentDocument.updateTime=" + quote(VERSION, safe="")
            gate.dispatch(delete, True, lambda: (200, {}))
        else:
            gate.dispatch(recovery[0], True, lambda: (404, ABSENT))
            delete = dict(recovery[1])
            delete.pop("versionFrom")
            gate.dispatch(delete, True, lambda: pytest.fail("no proof: must not delete"))
        gate.dispatch(recovery[2], True, lambda: (404, ABSENT))
    uncertain = status_code not in (0, 3)
    assert unconfirmed_creates(gate.snapshot(), "limits") == int(uncertain)
    if uncertain:
        with pytest.raises(ValueError, match="ownership retained"):
            gate.finish()
        # Test Ledger's independent guard: do not let its rejection rest on
        # Gate's complete flag alone. This is explicit corrupt-journal injection.
        with gate.locked() as state:
            state["jobs"]["limits"]["complete"] = True
            _save(gate.path, state)
        before = ledger.snapshot()
        with pytest.raises(ValueError, match="cleanup/accounting incomplete"):
            ledger.finish(ticket)
        assert_held(ledger, ticket, before)
        next_plan = copy.deepcopy(plan)
        next_plan["nonce"] = "e" * 32
        next_claim = make_claim(tmp_path / "next-gate", next_plan)
        with pytest.raises(ValueError, match="lock conflict"):
            ledger.reserve(envelope(), next_claim, next_plan, now=1100)
    else:
        gate.finish()
        ledger.finish(ticket)
        snapshot = ledger.snapshot()
        assert snapshot["reservations"][ticket["reservation"]]["state"] == "released"
        assert snapshot["envelopes"][ticket["envelopeDigest"]]["allocated"] == claim["budget"]
