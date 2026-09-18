# ruff: noqa: I001 -- reservations bootstraps the shared module path.
"""Real filesystem/process tests of bounded shared admission; no production I/O."""

import multiprocessing
import json
import os
from types import SimpleNamespace
import threading
import time
from pathlib import Path
from urllib.parse import quote

import pytest
from reservations import (
    COMMIT_COLLECTOR_SOURCE_DIGEST,
    COMMIT_SOURCE_COMMIT,
    COMMIT_SOURCE_DIGESTS,
    Ledger,
    conflicts,
)
from broad_contract import digest
from shared_gate import Gate, _save, create
from shared_production import ProductionGate
import shared_production


def envelope():
    return {
        "permissionDigest": "a" * 64,
        "issuedAt": 1000,
        "expiresAt": 10000,
        "limits": {
            "requests": 100,
            "accounts": 10,
            "resources": 10,
            "costMicrousd": 10000,
        },
        "concurrency": 4,
        "scopes": [{"key": "project/p", "mode": "EXCLUSIVE"}],
    }


def plan(label="a"):
    operation = {
        "service": "firestore",
        "method": "GET",
        "path": f"/v1/projects/p/databases/(default)/documents/owned/{label}",
        "body": None,
        "privileged": True,
    }
    return {
        "contract": "shared-local-v2",
        "nonce": digest(label)[:32],
        "wallSeconds": 100,
        "recoverySeconds": 40,
        "intervalSeconds": 0.25,
        "observationRequests": 0,
        "requestCostMicrousd": 1,
        "costMicrousd": 10,
        "jobs": {
            "limits": {
                "observation": [],
                "recovery": [operation],
                "resources": [operation["path"].removeprefix("/v1/")],
            }
        },
    }


def claim(tmp_path, label, locks=None):
    owned = {
        "key": f"project/p/firestore/(default)/documents/owned/{label}",
        "mode": "WRITE",
    }
    locks = list(locks or [])
    if owned not in locks:
        locks.append(owned)
    return {
        "campaignId": label,
        "manifestDigest": digest(label),
        "nonceDigest": digest(plan(label)["nonce"]),
        "gatePath": str((tmp_path / label).resolve()),
        "gatePlanDigest": digest(plan(label)),
        "locks": locks,
        "budget": {"requests": 2, "accounts": 0, "resources": 1, "costMicrousd": 10},
        "durationSeconds": 100,
    }


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (("project/p/config", "READ"), ("project/p/config/policy", "READ"), False),
        (("project/p/config", "WRITE"), ("project/p/config/policy", "READ"), True),
        (("project/p/config", "READ"), ("project/p/config/policy", "WRITE"), True),
        (("project/p/data/a/*", "EXCLUSIVE"), ("project/p/data/a/doc", "READ"), True),
        (("project/p/data/a", "WRITE"), ("project/p/data/ab", "WRITE"), False),
        (("project/p/data/a", "WRITE"), ("project/q/data/a", "WRITE"), False),
    ],
)
def test_segment_aware_lock_conflicts(left, right, expected):
    assert (
        conflicts(
            {"key": left[0], "mode": left[1]}, {"key": right[0], "mode": right[1]}
        )
        is expected
    )


@pytest.mark.parametrize(
    "key",
    [
        "project/p//data",
        "project/p/../data",
        "project/p/data%2Fa",
        "project/p/*/a",
        "/project/p/data",
        "project/p/data/",
    ],
)
def test_ambiguous_scope_refused_without_mutation(tmp_path, key):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(),
            claim(tmp_path, "a", [{"key": key, "mode": "READ"}]),
            plan(),
            now=1100,
        )
    assert ledger.snapshot() == before


def test_atomic_capacity_and_cross_envelope_conflicts(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a", [{"key": "project/p/config", "mode": "WRITE"}])
    ledger.reserve(envelope(), first, plan(), now=1100)
    before = ledger.snapshot()
    other = envelope()
    other["permissionDigest"] = "b" * 64
    with pytest.raises(ValueError):
        ledger.reserve(
            other,
            claim(tmp_path, "b", [{"key": "project/p/config/policy", "mode": "READ"}]),
            plan("b"),
            now=1100,
        )
    assert ledger.snapshot() == before
    too_large = claim(tmp_path, "c")
    too_large["budget"]["accounts"] = 11
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), too_large, plan("c"), now=1100)
    assert ledger.snapshot() == before


def test_expiry_never_releases_locks_and_nonce_is_never_reused(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    with pytest.raises(ValueError):
        ledger.validate(ticket, now=1201)
    second = claim(tmp_path, "b", first["locks"])
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), second, plan("b"), now=1201)
    second["locks"] = [
        {"key": "project/p/data/b", "mode": "WRITE"},
        {
            "key": "project/p/firestore/(default)/documents/owned/a",
            "mode": "WRITE",
        },
    ]
    second["nonceDigest"] = first["nonceDigest"]
    second["gatePlanDigest"] = first["gatePlanDigest"]
    with pytest.raises(ValueError, match="reuse"):
        ledger.reserve(envelope(), second, plan("a"), now=1201)


def test_cleanup_releases_scope_but_never_returns_budget(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    operation = plan()["jobs"]["limits"]["recovery"][0]
    gate.dispatch(
        operation, True, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    gate.finish()
    ledger.finish(ticket)
    state = ledger.snapshot()
    assert state["envelopes"][digest(envelope())]["allocated"] == first["budget"]
    with pytest.raises(ValueError):
        ledger.validate(ticket, now=1110)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    ledger.reserve(
        envelope(), claim(tmp_path, "b", first["locks"]), plan("b"), now=1110
    )


def _stopped_pid():
    child = multiprocessing.get_context("spawn").Process(target=time.sleep, args=(0,))
    child.start()
    pid = child.pid
    child.join(timeout=10)
    assert child.exitcode == 0
    return pid


def generation(label="9"):
    """A source closure of a later generation than the recorded legacy one."""
    return {
        "sourceCommit": digest(f"commit-{label}")[:40],
        "collectorSourceDigest": digest(f"collector-{label}"),
        "sourceDigests": {
            name: digest(f"{name}-{label}") for name in COMMIT_SOURCE_DIGESTS
        },
    }


# The preflight the production adapter actually issues: two credential slots,
# then four privileged metadata GETs.
CREDENTIAL_SLOTS = ("oauth-refresh", "oauth-tokeninfo")
PREFLIGHT = ("project", "database", "auth", "key")


def _no_data_attempt(tmp_path, source_generation=None, stop=2, mode="decision"):
    """One failed attempt that stopped at preflight slot `stop` with no data sent.

    `mode` is "decision" when the request was sent and its evidence appended
    before the baseline comparison failed, and "transport" when the slot was
    consumed but no evidence could be appended.
    """
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    frozen = plan()
    frozen["collectorSourceDigest"] = (
        COMMIT_COLLECTOR_SOURCE_DIGEST
        if source_generation is None
        else source_generation["collectorSourceDigest"]
    )
    frozen["observationRequests"] = 17
    frozen["management"] = {
        "observation": [
            {"id": name, "timeout": 13, "duration": 12}
            for name in (*CREDENTIAL_SLOTS, *PREFLIGHT)
        ],
        "recovery": [],
    }
    used = [f"observation:{name}" for name in (*CREDENTIAL_SLOTS, *PREFLIGHT[:stop])]
    observed = PREFLIGHT[: stop if mode == "decision" else stop - 1]
    first["gatePlanDigest"] = digest(frozen)
    first["budget"]["requests"] = 27
    ticket = ledger.reserve(
        envelope(), first, frozen, generation=source_generation, now=1100
    )
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], "limits")
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        state["jobs"]["limits"]["pid"] = state["coordinatorPid"]
        state["total"] = len(used)
        state["observation"] = len(used)
        state["costMicrousd"] = len(used)
        state["managementUsed"] = used
        state["managementEvents"] = [
            {"id": item, "started": index, "durationReserved": 12}
            for index, item in enumerate(state["managementUsed"])
        ]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt = {
        "kind": "commit-acquisition-receipt-v2",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "claimDigest": ticket["claimDigest"],
        "gate": snapshot,
        "chargedCalls": len(used),
        "collection": None,
        "productionExecuted": False,
        "failure": "ValueError",
        "releaseEligible": False,
        "reservationStateAtPublication": "held",
        "executionKind": "fixed-production-wire",
        "metadata": [{"id": f"observation:{name}", "status": 200} for name in observed],
        "credentialEvidence": [
            {
                "slot": "refresh",
                "workerReaped": True,
                "complete": True,
                "verified": True,
                "status": 200,
            },
            {
                "slot": "tokeninfo",
                "workerReaped": True,
                "complete": True,
                "verified": True,
                "status": 200,
            },
        ],
    }
    if source_generation is not None:
        # A receipt written before the generation binding existed carries none,
        # which is what the legacy branch of this helper reproduces.
        receipt["generation"] = source_generation
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": frozen["collectorSourceDigest"],
        "sourceCommit": COMMIT_SOURCE_COMMIT
        if source_generation is None
        else source_generation["sourceCommit"],
        "sourceDigests": COMMIT_SOURCE_DIGESTS
        if source_generation is None
        else source_generation["sourceDigests"],
    }
    return ledger, gate, ticket, record


def test_no_data_abort_releases_only_lock_and_keeps_budget_and_nonce(tmp_path):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    ledger.abort_no_data(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert row["abortRecordDigest"] == digest(record)
    assert gate.snapshot()["stopped"] is True
    with pytest.raises(ValueError):
        gate.dispatch(plan()["jobs"]["limits"]["recovery"][0], True, lambda: None)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        gate.claim()
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        gate.coordinator_call(0, lambda: None)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        gate.stop(environment=True)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    with pytest.raises(ValueError):
        gate.finish()
    assert row["finalGateDigest"] == digest(gate.snapshot())
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["envelopes"][digest(envelope())]["allocated"]
        == row["claim"]["budget"]
    )
    ledger.reserve(
        envelope(),
        claim(tmp_path, "b", claim(tmp_path, "a")["locks"]),
        plan("b"),
        now=1110,
    )
    reuse = claim(tmp_path, "a")
    reuse["gatePath"] = str((tmp_path / "other-gate").resolve())
    with pytest.raises(ValueError, match="reuse"):
        ledger.reserve(envelope(), reuse, plan(), now=1110)


@pytest.mark.parametrize("stop", [1, 2, 3, 4])
@pytest.mark.parametrize("mode", ["decision", "transport"])
def test_no_data_abort_accepts_every_preflight_stop_point(tmp_path, stop, mode):
    """Any preflight gate can stop an attempt, and all four are retirable.

    The evidence contract used to admit exactly one stop point, which left an
    attempt that reached the auth or API-key gate with no documented retirement.
    """
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, stop=stop, mode=mode)
    ledger.abort_no_data(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert gate.snapshot()["stopped"] is True


@pytest.mark.parametrize(
    "ids",
    [
        ["observation:database"],
        ["observation:database", "observation:project"],
        ["observation:project", "observation:auth"],
        ["observation:project", "observation:database", "observation:key"],
        [
            "observation:project",
            "observation:database",
            "observation:auth",
            "observation:key",
        ],
        [],
    ],
    ids=[
        "wrong-first",
        "reordered",
        "skips-database",
        "skips-auth",
        "too-many",
        "none",
    ],
)
def test_no_data_abort_refuses_metadata_that_is_not_a_preflight_prefix(tmp_path, ids):
    """Only a prefix of the declared preflight sequence proves where it stopped."""
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path, stop=3)
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    receipt["metadata"] = [{"id": name, "status": 200} for name in ids]
    path.write_text(json.dumps(receipt))
    record = {**record, "receiptDigest": digest(receipt)}
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


@pytest.mark.parametrize(
    "damage",
    [
        {"gate": {"total": 6}},
        {"gate": {"observation": 4}},
        {"gate": {"recovery": 1}},
        {"job": {"observation": 1}},
        {"job": {"recovery": 1}},
        {"job": {"owned": ["projects/p/databases/(default)/documents/owned/a"]}},
        {"job": {"creationProofs": {"a": {"name": "a"}}}},
        {"job": {"absent": ["a"]}},
    ],
    ids=[
        "charged-more-than-used",
        "observation-count",
        "recovery-count",
        "job-observation",
        "job-recovery",
        "job-owned",
        "job-creation-proof",
        "job-absent",
    ],
)
def test_no_data_abort_refuses_a_receipt_that_shows_dispatched_data(tmp_path, damage):
    """The contract must say "no data left this run", not merely "it stopped early"."""
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path, stop=3)
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    receipt["gate"].update(damage.get("gate", {}))
    for job in receipt["gate"]["jobs"].values():
        job.update(damage.get("job", {}))
    if "total" in damage.get("gate", {}):
        receipt["chargedCalls"] = receipt["gate"]["total"]
    path.write_text(json.dumps(receipt))
    record = {
        **record,
        "receiptDigest": digest(receipt),
        "gateDigest": digest(receipt["gate"]),
    }
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_no_data_abort_requires_the_receipt_to_bind_the_recorded_generation(tmp_path):
    """A row that recorded a generation is retired only by a receipt naming it."""
    source = generation("later")
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path, source, stop=3)
    path = Path(record["receiptPath"])
    receipt = json.loads(path.read_text())
    del receipt["generation"]
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="recorded generation"):
        ledger.abort_no_data(ticket, {**record, "receiptDigest": digest(receipt)})
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_no_data_abort_retires_a_reservation_of_a_later_generation(tmp_path):
    later = generation()
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, later)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["generation"] == (
        later
    )
    ledger.abort_no_data(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert row["abortRecordDigest"] == digest(record)
    assert gate.snapshot()["stopped"] is True
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )


def test_no_data_abort_refuses_a_receipt_naming_another_generation(tmp_path):
    """A receipt that records a closure must record the one being proven."""
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, generation())
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["generation"] = generation("10")
    receipt_path.write_text(json.dumps(receipt))
    record = {**record, "receiptDigest": digest(receipt)}
    with pytest.raises(ValueError, match="recorded generation"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    assert gate.snapshot()["stopped"] is False


def test_no_data_abort_refuses_a_generation_the_reservation_never_recorded(tmp_path):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path, generation())
    other = generation("10")
    for field, value in (
        ("sourceCommit", other["sourceCommit"]),
        ("sourceDigests", other["sourceDigests"]),
        ("sourceCommit", COMMIT_SOURCE_COMMIT),
        ("sourceDigests", COMMIT_SOURCE_DIGESTS),
    ):
        with pytest.raises(ValueError, match="source closure"):
            ledger.abort_no_data(ticket, {**record, field: value})
        assert (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
        )
    assert gate.snapshot()["stopped"] is False


def test_no_data_abort_of_a_reservation_without_a_generation_stays_on_the_legacy_one(
    tmp_path,
):
    ledger, _gate, ticket, record = _no_data_attempt(tmp_path)
    assert "generation" not in ledger.snapshot()["reservations"][ticket["reservation"]]
    later = generation()
    with pytest.raises(ValueError, match="source closure"):
        ledger.abort_no_data(ticket, {**record, "sourceCommit": later["sourceCommit"]})
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )


@pytest.mark.parametrize(
    "damage",
    [
        {"sourceCommit": "not-a-commit"},
        {"sourceCommit": "A" * 40},
        {"collectorSourceDigest": "0" * 63},
        {"sourceDigests": {}},
        {"sourceDigests": {"shared_gate.py": "0" * 63}},
        {"sourceDigests": {"../shared_gate.py": "0" * 64}},
        {"sourceDigests": ["shared_gate.py"]},
        {"extra": "field"},
    ],
)
def test_reserve_refuses_a_malformed_generation_without_mutation(tmp_path, damage):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(),
            claim(tmp_path, "a"),
            plan(),
            generation={**generation(), **damage},
            now=1100,
        )
    assert ledger.snapshot() == before


def test_recorded_generation_is_revalidated_when_the_ledger_is_read(tmp_path):
    ledger, _gate, ticket, _record = _no_data_attempt(tmp_path, generation())
    state = json.loads((ledger.path / "state.json").read_text())
    state["reservations"][ticket["reservation"]]["generation"]["sourceCommit"] = "0"
    (ledger.path / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="frozen source commit"):
        ledger.snapshot()


@pytest.mark.parametrize(
    "damage",
    [
        "event",
        "counter",
        "inflight",
        "owned",
        "proof",
        "live-worker",
        "management",
        "cost",
    ],
)
def test_no_data_abort_rejects_positive_or_uncertain_data(tmp_path, damage):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    with gate.locked() as state:
        job = state["jobs"]["limits"]
        if damage == "event":
            state["events"].append({"completed": False})
        elif damage == "counter":
            job["observation"] = 1
        elif damage == "inflight":
            job["inflight"] = True
        elif damage == "owned":
            job["owned"].append(job["resources"][0])
        elif damage == "proof":
            job["creationProofs"][job["resources"][0]] = {}
        elif damage == "management":
            state["managementEvents"].pop()
        elif damage == "cost":
            state["costMicrousd"] += 1
        else:
            job["pid"] = os.getpid()
        _save(gate.path, state)
    with pytest.raises(ValueError):
        ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        != "aborted-no-data"
    )


@pytest.mark.parametrize(
    "damage", ["receipt", "ticket", "source", "gate", "missing-gate"]
)
def test_no_data_abort_rejects_changed_binding(tmp_path, damage):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    record = dict(record)
    if damage == "receipt":
        Path(record["receiptPath"]).write_text("{}")
    elif damage == "ticket":
        record["ticket"] = {**ticket, "reservation": "0" * 64}
    elif damage == "source":
        record["collectorSourceDigest"] = "0" * 64
    elif damage == "gate":
        record["gateDigest"] = "0" * 64
    else:
        (gate.path / "state.json").unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        != "aborted-no-data"
    )


@pytest.mark.parametrize("gate_stopped", [False, True])
def test_no_data_abort_recovers_closing_crash(tmp_path, gate_stopped):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    with ledger._locked() as state:
        row = ledger._row(state, ticket)
        row["state"] = "closing"
        row["abortRecordDigest"] = digest(record)
        ledger._save(state)
    if gate_stopped:
        gate.abort_no_data(record["planDigest"], record["gateDigest"], digest(record))
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )


def test_no_data_abort_rejects_tampered_gate_after_stop(tmp_path):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    with ledger._locked() as state:
        row = ledger._row(state, ticket)
        row["state"] = "closing"
        row["abortRecordDigest"] = digest(record)
        ledger._save(state)
    gate.abort_no_data(record["planDigest"], record["gateDigest"], digest(record))
    with gate.locked() as state:
        state["jobs"]["limits"]["owned"].append(state["jobs"]["limits"]["resources"][0])
        _save(gate.path, state)
    with pytest.raises(ValueError, match="terminal Gate"):
        ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "closing"
    )


@pytest.mark.parametrize("missing", ["coordinator", "job", "both", "malformed"])
def test_no_data_abort_requires_recorded_worker_identity(tmp_path, missing):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    with gate.locked() as state:
        if missing in {"coordinator", "both"}:
            state["coordinatorPid"] = None
        if missing in {"job", "both"}:
            state["jobs"]["limits"]["pid"] = None
        if missing == "malformed":
            state["jobs"]["limits"]["pid"] = "not-a-pid"
        _save(gate.path, state)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["gate"] = gate.snapshot()
    receipt_path.write_text(json.dumps(receipt))
    record["gateDigest"] = digest(receipt["gate"])
    record["receiptDigest"] = digest(receipt)
    with pytest.raises(ValueError, match="worker identity"):
        ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "closing"
    )


def test_terminal_abort_rejects_recovery_management_without_gate_mutation(
    tmp_path, monkeypatch
):
    ledger, gate, ticket, record = _no_data_attempt(tmp_path)
    ledger.abort_no_data(ticket, record)
    frozen = gate.snapshot()
    worker_pid = frozen["coordinatorPid"]
    monkeypatch.setattr(shared_production.os, "getpid", lambda: worker_pid)
    production_gate = ProductionGate(gate.path, "limits")
    coordinator = SimpleNamespace(budget=SimpleNamespace(recovery=True))
    with pytest.raises(ValueError, match="management stopped"):
        production_gate.manage(coordinator, "project", lambda: "accepted")
    assert gate.snapshot() == frozen
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["finalGateDigest"] == digest(frozen)


def contender(root, barrier, queue, label):
    ledger = Ledger(Path(root) / "ledger")
    request = claim(Path(root), label, [{"key": "project/p/shared", "mode": "WRITE"}])
    barrier.wait(timeout=10)
    try:
        ledger.reserve(envelope(), request, plan(label), now=1100)
        queue.put("accepted")
    except ValueError:
        queue.put("refused")


def test_two_processes_cannot_both_reserve_conflicting_scope(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ctx = multiprocessing.get_context("spawn")
    barrier, queue = ctx.Barrier(2), ctx.Queue()
    children = [
        ctx.Process(target=contender, args=(str(tmp_path), barrier, queue, label))
        for label in ("a", "b")
    ]
    try:
        for child in children:
            child.start()
        for child in children:
            child.join(timeout=15)
            assert child.exitcode == 0
        assert sorted([queue.get(timeout=2), queue.get(timeout=2)]) == [
            "accepted",
            "refused",
        ]
        assert len(ledger.snapshot()["reservations"]) == 1
        assert (
            ledger.snapshot()["envelopes"][digest(envelope())]["allocated"]["requests"]
            == 2
        )
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
        queue.close()
        queue.join_thread()


def test_same_permission_cannot_multiply_its_envelope(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    before = ledger.snapshot()
    changed = envelope()
    changed["limits"]["requests"] += 100
    with pytest.raises(ValueError, match="another envelope"):
        ledger.reserve(changed, claim(tmp_path, "b"), plan("b"), now=1100)
    assert ledger.snapshot() == before


def test_readers_share_scope_but_concurrency_still_bounds_admission(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    policy = envelope()
    policy["concurrency"] = 2
    locks = [{"key": "project/p/config", "mode": "READ"}]
    ledger.reserve(policy, claim(tmp_path, "a", locks), plan(), now=1100)
    ledger.reserve(policy, claim(tmp_path, "b", locks), plan("b"), now=1100)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="concurrency"):
        ledger.reserve(policy, claim(tmp_path, "c"), plan("c"), now=1100)
    assert ledger.snapshot() == before


def test_ticket_cannot_move_to_copied_or_missing_ledger(tmp_path):
    import shutil

    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    shutil.copytree(tmp_path / "ledger", tmp_path / "copy")
    with pytest.raises(ValueError, match="ticket"):
        Ledger(tmp_path / "copy").validate(ticket, now=1100)
    with pytest.raises(FileNotFoundError):
        Ledger(tmp_path / "missing")
    (tmp_path / "alias").symlink_to(tmp_path / "ledger", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        Ledger(tmp_path / "alias")


def interrupted_worker(root, connection):
    ledger = Ledger(Path(root) / "ledger")
    request = claim(Path(root), "a")
    ticket = ledger.reserve(envelope(), request, plan(), now=1100)
    create(Path(request["gatePath"]), plan())
    gate = Gate(request["gatePath"], "limits")
    gate.claim()

    def interrupted():
        connection.send(ticket)
        connection.close()
        raise SystemExit(23)

    gate.dispatch(plan()["jobs"]["limits"]["recovery"][0], True, interrupted)


def test_exited_worker_keeps_uncertain_gate_and_shared_ownership(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    child = ctx.Process(target=interrupted_worker, args=(str(tmp_path), sender))
    try:
        child.start()
        sender.close()
        assert receiver.poll(10)
        ticket = receiver.recv()
        child.join(timeout=10)
        assert child.exitcode == 23
        gate = Gate(tmp_path / "a", "limits").snapshot()
        assert gate["total"] == 1
        assert gate["jobs"]["limits"]["inflight"] is True
        with pytest.raises(ValueError, match="cleanup"):
            ledger.finish(ticket)
        row = ledger.snapshot()["reservations"][ticket["reservation"]]
        assert row["state"] == "held"
        with pytest.raises(ValueError, match="conflict"):
            ledger.reserve(
                envelope(),
                claim(tmp_path, "b", row["claim"]["locks"]),
                plan("b"),
                now=5000,
            )
    finally:
        receiver.close()
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)


def test_closing_refuses_dispatch_without_gate_ledger_lock_inversion(tmp_path):
    import threading
    import time

    ledger = Ledger.create(tmp_path / "ledger")
    request = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), request, plan(), now=1100)
    create(Path(request["gatePath"]), plan())
    gate = Gate(request["gatePath"], "limits")
    gate.claim()
    gate.dispatch(
        plan()["jobs"]["limits"]["recovery"][0],
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    gate.finish()
    errors = []

    def finish():
        try:
            ledger.finish(ticket)
        except Exception as error:  # noqa: BLE001 -- Preserve thread failures for assertions.
            errors.append(error)

    worker = threading.Thread(target=finish, daemon=True)
    with gate.locked():
        worker.start()
        until = time.monotonic() + 5
        while (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
            != "closing"
        ):
            assert time.monotonic() < until
            time.sleep(0.01)
        with pytest.raises(ValueError, match="unavailable"):
            ledger.validate(ticket, now=1110)
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert errors == []
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
    )


def test_production_gate_cannot_borrow_another_permission_budget(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    frozen = plan()
    frozen["permissionDigest"] = "b" * 64
    request = claim(tmp_path, "a")
    request["gatePlanDigest"] = digest(frozen)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="permission differs"):
        ledger.reserve(envelope(), request, frozen, now=1100)
    assert ledger.snapshot() == before


def test_validate_samples_default_clock_after_waiting_for_ledger_lock(tmp_path):
    now = time.time()
    policy = envelope()
    policy.update(issuedAt=now - 1, expiresAt=now + 4.5)
    request = claim(tmp_path, "a")
    short_plan = plan()
    short_plan["wallSeconds"] = 3
    short_plan["recoverySeconds"] = 0.5
    request["gatePlanDigest"] = digest(short_plan)
    request["durationSeconds"] = 3
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(policy, request, short_plan, now=now)
    entered = threading.Event()
    errors = []

    def validate():
        entered.set()
        try:
            ledger.validate(ticket, duration=1)
        except ValueError as error:
            assert "unavailable" in str(error)
            errors.append(error)
        else:
            errors.append(
                AssertionError("validate accepted after the reservation deadline")
            )

    with ledger._locked():
        worker = threading.Thread(target=validate, daemon=True)
        worker.start()
        assert entered.wait(2)
        time.sleep(2.2)
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert errors and isinstance(errors[0], ValueError)


def test_reserve_samples_default_clock_after_waiting_for_ledger_lock(tmp_path):
    now = time.time()
    policy = envelope()
    policy.update(issuedAt=now - 1, expiresAt=now + 3.5)
    request = claim(tmp_path, "a")
    short_plan = plan()
    short_plan["wallSeconds"] = 3
    short_plan["recoverySeconds"] = 0.5
    request["gatePlanDigest"] = digest(short_plan)
    request["durationSeconds"] = 3
    ledger = Ledger.create(tmp_path / "ledger")
    entered = threading.Event()
    errors = []

    def reserve():
        entered.set()
        try:
            ledger.reserve(policy, request, short_plan)
        except ValueError as error:
            errors.append(error)

    with ledger._locked():
        worker = threading.Thread(target=reserve, daemon=True)
        worker.start()
        assert entered.wait(2)
        time.sleep(3.2)
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert any("permission window" in str(error) for error in errors)
    assert ledger.snapshot()["reservations"] == {}


@pytest.mark.parametrize(
    "locks",
    [
        [],
        [{"key": "project/p/firestore/(default)/documents/other", "mode": "WRITE"}],
        [{"key": "project/p/firestore/(default)/documents/owned/a", "mode": "READ"}],
        [{"key": "project/q/firestore/(default)/documents/owned/a", "mode": "WRITE"}],
    ],
)
def test_gate_firestore_resources_require_covering_write_lock(tmp_path, locks):
    ledger = Ledger.create(tmp_path / "ledger")
    request = claim(tmp_path, "a", locks)
    request["locks"] = locks
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), request, plan(), now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("covered", [True, False])
def test_gate_resource_lock_prevents_same_document_escape(tmp_path, covered):
    ledger = Ledger.create(tmp_path / "ledger")
    ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    before = ledger.snapshot()
    other_plan = plan("b")
    other_plan["jobs"]["limits"]["recovery"][0]["path"] = plan()["jobs"]["limits"][
        "recovery"
    ][0]["path"]
    other_plan["jobs"]["limits"]["resources"] = [
        other_plan["jobs"]["limits"]["recovery"][0]["path"].removeprefix("/v1/")
    ]
    request = claim(
        tmp_path,
        "b",
        [
            {"key": "project/p/data/alternate", "mode": "WRITE"},
            {
                "key": "project/p/firestore/(default)/documents/owned/*",
                "mode": "WRITE",
            },
        ],
    )
    if not covered:
        request["locks"] = claim(tmp_path, "b")["locks"]
    request["gatePlanDigest"] = digest(other_plan)
    request["nonceDigest"] = digest(other_plan["nonce"])
    with pytest.raises(ValueError, match="conflict" if covered else "not covered"):
        ledger.reserve(envelope(), request, other_plan, now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize(
    "body",
    [
        {"nonJson": "<html>not found</html>"},
        {"error": {"code": 404, "status": "PERMISSION_DENIED"}},
        {"error": {"code": "404", "status": "NOT_FOUND"}},
        {"error": {"code": 404.0, "status": "NOT_FOUND"}},
    ],
)
def test_untyped_absence_never_releases_shared_ownership(tmp_path, body):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    operation = plan()["jobs"]["limits"]["recovery"][0]
    with pytest.raises(ValueError, match="typed.*absence"):
        gate.dispatch(operation, True, lambda: (404, body))
    with pytest.raises(ValueError):
        gate.finish()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(), claim(tmp_path, "b", first["locks"]), plan("b"), now=1110
        )


def test_absent_boolean_cannot_replace_bound_cleanup_evidence(tmp_path):
    from shared_gate import _save

    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    with gate.locked() as state:
        job = state["jobs"]["limits"]
        job.update(complete=True, absent=list(job["resources"]), recovery=1)
        _save(gate.path, state)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


@pytest.mark.parametrize(
    "field,value",
    [
        ("requestDigest", "wrong-resource"),
        ("responseDigest", "wrong-body"),
        ("completed", False),
        ("phase", "observation"),
    ],
)
def test_absence_release_checks_request_response_and_completion(tmp_path, field, value):
    from shared_gate import _save

    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    operation = plan()["jobs"]["limits"]["recovery"][0]
    gate.dispatch(
        operation, True, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    gate.finish()
    with gate.locked() as state:
        state["events"][0][field] = value
        _save(gate.path, state)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_a_claim_may_name_the_gate_job_it_reserved(tmp_path):
    """The reservation addresses the Gate by the job its own campaign declared."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = {**claim(tmp_path, "a"), "gateJob": "limits"}
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    assert ledger.bound_claim(ticket)["gateJob"] == "limits"
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    gate.dispatch(
        plan()["jobs"]["limits"]["recovery"][0],
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    gate.finish()
    ledger.finish(ticket)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
    )


def test_a_named_gate_job_must_exist_in_the_reserved_gate(tmp_path):
    """A claim that names a job the Gate never hosted is a binding error."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = {**claim(tmp_path, "a"), "gateJob": "probe-1"}
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    gate.dispatch(
        plan()["jobs"]["limits"]["recovery"][0],
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    gate.finish()
    with pytest.raises(ValueError, match="registered Gate job"):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


@pytest.mark.parametrize("name", ["", "a/b", "a b", 7, None, "x" * 65])
def test_a_malformed_gate_job_name_is_refused_without_mutation(tmp_path, name):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(), {**claim(tmp_path, "a"), "gateJob": name}, plan(), now=1100
        )
    assert ledger.snapshot() == before


def test_a_claim_key_outside_the_closed_set_is_still_refused(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="closed campaign claim"):
        ledger.reserve(
            envelope(), {**claim(tmp_path, "a"), "gateSlot": "limits"}, plan(), now=1100
        )
    assert ledger.snapshot() == before


# A second campaign shape: three probes, an interleaved schedule, one bearer
# credential slot and its own preflight gates and receipt kind. Synthetic, and
# deliberately unlike the Commit lane in every one of those dimensions.
CAMPAIGN_CREDENTIALS = ("bearer-issue",)
CAMPAIGN_PREFLIGHT = ("project", "database", "owned-scope")
CAMPAIGN_PROBES = ("p1", "p2", "p3")
CAMPAIGN_RECEIPT_KIND = "request-bytes-acquisition-receipt-v1"


def campaign_plan(tmp_path):
    op = lambda key: {
        "service": "firestore",
        "path": "/v1/" + key,
        "body": None,
        "method": "GET",
        "privileged": True,
        "form": False,
    }
    owned = {
        probe: f"projects/p/databases/(default)/documents/owned/a/probe/{probe}"
        for probe in CAMPAIGN_PROBES
    }
    jobs = {
        probe: {
            "resources": [owned[probe]],
            "observation": [op(owned[probe]), op(owned[probe])],
            "recovery": [op(owned[probe]), op(owned[probe])],
            "schedule": [
                {"phase": "observation", "index": 0},
                {"phase": "recovery", "index": 0},
                {"phase": "observation", "index": 1},
                {"phase": "recovery", "index": 1},
            ],
        }
        for probe in CAMPAIGN_PROBES
    }
    return {
        "contract": "shared-local-v1",
        "nonce": plan("a")["nonce"],
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": 12,
        "costMicrousd": 5000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": 2,
        "jobSlots": 3,
        "receiptKind": CAMPAIGN_RECEIPT_KIND,
        "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
        "management": {
            "observation": [
                {"id": name, "timeout": 13, "duration": 12}
                for name in (*CAMPAIGN_CREDENTIALS, *CAMPAIGN_PREFLIGHT)
            ],
            "recovery": [],
            "credentialIds": list(CAMPAIGN_CREDENTIALS),
            "credentialSlots": ["bearer"],
        },
        "jobs": jobs,
    }


def _campaign_attempt(tmp_path, *, stop=1, mode="decision", dispatched=False):
    """A failed attempt by the three-probe campaign, stopped at preflight `stop`."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    first["gateJob"] = CAMPAIGN_PROBES[0]
    frozen = campaign_plan(tmp_path)
    first["gatePlanDigest"] = digest(frozen)
    first["budget"] = {
        "requests": 60,
        "accounts": 1,
        "resources": 3,
        "costMicrousd": 9000,
    }
    first["durationSeconds"] = 600
    ticket = ledger.reserve(envelope(), first, frozen, now=1100)
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], CAMPAIGN_PROBES[0])
    used = [
        f"observation:{name}"
        for name in (*CAMPAIGN_CREDENTIALS, *CAMPAIGN_PREFLIGHT[:stop])
    ]
    observed = CAMPAIGN_PREFLIGHT[: stop if mode == "decision" else stop - 1]
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        for probe in CAMPAIGN_PROBES:
            state["jobs"][probe]["pid"] = state["coordinatorPid"]
        state["total"] = len(used)
        state["observation"] = len(used)
        state["costMicrousd"] = len(used)
        state["managementUsed"] = used
        state["managementEvents"] = [
            {"id": item, "started": index, "durationReserved": 12}
            for index, item in enumerate(used)
        ]
        if dispatched:
            # The transport-deadline stop: a probe Commit was sent and its
            # outcome is unknown, so no evidence can prove that no data exists.
            state["jobs"][CAMPAIGN_PROBES[0]]["observation"] = 1
            state["jobs"][CAMPAIGN_PROBES[0]]["scheduleDone"] = 1
            state["total"] += 1
            state["observation"] += 1
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt = {
        "kind": CAMPAIGN_RECEIPT_KIND,
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "claimDigest": ticket["claimDigest"],
        "gate": snapshot,
        "chargedCalls": snapshot["total"],
        "collection": None,
        "productionExecuted": False,
        "failure": "ValueError",
        "releaseEligible": False,
        "reservationStateAtPublication": "held",
        "executionKind": "fixed-production-wire",
        "metadata": [{"id": f"observation:{name}", "status": 200} for name in observed],
        "credentialEvidence": [
            {
                "slot": "bearer",
                "workerReaped": True,
                "complete": True,
                "verified": True,
                "status": 200,
            }
        ],
    }
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": frozen["collectorSourceDigest"],
        "sourceCommit": COMMIT_SOURCE_COMMIT,
        "sourceDigests": COMMIT_SOURCE_DIGESTS,
    }
    return ledger, gate, ticket, record


@pytest.mark.parametrize("stop", [1, 2, 3])
@pytest.mark.parametrize("mode", ["decision", "transport"])
def test_every_preflight_stop_of_a_second_campaign_is_retirable(tmp_path, stop, mode):
    """The evidence contract follows the Gate plan, not the Commit lane's slots."""
    ledger, gate, ticket, record = _campaign_attempt(tmp_path, stop=stop, mode=mode)
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )
    assert gate.snapshot()["stopped"] is True
    assert all(job["stopped"] for job in gate.snapshot()["jobs"].values())


def test_a_transport_deadline_stop_is_never_retirable_as_no_data(tmp_path):
    """A dispatched probe Commit may have been applied, whatever the receipt says."""
    ledger, gate, ticket, record = _campaign_attempt(tmp_path, dispatched=True)
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    assert gate.snapshot()["stopped"] is False


def test_a_second_campaign_receipt_must_carry_its_own_declared_kind(tmp_path):
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["kind"] = "commit-acquisition-receipt-v2"
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, {**record, "receiptDigest": digest(receipt)})
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_a_second_campaign_credential_slot_set_is_its_own(tmp_path):
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["credentialEvidence"] = [
        {**receipt["credentialEvidence"][0], "slot": slot}
        for slot in ("refresh", "tokeninfo")
    ]
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, {**record, "receiptDigest": digest(receipt)})
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_management_outside_the_declared_campaign_prefix_is_refused(tmp_path):
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path, stop=2)
    gate = Gate(Path(record["receiptPath"]).parent / "gate", CAMPAIGN_PROBES[0])
    with gate.locked() as state:
        state["managementUsed"] = [
            "observation:bearer-issue",
            "observation:owned-scope",
        ]
        state["managementEvents"] = [
            {"id": item, "started": index, "durationReserved": 12}
            for index, item in enumerate(state["managementUsed"])
        ]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["gate"] = snapshot
    receipt["chargedCalls"] = snapshot["total"]
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(
            ticket,
            {
                **record,
                "gateDigest": digest(snapshot),
                "receiptDigest": digest(receipt),
            },
        )
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


# A third campaign shape: no credential acquisition, no metadata preflight, and
# probe slots that read before they write. Its stop points are real no-data
# stops even though data requests were sent.
READONLY_RECEIPT_KIND = "request-bytes-acquisition-receipt-v1"


def readonly_plan(creates=False):
    owned = "projects/p/databases/(default)/documents/owned/a/probe/u01"
    op = {
        "service": "firestore",
        "path": "/v1/" + owned,
        "body": None,
        "method": "GET",
        "privileged": True,
        "form": False,
    }
    return {
        "contract": "shared-local-v1",
        "nonce": plan("a")["nonce"],
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": 3,
        "costMicrousd": 5000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": 2,
        "jobSlots": 1,
        "receiptKind": READONLY_RECEIPT_KIND,
        "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
        "management": {
            "observation": [],
            "recovery": [],
            "credentialIds": [],
            "credentialSlots": [],
        },
        "jobs": {
            "probe": {
                "resources": [owned],
                "observation": [dict(op), dict(op), dict(op)],
                "recovery": [dict(op)],
                "schedule": [
                    {"phase": "observation", "index": 0, "creates": creates},
                    {"phase": "observation", "index": 1, "creates": creates},
                    {"phase": "observation", "index": 2, "creates": creates},
                    {"phase": "recovery", "index": 0},
                ],
            }
        },
    }


def _readonly_attempt(tmp_path, *, dispatched=0, creates=False):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    first["gateJob"] = "probe"
    frozen = readonly_plan(creates)
    first["gatePlanDigest"] = digest(frozen)
    first["budget"] = {
        "requests": 60,
        "accounts": 1,
        "resources": 1,
        "costMicrousd": 9000,
    }
    first["durationSeconds"] = 600
    ticket = ledger.reserve(envelope(), first, frozen, now=1100)
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], "probe")
    gate.claim()
    for index in range(dispatched):
        gate.dispatch(
            frozen["jobs"]["probe"]["observation"][index],
            False,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        state["jobs"]["probe"]["pid"] = state["coordinatorPid"]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt = {
        "kind": READONLY_RECEIPT_KIND,
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "claimDigest": ticket["claimDigest"],
        "gate": snapshot,
        "chargedCalls": snapshot["total"],
        "collection": None,
        "productionExecuted": False,
        "failure": "ValueError",
        "releaseEligible": False,
        "reservationStateAtPublication": "held",
        "executionKind": "fixed-production-wire",
        "metadata": [],
        "credentialEvidence": [],
    }
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": frozen["collectorSourceDigest"],
        "sourceCommit": COMMIT_SOURCE_COMMIT,
        "sourceDigests": COMMIT_SOURCE_DIGESTS,
    }
    return ledger, gate, ticket, record


def test_a_stop_before_the_schedule_starts_is_retirable(tmp_path):
    """A campaign with no preflight slots still has a stop point at zero."""
    ledger, gate, ticket, record = _readonly_attempt(tmp_path)
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )
    assert gate.snapshot()["stopped"] is True


@pytest.mark.parametrize("dispatched", [1, 2, 3])
def test_a_stop_after_only_non_creating_slots_is_retirable(tmp_path, dispatched):
    """Ownership reads create nothing, so a stop during them leaves no residue."""
    ledger, gate, ticket, record = _readonly_attempt(tmp_path, dispatched=dispatched)
    assert gate.snapshot()["jobs"]["probe"]["observation"] == dispatched
    ledger.abort_no_data(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert gate.snapshot()["stopped"] is True


@pytest.mark.parametrize("dispatched", [1, 2])
def test_a_stop_after_a_slot_that_may_create_is_never_retirable(tmp_path, dispatched):
    """A slot the plan did not declare non-creating may have written a document."""
    ledger, gate, ticket, record = _readonly_attempt(
        tmp_path, dispatched=dispatched, creates=True
    )
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    assert gate.snapshot()["stopped"] is False


def test_an_abort_refuses_a_gate_job_the_claim_did_not_reserve(tmp_path):
    """abort_no_data checks the named job exists, exactly as finish does."""
    ledger, _gate, ticket, record = _readonly_attempt(tmp_path)
    with ledger._locked() as state:
        ledger._row(state, ticket)["claim"]["gateJob"] = "probe-absent"
        row = ledger._row(state, ticket)
        row["claimDigest"] = digest(row["claim"])
        ledger._save(state)
    ticket = {
        **ticket,
        "claimDigest": digest(
            ledger.snapshot()["reservations"][ticket["reservation"]]["claim"]
        ),
    }
    with pytest.raises(ValueError, match="registered Gate job"):
        ledger.abort_no_data(ticket, {**record, "ticket": ticket})


def test_a_receipt_gate_plan_must_match_its_own_digest(tmp_path):
    """The embedded plan is read for the contract, so it is pinned before it is read."""
    ledger, _gate, ticket, record = _readonly_attempt(tmp_path)
    receipt_path = Path(record["receiptPath"])
    receipt = json.loads(receipt_path.read_text())
    receipt["gate"]["plan"]["receiptKind"] = "commit-acquisition-receipt-v2"
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="no-data attempt"):
        ledger.abort_no_data(
            ticket,
            {
                **record,
                "gateDigest": digest(receipt["gate"]),
                "receiptDigest": digest(receipt),
            },
        )
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


# An uncertain stop: a probe Commit was dispatched and its outcome is unknown.
# Such a row is correctly refused by the no-data path, and before the escalation
# exit existed it stayed held and active forever, holding its lock key and its
# whole allocation even after the owner had removed the residue by hand.
ESCALATION_KIND = "shared-owner-escalation-close-v1"


def _typed_absence():
    return {"status": 404, "body": {"error": {"code": 404, "status": "NOT_FOUND"}}}


def _escalation_record(ledger, ticket, record, *, resources=None, attest=None):
    """An owner attestation plus typed absence for every owned resource."""
    import platform

    receipt = json.loads(Path(record["receiptPath"]).read_text())
    owned = sorted(
        name
        for job in receipt["gate"]["plan"]["jobs"].values()
        for name in job["resources"]
    )
    claim = ledger.bound_claim(ticket)
    now = time.time()
    attestation = {
        "kind": "owner-escalation-attestation-v1",
        "status": "attested",
        "campaignId": claim["campaignId"],
        "nonceDigest": claim["nonceDigest"],
        "claimDigest": ticket["claimDigest"],
        "ledgerRoot": str(ledger.path),
        "reservation": ticket["reservation"],
        "receiptDigest": record["receiptDigest"],
        "gateDigest": record["gateDigest"],
        "ownerIdentity": "t-k",
        "recoveryOwner": "t-k",
        "residueRemoved": True,
        "resourceCount": len(owned),
        "resourcesDigest": digest(owned),
        "attestedAt": now - 1,
        "expiresAt": now + 3600,
        "executionHost": {
            "platform": platform.system().lower(),
            "machine": platform.machine(),
        },
    }
    attestation.update(attest or {})
    return {
        "kind": ESCALATION_KIND,
        "ticket": ticket,
        "gateDigest": record["gateDigest"],
        "receiptPath": record["receiptPath"],
        "receiptDigest": record["receiptDigest"],
        "attestation": attestation,
        "absence": {
            name: _typed_absence()
            for name in (owned if resources is None else resources)
        },
    }


def test_an_escalated_stop_closes_and_stops_being_active(tmp_path):
    """The row reaches a terminal state and releases its lock key, nothing more."""
    ledger, gate, ticket, record = _campaign_attempt(tmp_path, dispatched=True)
    with pytest.raises(ValueError):
        ledger.abort_no_data(ticket, record)
    escalation = _escalation_record(ledger, ticket, record)
    ledger.close_after_escalation(ticket, escalation)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "closed-after-escalation"
    assert row["escalationRecordDigest"] == digest(escalation)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    # The allocation is never refunded, only the conflict lock is freed.
    envelope_row = ledger.snapshot()["envelopes"][digest(envelope())]
    assert envelope_row["allocated"] == row["claim"]["budget"]
    reuse = claim(tmp_path, "b", row["claim"]["locks"])
    reuse["gatePath"] = str((tmp_path / "second-gate").resolve())
    ledger.reserve(envelope(), reuse, plan("b"), now=1110)
    ledger.close_after_escalation(ticket, escalation)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-escalation"
    )


def test_an_escalated_close_refuses_without_a_bound_owner_attestation(tmp_path):
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path, dispatched=True)
    base = _escalation_record(ledger, ticket, record)
    for damage in (
        {"status": "pending"},
        {"kind": "other-attestation-v1"},
        {"campaignId": "another-campaign"},
        {"nonceDigest": "0" * 64},
        {"claimDigest": "0" * 64},
        {"reservation": "0" * 64},
        {"receiptDigest": "0" * 64},
        {"gateDigest": "0" * 64},
        {"ledgerRoot": "/nonexistent/ledger"},
        {"residueRemoved": False},
        {"resourceCount": 99},
        {"resourcesDigest": "0" * 64},
        {"ownerIdentity": "<<ROOT: who>>"},
        {"recoveryOwner": ""},
        {"attestedAt": time.time() + 600},
        {"expiresAt": time.time() - 1},
        {"executionHost": {"platform": "other", "machine": "other"}},
    ):
        with pytest.raises(ValueError):
            ledger.close_after_escalation(
                ticket, _escalation_record(ledger, ticket, record, attest=damage)
            )
        assert (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
        )
    escalation = dict(base)
    del escalation["attestation"]
    with pytest.raises(ValueError, match="escalation close record"):
        ledger.close_after_escalation(ticket, escalation)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_an_escalated_close_refuses_a_resource_not_proven_absent(tmp_path):
    """Every owned resource, not merely the ones the owner chose to read back."""
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path, dispatched=True)
    receipt = json.loads(Path(record["receiptPath"]).read_text())
    owned = sorted(
        name
        for job in receipt["gate"]["plan"]["jobs"].values()
        for name in job["resources"]
    )
    with pytest.raises(ValueError, match="absent"):
        ledger.close_after_escalation(
            ticket, _escalation_record(ledger, ticket, record, resources=owned[:-1])
        )
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    escalation = _escalation_record(ledger, ticket, record)
    escalation["absence"][owned[0]] = {"status": 200, "body": {"name": owned[0]}}
    with pytest.raises(ValueError, match="absent"):
        ledger.close_after_escalation(ticket, escalation)
    escalation["absence"][owned[0]] = {"status": 404, "body": {"error": {"code": 500}}}
    with pytest.raises(ValueError, match="absent"):
        ledger.close_after_escalation(ticket, escalation)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_the_escalation_exit_and_the_no_data_abort_are_mutually_exclusive(tmp_path):
    """Neither path can be reached with the other's evidence."""
    ledger, _gate, ticket, record = _campaign_attempt(tmp_path, stop=1)
    escalation = _escalation_record(ledger, ticket, record)
    with pytest.raises(ValueError, match="no-data"):
        ledger.close_after_escalation(ticket, escalation)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )

    other, _gate, other_ticket, other_record = _campaign_attempt(
        tmp_path / "second", dispatched=True
    )
    with pytest.raises(ValueError, match="no-data abort record"):
        other.abort_no_data(
            other_ticket, _escalation_record(other, other_ticket, other_record)
        )
    with pytest.raises(ValueError):
        other.close_after_escalation(other_ticket, other_record)
    assert (
        other.snapshot()["reservations"][other_ticket["reservation"]]["state"] == "held"
    )


def abandoned_plan():
    """A scheduled probe whose observation can stop before it creates anything."""
    owned = "projects/p/databases/(default)/documents/owned/a/probe/u01"
    read = {
        "kind": "ownership-read",
        "resource": owned,
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + owned,
        "body": None,
        "privileged": True,
        "form": False,
    }
    return {
        "contract": "shared-local-v1",
        "nonce": plan("a")["nonce"],
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": 2,
        "costMicrousd": 5000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": 2,
        "jobSlots": 1,
        "receiptKind": READONLY_RECEIPT_KIND,
        "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
        "management": {
            "observation": [],
            "recovery": [],
            "credentialIds": [],
            "credentialSlots": [],
        },
        "jobs": {
            "probe": {
                "resources": [owned],
                "observation": [dict(read), dict(read)],
                "recovery": [dict(read)],
                "schedule": [
                    {"phase": "observation", "index": 0, "creates": False},
                    {"phase": "observation", "index": 1, "creates": False},
                    {"phase": "recovery", "index": 0, "creates": False},
                ],
            }
        },
    }


def test_a_stop_before_any_create_retires_as_no_data(tmp_path):
    """An abandoned observation that wrote nothing is still a no-data stop."""
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    first["gateJob"] = "probe"
    frozen = abandoned_plan()
    first["gatePlanDigest"] = digest(frozen)
    first["budget"] = {
        "requests": 60,
        "accounts": 1,
        "resources": 1,
        "costMicrousd": 9000,
    }
    first["durationSeconds"] = 600
    ticket = ledger.reserve(envelope(), first, frozen, now=1100)
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], "probe")
    gate.claim()
    gate.abandon_observation("transport-deadline")
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        state["jobs"]["probe"]["pid"] = state["coordinatorPid"]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    assert snapshot["jobs"]["probe"]["stopReason"] == "transport-deadline"
    receipt = {
        "kind": READONLY_RECEIPT_KIND,
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "claimDigest": ticket["claimDigest"],
        "gate": snapshot,
        "chargedCalls": snapshot["total"],
        "collection": None,
        "productionExecuted": False,
        "failure": "TimeoutError",
        "releaseEligible": False,
        "reservationStateAtPublication": "held",
        "executionKind": "fixed-production-wire",
        "metadata": [],
        "credentialEvidence": [],
    }
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": frozen["collectorSourceDigest"],
        "sourceCommit": COMMIT_SOURCE_COMMIT,
        "sourceDigests": COMMIT_SOURCE_DIGESTS,
    }
    ledger.abort_no_data(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "aborted-no-data"
    )


ABANDON_KIND = "shared-abandoned-cleanup-close-v1"
CREATED_VERSION = "2026-09-19T00:00:00.000000Z"


def abandoned_cleanup_plan():
    """One probe that creates a document, stops early, then cleans up."""
    owned = "projects/p/databases/(default)/documents/owned/a/probe/u01"
    fields = {"blob": {"stringValue": "x"}}
    commit = {
        "service": "firestore",
        "method": "POST",
        "path": "/v1/projects/p/databases/(default)/documents:commit",
        "body": {
            "writes": [
                {
                    "update": {"name": owned, "fields": fields},
                    "currentDocument": {"exists": False},
                }
            ]
        },
        "privileged": True,
        "form": False,
    }
    read = {
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + owned,
        "body": None,
        "privileged": True,
        "form": False,
    }
    delete = {
        **read,
        "method": "DELETE",
        "versionFrom": 0,
    }
    return (
        owned,
        fields,
        {
            "contract": "shared-local-v1",
            "nonce": plan("a")["nonce"],
            "wallSeconds": 600,
            "recoverySeconds": 300,
            "observationRequests": 2,
            "costMicrousd": 5000,
            "requestCostMicrousd": 1,
            "intervalSeconds": 0.25,
            "requestSeconds": 2,
            "jobSlots": 1,
            "receiptKind": READONLY_RECEIPT_KIND,
            "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
            "management": {
                "observation": [],
                "recovery": [],
                "credentialIds": [],
                "credentialSlots": [],
            },
            "jobs": {
                "probe": {
                    "resources": [owned],
                    "observation": [commit, dict(read)],
                    "recovery": [dict(read), delete, dict(read)],
                    "schedule": [
                        {"phase": "observation", "index": 0},
                        {"phase": "observation", "index": 1, "creates": False},
                        {"phase": "recovery", "index": 0, "creates": False},
                        {"phase": "recovery", "index": 1, "creates": False},
                        {"phase": "recovery", "index": 2, "creates": False},
                    ],
                }
            },
        },
    )


def _abandoned_cleanup(
    tmp_path, *, absent=True, abandon=True, cleanup=True, lost=False, steps=3
):
    owned, fields, frozen = abandoned_cleanup_plan()
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    first["gatePath"] = str((tmp_path / "a" / "gate").resolve())
    first["gateJob"] = "probe"
    first["gatePlanDigest"] = digest(frozen)
    first["budget"] = {
        "requests": 60,
        "accounts": 1,
        "resources": 1,
        "costMicrousd": 9000,
    }
    first["durationSeconds"] = 600
    ticket = ledger.reserve(envelope(), first, frozen, now=1100)
    create(Path(first["gatePath"]), frozen)
    gate = Gate(first["gatePath"], "probe")
    gate.claim()
    probe = frozen["jobs"]["probe"]

    def commit():
        if lost:
            raise TimeoutError("transport deadline")
        return (
            200,
            {
                "writeResults": [{"updateTime": CREATED_VERSION}],
                "commitTime": CREATED_VERSION,
            },
        )

    if lost:
        with pytest.raises(TimeoutError):
            gate.dispatch(probe["observation"][0], False, commit)
    else:
        gate.dispatch(probe["observation"][0], False, commit)
    if abandon:
        gate.abandon_observation("transport-deadline")
    if cleanup and steps >= 1:
        gate.dispatch(
            probe["recovery"][0],
            True,
            lambda: (
                200,
                {"name": owned, "fields": fields, "updateTime": CREATED_VERSION},
            ),
        )
    if cleanup and steps >= 2:
        deleted = dict(probe["recovery"][1])
        del deleted["versionFrom"]
        deleted["path"] += "?currentDocument.updateTime=" + quote(
            CREATED_VERSION, safe=""
        )
        gate.dispatch(deleted, True, lambda: (200, {}))
    if cleanup and steps >= 3:
        gate.dispatch(
            probe["recovery"][2],
            True,
            lambda: (
                (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
                if absent
                else (
                    200,
                    {"name": owned, "fields": fields, "updateTime": CREATED_VERSION},
                )
            ),
        )
    with gate.locked() as state:
        state["coordinatorPid"] = _stopped_pid()
        state["jobs"]["probe"]["pid"] = state["coordinatorPid"]
        _save(gate.path, state)
    snapshot = gate.snapshot()
    receipt = {
        "kind": READONLY_RECEIPT_KIND,
        "ticket": ticket,
        "planDigest": first["gatePlanDigest"],
        "claimDigest": ticket["claimDigest"],
        "gate": snapshot,
        "chargedCalls": snapshot["total"],
        "collection": None,
        "productionExecuted": True,
        "failure": "TimeoutError",
        "releaseEligible": False,
        "reservationStateAtPublication": "held",
        "executionKind": "fixed-production-wire",
        "metadata": [],
        "credentialEvidence": [],
    }
    path = tmp_path / "a" / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = {
        "kind": ABANDON_KIND,
        "ticket": ticket,
        "gateDigest": digest(snapshot),
        "receiptPath": str(path.resolve()),
        "receiptDigest": digest(receipt),
    }
    return ledger, gate, ticket, record


def test_an_abandoned_run_that_cleaned_up_retires_without_an_attestation(tmp_path):
    """The Gate's own journal proves absence, so no owner statement is needed."""
    ledger, gate, ticket, record = _abandoned_cleanup(tmp_path)
    escalation = _escalation_record(
        ledger, ticket, {**record, "kind": "shared-no-data-abort-v1"}
    )
    with pytest.raises(ValueError, match="recoverable"):
        ledger.close_after_escalation(ticket, escalation)
    ledger.close_after_abandon(ticket, record)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "closed-after-abandon"
    assert row["abandonRecordDigest"] == digest(record)
    assert row["finalGateDigest"] == digest(gate.snapshot())
    reuse = claim(tmp_path, "b", row["claim"]["locks"])
    reuse["gatePath"] = str((tmp_path / "second-gate").resolve())
    ledger.reserve(envelope(), reuse, plan("b"), now=1110)
    ledger.close_after_abandon(ticket, record)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-abandon"
    )


def test_a_created_document_still_present_keeps_the_escalation_exit(tmp_path):
    """One document left behind is exactly what the owner has to attest to."""
    ledger, _gate, ticket, record = _abandoned_cleanup(tmp_path, absent=False)
    with pytest.raises(ValueError, match="abandoned cleanup"):
        ledger.close_after_abandon(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    escalation = _escalation_record(
        ledger, ticket, {**record, "kind": "shared-no-data-abort-v1"}
    )
    ledger.close_after_escalation(ticket, escalation)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-escalation"
    )


def test_an_incomplete_or_unabandoned_cleanup_is_refused(tmp_path):
    ledger, _gate, ticket, record = _abandoned_cleanup(tmp_path, cleanup=False)
    with pytest.raises(ValueError, match="abandoned cleanup"):
        ledger.close_after_abandon(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    other, _gate, other_ticket, other_record = _abandoned_cleanup(
        tmp_path / "second", abandon=False, cleanup=False
    )
    with pytest.raises(ValueError, match="abandoned cleanup"):
        other.close_after_abandon(other_ticket, other_record)
    assert (
        other.snapshot()["reservations"][other_ticket["reservation"]]["state"] == "held"
    )


def test_a_dispatched_commit_with_no_answer_is_never_closed_as_abandoned(tmp_path):
    """Uncreated means no write was sent, not that no proof came back."""
    ledger, gate, ticket, record = _abandoned_cleanup(
        tmp_path, lost=True, cleanup=False
    )
    assert gate.snapshot()["jobs"]["probe"]["unconfirmedCreates"] == 1
    with pytest.raises(ValueError, match="abandoned cleanup"):
        ledger.close_after_abandon(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    escalation = _escalation_record(
        ledger, ticket, {**record, "kind": "shared-no-data-abort-v1"}
    )
    ledger.close_after_escalation(ticket, escalation)
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
        == "closed-after-escalation"
    )


def test_a_partial_recovery_is_never_closed_as_abandoned(tmp_path):
    """Deleted is not the same as proven absent, and only the proof retires it."""
    ledger, gate, ticket, record = _abandoned_cleanup(tmp_path, steps=2)
    job = gate.snapshot()["jobs"]["probe"]
    assert job["recovery"] == 2
    assert job["absent"] == []
    with pytest.raises(ValueError, match="abandoned cleanup"):
        ledger.close_after_abandon(ticket, record)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
