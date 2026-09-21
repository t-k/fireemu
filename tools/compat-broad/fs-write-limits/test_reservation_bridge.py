# ruff: noqa: I001 -- Import the limits/shared path bootstrap first.
"""Offline real Gate/ledger integration; no credential command or network."""

import threading
import time

import pytest
from production_bridge import (
    LimitsGate,
    ReservedCoordinator,
    bind_reserved_wire,
    execution_plan,
    source_digest,
)
from reservations import Ledger
from broad_contract import digest
from shared_gate import create


def setup(tmp_path, *, ledger=None, nonce="d" * 32):
    now = time.time()
    permission = {"expiresAt": now + 2000, "collectorSourceDigest": source_digest()}
    plan = execution_plan(permission, nonce)
    ledger = ledger or Ledger.create(tmp_path / "ledger")
    envelope = {
        "permissionDigest": digest(permission),
        "issuedAt": now - 1,
        "expiresAt": now + 2000,
        "limits": {
            "requests": 40,
            "accounts": 0,
            "resources": 4,
            "costMicrousd": 44000,
        },
        "concurrency": 1,
        "scopes": [{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}],
    }
    claim = {
        "campaignId": "FS-DATA-WRITE-LIMITS-02",
        "manifestDigest": digest(plan),
        "nonceDigest": digest(nonce),
        "gatePath": str((tmp_path / "gate").resolve()),
        "gatePlanDigest": digest(plan),
        "locks": [
            {
                "key": "project/fireemu-35fe6/firestore/(default)/documents/oracle/"
                + nonce,
                "mode": "WRITE",
            }
        ],
        "budget": dict(envelope["limits"]),
        "durationSeconds": 960,
    }
    ticket = ledger.reserve(envelope, claim, plan)
    create(tmp_path / "gate", plan)
    gate = LimitsGate(tmp_path / "gate")
    gate.claim()
    coordinator = ReservedCoordinator(
        permission,
        nonce,
        tmp_path / "coordinator",
        gate,
        "synthetic-key",
        ledger=ledger,
        ticket=ticket,
    )
    coordinator.ready = True  # Offline metadata fixture only.
    coordinator.credential.accept(
        "synthetic-token", {"expires_in": 2000}, time.monotonic()
    )
    return coordinator, gate, ledger, ticket, plan


def test_reserved_wire_charges_gate_within_full_shared_allocation(tmp_path):
    coordinator, gate, ledger, ticket, plan = setup(tmp_path)
    sent = []

    def transport(value):
        sent.append(value)
        return {
            "complete": True,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    wire = bind_reserved_wire(coordinator, plan, transmit=transport)
    operation = plan["jobs"]["limits"]["observation"][0]

    def send():
        result = wire(operation, False, 0, 0)
        return result["status"], result["body"]

    gate.dispatch(operation, False, send)
    assert len(sent) == gate.snapshot()["total"] == 1
    assert (
        ledger.snapshot()["envelopes"][ticket["envelopeDigest"]]["allocated"][
            "requests"
        ]
        == 40
    )
    assert ledger.validate(ticket) == ticket["claimDigest"]


@pytest.mark.parametrize("same_ledger", [True, False])
@pytest.mark.parametrize("kind", ["data", "metadata"])
def test_held_replacement_ticket_cannot_bypass_closing_original(
    tmp_path, same_ledger, kind
):
    coordinator, gate, ledger, ticket, plan = setup(tmp_path / "first")
    _, _, replacement_ledger, replacement_ticket, _ = setup(
        tmp_path / "second", ledger=ledger if same_ledger else None, nonce="e" * 32
    )
    sent = []
    wire = bind_reserved_wire(
        coordinator, plan, transmit=lambda value: sent.append(value)
    )
    # Real finalization uses this same transition before waiting for the Gate.
    with ledger._locked() as state:
        state["reservations"][ticket["reservation"]]["state"] = "closing"
        ledger._save(state)
    assert replacement_ledger.validate(replacement_ticket)
    coordinator.ledger = replacement_ledger
    coordinator.reservation_ticket = replacement_ticket
    operation = plan["jobs"]["limits"]["observation"][0]
    with pytest.raises(ValueError, match="binding changed"):
        if kind == "data":
            gate.dispatch(operation, False, lambda: wire(operation, False, 0, 0))
        else:
            gate.manage(coordinator, "project", lambda: coordinator.reserve("metadata"))
    assert sent == []
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "closing"
    )


@pytest.mark.parametrize("kind", ["data", "metadata"])
def test_closing_lease_blocks_post_wait_data_and_metadata_attempts(tmp_path, kind):
    coordinator, gate, ledger, ticket, plan = setup(tmp_path)
    sent, finish_errors = [], []
    wire = bind_reserved_wire(
        coordinator, plan, transmit=lambda value: sent.append(value)
    )

    def finish():
        try:
            ledger.finish(ticket)
        except ValueError as error:
            finish_errors.append(error)

    worker = threading.Thread(target=finish, daemon=True)

    def after_wait():
        worker.start()
        until = time.monotonic() + 5
        while (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
            != "closing"
        ):
            assert time.monotonic() < until
            time.sleep(0.01)
        if kind == "data":
            operation = plan["jobs"]["limits"]["observation"][0]
            return wire(operation, False, 0, 0)
        coordinator.reserve("metadata")
        sent.append("must-not-send")

    with pytest.raises(ValueError, match="reservation unavailable"):
        if kind == "data":
            gate.dispatch(plan["jobs"]["limits"]["observation"][0], False, after_wait)
        else:
            gate.manage(coordinator, "project", after_wait)
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(finish_errors) == 1
    assert sent == []
    assert gate.snapshot()["total"] == 1
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


@pytest.mark.parametrize("recovery", [False, True])
@pytest.mark.parametrize("kind", ["data", "metadata"])
@pytest.mark.parametrize("shared_wait", [0, 1, 14])
def test_shared_wait_rechecks_phase_deadline_before_transmission(
    tmp_path, monkeypatch, recovery, kind, shared_wait
):
    from contextlib import contextmanager

    # Freeze the origin before Gate creation so exact deadlines do not inherit
    # platform uptime rounding from differently grouped float additions.
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    coordinator, gate, ledger, _, plan = setup(tmp_path)
    sent = []

    def transmit(value):
        sent.append(value)
        return {
            "complete": True,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    wire = bind_reserved_wire(coordinator, plan, transmit=transmit)
    coordinator.budget.recovery = recovery
    state = gate.snapshot()
    deadline = (
        state["started"]
        + plan["wallSeconds"]
        - (0 if recovery else plan["recoverySeconds"])
    )
    clock[0] = deadline - 13
    original_locked = ledger._locked

    @contextmanager
    def waited_lock():
        with original_locked() as live:
            clock[0] += shared_wait
            yield live

    monkeypatch.setattr(ledger, "_locked", waited_lock)
    phase = "recovery" if recovery else "observation"
    operation = plan["jobs"]["limits"][phase][0]

    def data():
        value = wire(operation, recovery, 0, 16 if recovery else 0)
        return value["status"], value["body"]

    def metadata():
        coordinator.reserve("metadata")
        sent.append("metadata-sent")

    def attempt():
        if kind == "data":
            gate.dispatch(operation, recovery, data)
        else:
            gate.manage(coordinator, "project", metadata)

    if shared_wait:
        with pytest.raises(ValueError, match="phase deadline"):
            attempt()
        assert sent == []
    else:
        attempt()
        assert len(sent) == 1


@pytest.mark.parametrize(
    "response_kind", ["valid", "html", "wrong-status", "incomplete"]
)
def test_cleanup_proof_controls_ledger_release_after_owned_creation(
    tmp_path, response_kind
):
    from collector import collect
    from compiler import compile_limits_plan

    _, gate, ledger, ticket, plan = setup(tmp_path)
    compiled = compile_limits_plan("fireemu-35fe6", "(default)", plan["nonce"])
    stored, deleted = {}, []
    absent = {"error": {"code": 404, "status": "NOT_FOUND"}}

    def wire(operation, recovery, index, request_index):
        resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        status, body, complete = 404, absent, True
        if recovery and operation["method"] == "GET" and response_kind != "valid":
            if response_kind == "html":
                body = {"nonJson": "<html>missing route</html>"}
            elif response_kind == "wrong-status":
                body = {"error": {"code": 404, "status": "PERMISSION_DENIED"}}
            else:
                complete = False
        elif operation["method"] == "PATCH":
            if index in (4, 6):
                stored[resource] = {
                    "name": resource,
                    "fields": operation["body"]["fields"],
                    "updateTime": "2026-09-17T00:00:00Z",
                }
                status, body = 200, stored[resource]
            else:
                status, body = (
                    400,
                    {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
                )
        elif operation["method"] == "DELETE":
            del stored[resource]
            deleted.append(resource)
            status, body = 200, {}
        elif resource in stored:
            status, body = 200, stored[resource]
        return {"complete": complete, "status": status, "body": body, "failure": None}

    result = collect(gate, compiled, tmp_path / "collection", wire)
    if response_kind == "valid":
        assert result["cleanupComplete"] is True
        ledger.finish(ticket)
        assert stored == {}
        assert len(deleted) == 2
        assert (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
            == "released"
        )
    else:
        assert result["cleanupComplete"] is False
        assert len(stored) == 2
        assert deleted == []
        with pytest.raises(ValueError):
            ledger.finish(ticket)
        assert (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
        )
