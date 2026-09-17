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


def setup(tmp_path):
    now = time.time()
    nonce = "d" * 32
    permission = {"expiresAt": now + 2000, "collectorSourceDigest": source_digest()}
    plan = execution_plan(permission, nonce)
    ledger = Ledger.create(tmp_path / "ledger")
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
        "campaignId": "limits",
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

    worker = threading.Thread(target=finish)

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
