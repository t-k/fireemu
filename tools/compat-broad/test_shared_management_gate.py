"""Closed management slots use the real durable Gate and no network."""

import json
import time

import pytest
import shared_gate
from shared_gate import Gate, create
from test_shared_gate import plan


def management_gate(tmp_path):
    value = plan()
    value["permissionExpiresAt"] = time.time() + 600
    value["observationRequests"] = 3
    value["costMicrousd"] = 1000
    value["management"] = {
        "dispatchKind": "closed-v1",
        "observation": [
            {"id": "first", "timeout": 13},
            {"id": "second", "timeout": 13},
        ],
        "recovery": [{"id": "after", "timeout": 13}],
    }
    path = tmp_path / "gate"
    create(path, value)
    return Gate(path, "a")


def receipt(status=200):
    return {
        "status": status,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": {"ok": True},
    }


def test_management_is_durably_debited_before_callback(tmp_path):
    gate = management_gate(tmp_path)
    before = gate.snapshot()

    def send(deadline):
        state = json.loads((gate.path / "state.json").read_bytes())
        assert state["coordinatorInflight"] is True
        assert state["total"] == before["total"] + 1
        assert state["costMicrousd"] == before["costMicrousd"] + 100
        assert state["managementUsed"] == ["observation:first"]
        assert state["managementEvents"][0]["completed"] is False
        assert time.monotonic() < deadline <= time.monotonic() + 13
        return receipt()

    assert gate.management_dispatch("observation", "first", send) == receipt()
    state = gate.snapshot()
    assert state["coordinatorInflight"] is False
    assert state["managementEvents"][0]["completed"] is True
    assert "body" not in state["managementEvents"][0]


@pytest.mark.parametrize(
    "phase,slot",
    [
        ("observation", "second"),
        ("observation", "unknown"),
        ("recovery", "after"),
        ("bad", "first"),
    ],
)
def test_management_rejects_out_of_order_without_sending(tmp_path, phase, slot):
    gate = management_gate(tmp_path)
    with pytest.raises(ValueError):
        gate.management_dispatch(phase, slot, lambda _: pytest.fail("must not send"))
    assert gate.snapshot()["total"] == 0


def test_management_failure_stays_charged_and_cannot_replay(tmp_path):
    gate = management_gate(tmp_path)

    def fail(_):
        raise TimeoutError("private details must not persist")

    with pytest.raises(TimeoutError):
        gate.management_dispatch("observation", "first", fail)
    state = gate.snapshot()
    assert state["total"] == 1
    assert state["coordinatorInflight"] is True
    assert state["managementEvents"][0]["failure"] == "TimeoutError"
    with pytest.raises(ValueError):
        gate.management_dispatch(
            "observation", "first", lambda _: pytest.fail("replay")
        )


@pytest.mark.parametrize("status", [401, 403])
def test_credential_rejection_blocks_following_management_and_data(tmp_path, status):
    gate = management_gate(tmp_path)
    assert (
        gate.management_dispatch("observation", "first", lambda _: receipt(status))[
            "status"
        ]
        == status
    )
    assert gate.snapshot()["credentialRejected"] is True
    with pytest.raises(ValueError):
        gate.management_dispatch("observation", "second", lambda _: pytest.fail("send"))
    gate.claim()
    with pytest.raises(ValueError):
        gate.dispatch(
            plan()["jobs"]["a"]["recovery"][0], True, lambda: pytest.fail("send")
        )


def test_pending_save_failure_never_sends(tmp_path, monkeypatch):
    gate = management_gate(tmp_path)

    def fail(*_):
        raise OSError("disk")

    monkeypatch.setattr(shared_gate, "_save", fail)
    with pytest.raises(OSError):
        gate.management_dispatch("observation", "first", lambda _: pytest.fail("send"))


def test_expired_permission_never_sends(tmp_path):
    gate = management_gate(tmp_path)
    with gate.locked() as state:
        state["started"] -= 1000
        shared_gate._save(gate.path, state)
    with pytest.raises(ValueError):
        gate.management_dispatch("observation", "first", lambda _: pytest.fail("send"))


def test_data_cannot_bypass_management_preflight(tmp_path):
    gate = management_gate(tmp_path)
    gate.claim()
    with pytest.raises(ValueError, match="preflight"):
        gate.dispatch(
            plan()["jobs"]["a"]["observation"][0], False, lambda: pytest.fail("send")
        )


def test_complete_management_and_data_sequence(tmp_path):
    gate = management_gate(tmp_path)
    for slot in ("first", "second"):
        gate.management_dispatch("observation", slot, lambda _: receipt())
    before = gate.snapshot()["reservedRecovery"]
    # Both actual job cleanup slots must be consumed before postflight.
    for key in ("a", "b"):
        job = Gate(gate.path, key)
        job.claim()
        job.dispatch(
            plan()["jobs"][key]["recovery"][0],
            True,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
    gate.management_dispatch("recovery", "after", lambda _: receipt())
    state = gate.snapshot()
    assert before == 3
    assert state["reservedRecovery"] == 0
    assert state["total"] == 5
    assert state["managementUsed"] == [
        "observation:first",
        "observation:second",
        "recovery:after",
    ]
    with pytest.raises(ValueError):
        gate.management_dispatch("recovery", "after", lambda _: pytest.fail("replay"))


def test_permission_window_checked_before_send(tmp_path):
    value = plan()
    value["permissionExpiresAt"] = time.time() - 1
    value["management"] = {
        "dispatchKind": "closed-v1",
        "observation": [{"id": "first", "timeout": 13}],
        "recovery": [],
    }
    create(tmp_path / "expired", value)
    gate = Gate(tmp_path / "expired", "a")
    with pytest.raises(ValueError, match="deadline"):
        gate.management_dispatch("observation", "first", lambda _: pytest.fail("send"))


def test_reaped_incomplete_receipt_is_charged_not_validated(tmp_path):
    gate = management_gate(tmp_path)
    partial = {**receipt(), "complete": False}
    assert (
        gate.management_dispatch("observation", "first", lambda _: partial) == partial
    )
    state = gate.snapshot()
    assert state["total"] == 1
    assert state["coordinatorInflight"] is False
    assert state["managementEvents"][0]["completed"] is False
    assert state["stopped"] is True


@pytest.mark.parametrize(
    "malformed",
    [
        {**receipt(), "body": "x" * (256 * 1024)},
        {**receipt(), "secret": "must not be persisted"},
        {**receipt(), "complete": 1},
    ],
)
def test_malformed_management_receipt_retains_charge(tmp_path, malformed):
    gate = management_gate(tmp_path)
    with pytest.raises(ValueError, match="receipt"):
        gate.management_dispatch("observation", "first", lambda _: malformed)
    state = gate.snapshot()
    assert state["total"] == 1
    assert state["coordinatorInflight"] is True
    assert "must not be persisted" not in (gate.path / "state.json").read_text()


def test_tokeninfo_raw_body_never_persisted(tmp_path):
    value = plan()
    value["permissionExpiresAt"] = time.time() + 600
    value["management"] = {
        "dispatchKind": "closed-v1",
        "observation": [{"id": "oauth-tokeninfo", "timeout": 13}],
        "recovery": [],
    }
    create(tmp_path / "tokeninfo", value)
    gate = Gate(tmp_path / "tokeninfo", "a")
    with pytest.raises(ValueError, match="receipt"):
        gate.management_dispatch(
            "observation",
            "oauth-tokeninfo",
            lambda _: {**receipt(), "body": {"access_token": "secret-canary"}},
        )
    assert "secret-canary" not in (gate.path / "state.json").read_text()
    assert gate.snapshot()["total"] == 1


def test_reaped_no_status_failure_is_charged_and_leaves_nothing_inflight(tmp_path):
    """A worker that died before any HTTP status must not wedge the coordinator."""
    gate = management_gate(tmp_path)
    failed = {
        "status": None,
        "complete": False,
        "workerReaped": True,
        "bodyKind": None,
        "body": None,
    }
    assert gate.management_dispatch("observation", "first", lambda _: failed) == failed
    state = gate.snapshot()
    assert state["total"] == 1
    assert state["coordinatorInflight"] is False
    assert state["stopped"] is True
    assert state["managementEvents"][0]["completed"] is False
    assert state["managementEvents"][0]["status"] is None


@pytest.mark.parametrize(
    "unreaped",
    [
        {"status": None, "complete": False, "workerReaped": False, "bodyKind": None, "body": None},
        {"status": None, "complete": True, "workerReaped": True, "bodyKind": None, "body": None},
    ],
)
def test_no_status_receipt_must_be_reaped_and_incomplete(tmp_path, unreaped):
    gate = management_gate(tmp_path)
    with pytest.raises(ValueError, match="receipt"):
        gate.management_dispatch("observation", "first", lambda _: unreaped)
    assert gate.snapshot()["total"] == 1
