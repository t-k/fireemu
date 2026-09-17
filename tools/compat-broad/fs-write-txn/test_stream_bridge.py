"""Closed stream policy and real private-channel integration tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "production-admission"))
sys.path.insert(0, str(Path(__file__).parent))


def bridge():
    spec = importlib.util.find_spec("stream_bridge")
    assert spec is not None, "the stream protocol must use the existing shared Gate"
    return __import__("stream_bridge")


def test_compiler_freezes_fifteen_observation_and_ten_recovery_slots():
    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-001", "owner-001")
    assert len(plan["jobs"]["stream"]["observation"]) == 15
    assert len(plan["jobs"]["stream"]["recovery"]) == 10
    assert plan["streamBounds"] == {
        "rpcSlots": 25,
        "writeRpcs": 8,
        "outboundFrames": 16,
        "acceptedFrames": 256,
        "writes": 9,
        "maxMessageBytes": 1048576,
        "acceptedBytes": 268435456,
    }
    assert policy.REQUEST_SECONDS == 31


def test_stream_gate_rejects_http_absence_and_retains_uncertainty(tmp_path):
    policy = bridge()
    from shared_gate import Gate, create

    plan = policy.compile_plan("demo-stream-gate", "stream-run-002", "owner-002")
    create(tmp_path / "gate", plan)
    gate = Gate(tmp_path / "gate", "stream")
    gate.claim()
    op = policy.resolve(gate.snapshot(), "stream", False)[0]
    with pytest.raises(ValueError):
        gate.dispatch(
            op, False, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        )
    assert gate.snapshot()["jobs"]["stream"]["inflight"]


def test_compiler_rejects_arbitrary_queue_and_owner_changes(tmp_path):
    policy = bridge()
    from shared_gate import create

    plan = policy.compile_plan("demo-stream-gate", "stream-run-003", "owner-003")
    plan["jobs"]["stream"]["observation"][0]["request"]["name"] += "-foreign"
    with pytest.raises(ValueError, match="compiled"):
        create(tmp_path / "gate", plan)


def reservation(tmp_path, plan, requests=25):
    import time
    from reservations import Ledger
    from broad_contract import digest

    ledger = Ledger.create(tmp_path / "ledger")
    budget = {"requests": requests, "accounts": 0, "resources": 3, "costMicrousd": 2500}
    scope = {
        "key": f"project/{plan['projectId']}/firestore/(default)/documents/{plan['documentPrefix']}",
        "mode": "EXCLUSIVE",
    }
    envelope = {
        "permissionDigest": "a" * 64,
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 1200,
        "limits": budget,
        "concurrency": 1,
        "scopes": [scope],
    }
    claim = {
        "campaignId": plan["nonce"],
        "manifestDigest": digest(plan),
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str((tmp_path / "gate").resolve()),
        "gatePlanDigest": digest(plan),
        "locks": [scope],
        "budget": budget,
        "durationSeconds": 1100,
    }
    ticket = ledger.reserve(envelope, claim, plan)
    return ledger, ticket


def test_reservation_rejects_twenty_four_rpc_allocation(tmp_path):
    plan = bridge().compile_plan("demo-stream-gate", "stream-run-004", "owner-004")
    with pytest.raises(ValueError, match="sub-budget"):
        reservation(tmp_path, plan, 24)


def test_private_channel_rejects_oversized_and_truncated_frames():
    import socket
    import struct

    policy = bridge()
    assert hasattr(policy, "read_message"), "private length-bounded IPC is required"
    a, b = socket.socketpair()
    try:
        b.sendall(struct.pack("!I", policy.MAX_IPC_BYTES + 1))
        with pytest.raises(ValueError, match="bounded"):
            policy.read_message(a)
    finally:
        a.close()
        b.close()


def test_real_local_collector_gate_and_ledger_release(tmp_path):
    import os

    policy = bridge()
    assert hasattr(policy, "run_local"), "real Node collector IPC is required"
    host = os.environ.get("FIRESTORE_EMULATOR_HOST")
    if not host:
        pytest.skip("run under owned fireemu exec for real local integration")
    plan = policy.compile_plan(
        os.environ["GOOGLE_CLOUD_PROJECT"],
        "stream-integration-001",
        "integration-owner",
    )
    ledger, ticket = reservation(tmp_path, plan)
    result = policy.run_local(
        plan, tmp_path / "gate", ledger, ticket, port=int(host.rsplit(":", 1)[1])
    )
    from shared_gate import Gate, validate_absence_proofs

    state = Gate(tmp_path / "gate", "stream").snapshot()
    assert result["outcome"]["complete"] is True
    assert state["jobs"]["stream"]["complete"] is True
    assert state["total"] <= 25
    assert state["reservedRecovery"] == 0
    validate_absence_proofs(state, "stream")
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
    )
    locked = plan["jobs"]["stream"]["resources"][1]
    assert (
        state["jobs"]["stream"]["latestOwnedVersions"][locked]["eventIndex"]
        > state["jobs"]["stream"]["creationProofs"][locked]["eventIndex"]
    )


def test_grpc_terminal_cannot_hide_local_failure():
    policy = bridge()
    assert (
        policy.grpc_code(
            {
                "kind": "grpc_status",
                "complete": True,
                "status": {"code": 5},
                "error": {"code": "client_deadline"},
            }
        )
        is None
    )


def test_read_cannot_advance_owned_version_and_wrong_version_skips_delete(tmp_path):
    from shared_gate import Gate, create
    from broad_contract import digest

    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-005", "owner-005")
    create(tmp_path / "gate", plan)
    gate = Gate(tmp_path / "gate", "stream")
    state = gate.snapshot()
    job = state["jobs"]["stream"]
    name = job["resources"][0]
    old = {"seconds": "1", "nanos": 0}
    later = {"seconds": "2", "nanos": 0}
    fields = {
        "owner": {"stringValue": "o3-stream:owner-005"},
        "role": {"stringValue": "control"},
    }
    job["creationProofs"][name] = {"updateTime": old, "fieldsDigest": digest(fields)}
    job["latestOwnedVersions"] = {
        name: {"updateTime": old, "fieldsDigest": digest(fields)}
    }
    job["recovery"] = 1
    operation = policy.resolve(state, "stream", True)[0]
    raw = {
        "kind": "grpc_status",
        "complete": True,
        "operation": "GetDocument",
        "request": {"name": name},
        "response": {"name": name, "fields": fields, "updateTime": later},
    }
    event = {"phase": "recovery"}
    state["events"].append(event)
    policy.record(
        state,
        "stream",
        operation,
        {"protocol": policy.PROTOCOL, "requestDigest": digest(operation), "raw": raw},
        event,
    )
    assert job["latestOwnedVersions"][name]["updateTime"] == old
    job["recovery"] = 2
    assert policy.resolve(state, "stream", True)[2] == "no-acknowledged-owned-version"


def test_failed_rollback_prevents_destructive_cleanup(tmp_path):
    from shared_gate import Gate, create

    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-006", "owner-006")
    create(tmp_path / "gate", plan)
    state = Gate(tmp_path / "gate", "stream").snapshot()
    state["jobs"]["stream"].update(recovery=2, transactionUnknown=True)
    with pytest.raises(ValueError, match="release unknown"):
        policy.resolve(state, "stream", True)
