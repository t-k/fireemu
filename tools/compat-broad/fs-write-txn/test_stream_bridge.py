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
        "writeOutboundFrames": 16,
        "outboundFrames": 33,
        "acceptedFrames": 290,
        "writes": 9,
        "maxMessageBytes": 1048576,
        "acceptedBytes": 286261248,
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

    from broad_contract import digest
    from reservations import Ledger

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
    (tmp_path / "result.json").write_text(__import__("json").dumps(result))
    from shared_gate import Gate, validate_absence_proofs

    state = Gate(tmp_path / "gate", "stream").snapshot()
    assert result["outcome"]["complete"] is True
    assert state["jobs"]["stream"]["complete"] is True
    assert state["total"] == 23
    assert len(result["recoveryObservations"]) == 10
    assert all(item["absence"]["status"]["code"] == 5 for item in result["cleanup"])
    assert all("ownedRead" in item for item in result["cleanup"] if not item["skipped"])
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
    from broad_contract import digest
    from shared_gate import Gate, create

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


def test_dead_lease_denies_private_worker_before_loopback_wire(tmp_path):
    import socket
    import time

    from shared_gate import Gate

    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-007", "owner-007")
    ledger, ticket = reservation(tmp_path, plan)
    with ledger._locked() as state:
        state["reservations"][ticket["reservation"]]["deadline"] = time.time() - 1
        ledger._save(state)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        with pytest.raises(ValueError, match="unavailable"):
            policy.run_local(
                plan, tmp_path / "gate", ledger, ticket, port=listener.getsockname()[1]
            )
        with pytest.raises(TimeoutError):
            listener.accept()
    state = Gate(tmp_path / "gate", "stream").snapshot()
    assert state["total"] == 1
    assert state["jobs"]["stream"]["inflight"] is True
    assert len(state["events"]) == 1
    assert state["events"][0]["completed"] is False
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_transaction_cannot_be_substituted_without_prior_successful_journal(tmp_path):
    from shared_gate import Gate, create

    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-008", "owner-008")
    create(tmp_path / "gate", plan)
    state = Gate(tmp_path / "gate", "stream").snapshot()
    state["jobs"]["stream"].update(observation=7, transaction="Zm9yZ2Vk")
    with pytest.raises(ValueError, match="transaction"):
        policy.resolve(state, "stream", False)


def test_unary_byte_allowance_is_reserved(tmp_path):
    from shared_gate import Gate, create

    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-009", "owner-009")
    create(tmp_path / "gate", plan)
    state = Gate(tmp_path / "gate", "stream").snapshot()
    operation = policy.resolve(state, "stream", False)[0]
    policy.debit(state, state["jobs"]["stream"], operation)
    assert state["jobs"]["stream"]["streamUsed"]["acceptedBytes"] == 1048576


def write_state(tmp_path):
    from shared_gate import Gate, create

    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-010", "owner-010")
    create(tmp_path / "gate", plan)
    state = Gate(tmp_path / "gate", "stream").snapshot()
    state["jobs"]["stream"]["observation"] = 2
    operation = policy.resolve(state, "stream", False)[0]
    return policy, state, operation


def acknowledged_write(policy, state, operation, seconds="1"):
    import copy

    from broad_contract import digest

    payload = copy.deepcopy(operation["request"][0])
    payload["streamToken"] = "aGFuZA=="
    raw = {
        "kind": "grpc_status",
        "complete": True,
        "status": {"code": 0},
        "transportReceiptVersion": 2,
        "sentFrames": 2,
        "completedSendFrames": 2,
        "receivedFrames": 2,
        "events": [
            {
                "type": "send",
                "value": {
                    "database": f"projects/{state['plan']['projectId']}/databases/(default)"
                },
            },
            {"type": "data", "value": {"streamToken": "aGFuZA==", "writeResults": []}},
            {"type": "send", "value": payload},
            {
                "type": "data",
                "value": {
                    "streamToken": "bmV4dA==",
                    "writeResults": [{"updateTime": {"seconds": seconds, "nanos": 0}}],
                },
            },
        ],
    }
    return {"protocol": policy.PROTOCOL, "requestDigest": digest(operation), "raw": raw}


def test_substituted_stream_token_cannot_establish_creation(tmp_path):
    policy, state, operation = write_state(tmp_path)
    receipt = acknowledged_write(policy, state, operation)
    receipt["raw"]["events"][2]["value"]["streamToken"] = "Zm9yZ2Vk"
    state["events"].append({"phase": "observation"})
    with pytest.raises(ValueError, match="token"):
        policy.record(state, "stream", operation, receipt, state["events"][-1])
    assert not state["jobs"]["stream"]["creationProofs"]


def test_successful_owned_mutation_advances_latest_but_never_creation(tmp_path):
    policy, state, operation = write_state(tmp_path)
    job = state["jobs"]["stream"]
    state["events"].append({"phase": "observation"})
    policy.record(
        state,
        "stream",
        operation,
        acknowledged_write(policy, state, operation),
        state["events"][-1],
    )
    name = job["resources"][0]
    original = dict(job["creationProofs"][name])
    job["observation"] = 4
    operation = policy.resolve(state, "stream", False)[0]
    state["events"].append({"phase": "observation"})
    policy.record(
        state,
        "stream",
        operation,
        acknowledged_write(policy, state, operation, "2"),
        state["events"][-1],
    )
    assert job["creationProofs"][name] == original
    assert job["latestOwnedVersions"][name]["updateTime"]["seconds"] == "2"
    assert job["latestOwnedVersions"][name]["predecessor"] == 0


def test_incomplete_acknowledgement_grants_no_ownership(tmp_path):
    policy, state, operation = write_state(tmp_path)
    receipt = acknowledged_write(policy, state, operation)
    receipt["raw"]["events"][-1]["value"]["writeResults"] = []
    state["events"].append({"phase": "observation"})
    with pytest.raises(ValueError, match="cardinality"):
        policy.record(state, "stream", operation, receipt, state["events"][-1])
    assert not state["jobs"]["stream"]["creationProofs"]


def test_unary_frame_budget_exhaustion_refuses_before_debit(tmp_path):
    policy, state, _ = write_state(tmp_path)
    job = state["jobs"]["stream"]
    job["observation"] = 0
    operation = policy.resolve(state, "stream", False)[0]
    policy.debit(state, job, operation)
    assert job["streamUsed"]["outboundFrames"] == 1
    assert job["streamUsed"]["acceptedFrames"] == 2
    job["streamUsed"]["acceptedFrames"] = policy.BOUNDS["acceptedFrames"]
    before = dict(job["streamUsed"])
    with pytest.raises(ValueError, match="capacity"):
        policy.debit(state, job, operation)
    assert job["streamUsed"] == before


def test_unary_oversized_receipt_cannot_be_recorded(tmp_path):
    from broad_contract import digest

    policy, state, _ = write_state(tmp_path)
    state["jobs"]["stream"]["observation"] = 0
    operation = policy.resolve(state, "stream", False)[0]
    receipt = {
        "protocol": policy.PROTOCOL,
        "requestDigest": digest(operation),
        "raw": {
            "kind": "grpc_status",
            "complete": True,
            "operation": "GetDocument",
            "request": operation["request"],
            "status": {"code": 5},
            "details": "a" * 1048576,
        },
    }
    state["events"].append({})
    with pytest.raises(ValueError, match="byte bound"):
        policy.record(state, "stream", operation, receipt, state["events"][-1])


def test_node_runtime_is_frozen_in_plan():
    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-011", "owner-011")
    assert "nodeRuntime" in plan, (
        "private grant recipient must be frozen before reservation"
    )
    assert Path(plan["nodeRuntime"]["path"]).is_absolute()
    assert len(plan["nodeRuntime"]["sha256"]) == 64
    forged = dict(plan)
    forged["nodeRuntime"] = {"path": "/bin/echo", "sha256": "0" * 64}
    with pytest.raises(ValueError):
        policy.validate_plan(forged)


def test_source_and_runtime_bindings_are_rechecked_at_completion():
    policy = bridge()
    runtime = policy.node_runtime()
    policy.verify_execution_bindings(policy.source_digest(), runtime)
    with pytest.raises(ValueError, match="binding changed"):
        policy.verify_execution_bindings("0" * 64, runtime)
    with pytest.raises(ValueError, match="binding changed"):
        policy.verify_execution_bindings(
            policy.source_digest(), {**runtime, "sha256": "0" * 64}
        )


def test_failed_recovery_ledger_finish_keeps_original_reservation(tmp_path):
    from shared_gate import Gate, create

    policy = bridge()
    plan = policy.compile_plan("demo-stream-gate", "stream-run-012", "owner-012")
    ledger, ticket = reservation(tmp_path, plan)
    create(tmp_path / "gate", plan)
    gate = Gate(tmp_path / "gate", "stream")
    gate.claim()
    with pytest.raises(ValueError, match="incomplete"):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
