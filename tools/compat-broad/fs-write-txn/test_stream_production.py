"""Prepared stream management uses real Gate/Ledger and an owned HTTP fixture."""

import importlib.util
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "production-admission"))

from test_stream_bridge import (
    trusted_node_runtime,  # noqa: F401 -- Shared owned-runtime fixture.
)


def production():
    assert importlib.util.find_spec("stream_production") is not None, (
        "prepared stream metadata must share existing admission"
    )
    return __import__("stream_production")


def test_prepared_allocation_counts_metadata_separately():
    module = production()
    plan = module.prepared_plan("stream-preflight-001", "owner-001", "a" * 64)
    assert plan["observationRequests"] == 19
    assert plan["recoverySeconds"] >= 366
    assert plan["costMicrousd"] == 1_303_300
    assert plan["streamBounds"]["rpcSlots"] == 25
    assert plan["streamBounds"]["acceptedBytes"] == 273 * 1024 * 1024
    assert [item["id"] for item in plan["management"]["observation"]] == [
        "project",
        "database",
        "auth",
        "key",
    ]
    assert plan["management"]["observation"] == plan["management"]["recovery"]
    assert (
        sum(len(job["recovery"]) for job in plan["jobs"].values())
        + len(plan["management"]["recovery"])
        == 14
    )


def test_existing_ledger_snapshot_job_label_is_not_stream_blocker(tmp_path):
    import stream_bridge
    from shared_gate import Gate, create

    plan = stream_bridge.compile_plan(
        "demo-stream-gate", "stream-preflight-002", "owner-002"
    )
    create(tmp_path / "gate", plan)
    assert Gate(tmp_path / "gate", "limits").snapshot()["plan"] == plan


@pytest.fixture
def metadata_server():
    import copy
    import http.server
    import json
    import threading

    from batch_contract import NUMBER, PROJECT

    payloads = {
        "project": {"projectId": PROJECT, "projectNumber": NUMBER},
        "database": {
            "name": f"projects/{PROJECT}/databases/(default)",
            "uid": "local-shadow-database",
            "databaseEdition": "STANDARD",
            "type": "FIRESTORE_NATIVE",
            "locationId": "us-central1",
        },
        "auth": {
            "name": f"projects/{PROJECT}/config",
            "signIn": {"email": {"enabled": True}},
        },
        "key": {
            "parent": f"projects/{NUMBER}/locations/global",
            "name": f"projects/{NUMBER}/locations/global/keys/local-shadow",
        },
    }
    state = {"requests": [], "drift": False, "payloads": payloads}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            action = self.path.removeprefix("/")
            state["requests"].append(action)
            body = copy.deepcopy(payloads[action])
            if (
                state["drift"]
                and action == "database"
                and state["requests"].count("database") > 1
            ):
                body["locationId"] = "europe-west1"
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["origin"] = f"http://127.0.0.1:{server.server_port}"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def prepared_fixture(tmp_path, metadata_server, stale=None):
    import time

    import stream_bridge
    from batch_contract import PROJECT, Credential, database_evidence
    from broad_contract import digest
    from reservations import Ledger

    module = production()
    permission = {
        "kind": "local-stream-shadow-only",
        "project": PROJECT,
        "nonce": "stream-preflight-003",
        "expiresAt": time.time() + 1800,
        "collectorSourceDigest": stream_bridge.source_digest(),
        "authConfigDigest": digest(metadata_server["payloads"]["auth"]),
        "databaseProjectionDigest": database_evidence(
            metadata_server["payloads"]["database"]
        )["projectionDigest"],
        "pricingLocation": "us-central1",
    }
    if stale == "permission":
        permission["collectorSourceDigest"] = "0" * 64
    plan = module.prepared_plan(permission["nonce"], "owner-003", digest(permission))
    if stale == "plan":
        plan["observerSha256"] = "0" * 64
    ledger = Ledger.create(tmp_path / "ledger")
    scope = {
        "key": f"project/{PROJECT}/firestore/(default)/documents/{plan['documentPrefix']}",
        "mode": "EXCLUSIVE",
    }
    budget = {
        "requests": 33,
        "accounts": 0,
        "resources": 3,
        "costMicrousd": module.TOTAL_COST_MICROUSD,
    }
    envelope = {
        "permissionDigest": digest(permission),
        "issuedAt": time.time() - 1,
        "expiresAt": permission["expiresAt"],
        "limits": budget,
        "concurrency": 1,
        "scopes": [scope],
    }
    claim = {
        "campaignId": permission["nonce"],
        "manifestDigest": digest(plan),
        "nonceDigest": digest(permission["nonce"]),
        "gatePath": str((tmp_path / "gate").resolve()),
        "gatePlanDigest": digest(plan),
        "locks": [scope],
        "budget": budget,
        "durationSeconds": 1100,
    }
    ticket = ledger.reserve(envelope, claim, plan)
    credential = Credential()
    credential.accept("local-shadow-only", {"expires_in": 1800}, time.monotonic())
    return module, permission, plan, ledger, ticket, credential


def test_read_only_metadata_runs_through_existing_gate(tmp_path, metadata_server):
    from shared_gate import create

    module, permission, plan, ledger, ticket, credential = prepared_fixture(
        tmp_path, metadata_server
    )
    create(tmp_path / "gate", plan)
    gate = module.StreamProductionGate(tmp_path / "gate")
    gate.claim()
    coordinator = module.StreamCoordinator(
        permission,
        tmp_path / "coordinator",
        gate,
        "local-shadow-key",
        ledger=ledger,
        ticket=ticket,
        credential=credential,
        shadow_origin=metadata_server["origin"],
    )
    coordinator.checked_preflight(recovery=False)
    state = gate.snapshot()
    assert coordinator.ready
    assert metadata_server["requests"] == ["project", "database", "auth", "key"]
    assert state["total"] == state["observation"] == 4
    assert state["reservedRecovery"] == 14
    assert state["events"] == []
    with pytest.raises(ValueError, match="incomplete"):
        gate.finish()
    with pytest.raises(ValueError, match="incomplete"):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    with pytest.raises(ValueError, match="disabled"):
        coordinator.acquire()


@pytest.mark.parametrize("drift", [False, True])
def test_real_outer_shadow_runs_postflight_before_cleanup_and_releases_only_valid(
    tmp_path, metadata_server, drift
):
    import os

    host = os.environ.get("FIRESTORE_EMULATOR_HOST")
    if not host:
        pytest.skip("requires owned fireemu exec")
    module, permission, plan, ledger, ticket, credential = prepared_fixture(
        tmp_path, metadata_server
    )
    metadata_server["drift"] = drift
    receipt = module.execute_session(
        plan,
        permission,
        tmp_path,
        ledger,
        ticket,
        "local-shadow-key",
        credential,
        shadow={
            "metadataOrigin": metadata_server["origin"],
            "port": int(host.rsplit(":", 1)[1]),
        },
    )
    assert receipt["collection"] is not None, receipt["failures"]
    state = receipt["gate"]
    assert state["total"] == (29 if drift else 31)
    assert len(state["events"]) == 23
    assert len(state["jobs"]["stream"]["absenceProofs"]) == 3
    post = [
        event
        for event in state["managementEvents"]
        if event["id"].startswith("recovery:")
    ]
    cleanup = [event for event in state["events"] if event["phase"] == "recovery"]
    assert max(event["started"] for event in post) < min(
        event["started"] for event in cleanup
    )
    assert receipt["reservationReleased"] is (not drift)
    assert receipt["acquisitionValidated"] is (not drift)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == (
        "held" if drift else "released"
    )


@pytest.mark.parametrize("stale", ["permission", "plan"])
def test_common_admission_rejects_stale_source_before_metadata(
    tmp_path, metadata_server, stale
):
    from shared_gate import create

    module, permission, plan, ledger, ticket, credential = prepared_fixture(
        tmp_path, metadata_server, stale=stale
    )
    create(tmp_path / "gate", plan)
    gate = module.StreamProductionGate(tmp_path / "gate")
    gate.claim()
    with pytest.raises(ValueError, match="source"):
        module.StreamCoordinator(
            permission,
            tmp_path / "coordinator",
            gate,
            "local-shadow-key",
            ledger=ledger,
            ticket=ticket,
            credential=credential,
            shadow_origin=metadata_server["origin"],
        )
    assert metadata_server["requests"] == []
    assert gate.snapshot()["total"] == 0


def test_management_phase_is_rechecked_after_adapter_wait(tmp_path, metadata_server):
    import time

    from shared_gate import _save, create

    module, permission, plan, ledger, ticket, credential = prepared_fixture(
        tmp_path, metadata_server
    )
    create(tmp_path / "gate", plan)
    gate = module.StreamProductionGate(tmp_path / "gate")
    gate.claim()
    coordinator = module.StreamCoordinator(
        permission,
        tmp_path / "coordinator",
        gate,
        "local-shadow-key",
        ledger=ledger,
        ticket=ticket,
        credential=credential,
        shadow_origin=metadata_server["origin"],
    )
    with gate.locked() as state:
        state["started"] = (
            time.monotonic() - plan["wallSeconds"] + plan["recoverySeconds"] + 13.4
        )
        _save(gate.path, state)
    coordinator.last_request = time.monotonic() + 0.5
    with pytest.raises(ValueError, match="phase deadline"):
        coordinator.checked_preflight(recovery=False)
    assert metadata_server["requests"] == []
    assert gate.snapshot()["total"] == 1


def test_metadata_only_execution_is_reported_separately(tmp_path, metadata_server):
    from shared_gate import create

    module, permission, plan, ledger, ticket, credential = prepared_fixture(
        tmp_path, metadata_server
    )
    create(tmp_path / "gate", plan)
    gate = module.StreamProductionGate(tmp_path / "gate")
    gate.claim()
    coordinator = module.StreamCoordinator(
        permission,
        tmp_path / "coordinator",
        gate,
        "local-shadow-key",
        ledger=ledger,
        ticket=ticket,
        credential=credential,
        shadow_origin=metadata_server["origin"],
    )
    coordinator.checked_preflight(recovery=False)
    assert hasattr(module, "execution_facts"), (
        "metadata and data execution must be distinct"
    )
    facts = module.execution_facts(gate.snapshot(), production=True)
    assert facts == {
        "productionExecuted": True,
        "productionRequests": 4,
        "metadataRequests": 4,
        "dataRequests": 0,
        "productionDataExecuted": False,
        "completedDataObservation": False,
    }


def test_private_o8_handoff_is_bounded_and_expiry_checked():
    import json
    import os
    import time

    module = production()
    assert hasattr(module, "read_o8_handoff"), (
        "execute needs an explicit private credential FD"
    )
    for change in ["expired", "wrong-permission", "oversized"]:
        read_fd, write_fd = os.pipe()
        try:
            handoff = {
                "kind": "stream-o8-credential-v1",
                "permissionDigest": "a" * 64,
                "token": "local-test-secret",
                "apiKey": "local-test-key",
                "expiresAt": time.time() + 1800,
                "verifiedAt": time.time(),
            }
            if change == "expired":
                handoff["expiresAt"] = time.time() + 30
            elif change == "wrong-permission":
                handoff["permissionDigest"] = "b" * 64
            else:
                handoff["token"] = "x" * 20000
            data = json.dumps(handoff).encode()
            # A regular private file avoids a pipe writer blocking on oversized data.
            import tempfile

            with tempfile.TemporaryFile() as stream:
                stream.write(data)
                stream.seek(0)
                with pytest.raises(ValueError):
                    module.read_o8_handoff(stream.fileno(), "a" * 64)
        finally:
            os.close(read_fd)
            os.close(write_fd)


def test_prepare_refuses_missing_owner_input_before_output(tmp_path):
    module = production()
    assert hasattr(module, "prepare_inputs"), (
        "a closed prepared execution config is required"
    )
    with pytest.raises((ValueError, FileNotFoundError)):
        module.prepare_inputs(
            tmp_path / "missing-permission.json",
            tmp_path / "missing-local.json",
            tmp_path / "missing-artifact",
            tmp_path / "prepared.json",
        )
    assert not (tmp_path / "prepared.json").exists()


def test_ownerless_prepare_stops_without_local_proof(tmp_path):
    module = production()
    with pytest.raises((ValueError, FileNotFoundError)):
        module.prepare_inputs(
            None,
            tmp_path / "missing-local.json",
            tmp_path / "missing-artifact",
            tmp_path / "proposal.json",
        )
    assert not (tmp_path / "proposal.json").exists()


def test_valid_private_o8_handoff_preserves_bounded_credential():
    import json
    import tempfile
    import time

    module = production()
    now = time.time()
    value = {
        "kind": "stream-o8-credential-v1",
        "permissionDigest": "a" * 64,
        "token": "local-secret",
        "apiKey": "local-key",
        "verifiedAt": now,
        "expiresAt": now + 1800,
    }
    with tempfile.TemporaryFile() as stream:
        stream.write(json.dumps(value).encode())
        stream.seek(0)
        credential, key = module.read_o8_handoff(stream.fileno(), "a" * 64)
    assert key == "local-key"
    assert credential.token == "local-secret"
    assert credential.usable(time.monotonic(), 1100)


def test_cli_prepare_accepts_missing_permission_flag():
    import subprocess

    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("stream_production.py")),
            "prepare",
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "[--permission PERMISSION]" in result.stdout


def test_prepared_json_rejects_non_regular_inputs(tmp_path):
    import os

    path = tmp_path / "input.fifo"
    os.mkfifo(path, 0o600)
    with pytest.raises(ValueError, match="regular"):
        production().load_json(path)


@pytest.mark.parametrize("stage", ["gate", "coordinator"])
def test_reserved_setup_failure_retains_a_terminal_owner_receipt(
    tmp_path, metadata_server, stage
):
    module, permission, plan, ledger, ticket, credential = prepared_fixture(
        tmp_path, metadata_server
    )
    if stage == "gate":
        (tmp_path / "gate").mkdir()
    else:
        permission["collectorSourceDigest"] = "0" * 64
    receipt = module.execute_session(
        plan,
        permission,
        tmp_path,
        ledger,
        ticket,
        "local-shadow-key",
        credential,
        shadow={"metadataOrigin": metadata_server["origin"], "port": 1},
    )
    assert receipt["acquisitionValidated"] is False
    assert receipt["reservationReleased"] is False
    assert receipt["recoveryResponsibility"]["ticket"] == ticket
    assert receipt["recoveryResponsibility"]["state"] == "retained"
    assert (tmp_path / "failure-receipt.json").is_file()
    assert metadata_server["requests"] == []
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_o8_refuses_world_accessible_fifo_before_read(tmp_path):
    import os

    path = tmp_path / "credential.fifo"
    os.mkfifo(path)
    path.chmod(0o666)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with pytest.raises(ValueError, match="private"):
            production().read_o8_handoff(fd, "a" * 64)
    finally:
        os.close(fd)


def test_o8_refuses_unprotected_socket_before_read():
    import socket

    left, right = socket.socketpair()
    try:
        with pytest.raises(ValueError, match="private"):
            production().read_o8_handoff(left.fileno(), "a" * 64)
    finally:
        left.close()
        right.close()


def test_atomic_receipt_is_private_complete_and_immutable(tmp_path):
    import json

    path = tmp_path / "receipt.json"
    production().write_atomic_receipt(path, {"complete": True})
    assert json.loads(path.read_text()) == {"complete": True}
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        production().write_atomic_receipt(path, {"complete": False})
    assert json.loads(path.read_text()) == {"complete": True}
    assert list(tmp_path.glob("*.pending")) == []


def test_reserved_input_write_failure_keeps_terminal_responsibility(
    tmp_path, metadata_server
):
    module, permission, plan, ledger, ticket, credential = prepared_fixture(
        tmp_path, metadata_server
    )
    (tmp_path / "inputs.json").write_text("existing")
    receipt = module.execute_reserved_inputs(
        {"plan": plan, "permission": permission},
        tmp_path,
        ledger,
        ticket,
        "local-shadow-key",
        credential,
    )
    assert receipt["recoveryResponsibility"]["ticket"] == ticket
    assert receipt["reservationReleased"] is False
    assert receipt["productionExecuted"] is False
    assert (tmp_path / "failure-receipt.json").is_file()
    assert (tmp_path / "inputs.json").read_text() == "existing"
    assert metadata_server["requests"] == []


def test_recovery_capture_requires_exact_private_append_file(tmp_path):
    import os

    module = production()
    assert hasattr(module, "validate_recovery_capture")
    path = tmp_path / "recovery.jsonl"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    permission = {
        "recoveryDiagnostics": {
            "path": str(path),
            "ownerRetainsUntilReservationResolved": True,
        }
    }
    try:
        module.validate_recovery_capture(permission, fd=fd)
        path.chmod(0o644)
        with pytest.raises(ValueError):
            module.validate_recovery_capture(permission, fd=fd)
    finally:
        os.close(fd)


def test_upfront_network_reserve_preserves_all_fourteen_recovery_slots(
    tmp_path, metadata_server
):
    from shared_gate import create

    module, _permission, plan, ledger, ticket, _credential = prepared_fixture(
        tmp_path, metadata_server
    )
    assert plan["fixedCostMicrousd"] == 1_300_000
    assert plan["requestCostMicrousd"] == 100
    assert plan["costMicrousd"] == 1_303_300
    create(tmp_path / "gate", plan)
    state = module.StreamProductionGate(tmp_path / "gate").snapshot()
    assert state["costMicrousd"] == 1_300_000
    assert state["reservedRecovery"] == 14
    assert plan["costMicrousd"] - state["costMicrousd"] - 14 * 100 == 19 * 100
    assert ledger.bound_claim(ticket)["budget"]["costMicrousd"] == plan["costMicrousd"]
    pricing = module.pricing_basis()
    assert pricing["networkPlanningMiB"] == 5483
    assert pricing["calculatedNetworkMicrousd"] == 1_231_534
    assert pricing["freeQuotaCreditBytes"] == 0
