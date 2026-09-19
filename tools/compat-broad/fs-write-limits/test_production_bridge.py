# ruff: noqa: I001 -- Load the limits module path bootstrap before shared imports.
"""Offline real-Gate bridge tests; synthetic credentials never reach a network."""

import time
import hashlib

import pytest

from production_bridge import LimitsGate, bind_wire, execution_plan, source_digest
from compiler import compile_limits_plan
from broad_contract import digest
from shared_gate import create
from shared_production import Coordinator


def setup_bridge(tmp_path):
    nonce = "e" * 32
    permission = {
        "expiresAt": time.time() + 1800,
        "collectorSourceDigest": source_digest(),
    }
    plan = execution_plan(permission, nonce)
    create(tmp_path / "gate", plan)
    gate = LimitsGate(tmp_path / "gate", "limits")
    gate.claim()
    coordinator = Coordinator(
        permission, nonce, tmp_path / "coordinator", gate, "synthetic-key"
    )
    coordinator.ready = (
        True  # Explicit offline metadata fixture, not production approval.
    )
    coordinator.credential.accept(
        "synthetic-token", {"expires_in": 1800}, time.monotonic()
    )
    return coordinator, gate, plan


@pytest.mark.parametrize("unexpected_success", [False, True])
def test_closed_bridge_collects_and_recovers_through_actual_gate(
    tmp_path, unexpected_success
):
    from collector import collect

    coordinator, gate, plan = setup_bridge(tmp_path)
    compiled = compile_limits_plan("fireemu-35fe6", "(default)", coordinator.nonce)
    stored, sent = {}, []
    negatives = {
        doc["resource"]
        for key, doc in compiled["documents"].items()
        if key.startswith("over-")
    }

    def fixture_transport(value):
        sent.append(value)
        operation = value["operation"]
        name = operation["path"].split("?")[0].removeprefix("/v1/")
        status, body = 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        if operation["method"] == "PATCH":
            if name in negatives and not unexpected_success:
                status, body = (
                    400,
                    {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
                )
            else:
                stored[name] = {
                    **operation["body"],
                    "updateTime": "2026-09-17T00:00:00Z",
                }
                status, body = 200, stored[name]
        elif operation["method"] == "DELETE":
            del stored[name]
            status, body = 200, {}
        elif name in stored:
            status, body = 200, stored[name]
        return {"complete": True, "status": status, "body": body}

    wire = bind_wire(coordinator, plan, transmit=fixture_transport)
    recovery_seen = []

    def recovery():
        # Taking a real Gate snapshot here detects accidental lock recursion.
        recovery_seen.append(gate.snapshot()["jobs"]["limits"]["stopped"])
        coordinator.recover_credentials()

    result = collect(
        gate, compiled, tmp_path / "collection", wire, before_recovery=recovery
    )
    assert result["collectionComplete"] is True, result["infrastructureFailures"]
    assert recovery_seen == [True]
    assert stored == {}
    assert bool(result["expectationMismatches"]) is unexpected_success
    expected_count = 28 if unexpected_success else 26
    assert len(sent) == expected_count
    assert gate.snapshot()["total"] == expected_count
    assert all(value["token"] == "synthetic-token" for value in sent)
    assert all(
        digest(value["operation"]) == event["requestDigest"]
        for value, event in zip(sent, gate.snapshot()["events"], strict=True)
    )


@pytest.mark.parametrize(
    "change", ["permission", "credential", "nonce", "ready", "api-key", "phase"]
)
def test_post_admission_drift_refuses_wire_before_transport(tmp_path, change):
    coordinator, gate, plan = setup_bridge(tmp_path)
    sent = []
    wire = bind_wire(coordinator, plan, transmit=lambda value: sent.append(value))
    if change == "permission":
        coordinator.permission["expiresAt"] += 1
    elif change == "credential":
        coordinator.credential.expiry = time.monotonic()
    elif change == "nonce":
        coordinator.nonce = "f" * 32
    elif change == "ready":
        coordinator.ready = False
    elif change == "api-key":
        coordinator.api_key = "changed"
    else:
        coordinator.budget.recovery = True
    operation = plan["jobs"]["limits"]["observation"][0]
    with pytest.raises(ValueError):
        gate.dispatch(operation, False, lambda: wire(operation, False, 0, 0))
    assert sent == []
    assert gate.snapshot()["total"] == 1
    assert gate.snapshot()["events"][0]["completed"] is False


def test_proposal_cannot_bind_as_executable_plan(tmp_path):
    from production_plan import production_plan

    coordinator, _, _ = setup_bridge(tmp_path)
    with pytest.raises(ValueError):
        bind_wire(coordinator, production_plan(coordinator.nonce)["gatePlan"])


def test_bound_wire_cannot_send_outside_gate_dispatch(tmp_path):
    coordinator, _, plan = setup_bridge(tmp_path)
    sent = []
    wire = bind_wire(coordinator, plan, transmit=lambda value: sent.append(value))
    operation = plan["jobs"]["limits"]["observation"][0]
    with pytest.raises(ValueError):
        wire(operation, False, 0, 0)
    assert sent == []


def test_production_binding_requires_fixed_transport_and_artifact(tmp_path):
    coordinator, _gate, plan = setup_bridge(tmp_path)
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"artifact-v1")
    artifact_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="fixed remote transport"):
        bind_wire(
            coordinator,
            plan,
            transmit=lambda value: value,
            artifact=artifact,
            artifact_sha256=artifact_hash,
            production=True,
        )
    with pytest.raises(ValueError, match="reserved O7 coordinator"):
        bind_wire(coordinator, plan, production=True)


def test_production_artifact_drift_is_rejected_before_network(tmp_path):
    coordinator, _gate, plan = setup_bridge(tmp_path)
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"artifact-v1")
    artifact_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="reserved O7 coordinator"):
        bind_wire(
            coordinator,
            plan,
            artifact=artifact,
            artifact_sha256=artifact_hash,
            production=True,
        )


def test_binding_change_after_gate_wait_is_rejected(tmp_path):
    coordinator, gate, plan = setup_bridge(tmp_path)
    sent = []
    wire = bind_wire(coordinator, plan, transmit=lambda value: sent.append(value))
    operation = plan["jobs"]["limits"]["observation"][0]

    def after_wait():
        # This callback runs only after real Gate rate waiting and attempt charging.
        coordinator.permission["expiresAt"] += 1
        return wire(operation, False, 0, 0)

    with pytest.raises(ValueError):
        gate.dispatch(operation, False, after_wait)
    assert sent == []
    assert gate.snapshot()["total"] == 1


def test_charged_callback_cannot_send_twice(tmp_path):
    coordinator, gate, plan = setup_bridge(tmp_path)
    sent = []

    def transport(value):
        sent.append(value)
        return {
            "complete": True,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    wire = bind_wire(coordinator, plan, transmit=transport)
    operation = plan["jobs"]["limits"]["observation"][0]

    def twice():
        result = wire(operation, False, 0, 0)
        with pytest.raises(ValueError):
            wire(operation, False, 0, 0)
        return result["status"], result["body"]

    gate.dispatch(operation, False, twice)
    assert len(sent) == 1
    assert gate.snapshot()["total"] == 1


@pytest.mark.parametrize("status", [401, 403])
def test_rejected_credential_is_recorded_and_never_reused(tmp_path, status):
    import json
    from collector import collect

    coordinator, gate, plan = setup_bridge(tmp_path)
    compiled = compile_limits_plan("fireemu-35fe6", "(default)", coordinator.nonce)
    attempts = []

    def refused(value):
        attempts.append(value)
        return {
            "complete": True,
            "status": status,
            "body": {
                "error": {
                    "code": status,
                    "status": "UNAUTHENTICATED"
                    if status == 401
                    else "PERMISSION_DENIED",
                }
            },
        }

    output = tmp_path / "collection"
    result = collect(
        gate,
        compiled,
        output,
        bind_wire(coordinator, plan, transmit=refused),
        before_recovery=coordinator.recover_credentials,
    )
    assert len(attempts) == 1
    assert coordinator.credential.failed is True
    assert coordinator.credential.token is None or coordinator.credential.token == ""
    receipt = json.loads((output / "observation-00-wire.json").read_bytes())
    assert receipt["complete"] is True
    assert receipt["status"] == status
    assert receipt["body"]["error"]["code"] == status
    assert result["collectionComplete"] is False
    assert result["cleanupComplete"] is False
    assert any(
        f["phase"] == "recovery-admission" for f in result["infrastructureFailures"]
    )


@pytest.mark.parametrize("status", [429, 503])
def test_service_failure_after_controls_stops_later_writes(tmp_path, status):
    from collector import collect

    coordinator, gate, plan = setup_bridge(tmp_path)
    compiled = compile_limits_plan("fireemu-35fe6", "(default)", coordinator.nonce)
    stored, attempts = {}, []

    def responses(value):
        attempts.append((value["phase"], value["index"]))
        operation = value["operation"]
        name = operation["path"].split("?")[0].removeprefix("/v1/")
        if value["phase"] == "observation" and value["index"] == 8:
            return {
                "complete": True,
                "status": status,
                "body": {
                    "error": {
                        "code": status,
                        "status": "RESOURCE_EXHAUSTED"
                        if status == 429
                        else "UNAVAILABLE",
                    }
                },
            }
        if operation["method"] == "PATCH":
            stored[name] = {**operation["body"], "updateTime": "2026-09-17T00:00:00Z"}
            return {"complete": True, "status": 200, "body": stored[name]}
        if operation["method"] == "DELETE":
            del stored[name]
            return {"complete": True, "status": 200, "body": {}}
        if name in stored:
            return {"complete": True, "status": 200, "body": stored[name]}
        return {
            "complete": True,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    result = collect(
        gate,
        compiled,
        tmp_path / "collection",
        bind_wire(coordinator, plan, transmit=responses),
        before_recovery=coordinator.recover_credentials,
    )
    assert result["rows"][8]["complete"] is True
    assert result["rows"][8]["status"] == status
    assert result["rows"][8]["body"]["error"]["code"] == status
    assert any(
        f["phase"] == "observation" and f["index"] == 8
        for f in result["infrastructureFailures"]
    )
    assert result["expectationMismatches"] == []
    assert result["collectionComplete"] is False
    assert result["cleanupComplete"] is False
    assert coordinator.credential.failed is False
    assert stored == {}
    assert [index for phase, index in attempts if phase == "observation"] == list(
        range(9)
    )
    assert len(attempts) == gate.snapshot()["total"] == 19
