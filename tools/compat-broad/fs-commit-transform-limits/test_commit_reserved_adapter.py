"""Real Gate/Ledger contract tests; no credentials or network."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_adapter as adapter


def test_production_schedule_has_real_management_and_recovery_capacity(tmp_path):
    assert hasattr(adapter, "production_gate_plan"), "production schedule is missing"
    plan = adapter.compiler_plan("fireemu-35fe6", "(default)", "a" * 32)
    binding = {"permissionDigest": "a" * 64, "collectorSourceDigest": "b" * 64}
    projected = adapter.production_gate_plan(plan, binding)
    assert projected["nonce"] == plan["nonce"]
    assert projected["observationRequests"] == 17
    assert len(projected["management"]["observation"]) == 6
    assert len(projected["management"]["recovery"]) == 4
    assert projected["recoverySeconds"] >= 133
    assert projected["costMicrousd"] > 100000
    assert projected["costMicrousd"] == projected["fixedCostMicrousd"] + 2700
    gate = adapter.create_production_commit_gate(tmp_path / "gate", plan, binding)
    assert gate.snapshot()["reservedRecovery"] == 10
    assert adapter.gate_plan(plan)["costMicrousd"] == 1700
    assert "management" not in adapter.gate_plan(plan)
    with pytest.raises(ValueError):
        adapter.CommitGate(gate.path, plan)


def test_reserved_adapter_requires_exact_shared_ticket_and_charged_callback(tmp_path):
    import importlib.util

    assert importlib.util.find_spec("commit_reserved_adapter") is not None, (
        "reserved adapter missing"
    )
    from broad_contract import digest
    from commit_reserved_adapter import CommitReservedCoordinator, source_digest
    from reservations import Ledger

    plan = adapter.compiler_plan("fireemu-35fe6", "(default)", "b" * 32)
    permission = {"expiresAt": 4000000000}
    binding = {
        "permissionDigest": digest(permission),
        "collectorSourceDigest": source_digest(),
    }
    projected = adapter.production_gate_plan(plan, binding)
    ledger = Ledger.create(tmp_path / "shared")
    scope = [{"key": "project/fireemu-35fe6", "mode": "WRITE"}]
    budget = {
        "requests": 27,
        "accounts": 0,
        "resources": 2,
        "costMicrousd": projected["costMicrousd"],
    }
    envelope = {
        "permissionDigest": digest(permission),
        "issuedAt": 1,
        "expiresAt": 4000000000,
        "limits": budget,
        "concurrency": 1,
        "scopes": scope,
    }
    claim = {
        "campaignId": plan["campaignId"],
        "manifestDigest": digest(plan),
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str((tmp_path / "gate").resolve()),
        "gatePlanDigest": digest(projected),
        "locks": scope,
        "budget": budget,
        "durationSeconds": 1200,
    }
    ticket = ledger.reserve(envelope, claim, projected)
    gate = adapter.create_production_commit_gate(tmp_path / "gate", plan, binding)
    gate.claim()
    coordinator = CommitReservedCoordinator(
        permission,
        plan["nonce"],
        tmp_path / "coordinator",
        gate,
        "fixture-key",
        ledger=ledger,
        ticket=ticket,
    )
    coordinator.validate_reservation()
    wire = coordinator.bind_wire(lambda *_: pytest.fail("unadmitted wire"))
    with pytest.raises(ValueError, match="charged"):
        wire(plan["observation"][0])
    routes = (
        "cloudresourcemanager.googleapis.com/v1/projects/fireemu-35fe6",
        "firestore.googleapis.com/v1/projects/fireemu-35fe6/databases/(default)",
        "identitytoolkit.googleapis.com/admin/v2/projects/fireemu-35fe6/config",
        "apikeys.googleapis.com/v2/keys:lookupKey?keyString=fixture-key",
    )
    before = gate.snapshot()
    for recovery in (False, True):
        coordinator.budget.recovery = recovery
        for path in routes:
            for method, body, privileged, form in (
                ("PATCH", None, True, False),
                ("POST", None, True, False),
                ("DELETE", None, True, False),
                ("GET", {"signIn": {"allowDuplicateEmails": True}}, True, False),
                ("GET", None, False, False),
                ("GET", None, True, True),
            ):
                with pytest.raises(ValueError, match="closed metadata request"):
                    coordinator.request(
                        "metadata",
                        path,
                        body,
                        method=method,
                        privileged=privileged,
                        form=form,
                    )
    assert gate.snapshot() == before
    coordinator.permission["changed"] = True
    with pytest.raises(ValueError, match="binding"):
        coordinator.validate_reservation()
