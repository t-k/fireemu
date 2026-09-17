from __future__ import annotations

import copy
import time

import pytest
import shared_production as production
from batch_contract import Credential
from shared_gate import _save, create


def _bounded_plan():
    plan = production.schedule("a" * 32)
    plan.update(
        wallSeconds=960,
        recoverySeconds=600,
        observationRequests=22,
        requestCostMicrousd=7,
    )
    return plan


def test_plan_limits_are_derived_from_actual_frozen_gate_plan(tmp_path):
    plan = production.schedule("a" * 32)
    create(tmp_path / "gate", plan)
    stored = (tmp_path / "gate" / "state.json").read_text()
    assert '"wallSeconds": 1200' in stored
    assert production.plan_limits(plan) == {
        "observationDeadline": 900,
        "recoveryDeadline": 1200,
        "observationRequests": 18,
        "requestCostMicrousd": 100,
        "intervalSeconds": 0.25,
        "observationCredentialSeconds": 1200,
        "recoveryCredentialSeconds": 300,
    }


def test_plan_limits_reject_invalid_or_unsafe_plan():
    baseline = production.schedule("a" * 32)
    for key, value in (
        ("wallSeconds", 0),
        ("recoverySeconds", 1200),
        ("observationRequests", -1),
        ("requestCostMicrousd", 0),
        ("intervalSeconds", 0.1),
    ):
        plan = copy.deepcopy(baseline)
        plan[key] = value
        with pytest.raises(ValueError):
            production.plan_limits(plan)


def test_credential_coverage_keeps_phase_requirement_distinct():
    credential = Credential()
    credential.accept("token", {"expires_in": "1201"}, 100.0)
    assert credential.usable(
        100.0,
        production.plan_limits(production.schedule("a" * 32))[
            "observationCredentialSeconds"
        ],
    )
    assert not credential.usable(100.0, 1202)


def test_gate_plan_budget_fields_are_not_rewritten_by_helper():
    plan = production.schedule("a" * 32)
    before = copy.deepcopy(plan)
    production.plan_limits(plan)
    assert plan == before


def test_coordinator_reserve_uses_frozen_count_and_cost(tmp_path):
    plan = _bounded_plan()
    gate_path = tmp_path / "gate"
    create(gate_path, plan)
    gate = production.ProductionGate(gate_path, "partial")
    coordinator = production.Coordinator(
        {"expiresAt": 4_000_000_000},
        plan["nonce"],
        tmp_path / "coordinator",
        gate,
        "api-key",
    )

    def reserve_metadata():
        coordinator.reserve("metadata", 12)

    with gate.locked() as state:
        state["observation"] = 18
        state["costMicrousd"] = 0
        _save(gate_path, state)
    gate.manage(coordinator, "project", reserve_metadata)
    state = gate.snapshot()
    assert state["observation"] == 19
    assert state["costMicrousd"] == 7


def test_coordinator_reserve_uses_shortened_observation_deadline(tmp_path):
    plan = _bounded_plan()
    gate_path = tmp_path / "gate"
    create(gate_path, plan)
    gate = production.ProductionGate(gate_path, "partial")
    coordinator = production.Coordinator(
        {"expiresAt": 4_000_000_000},
        plan["nonce"],
        tmp_path / "coordinator",
        gate,
        "api-key",
    )
    with gate.locked() as state:
        state["started"] -= 400
        _save(gate_path, state)
    with pytest.raises(ValueError, match="capacity/deadline"):
        gate.manage(coordinator, "project", lambda: coordinator.reserve("metadata", 12))
    assert gate.snapshot()["observation"] == 0


def test_acquire_accepts_credential_covering_frozen_observation_budget(tmp_path):
    plan = _bounded_plan()
    gate_path = tmp_path / "gate"
    create(gate_path, plan)
    gate = production.ProductionGate(gate_path, "partial")
    coordinator = production.Coordinator(
        {"expiresAt": 4_000_000_000},
        plan["nonce"],
        tmp_path / "coordinator",
        gate,
        "api-key",
    )
    now = time.monotonic()
    coordinator.credential.accept("token", {"expires_in": "1000"}, now)
    coordinator.acquire()
    assert coordinator.credential.usable(now, 960)
