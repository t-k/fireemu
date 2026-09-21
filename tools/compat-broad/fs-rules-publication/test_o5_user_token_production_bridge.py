"""Bounded tests for the Rules production bridge seam."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "o8-core"))
sys.path.insert(0, str(HERE))

import o5_user_token_case as case
import o5_user_token_production_bridge as bridge


def _plan():
    return case.compile_case("fireemu-35fe6", "(default)", "a" * 32, "tenant-test")


def test_bridge_binds_compiler_accounting_146():
    plan = _plan()
    accounting = bridge.validate_compiled_accounting(plan)
    assert accounting["requestUpperBound"] == 146
    assert accounting["rulesRequests"] == 23
    assert accounting["recoveryRequests"] == 63


@pytest.mark.parametrize("mutation", ["observationRequests", "rulesRequests", "recoveryRequests", "requestUpperBound"])
def test_bridge_rejects_accounting_drift_without_wire(mutation):
    plan = _plan()
    original = bridge.campaign_budget
    bridge.campaign_budget = lambda _plan: {**original(plan), mutation: 1}
    try:
        with pytest.raises(ValueError, match="accounting"):
            bridge.validate_compiled_accounting(plan)
    finally:
        bridge.campaign_budget = original


def test_bound_execute_rejects_missing_capability_before_transport():
    plan = _plan()
    with pytest.raises(ValueError, match="capability"):
        bridge.bound_execute(
            plan,
            credentials={},
            frozen_inputs={"sourceInputs": {}},
            account_bindings={},
            identity_proofs={},
            capability=None,
        )


def test_bound_execute_rejects_expired_deadline_before_worker():
    plan = _plan()
    with pytest.raises(ValueError, match="worker source|capability"):
        bridge.bound_execute(
            plan,
            credentials={},
            frozen_inputs={"sourceInputs": {}},
            account_bindings={},
            identity_proofs={},
            capability=object(),
        )
