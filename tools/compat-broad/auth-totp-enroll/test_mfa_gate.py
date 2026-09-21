"""The Gate facade: the frozen plan is what the shared Gate creates and the walk sends."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import reservations
import shared_gate

import mfa_gate
from mfa_cases import owned_accounts

NONCE = "e" * 32


def plan(wall=1200, recovery=240):
    return mfa_gate.gate_plan(
        NONCE, wall_seconds=wall, recovery_seconds=recovery, cost_microusd=100_006
    )


def test_the_frozen_plan_is_created_by_the_shared_gate_at_its_wall_cap(tmp_path):
    value = plan()
    mfa_gate.create(tmp_path / "gate", value)
    gate = mfa_gate.MfaGate(tmp_path / "gate")
    snapshot = gate.snapshot()
    job = snapshot["plan"]["jobs"][mfa_gate.JOB]
    assert len(job["observation"]) == 93
    assert len(job["recovery"]) == 32
    assert job["resources"] == mfa_gate.route_resources("fireemu-35fe6")
    assert snapshot["plan"]["accountResources"] == [
        f"projects/fireemu-35fe6/auth/accounts/o2-mfa-{role}-{NONCE}"
        for role in mfa_gate.ROLE_ORDER
    ]
    assert set(mfa_gate.ROLE_ORDER) == set(owned_accounts())
    assert snapshot["plan"]["configResource"] == "projects/fireemu-35fe6/auth/config"
    # Only the base Gate's own non-creating recipes are declared non-creating.
    declared = [entry for entry in job["schedule"] if entry.get("creates") is False]
    assert all(
        job["observation"][entry["index"]]["kind"] in ("sign-in", "lookup")
        for entry in declared
    )
    assert declared


def test_the_plan_above_the_wall_cap_is_refused_by_the_shared_gate(tmp_path):
    with pytest.raises(ValueError, match="invalid shared allocation"):
        mfa_gate.create(tmp_path / "gate", plan(wall=2700, recovery=300))


def test_the_ledger_refuses_the_auth_resources_by_name():
    for name in (
        *mfa_gate.route_resources("fireemu-35fe6"),
        mfa_gate.account_resource("fireemu-35fe6", NONCE, "pending-control"),
        mfa_gate.config_resource("fireemu-35fe6"),
    ):
        with pytest.raises(ValueError, match="canonical Firestore resource required"):
            reservations._firestore_resource_scope(name)
    assert shared_gate.typed_absence(200, {"users": []}) is False


def test_no_binding_value_is_in_the_plan_and_every_placeholder_is_declared():
    value = plan()
    names = set()
    for phase in ("observation", "recovery"):
        for operation in value["jobs"][mfa_gate.JOB][phase]:
            stack = [operation["body"]]
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
                elif isinstance(item, str) and item.startswith("$binding:"):
                    names.add(item.removeprefix("$binding:"))
    observed = {
        name
        for phase in ("observation", "recovery")
        for operation in value["jobs"][mfa_gate.JOB][phase]
        for name in operation["binds"]
    }
    unbound = names - observed - set(mfa_gate.MINTED_BINDINGS)
    assert unbound == set()
    assert "password" in names and "totpSignIn" in names


def test_the_facade_refuses_a_request_outside_its_slot_and_a_skip_of_a_creating_slot(
    tmp_path,
):
    mfa_gate.create(tmp_path / "gate", plan())
    gate = mfa_gate.MfaGate(tmp_path / "gate")
    gate.claim()
    with pytest.raises(ValueError, match="outside closed scenario"):
        gate.dispatch_runtime(
            "/v1/accounts:lookup",
            {"idToken": "x"},
            owner=False,
            recovery=False,
            send=lambda: (200, {}),
        )
    with pytest.raises(ValueError, match="can be skipped"):
        gate.skip_planned("not a finalize")
