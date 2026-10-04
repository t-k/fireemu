"""One bounded sandbox data request is charged before its fixed HTTPS send."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_expiry_plan as plan
import txn_sandbox_contract as contract
import txn_sandbox_wire as wire


NONCE = "0123456789abcdef0123456789abcdef"
OWNER = "11111111222233334444555566667777"
TOKEN = "test-token-value"


def request(site="preflight/absence/control"):
    return {
        "rpc": "GetDocument",
        "database": "(default)",
        "projectId": "fireemu-oracle-sbx",
        "name": (
            "projects/fireemu-oracle-sbx/databases/(default)/documents/"
            f"oracle/{NONCE}/txn-expiry-04/control"
        ),
        "body": None,
        "query": None,
        "maxResponseBytes": 65536,
        "maxRequestBytes": 8192,
        "timeoutSeconds": 10,
        "site": site,
    }


def test_fixed_wire_charges_then_sends_one_bounded_request(monkeypatch):
    seen = []

    def exchange(**kwargs):
        seen.append(kwargs)
        return 404, "application/json", json.dumps(
            {"error": {"code": 404, "status": "NOT_FOUND", "message": "missing"}}
        ).encode(), None

    monkeypatch.setattr(wire, "_run_process_exchange", exchange)
    budget = contract.RequestBudget(plan.compile_plan(NONCE, OWNER))
    response = wire.FixedDataWire(TOKEN, budget)(request())
    assert response["code"] == 5
    assert budget.observation == 1
    assert len(seen) == 1
    payload = seen[0]["request_payload"]
    header = json.loads(payload.split(b"\n", 1)[0])
    assert header["authorization"] == f"Bearer {TOKEN}"
    assert header["project"] == "fireemu-oracle-sbx"
    assert b"firestore.googleapis.com" not in payload


def test_fixed_wire_refuses_out_of_scope_and_exhausted_budget_before_send(monkeypatch):
    called = []
    monkeypatch.setattr(wire, "_run_process_exchange", lambda **kwargs: called.append(kwargs))
    budget = contract.RequestBudget(plan.compile_plan(NONCE, OWNER))
    candidate = request()
    candidate["projectId"] = "other-project"
    with pytest.raises(ValueError, match="project"):
        wire.FixedDataWire(TOKEN, budget)(candidate)
    assert called == [] and budget.total == 0
    budget.observation = budget.observation_limit
    with pytest.raises(ValueError, match="observation"):
        wire.FixedDataWire(TOKEN, budget)(request())
    assert called == []


def test_fixed_wire_uses_recovery_reserve_and_latches_incomplete_reply(monkeypatch):
    monkeypatch.setattr(
        wire,
        "_run_process_exchange",
        lambda **_kwargs: (None, "", b"", "timeout"),
    )
    budget = contract.RequestBudget(plan.compile_plan(NONCE, OWNER))
    response = wire.FixedDataWire(TOKEN, budget)(request("cleanup/typed-absence/control"))
    assert response["complete"] is False
    assert budget.recovery == 1 and budget.observation == 0
