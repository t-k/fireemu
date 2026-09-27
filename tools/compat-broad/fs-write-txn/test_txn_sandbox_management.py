"""Metadata pre/postflight is bounded, pinned and never saves credential bodies."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_expiry_plan as plan
import txn_sandbox_contract as contract
import txn_sandbox_management as management


NONCE = "0123456789abcdef0123456789abcdef"
OWNER = "11111111222233334444555566667777"
TOKEN = "test-access-token"
BASELINE = {
    "projectNumber": "123456789",
    "databaseProjectionDigest": "a" * 64,
    "authConfigDigest": "b" * 64,
    "rulesetName": "projects/fireemu-oracle-sbx/rulesets/ruleset-a",
    "credentialPrincipal": {
        "clientId": "client-a",
        "subject": "owner@example.com",
        "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
    },
}


def answer(slot):
    body = {
        "oauth-tokeninfo": {
            "issued_to": "client-a",
            "user_id": "owner@example.com",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "expires_in": 3600,
        },
        "project": {"projectId": "fireemu-oracle-sbx", "projectNumber": "123456789"},
        "database": {"name": "projects/fireemu-oracle-sbx/databases/(default)"},
        "auth": {"key": "redacted"},
        "rules": {
            "name": "projects/fireemu-oracle-sbx/releases/cloud.firestore",
            "rulesetName": BASELINE["rulesetName"],
        },
    }[slot]
    return {"complete": True, "workerReaped": True, "status": 200, "body": body}


def test_pre_and_postflight_use_exact_eight_management_slots(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_metadata", lambda slot, body, baseline: {"bodyDigest": slot})
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    seen = []
    budget = contract.RequestBudget(plan.compile_plan(NONCE, OWNER))
    session = management.MetadataSession(
        TOKEN,
        BASELINE,
        budget,
        request_fn=lambda slot, token: seen.append(slot) or answer(slot),
    )
    first = session.preflight()
    second = session.postflight()
    assert seen == [
        "oauth-tokeninfo", "project", "database", "auth", "rules",
        "project", "database", "auth",
    ]
    assert budget.management == 8
    assert first["rulesetName"] == BASELINE["rulesetName"]
    assert second["project"] == "project"
    assert TOKEN not in repr(first) + repr(second)


def test_metadata_refusal_stops_later_slots(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    seen = []

    def request(slot, token):
        seen.append(slot)
        result = answer(slot)
        if slot == "project":
            result["status"] = 403
        return result

    budget = contract.RequestBudget(plan.compile_plan(NONCE, OWNER))
    session = management.MetadataSession(TOKEN, BASELINE, budget, request_fn=request)
    with pytest.raises(ValueError, match="project"):
        session.preflight()
    assert seen == ["oauth-tokeninfo", "project"]
    assert budget.management == 2


def test_rules_release_mismatch_stops_before_data(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    monkeypatch.setattr(management.preflight, "verify_metadata", lambda slot, body, baseline: {"bodyDigest": slot})

    def request(slot, token):
        result = answer(slot)
        if slot == "rules":
            result["body"]["rulesetName"] = "different"
        return result

    session = management.MetadataSession(
        TOKEN, BASELINE, contract.RequestBudget(plan.compile_plan(NONCE, OWNER)),
        request_fn=request,
    )
    with pytest.raises(ValueError, match="rules"):
        session.preflight()
