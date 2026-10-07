"""Metadata pre/postflight is bounded, pinned and never saves credential bodies."""

import hashlib
import json
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
RULESET = "projects/fireemu-oracle-sbx/rulesets/ruleset-a"
RULES_SOURCE = "match /conf_txn/{id} { allow read, write: if true; }"
BASELINE = {
    "projectNumber": "123456789",
    "databaseExpected": {
        "name": "projects/fireemu-oracle-sbx/databases/(default)",
        "type": "FIRESTORE_NATIVE",
        "databaseEdition": "STANDARD",
        "locationId": "us-central1",
        "concurrencyMode": "PESSIMISTIC",
    },
    "rulesSourceSha256": hashlib.sha256(RULES_SOURCE.encode()).hexdigest(),
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
        "database": {
            **BASELINE["databaseExpected"],
            "uid": "synthetic-database-uid",
        },
        "auth": {"key": "redacted"},
        "rules-release": {
            "name": "projects/fireemu-oracle-sbx/releases/cloud.firestore",
            "rulesetName": RULESET,
        },
        "ruleset-source": {
            "name": RULESET,
            "source": {"files": [{"name": "firestore.rules", "content": RULES_SOURCE}]},
        },
    }[slot]
    return {"complete": True, "workerReaped": True, "status": 200, "body": body}


@pytest.mark.parametrize("slot,resource", [
    ("rules-release", None),
    ("ruleset-source", RULESET),
])
def test_default_rules_transport_uses_the_http_module_and_closes_the_connection(monkeypatch, slot, resource):
    events = []
    expected = answer(slot)

    class Response:
        status = 200

        def read(self, limit):
            events.append(("read", limit))
            return json.dumps(expected["body"]).encode()

    class Connection:
        def __init__(self, host, *, timeout):
            events.append(("connect", host, timeout))

        def request(self, method, path, *, headers):
            events.append(("request", method, path, headers))

        def getresponse(self):
            return Response()

        def close(self):
            events.append(("close",))

    monkeypatch.setattr(management.http.client, "HTTPSConnection", Connection)
    assert management._default_request(slot, TOKEN, resource) == expected
    name = management.RULES_RELEASE if slot == "rules-release" else RULESET
    assert events == [
        ("connect", "firebaserules.googleapis.com", 12),
        ("request", "GET", f"/v1/{name}", {
            "Authorization": "Bearer " + TOKEN,
            "x-goog-user-project": "fireemu-oracle-sbx",
        }),
        ("read", management.RULES_RESPONSE_LIMIT + 1),
        ("close",),
    ]


def test_pre_and_postflight_use_exact_seven_management_slots_without_auth(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_metadata", lambda slot, body, baseline: {"bodyDigest": slot})
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    seen = []
    budget = contract.RequestBudget(plan.compile_plan(NONCE, OWNER))
    session = management.MetadataSession(
        TOKEN,
        BASELINE,
        budget,
        request_fn=lambda slot, token, resource=None: seen.append((slot, resource)) or answer(slot),
    )
    first = session.preflight()
    second = session.postflight()
    assert seen == [
        ("oauth-tokeninfo", None), ("project", None), ("database", None),
        ("rules-release", None), ("ruleset-source", RULESET),
        ("project", None), ("database", None),
    ]
    assert budget.management == 7
    assert first["rulesetName"] == RULESET
    assert first["rulesSourceSha256"] == BASELINE["rulesSourceSha256"]
    assert second["project"] == "project"
    assert TOKEN not in repr(first) + repr(second)


def test_uninitialized_auth_needs_no_baseline_or_request(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    monkeypatch.setattr(management.preflight, "verify_metadata", lambda slot, body, baseline: {"bodyDigest": slot})
    seen = []
    baseline = dict(BASELINE)
    session = management.MetadataSession(
        TOKEN, baseline, contract.RequestBudget(plan.compile_plan(NONCE, OWNER)),
        request_fn=lambda slot, token, resource=None: seen.append(slot) or answer(slot),
    )
    session.preflight()
    session.postflight()
    assert "auth" not in seen


def test_project_and_database_are_bound_before_data_and_compared_afterwards(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    seen = []

    def request(slot, token, resource=None):
        seen.append(slot)
        result = answer(slot)
        if slot == "database" and seen.count("database") == 2:
            result["body"]["uid"] = "changed-database-uid"
        return result

    session = management.MetadataSession(
        TOKEN, BASELINE, contract.RequestBudget(plan.compile_plan(NONCE, OWNER)),
        request_fn=request,
    )
    session.preflight()
    with pytest.raises(ValueError, match="changed after observation"):
        session.postflight()


@pytest.mark.parametrize("mode", ["OPTIMISTIC", None])
def test_preflight_refuses_a_database_without_pessimistic_concurrency(monkeypatch, mode):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    monkeypatch.setattr(management.preflight, "verify_metadata", lambda slot, body, baseline: {"bodyDigest": slot})

    def request(slot, token, resource=None):
        result = answer(slot)
        if slot == "database":
            result["body"]["concurrencyMode"] = mode
        return result

    session = management.MetadataSession(
        TOKEN, BASELINE, contract.RequestBudget(plan.compile_plan(NONCE, OWNER)),
        request_fn=request,
    )
    with pytest.raises(ValueError, match="PESSIMISTIC"):
        session.preflight()


def test_metadata_refusal_stops_later_slots(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    seen = []

    def request(slot, token, resource=None):
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


def test_rules_release_and_source_mismatch_stop_before_data(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    monkeypatch.setattr(management.preflight, "verify_metadata", lambda slot, body, baseline: {"bodyDigest": slot})

    def request(slot, token, resource=None):
        result = answer(slot)
        if slot == "rules-release":
            result["body"]["rulesetName"] = "different"
        return result

    session = management.MetadataSession(
        TOKEN, BASELINE, contract.RequestBudget(plan.compile_plan(NONCE, OWNER)),
        request_fn=request,
    )
    with pytest.raises(ValueError, match="rules"):
        session.preflight()

    def changed_source(slot, token, resource=None):
        result = answer(slot)
        if slot == "ruleset-source":
            result["body"]["source"]["files"][0]["content"] = "allow read: if false;"
        return result

    session = management.MetadataSession(
        TOKEN, BASELINE, contract.RequestBudget(plan.compile_plan(NONCE, OWNER)),
        request_fn=changed_source,
    )
    with pytest.raises(ValueError, match="source"):
        session.preflight()

    def ambiguous_source(slot, token, resource=None):
        result = answer(slot)
        if slot == "ruleset-source":
            result["body"]["source"]["files"].append(
                {"name": "extra.rules", "content": RULES_SOURCE}
            )
        return result

    session = management.MetadataSession(
        TOKEN, BASELINE, contract.RequestBudget(plan.compile_plan(NONCE, OWNER)),
        request_fn=ambiguous_source,
    )
    with pytest.raises(ValueError, match="ambiguous"):
        session.preflight()


def test_the_program_session_of_the_default_project_reports_what_the_shared_session_reports(monkeypatch):
    import txn_program_management as program_management

    monkeypatch.setattr(management.preflight, "verify_metadata", lambda slot, body, baseline: {"bodyDigest": slot})
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    session = program_management.MetadataSession(TOKEN, BASELINE, contract.RequestBudget(plan.compile_plan(NONCE, OWNER)), request_fn=lambda slot, token, resource=None: answer(slot))
    first, second = session.preflight(), session.postflight()
    assert "databaseSettings" not in first and "databaseSettings" not in second
    assert first["rulesetName"] == RULESET
