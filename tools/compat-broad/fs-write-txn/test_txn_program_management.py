"""Offline metadata tests for the frozen query baseline and credential principal."""

import copy

import pytest

from txn_program_management import MetadataSession
from txn_program_program import RequestBudget, compile_plan
from txn_program_support_for_tests import TABLE

PROJECT = "fireemu-oracle-query"
BASELINE = {
    "projectNumber": "123456789",
    "databaseExpected": {"name": f"projects/{PROJECT}/databases/(default)", "type": "FIRESTORE_NATIVE", "databaseEdition": "STANDARD", "locationId": "eur3", "concurrencyMode": "OPTIMISTIC"},
    "credentialPrincipal": {"clientId": "test-client", "subject": "test-subject", "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"]},
}


def test_query_reads_the_frozen_baseline_and_coordinator_principal_without_rules_assumptions():
    table = {**TABLE, "project": PROJECT}
    budget = RequestBudget(compile_plan(table, "a" * 32, "b" * 32), table)
    calls = []
    def request(slot, token, resource):
        calls.append(slot)
        body = {
            "oauth-tokeninfo": {"issued_to": "test-client", "user_id": "test-subject", "scope": BASELINE["credentialPrincipal"]["requiredScopes"][0], "expires_in": 3600},
            "project": {"projectId": PROJECT, "projectNumber": "123456789"},
            "database": {**BASELINE["databaseExpected"], "uid": "synthetic-query-uid"},
        }[slot]
        return {"complete": True, "workerReaped": True, "status": 200, "body": body}
    session = MetadataSession("synthetic-token", copy.deepcopy(BASELINE), budget, project=PROJECT, request_fn=request)
    assert session.preflight()["oauth-tokeninfo"]["verified"] is True
    session.postflight()
    assert calls == ["oauth-tokeninfo", "project", "database", "project", "database"]
    assert budget.used["management"] == 5
    session.baseline["credentialPrincipal"]["subject"] = "other-subject"
    with pytest.raises(ValueError, match="identity"):
        session._read("oauth-tokeninfo")


@pytest.mark.parametrize("change", ["project", "database", "principal", "setting"])
def test_query_refuses_near_misses_in_its_baseline_or_readback(change):
    baseline = copy.deepcopy(BASELINE)
    project = PROJECT
    if change == "project":
        project = "fireemu-oracle-idp"
    elif change == "database":
        baseline["databaseExpected"]["name"] += "-other"
    elif change == "principal":
        baseline["credentialPrincipal"]["requiredScopes"] = []
    answer = {**BASELINE["databaseExpected"], "concurrencyMode": "PESSIMISTIC"}
    with pytest.raises(ValueError):
        session = MetadataSession("synthetic-token", baseline, None, project=project, request_fn=lambda *args: {"complete": True, "workerReaped": True, "status": 200, "body": answer})
        class Budget:
            def charge(self, phase):
                assert phase == "management"
        session.budget = Budget()
        session._read("database")
