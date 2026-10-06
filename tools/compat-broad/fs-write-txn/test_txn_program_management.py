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


NAMED = f"projects/{PROJECT}/databases/txn-" + "a" * 32
OPERATION = NAMED + "/operations/create-1"


def named_session(answers):
    table = {**TABLE, "project": PROJECT, "caps": {**TABLE["caps"], "management": 32}}
    budget = RequestBudget(compile_plan(table, "a" * 32, "b" * 32), table)
    calls, saved = [], []
    def request(slot, token, resource):
        calls.append((slot, resource))
        answer = answers.pop(0)
        if isinstance(answer, Exception): raise answer
        return answer
    session = MetadataSession("synthetic-token", copy.deepcopy(BASELINE), budget, project=PROJECT, request_fn=request)
    session._ready = True
    return session, calls, saved


def answer(body, status=200, complete=True):
    return {"complete": complete, "workerReaped": True, "status": status, "body": body}


ABSENT = answer({"error": {"status": "NOT_FOUND", "code": 404}}, 404)


def test_named_database_create_wait_delete_and_readback_are_journaled(monkeypatch):
    monkeypatch.setattr("txn_program_management.time.sleep", lambda _: None)
    session, calls, saved = named_session([
        ABSENT, answer({"name": OPERATION}), answer({"name": OPERATION, "done": False}),
        answer({"name": OPERATION, "done": True, "response": {"name": NAMED}}), answer({"name": NAMED}),
        answer({"name": NAMED + "/operations/delete-1", "done": True, "response": {}}), ABSENT,
    ])
    session.create_named_database(NAMED, saved.append)
    assert session.named_database["closureReady"] is False
    session.delete_named_database(saved.append)
    assert session.named_database["closureReady"] is True
    assert [slot for slot, _ in calls] == ["named-database", "create-database", "database-operation", "database-operation", "named-database", "delete-database", "named-database"]
    assert saved[1]["unknownCreate"] is True
    assert any(s["unknownDelete"] for s in saved)
    assert saved[-1]["closureReady"] is True
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)


@pytest.mark.parametrize("mutation", ["create", "delete"])
def test_unknown_mutations_are_sticky_and_require_a2_at_least_ten_minutes_later(mutation, monkeypatch):
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1000)
    initial = [ABSENT, answer({"name": OPERATION, "done": True, "response": {"name": NAMED}}), answer({"name": NAMED})]
    unknown = answer(None, status=503, complete=False)
    session, calls, saved = named_session([ABSENT, unknown] if mutation == "create" else initial + [unknown])
    if mutation == "create":
        with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    else:
        session.create_named_database(NAMED, saved.append)
        with pytest.raises(ValueError): session.delete_named_database(saved.append)
    assert session.named_database["closureReady"] is False
    assert session.named_database["unknown" + mutation.capitalize()] is True
    before = len(calls)
    with pytest.raises(ValueError): session.delete_named_database(saved.append)
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1599.99)
    with pytest.raises(ValueError): session.readback_named_database(1599.99, saved.append)
    assert len(calls) == before
    session.request = lambda *args: ABSENT
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1600)
    state = session.readback_named_database(1600, saved.append)
    assert state["closureReady"] is (mutation == "delete")
    assert state["a2"] is True


@pytest.mark.parametrize("resource", [NAMED + "/extra", NAMED.replace("txn-", "other-"), NAMED.replace(PROJECT, "fireemu-oracle-txn"), NAMED.replace("a" * 32, "{nonce}")])
def test_management_never_mutates_a_database_outside_the_resolved_run_name(resource):
    session, calls, saved = named_session([])
    with pytest.raises(ValueError): session.create_named_database(resource, saved.append)
    assert calls == saved == []


def test_unknown_create_is_never_closed_by_a2_404_even_after_a_confirmed_create_reads_404():
    session, calls, saved = named_session([ABSENT, answer({"name": OPERATION, "done": True, "response": {"name": NAMED}}), ABSENT])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    assert session.named_database["closureReady"] is False


def test_a2_can_prove_an_unknown_create_exists_before_one_owned_delete(monkeypatch):
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1000)
    session, calls, saved = named_session([ABSENT, answer(None, 503, False)])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1600)
    answers = [answer({"name": NAMED}), answer({"name": NAMED + "/operations/delete-1", "done": True, "response": {}}), ABSENT]
    session.request = lambda *args: answers.pop(0)
    state = session.readback_named_database(1600, saved.append)
    assert state["createConfirmed"] is True and state["unknownCreate"] is False
    assert state["closureReady"] is False
    assert session.delete_named_database(saved.append)["closureReady"] is True


def test_confirmed_create_then_404_only_closes_on_a2_readback(monkeypatch):
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1000)
    session, calls, saved = named_session([ABSENT, answer({"name": OPERATION, "done": True, "response": {"name": NAMED}}), ABSENT, ABSENT])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    assert session.named_database["closureReady"] is False
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1600)
    assert session.readback_named_database(1600, saved.append)["closureReady"] is True


def test_query_refuses_a_valid_baseline_with_different_readback_settings():
    session, calls, saved = named_session([])
    session.request = lambda *args: answer({**BASELINE["databaseExpected"], "concurrencyMode": "PESSIMISTIC"})
    with pytest.raises(ValueError, match="expected settings"):
        session._read("database")


@pytest.mark.parametrize("change", ["operation", "created-name"])
def test_create_refuses_foreign_operation_or_response_identity(change):
    operation = OPERATION.replace(PROJECT, "fireemu-oracle-txn") if change == "operation" else OPERATION
    created = NAMED + "-other" if change == "created-name" else NAMED
    session, calls, saved = named_session([ABSENT, answer({"name": operation, "done": True, "response": {"name": created}}), answer({"name": NAMED})])
    with pytest.raises(ValueError, match="differs"):
        session.create_named_database(NAMED, saved.append)
    assert session.named_database["unknownCreate"] is True
    assert session.named_database["closureReady"] is False


def test_confirmed_create_without_delete_cannot_close_on_an_immediate_absence():
    session, calls, saved = named_session([ABSENT, answer({"name": OPERATION, "done": True, "response": {"name": NAMED}}), answer({"name": NAMED}), ABSENT])
    session.create_named_database(NAMED, saved.append)
    assert session.readback_named_database(None, saved.append)["closureReady"] is False


def test_named_requests_charge_before_dispatch_and_refuse_exhausted_budget():
    session, calls, saved = named_session([ABSENT, answer({"name": OPERATION, "done": True, "response": {"name": NAMED}}), answer({"name": NAMED})])
    session.create_named_database(NAMED, saved.append)
    assert session.budget.used["management"] == len(calls) == 3
    for _ in range(29):
        session.budget.charge("management")
    before = len(calls)
    with pytest.raises(ValueError, match="exhausted"):
        session.readback_named_database(None, saved.append)
    assert len(calls) == before
