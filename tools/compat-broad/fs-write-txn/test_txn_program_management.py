"""Offline metadata tests for the frozen query baseline and credential principal."""

import copy

import pytest

from txn_program_management import MetadataSession
from txn_program_program import RequestBudget, compile_plan
from txn_program_support_for_tests import TABLE

PROJECT = "fireemu-oracle-query"
BASELINE = {
    "projectNumber": "123456789",
    "databaseExpected": {"name": f"projects/{PROJECT}/databases/(default)", "type": "FIRESTORE_NATIVE", "databaseEdition": "STANDARD", "locationId": "us-central1", "concurrencyMode": "OPTIMISTIC"},
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


RECORDED_DATABASE = {key: "synthetic" for key in ("appEngineIntegrationMode", "concurrencyMode", "createTime", "databaseEdition", "deleteProtectionState", "earliestVersionTime", "enhancedTextSearchQueryMode", "etag", "locationId", "pointInTimeRecoveryEnablement", "realtimeUpdatesMode", "type", "uid", "updateTime", "versionRetentionPeriod")}
RECORDED_DATABASE.update(name=NAMED, freeTier=False)
CREATE = answer({"done": True, "metadata": {"@type": "type.googleapis.com/google.firestore.admin.v1.CreateDatabaseMetadata"}, "name": OPERATION, "response": {"@type": "type.googleapis.com/google.firestore.admin.v1.Database", **RECORDED_DATABASE}})
DELETE = answer({"metadata": {"@type": "type.googleapis.com/google.firestore.admin.v1.DeleteDatabaseMetadata"}, "name": NAMED + "/operations/delete-1", "response": {**CREATE["body"]["response"], "name": "projects/fireemu-oracle-query/databases/synthetic-uid", "previousId": NAMED.rsplit("/", 1)[1], "deleteTime": "2030-01-01T00:00:00Z"}})
RECORDED_QUOTA = answer({"error": {"code": 429, "message": "Synthetic quota", "status": "RESOURCE_EXHAUSTED", "details": [{"@type": "synthetic", "domain": "synthetic", "reason": "synthetic", "metadata": {key: "synthetic" for key in ("consumer", "quota_limit", "quota_limit_value", "quota_location", "quota_metric", "quota_unit", "service", "window_start_time")}}]}}, 429)
ABSENT = answer({"error": {"status": "NOT_FOUND", "code": 404, "message": "Synthetic missing database"}}, 404)


def test_named_database_create_wait_delete_and_readback_are_journaled(monkeypatch):
    monkeypatch.setattr("txn_program_management.time.sleep", lambda _: None)
    session, calls, saved = named_session([
        ABSENT, answer({"name": OPERATION}), answer({"name": OPERATION, "done": False}),
        answer({"name": OPERATION, "done": True, "response": {"name": NAMED}}), answer({"name": NAMED}),
        copy.deepcopy(DELETE), ABSENT,
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
    answers = [answer({"name": NAMED}), copy.deepcopy(DELETE), ABSENT]
    session.request = lambda *args: answers.pop(0)
    state = session.readback_named_database(1600, saved.append)
    assert state["createConfirmed"] is True and state["unknownCreate"] is False
    assert state["closureReady"] is False
    assert session.delete_named_database(saved.append)["closureReady"] is True


def test_confirmed_create_without_delete_never_closes_on_a2_absence(monkeypatch):
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1000)
    session, calls, saved = named_session([ABSENT, answer({"name": OPERATION, "done": True, "response": {"name": NAMED}}), ABSENT, ABSENT])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    assert session.named_database["closureReady"] is False
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1600)
    assert session.readback_named_database(1600, saved.append)["closureReady"] is False


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


@pytest.mark.parametrize("status", [404, 429])
def test_recorded_delete_layout_settles_only_with_own_not_found_readback(status):
    readback = ABSENT if status == 404 else copy.deepcopy(RECORDED_QUOTA)
    session, calls, saved = named_session([ABSENT, copy.deepcopy(CREATE), answer(copy.deepcopy(RECORDED_DATABASE)), copy.deepcopy(DELETE), readback] + ([copy.deepcopy(readback)] if status == 429 else []))
    session.create_named_database(NAMED, saved.append)
    state = session.delete_named_database(saved.append)
    assert state["closureReady"] is (status == 404)
    assert state["deleteConfirmed"] is (status == 404)
    assert state["unknownDelete"] is (status != 404)
    assert [slot for slot, _ in calls] == ["named-database", "create-database", "named-database", "delete-database", "named-database"] + (["named-database"] if status == 429 else [])
    with pytest.raises(ValueError): session.delete_named_database(saved.append)


@pytest.mark.parametrize("change", ["status", "complete", "metadata", "operation", "previousId", "deleteTime", "error", "response"])
def test_delete_near_misses_remain_unknown_without_resend(change):
    deleted = copy.deepcopy(DELETE)
    if change == "status": deleted["status"] = 201
    elif change == "complete": deleted["complete"] = False
    elif change == "metadata": deleted["body"]["metadata"]["@type"] = "other"
    elif change == "operation": deleted["body"]["name"] = OPERATION.replace(PROJECT, "fireemu-oracle-txn")
    elif change == "previousId": deleted["body"]["response"]["previousId"] = "other"
    elif change == "deleteTime": del deleted["body"]["response"]["deleteTime"]
    elif change == "error": deleted["body"]["error"] = {}
    else: deleted["body"]["response"] = []
    session, calls, saved = named_session([ABSENT, copy.deepcopy(CREATE), answer(copy.deepcopy(RECORDED_DATABASE)), deleted, ABSENT])
    session.create_named_database(NAMED, saved.append)
    with pytest.raises(ValueError): session.delete_named_database(saved.append)
    assert session.named_database["unknownDelete"] and not session.named_database["deleteConfirmed"]
    assert len(calls) == 4


@pytest.mark.parametrize("status,complete,absent", [(400, True, True), (409, True, True), (400, True, False), (408, True, True), (429, True, True), (499, True, True), (503, True, True), (400, False, True)])
def test_create_refusal_needs_complete_error_and_own_absence(status, complete, absent):
    refusal = answer({"error": {"code": status, "message": "Synthetic refusal", "status": "INVALID_ARGUMENT"}}, status, complete)
    session, calls, saved = named_session([ABSENT, refusal, ABSENT if absent else answer({"name": NAMED})])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    settled = complete and status in (400, 409) and absent
    assert session.named_database["unknownCreate"] is (not settled)
    assert session.named_database["closureReady"] is settled
    assert session.named_database.get("createRefused", False) is (complete and status in (400, 409))
    assert not session.named_database["createConfirmed"]
    assert [slot for slot, _ in calls].count("create-database") == 1


@pytest.mark.parametrize("change", ["name", "error"])
def test_create_poll_identity_and_inline_error_cannot_confirm_creation(change, monkeypatch):
    monkeypatch.setattr("txn_program_management.time.sleep", lambda _: None)
    body = copy.deepcopy(CREATE["body"])
    if change == "name": body["name"] = OPERATION + "-different"
    else: body["error"] = {"code": 9}
    session, calls, saved = named_session([ABSENT, answer({"name": OPERATION}), answer(body)])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    assert session.named_database["unknownCreate"] and not session.named_database["createConfirmed"]


def test_delete_does_not_consult_the_recorded_mismatched_operation_poll():
    session, calls, saved = named_session([ABSENT, copy.deepcopy(CREATE), answer(copy.deepcopy(RECORDED_DATABASE)), copy.deepcopy(DELETE), ABSENT])
    request = session.request
    def with_poll(slot, *args):
        if slot == "database-operation": return answer({"name": NAMED + "/operations/different", "metadata": DELETE["body"]["metadata"], "response": {"@type": "synthetic"}})
        return request(slot, *args)
    session.request = with_poll
    session.create_named_database(NAMED, saved.append)
    assert session.delete_named_database(saved.append)["closureReady"]
    assert all(slot != "database-operation" for slot, _ in calls)


def test_invalid_delete_layout_cannot_settle_before_a2_even_on_absence(monkeypatch):
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1000)
    session, calls, saved = named_session([ABSENT, copy.deepcopy(CREATE), answer(copy.deepcopy(RECORDED_DATABASE)), answer({"name": OPERATION, "done": True, "response": {}}), ABSENT, ABSENT])
    session.create_named_database(NAMED, saved.append)
    with pytest.raises(ValueError): session.delete_named_database(saved.append)
    assert not session.readback_named_database(None, saved.append)["closureReady"]
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1600)
    state = session.readback_named_database(1600, saved.append)
    assert state["closureReady"] and state["deleteConfirmed"] and not state["unknownDelete"]


@pytest.mark.parametrize("status", ["CANCELLED", "UNKNOWN", "DEADLINE_EXCEEDED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS"])
def test_create_error_status_that_means_unknown_is_never_a_refusal(status):
    session, calls, saved = named_session([ABSENT, answer({"error": {"code": 400, "status": status, "message": "Synthetic unknown"}}, 400), ABSENT])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    assert session.named_database["unknownCreate"] and not session.named_database.get("createRefused")
    assert len(calls) == 2


def test_a2_confirming_creation_clears_refusal_and_still_owes_delete(monkeypatch):
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1000)
    session, calls, saved = named_session([ABSENT, answer({"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "Synthetic refusal"}}, 400), answer({"name": NAMED}), answer({"name": NAMED}), ABSENT])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1600)
    state = session.readback_named_database(1600, saved.append)
    assert state["createConfirmed"] and not state["createRefused"] and not state["closureReady"]
    monkeypatch.setattr("txn_program_management.time.time", lambda: 2200)
    assert not session.readback_named_database(2200, saved.append)["closureReady"]


@pytest.mark.parametrize("change", ["code", "status", "error", "body"])
def test_create_refusal_error_shape_near_misses_stay_unknown(change):
    refusal = answer({"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "Synthetic refusal"}}, 400)
    if change == "code": refusal["body"]["error"]["code"] = 409
    elif change == "status": del refusal["body"]["error"]["status"]
    elif change == "error": refusal["body"]["error"] = []
    else: refusal["body"] = []
    session, calls, saved = named_session([ABSENT, refusal, ABSENT])
    with pytest.raises(ValueError): session.create_named_database(NAMED, saved.append)
    assert session.named_database["unknownCreate"] and not session.named_database.get("createRefused")
    assert len(calls) == 2


def test_a_confirmed_database_cannot_close_as_refused_without_delete(monkeypatch):
    session, calls, saved = named_session([ABSENT, copy.deepcopy(CREATE), answer(copy.deepcopy(RECORDED_DATABASE)), ABSENT])
    session.create_named_database(NAMED, saved.append)
    session.named_database["createRefused"] = True
    monkeypatch.setattr("txn_program_management.time.time", lambda: session.named_database["lastRequestEpoch"] + 600)
    assert not session.readback_named_database(session.named_database["lastRequestEpoch"] + 600, saved.append)["closureReady"]


def test_a2_absence_keeps_unknown_create_open_even_with_prior_delete_evidence(monkeypatch):
    session, calls, saved = named_session([ABSENT])
    session.named_database = {"database": NAMED, "createConfirmed": True, "unknownCreate": True, "createRefused": False, "deleteAttempted": True, "deleteAccepted": True, "unknownDelete": True, "deleteConfirmed": False, "closureReady": False, "lastRequestEpoch": 1000, "a2": False}
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1600)
    state = session.readback_named_database(1600, saved.append)
    assert state["unknownCreate"] and state["unknownDelete"]
    assert not state["closureReady"] and not state["deleteConfirmed"]
    assert [slot for slot, _ in calls] == ["named-database"]


@pytest.mark.parametrize("status", [429, 500, 503, 599, 408, 499, 600, 200, "503", None, 500.0])
def test_post_delete_reread_is_bounded_and_only_for_transient_status(status):
    retry = status == 429 or type(status) is int and 500 <= status < 600
    session, calls, saved = named_session([ABSENT, copy.deepcopy(CREATE), answer(copy.deepcopy(RECORDED_DATABASE)), copy.deepcopy(DELETE), answer(None, status), ABSENT])
    session.create_named_database(NAMED, saved.append)
    state = session.delete_named_database(saved.append)
    assert state["closureReady"] is retry
    assert [slot for slot, _ in calls].count("delete-database") == 1
    assert [slot for slot, _ in calls].count("named-database") == 3 + int(retry)
    assert session.budget.used["management"] == 5 + int(retry)
    if retry:
        assert all(value["unknownDelete"] and not value["closureReady"] for value in saved[-3:-1])


def test_post_delete_reread_stops_after_one_transient_answer():
    session, calls, saved = named_session([ABSENT, copy.deepcopy(CREATE), answer(copy.deepcopy(RECORDED_DATABASE)), copy.deepcopy(DELETE), answer(None, 429), answer(None, 503), ABSENT])
    session.create_named_database(NAMED, saved.append)
    state = session.delete_named_database(saved.append)
    assert state["unknownDelete"] and not state["closureReady"]
    assert [slot for slot, _ in calls].count("named-database") == 4
    assert len(calls) == 6


def test_post_delete_reread_preserves_management_slots_for_postflight():
    session, calls, saved = named_session([ABSENT, copy.deepcopy(CREATE), answer(copy.deepcopy(RECORDED_DATABASE)), copy.deepcopy(DELETE), answer(None, 429), ABSENT])
    session.budget._caps["management"] = 7
    session.create_named_database(NAMED, saved.append)
    assert not session.delete_named_database(saved.append)["closureReady"]
    assert len(calls) == 5


def test_a2_does_not_reread_a_transient_response(monkeypatch):
    session, calls, saved = named_session([answer(None, 429), ABSENT])
    session.named_database = {"database": NAMED, "createConfirmed": True, "unknownCreate": False, "deleteAttempted": True, "deleteAccepted": True, "unknownDelete": True, "closureReady": False, "lastRequestEpoch": 1000}
    monkeypatch.setattr("txn_program_management.time.time", lambda: 1600)
    assert not session.readback_named_database(1600, saved.append)["closureReady"]
    assert len(calls) == 1



def test_plain_database_readback_does_not_reread_without_an_accepted_delete():
    session, calls, saved = named_session([answer(None, 429), ABSENT])
    session.named_database = {"database": NAMED, "createConfirmed": True, "unknownCreate": False, "deleteAttempted": False, "closureReady": False, "lastRequestEpoch": 1000}
    assert not session.readback_named_database(None, saved.append)["closureReady"]
    assert len(calls) == 1
