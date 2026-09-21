"""Closed Auth-list Gate regressions; synthetic replies, no production transport.

Uses the unmodified campaign_manifest and the actual shared Gate implementation.
These are Gate/contract tests, not an execution of the fireemu artifact or SDK.
"""
from __future__ import annotations

import copy
import fcntl
import socket
from pathlib import Path
import sys
from urllib.parse import quote

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import shared_gate
from campaign_auth_list import campaign_manifest
from campaign_gate import CampaignGate, create


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("network forbidden in the Gate contract suite")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


class Clock:
    def __init__(self):
        self.value = 100.0

    def monotonic(self):
        return self.value

    def sleep(self, value):
        self.value += value


def replace(value, bindings):
    if isinstance(value, str) and value.startswith("$binding:"):
        return bindings[value.removeprefix("$binding:")]
    if isinstance(value, dict):
        return {key: replace(item, bindings) for key, item in value.items()}
    if isinstance(value, list):
        return [replace(item, bindings) for item in value]
    return value


class LocalReplies:
    """In-memory fixture, intentionally not an Auth/Firestore oracle."""
    def __init__(self, nonce):
        self.docs = {}
        self.users = {}
        self.tokens = {}
        self.nonce = nonce
        self.calls = []
        self.absence = "users"
        self.uid_mode = "normal"

    def __call__(self, operation):
        self.calls.append(copy.deepcopy(operation))
        kind, body = operation["operationType"], operation.get("body")
        resource = operation["resource"]
        if kind == "firestore-document-create":
            assert resource not in self.docs
            value = {"name": resource, "fields": copy.deepcopy(body["fields"]), "updateTime": "2026-09-14T00:00:00Z"}
            self.docs[resource] = value
            return 200, copy.deepcopy(value)
        if kind == "firestore-document-read":
            if resource in self.docs:
                return 200, copy.deepcopy(self.docs[resource])
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        if kind == "firestore-document-delete":
            assert "?currentDocument.updateTime=" in operation["path"]
            self.docs.pop(resource, None)
            return 200, {}
        if kind == "firestore-list-collection-ids":
            if body.get("pageToken"):
                return 200, {"collectionIds": ["beta"]}
            if body.get("pageSize") == 1:
                return 200, {"collectionIds": ["alpha"], "nextPageToken": "local-continuation"}
            if resource.endswith("/documents"):
                return 200, {"collectionIds": ["child-" + self.nonce, "missing-parent-" + self.nonce, "paged-parent-" + self.nonce]}
            return 200, {"collectionIds": ["children"]}
        if kind == "auth-sign-up":
            uid = resource if self.uid_mode == "resource" else "uid-" + str(len(self.users) + 1)
            self.users[uid] = body["email"]
            return 200, {"localId": uid, "idToken": "signup-id-" + uid, "refreshToken": "signup-refresh-" + uid}
        uid = operation["provenance"]["uid"]
        if kind == "auth-sign-in":
            assert self.users[uid] == body["email"]
            self.tokens["id-" + uid] = uid
            return 200, {"localId": uid, "idToken": "id-" + uid, "refreshToken": "refresh-" + uid}
        if kind == "auth-refresh":
            assert body["refresh_token"] == "refresh-" + uid
            self.tokens["renewed-" + uid] = uid
            return 200, {"user_id": uid, "id_token": "renewed-" + uid}
        if kind == "auth-delete":
            assert body["localId"] == uid
            self.users.pop(uid, None)
            return 200, {}
        if kind == "auth-lookup":
            if "idToken" in body:
                assert self.tokens[body["idToken"]] == uid
                return 200, {"users": [{"localId": uid}]}
            assert body["localId"] == uid
            if uid in self.users:
                return 200, {"users": [{"localId": uid}]}
            if self.absence == "kind":
                return 200, {"kind": "identitytoolkit#GetAccountInfoResponse"}
            if self.absence == "404":
                return 404, {"error": {"code": 404, "status": "USER_NOT_FOUND"}}
            return 200, {"users": []}
        raise AssertionError("fixture operation outside contract")


class Scenario:
    def __init__(self, tmp_path, monkeypatch):
        self.plan = campaign_manifest("a" * 32)
        self.clock = Clock()
        monkeypatch.setattr(shared_gate, "time", self.clock)
        self.path = tmp_path / "gate"
        create(self.path, self.plan)
        self.gate = CampaignGate(self.path, "auth-list")
        for index in range(2):
            self.gate.coordinator_call(index, lambda: (200, {}))
        self.gate.claim()
        self.backend = LocalReplies(self.plan["nonce"])
        self.bindings = {}
        self.versions = {}

    def bind_response(self, operation, body):
        kind, key = operation["operationType"], operation["resource"]
        values = {}
        if kind == "auth-sign-up":
            values = {key + "Uid": body["localId"], key + "Principal": "owned-account:" + body["localId"]}
        elif kind == "auth-sign-in":
            values = {key + "IdToken": body["idToken"], key + "Refresh": body["refreshToken"]}
        elif kind == "auth-refresh":
            values = {key + "IdToken": body["id_token"]}
        elif kind == "firestore-list-collection-ids" and "nextPageToken" in body:
            values = {"pagedToken": body["nextPageToken"]}
        for name, value in values.items():
            self.gate.bind(name, value)
            self.bindings[name] = value

    def operation(self, phase, index):
        operation = replace(copy.deepcopy(self.plan["jobs"]["auth-list"][phase][index]), self.bindings)
        source = operation.pop("versionFrom", None)
        if source is not None:
            operation["path"] += "?currentDocument.updateTime=" + quote(self.versions[operation["resource"]], safe="")
        return operation

    def step(self, phase, index, reply=None, mutation=None):
        operation = self.operation(phase, index)
        if mutation:
            mutation(operation)
        response = self.gate.dispatch(operation, phase == "recovery", lambda: reply(operation) if reply else self.backend(operation))
        status, body = response
        if phase == "observation":
            self.bind_response(operation, body)
        elif operation["operationType"] == "firestore-document-read" and status == 200:
            self.versions[operation["resource"]] = body["updateTime"]
        return response

    def observations(self, end=18):
        for i in range(self.gate.snapshot()["jobs"]["auth-list"]["observation"], end):
            self.step("observation", i)

    def recovery(self, end=19):
        for i in range(self.gate.snapshot()["jobs"]["auth-list"]["recovery"], end):
            self.step("recovery", i)

    def complete(self):
        self.observations()
        self.recovery()
        self.gate.finish()


@pytest.mark.parametrize("absence", ["users", "kind"])
def test_actual_manifest_completes_two_accounts_and_five_documents(tmp_path, monkeypatch, absence):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.backend.absence = absence
    scenario.complete()
    state = scenario.gate.snapshot()
    job = state["jobs"]["auth-list"]
    assert job["complete"] is True
    assert state["total"] == 39
    assert (state["observation"], state["recovery"], state["reservedRecovery"]) == (18, 19, 0)
    assert state["costMicrousd"] == 6900
    assert shared_gate.unconfirmed_creates(state, "auth-list") == 0
    assert not scenario.backend.users and not scenario.backend.docs
    assert len(job["authAccounts"]) == 2
    assert len(job["creationProofs"]) == 5
    assert len(job["absenceProofs"]) == 7
    assert sum(
        resource.startswith("projects/demo-firestore-probe/auth/accounts/")
        for resource in job["absenceProofs"]
    ) == 2
    assert not any(word in (scenario.path / "state.json").read_text() for word in ("signup-id-uid", "signup-refresh-uid", "renewed-uid", '"id-uid', '"refresh-uid'))


def test_one_accounts_absence_never_completes_shared_route_sentinels(tmp_path, monkeypatch):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations()
    scenario.recovery(18)
    job = scenario.gate.snapshot()["jobs"]["auth-list"]
    assert len(job["absent"]) == 6
    assert all(item.startswith("projects/") for item in job["absent"])
    with pytest.raises(ValueError):
        scenario.gate.finish()
    scenario.recovery()
    scenario.gate.finish()


@pytest.mark.parametrize("reply", [
    (200, {}), (200, {"users": None}), (200, {"users": False}),
    (200, {"users": {}}), (200, {"users": [None]}),
    (200, {"users": [{"localId": "uid-2"}]}),
    (200, {"kind": "wrong"}), (200, {"users": [], "error": {}}),
    (404, {"error": {"status": "NOT_FOUND"}}),
    (404, {"error": {"status": "USER_NOT_FOUND", "code": "404"}}),
    (404, {"error": {"status": "USER_NOT_FOUND", "code": True}}),
    (404, {"error": None}), (500, {"users": []}),
    (True, {"users": []}), (200.0, {"users": []}),
])
def test_final_absence_requires_typed_account_response(tmp_path, monkeypatch, reply):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations()
    scenario.recovery(18)
    with pytest.raises(ValueError):
        scenario.step("recovery", 18, reply=lambda _: reply)
    with pytest.raises(ValueError):
        scenario.gate.finish()
    job = scenario.gate.snapshot()["jobs"]["auth-list"]
    assert job["complete"] is False
    assert len(job["absent"]) == 6


@pytest.mark.parametrize("index,kind", [(5,"signup"),(6,"signin"),(7,"refresh"),(8,"lookup")])
@pytest.mark.parametrize("failure", ["wrong-uid", "missing-field", "error", "wrong-status"])
def test_auth_observation_validation_is_inside_persistent_gate_lock(tmp_path, monkeypatch, index, kind, failure):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations(index)
    def reply(op):
        status, body = scenario.backend(op)
        field = "user_id" if kind == "refresh" else "localId"
        if failure == "wrong-status":
            return 500, body
        if failure == "error":
            body["error"] = {"message": "bad"}
        elif kind == "lookup":
            body["users"] = [] if failure == "missing-field" else [{"localId": "foreign"}]
        elif failure == "missing-field":
            body.pop(field)
        else:
            body[field] = "" if kind == "signup" else "foreign"
        return status, body
    with pytest.raises(ValueError):
        scenario.step("observation", index, reply=reply)
    state = scenario.gate.snapshot()
    assert state["jobs"]["auth-list"]["stopped"] is True
    assert state["events"][-1]["failure"] == "InvalidLocalCampaignResponse"
    if kind == "signup":
        assert shared_gate.unconfirmed_creates(state, "auth-list") == 1
    with pytest.raises(ValueError):
        scenario.gate.finish()


@pytest.mark.parametrize("outcome", ["timeout", "500", "504", "missing-uid"])
def test_uncertain_signup_never_becomes_created_or_finishable(tmp_path, monkeypatch, outcome):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations(5)
    def reply(op):
        scenario.backend(op)  # It may already have created the user.
        if outcome == "timeout":
            raise TimeoutError("local injected timeout")
        if outcome == "missing-uid":
            return 200, {"idToken": "secret", "refreshToken": "secret"}
        return int(outcome), {"error": {"code": int(outcome), "status": "INTERNAL"}}
    with pytest.raises((ValueError, TimeoutError)):
        scenario.step("observation", 5, reply=reply)
    state = scenario.gate.snapshot()
    assert len(scenario.backend.users) == 1
    assert shared_gate.unconfirmed_creates(state, "auth-list") == 1
    assert not state["jobs"]["auth-list"].get("authAccounts")
    with pytest.raises(ValueError):
        scenario.gate.finish()


@pytest.mark.parametrize("field", ["uid", "principal", "body", "project", "alias"])
def test_switched_cleanup_identity_is_refused_before_dispatch(tmp_path, monkeypatch, field):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations()
    scenario.recovery(15)
    before = scenario.gate.snapshot()
    calls = len(scenario.backend.calls)
    def mutation(op):
        if field == "uid":
            op["provenance"]["uid"] = "uid-2"
        elif field == "principal":
            op["principal"] = "owned-account:uid-2"
        elif field == "body":
            op["body"]["localId"] = "uid-2"
        elif field == "project":
            op["path"] = op["path"].replace("demo-firestore-probe", "other-project")
        else:
            op["resource"] = "reference-" + scenario.plan["nonce"]
    with pytest.raises(ValueError):
        scenario.step("recovery", 15, mutation=mutation)
    assert before == scenario.gate.snapshot()
    assert calls == len(scenario.backend.calls)


def test_unobserved_or_changed_uid_bindings_are_refused(tmp_path, monkeypatch):
    scenario = Scenario(tmp_path, monkeypatch)
    key = "changed-" + scenario.plan["nonce"]
    with pytest.raises(ValueError):
        scenario.gate.bind(key + "Uid", "attacker")
    scenario.observations(6)
    with pytest.raises(ValueError):
        scenario.gate.bind(key + "Uid", "uid-2")
    with pytest.raises(ValueError):
        scenario.gate.bind(key + "IdToken", "unobserved-token")


def test_duplicate_uid_across_created_accounts_retains_uncertainty(tmp_path, monkeypatch):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations(9)
    def reply(op):
        _, body = scenario.backend(op)
        body["localId"] = "uid-1"
        return 200, body
    with pytest.raises(ValueError):
        scenario.step("observation", 9, reply=reply)
    assert shared_gate.unconfirmed_creates(scenario.gate.snapshot(), "auth-list") == 1


@pytest.mark.parametrize("mutation", [
    "transport", "production", "owner", "project", "omit-account", "extra-op", "ledger", "budget", "unknown", "nonce"
])
def test_plan_drift_is_rejected_before_creating_gate(tmp_path, mutation):
    plan = campaign_manifest("a" * 32)
    if mutation == "transport": plan["transport"] = "production"
    elif mutation == "production": plan["productionExecutable"] = True
    elif mutation == "owner": plan["ownerInputs"]["owner"] = "owner"
    elif mutation == "project": plan["jobs"]["auth-list"]["observation"][0]["path"] += "wrong"
    elif mutation == "omit-account": plan["jobs"]["auth-list"]["observation"].pop(9)
    elif mutation == "extra-op": plan["jobs"]["auth-list"]["observation"].append(copy.deepcopy(plan["jobs"]["auth-list"]["observation"][0]))
    elif mutation == "ledger": plan["sharedLedger"] = {"reservation":"fake"}
    elif mutation == "budget": plan["costMicrousd"] *= 2
    elif mutation == "unknown": plan["extension"] = True
    else: plan["nonce"] = "{freshNonce}"
    with pytest.raises(ValueError):
        create(tmp_path / "gate", plan)
    assert not (tmp_path / "gate").exists()


@pytest.mark.parametrize("origin", [
    "https://identitytoolkit.googleapis.com", "http://example.com:8080", "http://localhost:8080", "http://127.0.0.1:8080/path",
    "http://user@127.0.0.1:8080", "http://127.0.0.1:8080?redirect=x", "http://127.0.0.1:8080#x",
    "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:70000", None, 42, "http://127.0.0.1:08080"
])
def test_external_or_ambiguous_local_origin_is_rejected(tmp_path, origin):
    plan = campaign_manifest("a" * 32)
    plan["localOrigins"]["auth"] = origin
    with pytest.raises(ValueError):
        create(tmp_path / "gate", plan)
    assert not (tmp_path / "gate").exists()


@pytest.mark.parametrize("mutation", [
    "missing-account", "uid", "create-event", "delete-event", "absence-event", "event-request", "event-response", "event-body", "event-kind",
    "event-uid", "event-account", "event-phase", "event-index", "event-status", "event-completed", "event-failure", "duplicate-event", "missing-event",
    "document-proof", "document-event", "incomplete-observation"
])
def test_completion_revalidates_journal_instead_of_trusting_absent_flags(tmp_path, monkeypatch, mutation):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations()
    scenario.recovery()
    with scenario.gate.locked() as state:
        job = state["jobs"]["auth-list"]
        account = job["authAccounts"]["changed-" + scenario.plan["nonce"]]
        event = state["events"][account["absenceEvent"]]
        if mutation == "missing-account": job["authAccounts"].pop("changed-" + scenario.plan["nonce"])
        elif mutation == "uid": account["uid"] = "foreign"
        elif mutation == "create-event": account["createEvent"] = 0
        elif mutation == "delete-event": account["deleteEvent"] = account["absenceEvent"]
        elif mutation == "absence-event": account["absenceEvent"] = account["deleteEvent"]
        elif mutation == "event-request": event["requestDigest"] = "0" * 64
        elif mutation == "event-response": event["responseDigest"] = "0" * 64
        elif mutation == "event-body": event["authEvidence"]["body"] = {}
        elif mutation == "event-kind": event["authEvidence"]["kind"] = "auth-delete"
        elif mutation == "event-uid": event["authEvidence"]["uid"] = "foreign"
        elif mutation == "event-account": event["authEvidence"]["account"] = "foreign"
        elif mutation == "event-phase": event["phase"] = "observation"
        elif mutation == "event-index": event["index"] = 0
        elif mutation == "event-status": event["status"] = True
        elif mutation == "event-completed": event["completed"] = False
        elif mutation == "event-failure": event["failure"] = "TimeoutError"
        elif mutation == "duplicate-event": state["events"].append(copy.deepcopy(event))
        elif mutation == "missing-event": state["events"].pop(account["absenceEvent"])
        elif mutation == "document-proof": job["absenceProofs"].pop(next(iter(job["absenceProofs"])))
        elif mutation == "document-event": state["events"][next(iter(job["absenceProofs"].values()))["eventIndex"]]["requestDigest"] = "0" * 64
        else: job["observation"] -= 1
        shared_gate._save(scenario.path, state)
    with pytest.raises(ValueError):
        scenario.gate.finish()
    assert scenario.gate.snapshot()["jobs"]["auth-list"]["complete"] is False


@pytest.mark.parametrize("index", [6,7,8,10,11,12])
def test_password_refresh_lookup_slots_are_noncreating_but_signup_is_not(index):
    operations = campaign_manifest("a" * 32)["jobs"]["auth-list"]["observation"]
    assert shared_gate.can_create(operations[index]) is False
    assert shared_gate.can_create(operations[5]) is True
    assert shared_gate.can_create(operations[9]) is True


@pytest.mark.parametrize("index", [6,7,8])
@pytest.mark.parametrize("mutation", ["service", "method", "host", "path", "query", "fragment", "body-ref", "field", "form", "value-type"])
def test_noncreating_exceptions_require_exact_auth_rpc(index, mutation):
    op = copy.deepcopy(campaign_manifest("a" * 32)["jobs"]["auth-list"]["observation"][index])
    if mutation == "service": op["service"] = "firestore"
    elif mutation == "method": op["method"] = "PATCH"
    elif mutation == "host": op["path"] = "attacker." + op["path"]
    elif mutation == "path": op["path"] += "/accounts:signUp"
    elif mutation == "query": op["path"] += "?other=1"
    elif mutation == "fragment": op["path"] += "#other"
    elif mutation == "body-ref": op["bodyRef"] = {"sha256": "0" * 64, "bytes": 100}
    elif mutation == "field": op["body"]["unknown"] = True
    elif mutation == "form": op["form"] = not op["form"]
    else:
        field = {6:"email",7:"refresh_token",8:"idToken"}[index]
        op["body"][field] = 1
    assert shared_gate.can_create(op) is True


@pytest.mark.parametrize("method", ["signUp", "signInWithIdp", "signInWithCustomToken", "signInWithEmailLink", "signInWithPhoneNumber", "signInWithGameCenter"])
def test_other_auth_methods_still_retain_creation_responsibility(method):
    op = copy.deepcopy(campaign_manifest("a" * 32)["jobs"]["auth-list"]["observation"][6])
    op["path"] = "identitytoolkit.googleapis.com/v1/accounts:" + method
    assert shared_gate.can_create(op) is True


@pytest.mark.parametrize("after_record", [False, True])
@pytest.mark.parametrize("interruption", [SystemExit, KeyboardInterrupt])
def test_interruption_during_response_recording_leaves_durable_uncertainty(tmp_path, monkeypatch, after_record, interruption):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations(5)
    original = scenario.gate._record_local_response
    def interrupted(*args):
        if after_record:
            original(*args)
        raise interruption("injected recorder interruption")
    monkeypatch.setattr(scenario.gate, "_record_local_response", interrupted)
    with pytest.raises(interruption):
        scenario.step("observation", 5)
    state = scenario.gate.snapshot()
    assert state["jobs"]["auth-list"]["inflight"] is True
    assert state["jobs"]["auth-list"]["complete"] is False
    with pytest.raises(ValueError):
        scenario.gate.finish()
    before = len(scenario.backend.calls)
    with pytest.raises(ValueError):
        scenario.step("recovery", 0)
    assert len(scenario.backend.calls) == before


def test_response_proof_is_recorded_while_exclusive_journal_lock_is_held(tmp_path, monkeypatch):
    scenario = Scenario(tmp_path, monkeypatch)
    original = scenario.gate._record_local_response
    called = []
    def checked(*args):
        with (scenario.path / "lock").open("rb") as fd:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        called.append(True)
        return original(*args)
    monkeypatch.setattr(scenario.gate, "_record_local_response", checked)
    scenario.complete()
    assert len(called) == 37


def test_plain_gate_does_not_invent_auth_creation_proofs(tmp_path, monkeypatch):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations(5)
    generic = shared_gate.Gate(scenario.path, "auth-list")
    operation = scenario.operation("observation", 5)
    from campaign_gate import _project_auth_operation
    operation = _project_auth_operation(operation, "demo-firestore-probe")
    generic.dispatch(operation, False, lambda: scenario.backend(operation))
    state = generic.snapshot()
    assert shared_gate.unconfirmed_creates(state, "auth-list") == 1
    assert state["events"][-1]["creationOutcome"] == "unknown"
    assert not state["jobs"]["auth-list"].get("authAccounts")
    with pytest.raises(ValueError):
        generic.finish()


@pytest.mark.parametrize("mutation", ["foreign-resource", "cross-uid-binding"])
def test_facade_rejects_runtime_auth_projection_tampering_before_send(
    tmp_path, monkeypatch, mutation
):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations(6)
    operation = scenario.operation("observation", 6)
    if mutation == "foreign-resource":
        operation["resource"] = "foreign-account"
    else:
        operation["provenance"]["uid"] = "$binding:reference-" + scenario.plan["nonce"] + "Uid"
    sent = []
    with pytest.raises(ValueError, match="Auth (account binding|resource|UID binding)"):
        scenario.gate.dispatch(
            operation,
            False,
            lambda: sent.append(True),
        )
    assert sent == []


def test_uid_equal_to_a_frozen_literal_does_not_rewrite_literal_metadata(tmp_path, monkeypatch):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.backend.uid_mode = "resource"
    scenario.complete()
    state = scenario.gate.snapshot()
    assert state["jobs"]["auth-list"]["complete"] is True
    assert all(key == value["uid"] for key, value in state["jobs"]["auth-list"]["authAccounts"].items())


@pytest.mark.parametrize("index", [5, 6, 7, 8])
@pytest.mark.parametrize("body", [None, {}, [], "malformed", False])
def test_malformed_auth_success_fails_closed_with_typed_error(tmp_path, monkeypatch, index, body):
    scenario = Scenario(tmp_path, monkeypatch)
    scenario.observations(index)
    with pytest.raises(ValueError):
        scenario.step("observation", index, reply=lambda _: (200, body))
    state = scenario.gate.snapshot()
    assert state["jobs"]["auth-list"]["stopped"] is True
    assert state["events"][-1]["failure"] == "InvalidLocalCampaignResponse"
    with pytest.raises(ValueError):
        scenario.gate.finish()
