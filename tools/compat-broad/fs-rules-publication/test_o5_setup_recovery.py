"""Incomplete setup rollback using the actual LocalShadow with an artificial API."""

import json
import urllib.parse

import o5_user_token_local_run as module
import pytest
from o5_user_token_case import compile_case

NONCE = "c" * 32
VERSION = "2026-09-19T00:00:00.000000001Z"


def fixture(monkeypatch, fault=None):
    shadow = module.LocalShadow(
        "http://127.0.0.1:18081", "http://127.0.0.1:18082", "demo-local", NONCE
    )
    shadow.plan = compile_case("demo-local", "(default)", NONCE, "tenant-test")
    users, documents, calls = {}, {}, []
    counts = {"signup": 0, "patch": 0}

    def request(method, url, body=None, credential=None):
        calls.append((method, url, body))
        path = urllib.parse.urlsplit(url).path
        if ":signUp" in path:
            counts["signup"] += 1
            uid = f"uid-{counts['signup']}"
            users[uid] = {"localId": uid}
            if body.get("email"):
                users[uid]["email"] = body["email"]
            if fault == "lost-signup" and counts["signup"] == 2:
                raise module.Refused("lost")
            return 200, {"localId": uid, "idToken": "local-opaque"}
        if ":update" in path:
            if fault == "claims":
                raise module.Refused("claims-failure")
            return 200, {}
        if ":signInWithPassword" in path:
            return 200, {"idToken": "local-opaque"}
        if ":lookup" in path:
            return 200, {"users": [users[u] for u in body["localId"] if u in users]}
        if ":delete" in path:
            users.pop(body["localId"], None)
            return 200, {"kind": "identitytoolkit#DeleteAccountResponse"}
        resource = path.removeprefix("/v1/")
        if method == "PATCH":
            assert urllib.parse.parse_qs(urllib.parse.urlsplit(url).query) == {
                "currentDocument.exists": ["false"]
            }
            counts["patch"] += 1
            if fault == "conflict" and counts["patch"] == 3:
                documents[resource] = {
                    "name": resource,
                    "fields": {"foreign": {}},
                    "updateTime": VERSION,
                }
                return 409, {"error": {"code": 409, "status": "ALREADY_EXISTS"}}
            documents[resource] = {
                "name": resource,
                "fields": body["fields"],
                "updateTime": VERSION,
            }
            if fault == "lost-patch" and counts["patch"] == 3:
                raise module.Refused("lost")
            if fault == "bad-ack" and counts["patch"] == 3:
                return 200, {"name": resource}
            return 200, documents[resource].copy()
        if method == "GET":
            if resource in documents:
                return 200, documents[resource].copy()
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        if method == "DELETE":
            assert urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)[
                "currentDocument.updateTime"
            ] == [documents[resource]["updateTime"]]
            documents.pop(resource)
            return 200, {}
        pytest.fail(f"unexpected method {method}")

    monkeypatch.setattr(module, "_request", request)
    return shadow, users, documents, calls


@pytest.mark.parametrize(
    "fault", ["claims", "lost-signup", "lost-patch", "bad-ack", "conflict"]
)
def test_partial_setup_recovers_only_acknowledged_owned_resources(monkeypatch, fault):
    shadow, users, documents, calls = fixture(monkeypatch, fault)
    with pytest.raises(module.Refused):
        shadow.setup()
    before = len(calls)
    result = shadow.recover_setup()
    assert result["requests"] <= result["requestLimit"]
    if fault == "claims":
        assert result["complete"] is True
        assert not users and not documents
    elif fault == "conflict":
        assert result["complete"] is True
        assert not users and len(documents) == 1
        assert list(documents.values())[0]["fields"] == {"foreign": {}}
    elif fault == "lost-signup":
        assert result["complete"] is False
        assert len(users) == 1
    else:
        assert result["complete"] is False
        assert not users and len(documents) == 1
    assert not any("signUp" in url for _, url, _ in calls[before:])


def test_complete_setup_can_be_rolled_back_with_versions_and_typed_final_reads(
    monkeypatch, tmp_path
):
    shadow, users, documents, calls = fixture(monkeypatch)
    shadow.setup_journal = tmp_path / "setup.jsonl"
    shadow.setup()
    count = len(documents)
    result = shadow.recover_setup()
    assert result["complete"] is True
    assert not users and not documents
    deletes = [url for method, url, _ in calls if method == "DELETE"]
    assert len(deletes) == count
    journal = [
        json.loads(line) for line in shadow.setup_journal.read_text().splitlines()
    ]
    assert sum(row["kind"] == "document-created" for row in journal) == count
    assert "local-opaque" not in shadow.setup_journal.read_text()
    assert shadow.setup_journal.stat().st_mode & 0o777 == 0o600


def test_changed_version_is_retained_and_other_resources_are_recovered(monkeypatch):
    shadow, users, documents, _ = fixture(monkeypatch)
    shadow.setup()
    target = next(iter(documents))
    documents[target]["updateTime"] = "2026-09-19T00:00:00.000000002Z"
    result = shadow.recover_setup()
    assert result["complete"] is False
    assert list(documents) == [target]
    assert not users


def test_pending_create_stays_pending_even_if_subsequent_read_would_be_absent(
    monkeypatch,
):
    shadow, users, documents, calls = fixture(monkeypatch, "lost-patch")
    with pytest.raises(module.Refused):
        shadow.setup()
    lost = [
        resource
        for resource, proof in shadow.setup_documents.items()
        if proof["outcome"] == "unknown"
    ][0]
    documents.pop(lost)
    result = shadow.recover_setup()
    assert result["complete"] is False
    assert any(row.get("outcome") == "creation-unconfirmed" for row in result["rows"])


def test_no_setup_effect_means_no_rollback_request(monkeypatch):
    shadow, _, _, calls = fixture(monkeypatch)
    result = shadow.recover_setup()
    assert result["complete"] is True
    assert calls == []


def test_second_rollback_cannot_refill_request_or_time_reserves(monkeypatch):
    shadow, _, _, calls = fixture(monkeypatch)
    shadow.recover_setup()
    with pytest.raises(module.Refused, match="already-started"):
        shadow.recover_setup()
    assert calls == []


@pytest.mark.parametrize("deadline", [0, -1, True, float("nan"), float("inf"), 601])
def test_setup_recovery_refuses_unbounded_or_malformed_deadline(monkeypatch, deadline):
    shadow, _, _, calls = fixture(monkeypatch)
    with pytest.raises(module.Refused):
        shadow.recover_setup(deadline_seconds=deadline)
    assert calls == []


def test_insufficient_remaining_time_does_not_start_a_recovery_request(monkeypatch):
    shadow, users, documents, calls = fixture(monkeypatch)
    shadow.setup()
    before = len(calls)
    result = shadow.recover_setup(deadline_seconds=1)
    assert result["complete"] is False
    assert len(calls) == before


@pytest.mark.parametrize("shape", ["lost", "foreign", "empty", "segment"])
def test_lost_or_malformed_tenant_creation_never_means_no_tenant_effect(
    monkeypatch, shape
):
    shadow, _, _, calls = fixture(monkeypatch)

    def create(*_a, **_k):
        if shape == "lost":
            raise module.Refused("lost")
        name = {
            "foreign": "projects/other/tenants/t",
            "empty": "",
            "segment": "projects/demo-local/tenants/a/b",
        }[shape]
        return 200, {"name": name}

    monkeypatch.setattr(module, "_request", create)
    with pytest.raises(module.Refused):
        shadow.create_tenant()
    assert shadow.delete_tenant() is False


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "present",
        "forbidden",
        "wrong-message",
        "bad-code",
        "delete-error",
        "status-conflict",
    ],
)
def test_tenant_deleted_requires_typed_final_absence(monkeypatch, fault):
    shadow, _, _, _ = fixture(monkeypatch)
    shadow.tenant = "owned-tenant"
    shadow.tenant_attempted = True
    calls = []

    def request(method, url, *_a):
        calls.append(method)
        if method == "DELETE":
            return (200, {"error": {}}) if fault == "delete-error" else (200, {})
        body = {"error": {"code": 404, "message": "TENANT_NOT_FOUND"}}
        if fault == "present":
            return 200, {"name": "projects/demo-local/tenants/owned-tenant"}
        if fault == "forbidden":
            return 403, body
        if fault == "wrong-message":
            body["error"]["message"] = "Not Found"
        if fault == "bad-code":
            body["error"]["code"] = "404"
        if fault == "status-conflict":
            body["error"]["status"] = "PERMISSION_DENIED"
        return 404, body

    monkeypatch.setattr(module, "_request", request)
    assert shadow.delete_tenant() is (fault is None)
    assert calls == ["DELETE", "GET"]


def test_child_executes_setup_rollback_but_does_not_relabel_failed_observation_as_complete(
    tmp_path, monkeypatch
):
    shadow, users, documents, _ = fixture(monkeypatch, "lost-patch")
    monkeypatch.setattr(module, "PROJECT", "demo-local")
    monkeypatch.setattr(module, "LocalShadow", lambda *_: shadow)
    monkeypatch.setattr(shadow, "create_tenant", lambda: "tenant-test")
    monkeypatch.setattr(shadow, "publish", lambda _label: None)
    monkeypatch.setattr(shadow, "delete_tenant", lambda: True)
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:18081")
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:18082")
    assert module.run_child(tmp_path, NONCE) == 2
    result = json.loads((tmp_path / "local-shadow.json").read_text())
    assert result["completed"] is False
    assert result["setupRecovery"]["complete"] is False
    assert len(documents) == 1 and not users


def test_failure_saving_acknowledged_setup_keeps_in_memory_proof_for_rollback(
    monkeypatch,
):
    shadow, users, documents, _ = fixture(monkeypatch)

    def fail(kind, **_fields):
        if kind == "document-created":
            raise OSError("journal-full")

    monkeypatch.setattr(shadow, "_record_setup", fail)
    with pytest.raises(OSError):
        shadow.setup()
    result = shadow.recover_setup()
    assert result["complete"] is True
    assert not users and not documents


@pytest.mark.parametrize(
    "kind",
    ["local-shadow.json", "setup-journal.jsonl", "journal.jsonl", "child-started"],
)
def test_child_refuses_existing_run_evidence_before_any_api_effect(
    tmp_path, monkeypatch, kind
):
    (tmp_path / kind).write_text("original")
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:18081")
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:18082")
    monkeypatch.setattr(
        module, "LocalShadow", lambda *_a: pytest.fail("API context constructed")
    )
    with pytest.raises((module.Refused, FileExistsError)):
        module.run_child(tmp_path, NONCE)
    assert (tmp_path / kind).read_text() == "original"
