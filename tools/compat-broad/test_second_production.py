"""Whole communication fixtures only; no fixture represents production evidence."""

import copy
import hashlib
import json
import subprocess
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import batch_adapter
import pytest
import second_production as production
from batch_contract import DATABASE_PROJECTION, NUMBER, PROJECT
from broad_contract import digest
from second_mapped import execute_45
from second_production_contract import approve, binding, manifest
from test_second_mapping import receipt


def fixture_permission():
    database = {
        "name": f"projects/{PROJECT}/databases/(default)",
        "uid": "fixture-database",
        "type": "FIRESTORE_NATIVE",
        "databaseEdition": "STANDARD",
        "locationId": "us-central1",
    }
    return {
        "kind": "second45-owner-execution-permission-v1",
        "comparisonContractDigest": digest(binding()),
        "manifestSha256": digest(manifest()),
        "observerSha256": production.observer_digest(),
        "nonce": "b" * 32,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "issuedAt": 900,
        "expiresAt": 9000,
        "ownerIdentity": "offline-fixture-not-permission",
        "permissionReference": "offline-fixture",
        "authConfigDigest": digest({"name": "fixture-auth"}),
        "databaseProjection": database,
        "databaseProjectionDigest": digest(database),
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "pricingLocation": "us-central1",
        "pricingCheckedAt": "fixture-only",
        "costAssumptions": {
            "retentionHours": 24,
            "indexStorageUpperUSD": 0.01,
            "networkUpperUSD": 0.05,
            "computedUpperUSD": 0.10,
            "ownerConfirmed": True,
        },
        "frozenCommit": "c" * 40,
    }


class CommunicationFixture:
    def __init__(self, permission, variant=None):
        self.permission, self.variant = permission, variant
        self.source = receipt("mapped")
        self.entries = iter(self.source["trace"])
        self.requests = []
        self.commands = []

    def wire(self, url, method, body, headers, **kwargs):
        self.requests.append((url, method, copy.deepcopy(body), copy.deepcopy(headers)))
        if url == "https://www.googleapis.com/oauth2/v1/tokeninfo":
            return 200, {"expires_in": "3600"}, "application/json"
        if not kwargs.get("receipt"):
            assert headers["x-goog-user-project"] == PROJECT
            if "cloudresourcemanager" in url:
                return (
                    200,
                    {"projectId": PROJECT, "projectNumber": NUMBER},
                    "application/json",
                )
            if "/databases/(default)" in url:
                value = copy.deepcopy(self.permission["databaseProjection"])
                if self.variant == "drift":
                    value["uid"] = "different"
                return 200, value, "application/json"
            if "lookupKey" in url:
                assert parse_qsl(urlsplit(url).query) == [
                    ("keyString", "fixture-key-K1")
                ]
                return (
                    200,
                    {
                        "parent": f"projects/{NUMBER}/locations/global",
                        "name": f"projects/{NUMBER}/locations/global/keys/fixture",
                    },
                    "application/json",
                )
            return 200, {"name": "fixture-auth"}, "application/json"
        entry = next(self.entries)
        expected = entry["sent"]
        path = (
            url.removeprefix("https://")
            if expected["service"] == "auth"
            else url.removeprefix("https://firestore.googleapis.com")
        )
        query = parse_qsl(urlsplit(path).query, keep_blank_values=True)
        if not expected["privileged"]:
            assert query == [("key", "fixture-key-K1")]
            assert "Authorization" not in headers
            assert "x-goog-user-project" not in headers
            query = [("key", "fake")]
        else:
            assert headers["Authorization"] == "Bearer fixture-access"
            assert headers["x-goog-user-project"] == PROJECT
        assert urlsplit(path).path == expected["path"]
        assert [list(p) for p in query] == expected["query"]
        assert method == expected["method"] and body == expected["body"]
        response = copy.deepcopy(entry["observation"])
        if self.variant == "timeout" and entry["phase"] == "setup":
            raise ValueError("whole request deadline exceeded")
        if self.variant == "auth-denied" and entry["phase"] == "baseline":
            response["httpStatus"] = response["http"]["status"] = 403
        if self.variant == "readback" and entry["phase"] == "before":
            response["body"] = {}
        if self.variant == "partial" and entry["phase"] == "diagnostic":
            response["http"].update(
                complete=False, failure="body-interrupted", digestScope="prefix"
            )
        if self.variant == "non-json" and entry["phase"] == "diagnostic":
            response["body"] = None
            response["http"]["bodyKind"] = "non-json"
        if self.variant == "unrecovered" and entry["phase"] == "recovery":
            response["httpStatus"] = response["http"]["status"] = 400
        return {"body": response["body"], "http": response["http"]}

    def command(self, args, **kwargs):
        assert args == ["gcloud", "auth", "application-default", "print-access-token"]
        self.commands.append(args)
        return subprocess.CompletedProcess(args, 0, "fixture-access\n", "")


@pytest.fixture
def boundary(monkeypatch, tmp_path):
    permission = fixture_permission()
    fixture = CommunicationFixture(permission)
    monkeypatch.setenv("PRODUCTION_ORACLE_API_KEY", "fixture-key-K1")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(production.time, "time", lambda: 1000)
    monkeypatch.setattr(production.time, "monotonic", lambda: 1000)
    monkeypatch.setattr(production.time, "sleep", lambda _n: None)
    monkeypatch.setattr(
        production.subprocess,
        "check_output",
        lambda args, **kw: "c" * 40 if args[1] == "rev-parse" else b"",
    )
    monkeypatch.setattr(batch_adapter.subprocess, "run", fixture.command)
    monkeypatch.setattr(batch_adapter, "wire", fixture.wire)
    monkeypatch.setattr(production, "wire", fixture.wire)
    return permission, fixture


def test_complete_45_uses_real_bound_key_and_keeps_client_principal(boundary, tmp_path):
    permission, fixture = boundary
    adapter = production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "run"
    )
    result = execute_45(adapter, adapter.output, {"executionCommit": "c" * 40})
    assert result["recordingComplete"], result["failure"]
    assert result["cleanupComplete"] and result["safety"]
    assert len(result["rows"]) == 45
    assert len(fixture.commands) == 1
    assert result["counts"]["total"] == 340
    assert result["configurationUnchanged"] is True
    assert len(result["metadataTrace"]) == 8
    assert result["productionCompatibility"] == "unobserved"


@pytest.mark.parametrize(
    "variant",
    ["drift", "auth-denied", "readback", "timeout", "partial", "unrecovered"],
)
def test_failures_preserve_early_inputs_and_partial_observations(
    boundary, tmp_path, variant
):
    permission, fixture = boundary
    fixture.variant = variant
    adapter = production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "run"
    )
    result = execute_45(adapter, adapter.output, {"executionCommit": "c" * 40})
    assert not result["recordingComplete"]
    saved = json.loads((adapter.output / "result.json").read_bytes())
    assert saved["runtimeIdentity"]["executionCommit"] == "c" * 40
    assert saved["manifestDigest"] == digest(manifest())
    if variant == "drift":
        assert not result["trace"]
        assert len(fixture.requests) == 3  # tokeninfo, project, Database; no retry.
    if variant == "unrecovered":
        assert not result["cleanupComplete"]


def test_legacy_permission_and_reused_nonce_rejected_before_auth(boundary, tmp_path):
    permission, fixture = boundary
    wrong = dict(permission, kind="owner-execution-permission")
    with pytest.raises(ValueError):
        production.Production45Adapter(
            manifest(), wrong, permission["nonce"], tmp_path / "wrong"
        )
    assert not fixture.requests and not fixture.commands
    production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "first"
    )
    with pytest.raises(FileExistsError):
        production.Production45Adapter(
            manifest(), permission, permission["nonce"], tmp_path / "second"
        )
    assert not fixture.requests and not fixture.commands


def test_every_closed_permission_binding_checked(boundary):
    permission, _fixture = boundary
    for key in (
        "kind",
        "manifestSha256",
        "observerSha256",
        "comparisonContractDigest",
        "nonce",
        "quotaProject",
        "ownerIdentity",
        "permissionReference",
        "databaseProjectionContractDigest",
    ):
        with pytest.raises(ValueError):
            approve(
                manifest(),
                dict(permission, **{key: None}),
                permission["nonce"],
                permission["observerSha256"],
                1000,
            )


def rewrite_response(entry, status, body):
    observation = entry["observation"]
    raw = json.dumps(body).encode()
    observation["body"] = body
    observation["httpStatus"] = observation["http"]["status"] = status
    observation["http"].update(
        receivedBytes=len(raw),
        retainedBytes=len(raw),
        bodySha256=hashlib.sha256(raw).hexdigest(),
    )


def test_successful_stale_delete_records_absence_and_skips_unnecessary_delete(
    boundary, tmp_path
):
    permission, fixture = boundary
    trace = fixture.source["trace"]
    index = next(
        i
        for i, entry in enumerate(trace)
        if entry["phase"] == "diagnostic" and entry["sent"]["method"] == "DELETE"
    )
    rewrite_response(trace[index], 200, {})
    rewrite_response(trace[index + 1], 404, {"error": {"code": 404}})
    rewrite_response(trace[index + 2], 404, {"error": {"code": 404}})
    del trace[index + 3]  # Current absence means there is no cleanup DELETE.
    adapter = production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "run"
    )
    result = execute_45(adapter, adapter.output, {})
    assert result["recordingComplete"], result["failure"]
    assert result["cleanupComplete"] and result["safety"]
    assert len(result["rows"]) == 45
    assert result["counts"]["total"] == 339
    row = next(r for r in result["rows"] if "stale-delete-state/after" in r["id"])
    assert row["observation"]["httpStatus"] == 404
    assert "after" not in row["versions"]


def test_unexpected_success_preserved_and_unsafe_auth_stops_before_next_case(
    boundary, tmp_path
):
    permission, fixture = boundary
    trace = fixture.source["trace"]
    index = next(i for i, entry in enumerate(trace) if entry["phase"] == "diagnostic")
    rewrite_response(
        trace[index], 200, {"localId": fixture.source["bindings"]["b"]["uid"]}
    )
    changed = copy.deepcopy(trace[index + 2]["observation"]["body"])
    changed["users"][0]["emailVerified"] = True
    rewrite_response(trace[index + 2], 200, changed)
    # After the protected change only recovery, never the next baseline, is allowed.
    recovery = [
        e for e in trace if e["phase"] == "recovery" and e["sent"]["service"] == "auth"
    ]
    fixture.entries = iter(trace[: index + 3] + recovery)
    adapter = production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "run"
    )
    result = execute_45(adapter, adapter.output, {})
    assert not result["recordingComplete"] and result["safety"] is False
    assert result["cleanupComplete"]
    assert len(result["rows"]) == 1
    assert result["rows"][0]["observation"]["httpStatus"] == 200
    assert result["rows"][0]["after"]["b"]["emailVerified"] is True
    assert all(e["phase"] == "recovery" for e in result["trace"][index + 3 :])


def test_observation_budget_stop_keeps_reserved_cleanup_and_postflight(
    boundary, tmp_path
):
    permission, fixture = boundary
    adapter = production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "run"
    )
    reserve = adapter.budget.reserve

    def limited(service, now, duration=12):
        if service == "auth" and adapter.phase == "baseline":
            adapter.budget.counts["auth"] = 388
        return reserve(service, now, duration)

    adapter.budget.reserve = limited
    setup = [e for e in fixture.source["trace"] if e["phase"] == "setup"]
    recovery = [
        e
        for e in fixture.source["trace"]
        if e["phase"] == "recovery" and e["sent"]["service"] == "auth"
    ]
    fixture.entries = iter(setup + recovery)
    result = execute_45(adapter, adapter.output, {})
    assert not result["recordingComplete"] and result["cleanupComplete"]
    assert result["counts"]["auth"] == 396
    assert result["configurationUnchanged"] is True


def test_expired_token_refresh_failure_latches_and_retains_owned_resources(
    boundary, tmp_path, monkeypatch
):
    permission, fixture = boundary
    adapter = production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "run"
    )
    original = fixture.wire

    def wire(*args, **kwargs):
        result = original(*args, **kwargs)
        if (
            kwargs.get("receipt")
            and adapter.phase == "setup"
            and len(adapter.accounts) == 2
        ):
            adapter.credential.expiry = 0
        return result

    def command(args, **kwargs):
        if fixture.commands:
            raise subprocess.TimeoutExpired(args, 60)
        return fixture.command(args, **kwargs)

    monkeypatch.setattr(production, "wire", wire)
    monkeypatch.setattr(batch_adapter.subprocess, "run", command)
    result = execute_45(adapter, adapter.output, {})
    assert not result["recordingComplete"] and not result["cleanupComplete"]
    assert len(result["unrecovered"]) == 2
    assert adapter.credential.failed
    assert adapter.credential.attempts == 2
    assert all(
        e.get("observation") is None
        for e in result["trace"]
        if e["phase"] == "recovery"
    )


def test_non_json_diagnostic_received_without_claiming_json_compatibility(
    boundary, tmp_path
):
    permission, fixture = boundary
    fixture.variant = "non-json"
    adapter = production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "run"
    )
    result = execute_45(adapter, adapter.output, {})
    assert result["recordingComplete"] and result["cleanupComplete"]
    row = result["rows"][0]
    assert row["observation"]["body"] is None
    assert row["observation"]["http"]["bodyKind"] == "non-json"
    assert result["productionCompatibility"] == "unobserved"


def test_verified_key_cannot_change_before_actual_wire(boundary, tmp_path):
    permission, fixture = boundary
    adapter = production.Production45Adapter(
        manifest(), permission, permission["nonce"], tmp_path / "run"
    )
    adapter.preflight()
    before = len(fixture.requests)
    adapter.api_key = "fixture-key-K2"
    with pytest.raises(ValueError, match="key binding"):
        adapter.collect(
            "auth",
            "identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake",
            {},
            "POST",
            None,
            {"ordinal": 0, "sent": {"privileged": False}},
        )
    assert len(fixture.requests) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("retentionHours", 25),
        ("indexStorageUpperUSD", None),
        ("networkUpperUSD", -1),
        ("computedUpperUSD", 1.01),
        ("computedUpperUSD", 0),
        ("ownerConfirmed", False),
    ],
)
def test_cost_assumptions_cannot_be_inferred_or_exceed_envelope(boundary, field, value):
    permission, _fixture = boundary
    permission["costAssumptions"][field] = value
    with pytest.raises(ValueError):
        approve(
            manifest(),
            permission,
            permission["nonce"],
            permission["observerSha256"],
            1000,
        )
