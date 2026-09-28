from __future__ import annotations

import json
import copy
import sys
import time
from pathlib import Path

import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "o8-core"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "production-admission"))
from o5_user_token_case import compile_case
from broad_contract import digest
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    READBACK_PUBLISH_ECHO,
    READBACK_RELEASE_GET,
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
    collect,
    RulesManagementSession,
)
from o5_user_token_local_run import _validated_child_python

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fs-write-limits"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import limits_03_descriptor
import compiler_03
from reservations import Ledger
import shared_gate

PROJECT = "fireemu-35fe6"
NONCE = "b" * 32


def case() -> dict:
    return compile_case(PROJECT, "(default)", NONCE)


def test_local_runner_child_uses_absolute_python_312() -> None:
    executable = _validated_child_python()
    assert executable.startswith("/")
    assert executable.rsplit("/", 1)[-1].startswith("python")


class Transport:
    """A scripted transport. It never opens a socket and holds no credential.

    With ``endpoint`` it behaves as a bound transport: every receipt names the
    host it reached and its own request counter, and a Ruleset release request
    is answered with a named release and a readback digest.
    """

    def __init__(
        self,
        plan: dict,
        *,
        leak: bool = False,
        nested_leak: bool = False,
        token_value: bool = False,
        incomplete_at: int | None = None,
        account_delete_fails: bool = False,
        endpoint: str | None = None,
        readback_kind: str | None = None,
        fingerprints: dict[str, str] | None = None,
    ):
        self.plan = plan
        self.leak = leak
        self.nested_leak = nested_leak
        self.token_value = token_value
        self.incomplete_at = incomplete_at
        self.account_delete_fails = account_delete_fails
        self.endpoint = endpoint
        self.readback_kind = readback_kind or (
            READBACK_RELEASE_GET
            if endpoint and not endpoint.startswith("127.")
            else READBACK_PUBLISH_ECHO
        )
        self.fingerprints = fingerprints or {}
        self.requests: list[dict] = []
        self.wire = 0
        self.releases = 0
        self.actions: list[tuple[str, str]] = []
        self.present = {resource: True for resource in plan["ownedResources"]}
        self.accounts = {entry["ref"]: True for entry in plan["ownedAccounts"]}

    def __call__(self, request: dict) -> dict:
        self.requests.append(request)
        self.wire += 1
        receipt = self._answer(request)
        if self.endpoint is not None:
            receipt["endpoint"] = self.endpoint
            receipt["wireSequence"] = self.wire
        return receipt

    def _answer(self, request: dict) -> dict:
        if request.get("phase") == "recovery":
            return self._recovery(request)
        if request.get("phase") == "principal":
            ref, action = request["principalRef"], request["action"]
            self.actions.append((ref, action))
            if action == "delete":
                self.accounts[ref] = False
            return {
                "complete": True,
                "status": "OK",
                "action": action,
                "authTime": 1_700_000_000,
                "validSince": 1_700_000_001 if action == "revoke" else None,
                "present": action != "delete",
                "disabled": None if action == "delete" else action == "disable",
                "uidFingerprint": self.fingerprints.get(ref, "0" * 16),
            }
        if request.get("phase") == "ruleset":
            self.releases += 1
            name = f"scripted-{request['ruleset']}-{self.releases}"
            if self.readback_kind == READBACK_RELEASE_GET:
                name = f"projects/{self.plan['project']}/releases/{name}"
            return {
                "complete": True,
                "status": "OK",
                "releaseName": name,
                "readbackKind": self.readback_kind,
                "readbackDigest": request["sourceDigest"],
            }
        index = request["index"]
        if self.incomplete_at == index:
            return {"complete": False, "failure": "transport-timeout"}
        if index == 0:
            if self.leak:
                return {"complete": True, "status": "OK", "idToken": "secret-value"}
            if self.nested_leak:
                return {
                    "complete": True,
                    "status": "OK",
                    "fields": {"nested": {"refreshToken": "secret"}},
                }
            if self.token_value:
                return {
                    "complete": True,
                    "status": "OK",
                    "fields": {"note": "aaaaaa.bbbbbb.cccccc"},
                }
        expected = self.plan["observation"][index]["expect"]["status"]
        return {
            "complete": True,
            "status": expected,
            "code": expected,
            "documentPresent": expected == "OK",
            "fields": {"caseId": request["caseId"]},
        }

    def _recovery(self, request: dict) -> dict:
        kind = request["kind"]
        if kind.startswith("account-"):
            ref = request["accountRef"]
            present = self.accounts.get(ref, False)
            if kind == "account-readback":
                return {
                    "complete": True,
                    "accountPresent": present,
                    "uid": f"uid-{ref}" if present else None,
                    "status": "OK",
                }
            if kind == "account-delete":
                assert request["precondition"]["uid"]
                if self.account_delete_fails:
                    return {"complete": False, "failure": "account-delete-refused"}
                self.accounts[ref] = False
                return {"complete": True, "status": "OK", "accountPresent": False}
            return {"complete": True, "accountPresent": self.accounts.get(ref, False)}
        resource = request["resource"]
        if kind == "readback":
            present = self.present.get(resource, False)
            return {
                "complete": True,
                "documentPresent": present,
                "version": "2026-09-18T00:00:00Z" if present else None,
                "status": "OK",
            }
        if kind == "delete":
            assert request["precondition"]["updateTime"]
            self.present[resource] = False
            return {"complete": True, "status": "OK", "documentPresent": False}
        return {"complete": True, "documentPresent": self.present.get(resource, False)}


def test_a_complete_run_records_every_row_and_recovers_every_resource() -> None:
    plan = case()
    transport = Transport(plan)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["contract"] == COLLECTOR_CONTRACT
    assert bundle["recordingComplete"] is True
    assert bundle["abort"] is None
    assert len(bundle["rows"]) == len(plan["observation"])
    assert bundle["cleanup"]["cleanupComplete"] is True
    assert bundle["cleanup"]["outstandingResources"] == []
    assert bundle["cleanup"]["outstandingAccounts"] == []


def test_every_owned_account_is_read_back_deleted_and_verified_absent() -> None:
    plan = case()
    bundle = collect(plan, Transport(plan), role=ROLE_PRODUCTION, run_id="run-1")
    kinds = [step["kind"] for step in bundle["cleanup"]["accountSteps"]]
    accounts = len(plan["ownedAccounts"])
    assert kinds.count("account-readback") == accounts
    assert kinds.count("account-delete") == accounts
    assert kinds.count("account-absence") == accounts
    assert bundle["attemptedAccounts"] == [
        entry["ref"] for entry in plan["ownedAccounts"]
    ]


def test_an_account_that_cannot_be_deleted_stays_outstanding() -> None:
    plan = case()
    bundle = collect(
        plan,
        Transport(plan, account_delete_fails=True),
        role=ROLE_PRODUCTION,
        run_id="run-1",
    )
    assert bundle["cleanup"]["outstandingAccounts"] == [
        entry["ref"] for entry in plan["ownedAccounts"]
    ]
    assert bundle["cleanup"]["cleanupComplete"] is False
    assert bundle["recordingComplete"] is False


def test_accounts_are_recovered_even_when_observation_aborts() -> None:
    plan = case()
    transport = Transport(plan, incomplete_at=1)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["abort"] == "incomplete-receipt"
    assert bundle["cleanup"]["outstandingAccounts"] == []
    assert [step["kind"] for step in bundle["cleanup"]["accountSteps"]].count(
        "account-delete"
    ) == len(plan["ownedAccounts"])


def test_an_account_delete_is_bound_to_the_observed_uid() -> None:
    plan = case()
    transport = Transport(plan)
    collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    deletes = [
        request
        for request in transport.requests
        if request.get("kind") == "account-delete"
    ]
    assert deletes
    for request in deletes:
        assert request["precondition"]["uid"].startswith("uid-")


def test_a_bundle_never_claims_production_authority() -> None:
    plan = case()
    bundle = collect(plan, Transport(plan), role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["status"] == "PREPARATION_ONLY"
    assert bundle["productionExecuted"] is False
    assert bundle["productionReady"] is False


def test_the_collector_never_receives_or_stores_a_token() -> None:
    plan = case()
    transport = Transport(plan)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    for request in transport.requests:
        assert "idToken" not in request
        assert "authorization" not in request
        assert "apiKey" not in request
    serialized = repr(bundle)
    assert "idToken" not in serialized
    assert "Bearer" not in serialized


def test_rows_bind_their_principal_without_a_secret() -> None:
    plan = case()
    bundle = collect(plan, Transport(plan), role=ROLE_PRODUCTION, run_id="run-1")
    for row, operation in zip(bundle["rows"], plan["observation"], strict=True):
        assert row["credentialRef"] == operation["credential"]["ref"]
        assert len(row["credentialFingerprint"]) == 16
    fingerprints = {
        row["credentialRef"]: row["credentialFingerprint"] for row in bundle["rows"]
    }
    assert len(set(fingerprints.values())) == len(fingerprints)


@pytest.mark.parametrize(
    "flag,marker",
    [
        ("leak", "credential-leak:idToken"),
        ("nested_leak", "credential-leak:refreshToken"),
        ("token_value", "credential-leak:token-shaped-value"),
    ],
)
def test_a_credential_anywhere_in_a_receipt_aborts_the_run(flag, marker) -> None:
    plan = case()
    bundle = collect(
        plan, Transport(plan, **{flag: True}), role=ROLE_PRODUCTION, run_id="run-1"
    )
    assert bundle["abort"] == marker
    assert len(bundle["rows"]) == 1
    assert bundle["rows"][0]["observed"] is None
    assert bundle["recordingComplete"] is False
    assert "secret" not in repr(bundle)


def test_a_recovery_receipt_with_an_unknown_key_is_refused() -> None:
    plan = case()
    transport = Transport(plan)

    def chatty(request: dict) -> dict:
        receipt = transport(request)
        if request.get("kind") == "readback":
            receipt["sessionCookie"] = "value"
        return receipt

    bundle = collect(plan, chatty, role=ROLE_PRODUCTION, run_id="run-1")
    failures = {step["failure"] for step in bundle["cleanup"]["documentSteps"]}
    assert any(
        failure is not None and failure.startswith("credential-leak")
        for failure in failures
    )
    assert bundle["cleanup"]["cleanupComplete"] is False


def test_an_incomplete_receipt_stops_later_rows_but_still_recovers() -> None:
    plan = case()
    transport = Transport(plan, incomplete_at=3)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["abort"] == "incomplete-receipt"
    assert len(bundle["rows"]) == 4
    assert bundle["recordingComplete"] is False
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_an_exhausted_deadline_stops_observation_before_the_request() -> None:
    plan = case()
    # Observation expires at 10s; recovery remains within its original 900s.
    # A monotonic clock must not roll back from 100s to 1s.
    ticks = iter([0.0, 100.0] + [100.0] * 500)
    transport = Transport(plan)
    bundle = collect(
        plan,
        transport,
        role=ROLE_PRODUCTION,
        run_id="run-1",
        deadline_seconds=10.0,
        recovery_deadline_seconds=900.0,
        clock=lambda: next(ticks),
    )
    assert bundle["abort"] == "deadline-exhausted"
    assert bundle["rows"] == []
    assert bundle["budget"]["observationSpent"] == 0
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_recovery_has_its_own_deadline() -> None:
    plan = case()
    ticks = iter([0.0] + [5000.0] * 2000)
    bundle = collect(
        plan,
        Transport(plan),
        role=ROLE_PRODUCTION,
        run_id="run-1",
        deadline_seconds=10.0,
        recovery_deadline_seconds=20.0,
        clock=lambda: next(ticks),
    )
    assert bundle["budget"]["recoveryDeadlineSeconds"] == 20.0
    failures = {step["failure"] for step in bundle["cleanup"]["documentSteps"]}
    assert "recovery-deadline-exhausted" in failures
    assert bundle["cleanup"]["cleanupComplete"] is False


def test_a_recovery_deadline_before_the_observation_deadline_is_rejected() -> None:
    plan = case()
    with pytest.raises(ValueError):
        collect(
            plan,
            Transport(plan),
            role=ROLE_PRODUCTION,
            run_id="run-1",
            deadline_seconds=600.0,
            recovery_deadline_seconds=100.0,
        )


def test_unknown_transport_exception_blocks_recovery() -> None:
    plan = case()
    transport = Transport(plan)
    calls = []

    def flaky(request: dict) -> dict:
        calls.append(request)
        if request.get("phase") != "recovery" and request["index"] == 2:
            raise TimeoutError("network detail that must not be recorded")
        return transport(request)

    bundle = collect(plan, flaky, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["rows"][2]["failure"] == "transport:TimeoutError"
    assert "network detail" not in repr(bundle)
    assert bundle["transport"]["workerReaped"] is False
    assert bundle["cleanup"]["cleanupComplete"] is False
    assert bundle["cleanup"]["blockedReason"] == "worker-reap-unconfirmed"
    assert len(calls) == 3


def test_explicit_reaped_transport_exception_allows_bounded_recovery() -> None:
    plan = case()
    transport = Transport(plan)

    class ReapedTimeoutError(TimeoutError):
        worker_reaped = True

    def flaky(request: dict) -> dict:
        if request.get("phase") != "recovery" and request["index"] == 2:
            raise ReapedTimeoutError("network detail that must not be recorded")
        return transport(request)

    bundle = collect(plan, flaky, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["rows"][2]["failure"] == "transport:ReapedTimeoutError"
    assert bundle["transport"]["workerReaped"] is True
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_deletion_requires_a_proven_version() -> None:
    plan = case()
    transport = Transport(plan)

    def unversioned(request: dict) -> dict:
        receipt = transport(request)
        if request.get("kind") == "readback":
            receipt["version"] = None
        return receipt

    bundle = collect(plan, unversioned, role=ROLE_PRODUCTION, run_id="run-1")
    kinds = [step["kind"] for step in bundle["cleanup"]["documentSteps"]]
    assert "delete" not in kinds
    assert bundle["cleanup"]["cleanupComplete"] is False
    assert bundle["recordingComplete"] is False


def test_an_already_absent_resource_is_not_deleted() -> None:
    plan = case()
    transport = Transport(plan)
    transport.present = {resource: False for resource in plan["ownedResources"]}
    transport.accounts = {entry["ref"]: False for entry in plan["ownedAccounts"]}
    bundle = collect(plan, transport, role=ROLE_LOCAL_SHADOW, run_id="run-2")
    assert [step["kind"] for step in bundle["cleanup"]["documentSteps"]] == [
        "readback" for _ in plan["ownedResources"]
    ]
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_bound_local_acquisition_keeps_local_rules_publication_without_management_session() -> None:
    plan = case()
    principals = {
        entry["ref"]: {
            "uidFingerprint": "a" * 16,
            "provider": "email",
            "tenant": entry["tenant"],
            "claimsDigest": digest(entry["claims"]),
        }
        for entry in plan["ownedAccounts"]
    }
    acquisition = {
        "environment": {"kind": "local-fireemu"},
        "campaignManifestDigest": "b" * 64,
        "nonceReservation": None,
        "ownerPermission": None,
        "artifact": {"artifactSha256": "c" * 64, "sourceCommit": "d" * 40},
        "principals": principals,
        "window": None,
    }
    transport = Transport(plan, endpoint="127.0.0.1:52879", fingerprints={ref: value["uidFingerprint"] for ref, value in principals.items()})
    bundle = collect(
        plan,
        transport,
        role=ROLE_LOCAL_SHADOW,
        run_id="local-bound-rules-publication",
        acquisition=acquisition,
    )
    assert bundle["recordingComplete"] is True
    assert bundle["abort"] is None
    assert len(bundle["rows"]) == 33
    assert [release["label"] for release in bundle["transport"]["rulesetReleases"]] == ["A", "B"]
    assert bundle["productionExecuted"] is False


def test_bound_production_still_refuses_without_rules_management_session() -> None:
    plan = case()
    principals = {
        entry["ref"]: {
            "uidFingerprint": "e" * 16,
            "provider": "email",
            "tenant": entry["tenant"],
            "claimsDigest": digest(entry["claims"]),
        }
        for entry in plan["ownedAccounts"]
    }
    acquisition = {
        "environment": {"kind": "production-oracle"},
        "campaignManifestDigest": "f" * 64,
        "nonceReservation": {"reservationId": "r", "campaignId": plan["campaignId"], "nonceDigest": digest(plan["nonce"])},
        "ownerPermission": {"kind": "owner", "permissionDigest": "1" * 64},
        "artifact": None,
        "principals": principals,
        "window": {"startsAt": time.time() - 1, "expiresAt": time.time() + 3600},
    }
    transport = Transport(plan, endpoint="firestore.googleapis.com:443", fingerprints={ref: value["uidFingerprint"] for ref, value in principals.items()})
    bundle = collect(
        plan,
        transport,
        role=ROLE_PRODUCTION,
        run_id="production-without-rules-session",
        acquisition=acquisition,
    )
    assert bundle["recordingComplete"] is False
    assert bundle["abort"] == "collector:ValueError"
    assert transport.requests
    assert all(request.get("phase") == "recovery" for request in transport.requests)


def test_attempted_creates_are_owned_even_when_the_response_is_lost() -> None:
    plan = case()
    transport = Transport(plan)
    creating = next(row for row in plan["observation"] if row["createdDocuments"])

    def lost(request: dict) -> dict:
        if request.get("phase") != "recovery" and request["index"] == creating["index"]:
            raise ConnectionError("lost")
        return transport(request)

    bundle = collect(plan, lost, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["attemptedResources"]
    for document in creating["createdDocuments"]:
        assert any(
            resource.endswith(document) for resource in bundle["attemptedResources"]
        )


def test_the_journal_records_every_attempt_before_the_response(tmp_path) -> None:
    plan = case()
    path = tmp_path / "journal.jsonl"
    # Abort after the first creating row, so the journal must carry its attempt.
    creating = next(row for row in plan["observation"] if row["createdDocuments"])
    transport = Transport(plan, incomplete_at=creating["index"] + 1)
    bundle = collect(
        plan,
        transport,
        role=ROLE_PRODUCTION,
        run_id="run-1",
        journal_path=path,
    )
    assert bundle["journal"] == str(path)
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    kinds = [entry["kind"] for entry in entries]
    assert kinds[0] == "run"
    assert "accounts" in kinds
    assert "attempt" in kinds
    assert "recovery" in kinds
    requested = [entry for entry in entries if entry["kind"] == "request"]
    assert [entry["caseId"] for entry in requested] == [
        row["caseId"] for row in bundle["rows"]
    ]
    assert "secret" not in path.read_text()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"role": "administrator", "run_id": "run-1"},
        {"role": ROLE_PRODUCTION, "run_id": ""},
        {"role": ROLE_PRODUCTION, "run_id": "run-1", "deadline_seconds": 0},
        {"role": ROLE_PRODUCTION, "run_id": "run-1", "deadline_seconds": 100000},
    ],
)
def test_invalid_collection_parameters_rejected(kwargs) -> None:
    plan = case()
    with pytest.raises(ValueError):
        collect(plan, Transport(plan), **kwargs)


def test_a_malformed_case_is_rejected_before_any_request() -> None:
    plan = case()
    plan["observation"][1]["expect"]["status"] = "OK"
    transport = Transport(plan)
    with pytest.raises(ValueError):
        collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    assert transport.requests == []


def test_rules_management_baseline_and_dynamic_bindings_use_real_gate(tmp_path) -> None:
    """The producer must derive A/B names from bounded response readbacks."""
    plan = case()
    gate_plan = {
        "contract": "shared-local-v1", "campaignId": "FS-RULES-USER-TOKEN-MATRIX-01",
        "project": PROJECT, "database": "(default)", "jobSlots": 1,
        "nonce": plan["nonce"],
        "jobs": {"rules-management": {"resources": [plan["ownedResources"][0]], "observation": [], "recovery": []}},
        "requestSeconds": 8.0, "observationRequests": 13, "requestCostMicrousd": 1,
        "costMicrousd": 23, "wallSeconds": 600.0, "recoverySeconds": 300.0,
        "intervalSeconds": 0.25, "coordinatorRequests": 0, "fixedCostMicrousd": 0,
        "permissionExpiresAt": time.time() + 3600,
        "management": {"dispatchKind": "closed-v1", "observation": [], "recovery": []},
    }
    gate_plan["management"]["observation"] = [
        {"id": slot, "timeout": 8.0}
        for slot in ("baseline-release-get", "baseline-ruleset-get", "baseline-executable-get", "create-a", "create-a-get", "patch-a", "patch-a-get", "patch-a-executable", "create-b", "create-b-get", "patch-b", "patch-b-get", "patch-b-executable")
    ]
    gate_plan["management"]["recovery"] = []
    gate_plan["observationRequests"] = len(gate_plan["management"]["observation"])
    gate_plan["management"]["recovery"] = [{"id": slot, "timeout": 8.0} for slot in ("restore-patch", "restore-get", "restore-executable", "restore-get-executable", "delete-a-get", "delete-a", "delete-a-absence", "delete-b-get", "delete-b", "delete-b-absence")]
    gate_plan["permissionExpiresAt"] = time.time() + 3600
    gate_plan["costMicrousd"] = 23
    ledger = Ledger.create(tmp_path / "ledger")
    now = time.time()
    envelope = {"permissionDigest": digest({"kind": "o5-test"}), "issuedAt": now - 1, "expiresAt": now + 3600, "limits": {"requests": 23, "accounts": 0, "resources": 1, "costMicrousd": 23}, "concurrency": 1, "scopes": [{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}]}
    claim = {"campaignId": "FS-RULES-USER-TOKEN-MATRIX-01", "manifestDigest": digest(plan), "nonceDigest": digest(plan["nonce"]), "gatePath": str((tmp_path / "gate").resolve()), "gatePlanDigest": digest(gate_plan), "locks": [{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}], "budget": dict(envelope["limits"]), "durationSeconds": 600}
    ticket = ledger.reserve(envelope, claim, gate_plan)
    shared_gate.create(tmp_path / "gate", gate_plan)
    gate = shared_gate.Gate(tmp_path / "gate", gate_plan["campaignId"])

    names = {"A": "projects/fireemu-35fe6/rulesets/server-a", "B": "projects/fireemu-35fe6/rulesets/server-b"}
    baseline = "projects/fireemu-35fe6/rulesets/pre-existing"
    source = {label: plan["rulesets"][label]["source"] for label in ("A", "B")}

    def execute(operation, **_kwargs):
        action = operation["action"]
        if action == "release-get":
            target = execute.active
            return {"status": 200, "body": {"name": operation["releaseName"], "rulesetName": target}}
        if action == "release-get-executable":
            target = execute.active
            return {"status": 200, "body": {"rulesetName": target}}
        if action == "create":
            return {"status": 200, "body": {"name": names[operation["label"]]}}
        if action == "get":
            label = "A" if operation["rulesetName"] == names["A"] else "B"
            return {"status": 200, "body": {"name": operation["rulesetName"], "source": {"files": [{"name": "firestore.rules", "content": source[label]}]}}}
        if action == "release-patch":
            execute.active = operation["rulesetName"]
            return {"status": 200, "body": {"name": operation["releaseName"], "rulesetName": execute.active}}
        raise AssertionError(action)

    execute.active = baseline
    session = RulesManagementSession(gate=gate, ledger=ledger, ticket=ticket, execute=execute, plan=plan)
    result = session.run_observation()
    assert result["created"] == names
    assert result["active"] == names
    assert gate.snapshot()["managementUsed"] == [
        "observation:" + slot["id"] for slot in gate_plan["management"]["observation"]
    ]
