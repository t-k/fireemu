"""The credential campaign hosted on the shared Gate through its typed facade."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import credential_gate as gate_module
import credential_admission as admission
import reservations
import credential_shadow as shadow
from credential_cases import observation_cases
from credential_collector import cleanup_report, enter_recovery, new_budget, new_tracker
from credential_gate import (
    CredentialGate,
    account_evidence,
    gate_environment,
    gate_plan,
    gate_poster,
)
from test_credential_shadow import _service
from test_credential_admission import Admission

PROJECT = "demo-app"
NONCE = "c" * 32


def _plan(signing: bool = True) -> dict:
    return gate_plan(
        PROJECT,
        NONCE,
        signing=signing,
        wall_seconds=600,
        recovery_seconds=90,
        cost_microusd=200,
        observation_window_seconds=510,
    )


def _environment(signing: bool = True) -> dict:
    return {**shadow.local_environment(), **gate_environment(PROJECT, signing=signing)}


def _budget() -> dict:
    return new_budget(
        60, 600, 0.0, started_monotonic=time.monotonic(), recovery_requests=12, recovery_wall_seconds=90
    )


def _management_receipt(slot: str) -> dict:
    if slot == "oauth-tokeninfo":
        body = {
            "kind": "request-byte-token-attestation-v1",
            "principalDigest": "a" * 64,
            "requiredScopeVerified": True,
            "identityMode": "subject",
            "identityVerified": True,
            "oauthClientVerified": True,
            "expiresInSeconds": 3500,
            "remainingSecondsAtVerification": 3400.0,
            "requiredSeconds": 600,
            "complete": True,
            "workerReaped": True,
        }
    elif slot.startswith("sign-"):
        body = {"kind": "custom-token-signature-v1", "signatureBytes": 256}
    else:
        body = {"slot": slot, "baselineVerified": True}
    return {"status": 200, "complete": True, "workerReaped": True, "bodyKind": "json", "body": body}


def _preflight(gate: CredentialGate, phase: str, *, signing: bool = True) -> None:
    for slot in gate_module.management_ids(signing)[phase]:
        gate.management_dispatch(phase, slot, lambda deadline, slot=slot: _management_receipt(slot))


def _transmit(service: dict):
    """Answer a declared slot from the in-memory service, with the runner's values."""

    def transmit(declared: dict, body: dict, timeout: float) -> tuple[int, dict]:
        host, _, rest = declared["path"].partition("/")
        base = "http://127.0.0.1:1/" + host
        rpc = rest.rsplit("/", 1)[-1]
        if rpc.startswith("accounts:"):
            path = "/" + rpc
        elif rpc.endswith(":createSessionCookie"):
            path = ":createSessionCookie"
        else:
            path = ""
        # The in-memory service distinguishes the client lookup from the admin one
        # by the key query the runner sends; restore it for that decision only.
        if not declared["owner"] and path:
            path += "?key=k"
        status, raw = service["sender"](base, path, body, declared["owner"], timeout)
        return status, json.loads(raw)

    return transmit


def _hosted_run(tmp_path: Path, monkeypatch, *, signing: bool = True, service=None):
    monkeypatch.setattr(shadow, "_rest", lambda budget, seconds: None)
    plan = _plan(signing)
    plan["permissionExpiresAt"] = time.time() + 3600
    gate_module.create(tmp_path / "gate", plan)
    gate = CredentialGate(tmp_path / "gate")
    gate.claim()
    _preflight(gate, "observation", signing=signing)
    service = service or _service()
    poster = gate_poster(gate, _transmit(service))
    budget, tracker, rows = _budget(), new_tracker(NONCE), {}
    rows, failure = shadow.collect(
        "", budget, tracker,
        runner=lambda base, b, t, r: shadow.run_cases(base, b, t, r, poster=poster, environment=_environment(signing)),
    )
    enter_recovery(budget, time.monotonic())
    problems = shadow.cleanup("", budget, tracker, poster=poster, environment=_environment(signing))
    return gate, rows, failure, problems, tracker, budget, service


def test_the_plan_freezes_every_request_the_runner_makes_in_order() -> None:
    plan = _plan()
    job = plan["jobs"][gate_module.JOB]
    assert len(job["observation"]) == 34
    assert len(job["recovery"]) == 8
    assert plan["observationRequests"] == 34 + 6
    assert plan["dataRequests"] == 42
    assert [op["kind"] for op in job["recovery"]] == [
        "delete", "uid-absence", "address-absence",
        "delete", "uid-absence", "address-absence",
        "delete", "uid-absence",
    ]
    without = _plan(signing=False)["jobs"][gate_module.JOB]
    assert len(without["observation"]) == 22
    assert len(without["recovery"]) == 6
    assert all(op["account"] != "custom" for op in without["observation"] + without["recovery"])
    # Nothing in the plan is a run-time value: every dynamic slot is a placeholder.
    serialized = json.dumps(plan)
    assert "$binding:" in serialized
    assert "$apiKey" not in serialized
    assert "Bearer" not in serialized


def test_bootstrap_plan_adds_four_modern_oauth_management_slots(tmp_path: Path) -> None:
    plan = gate_module.bootstrap_plan(_plan(), permission_digest="a" * 64)
    management = plan["management"]
    assert [item["id"] for item in management["observation"][:4]] == [
        "bootstrap-refresh",
        "bootstrap-tokeninfo",
        "bootstrap-project",
        "bootstrap-auth-config",
    ]
    assert [item["method"] for item in management["observation"][:4]] == [
        "POST", "GET", "GET", "GET"
    ]
    assert management["observation"][1]["path"] == (
        "https://oauth2.googleapis.com/tokeninfo?access_token=$binding:accessToken"
    )
    assert plan["observationRequests"] == 44
    assert plan["managementRequests"] == 11
    assert plan["observationRequests"] + len(plan["jobs"][gate_module.JOB]["recovery"]) + 1 == 53
    assert plan["bootstrap"]["permissionDigest"] == "a" * 64
    gate_module.create(tmp_path / "gate", plan)


def test_bootstrap_prefix_is_reserved_and_journaled_after_fixture_o7(tmp_path: Path) -> None:
    built = Admission(tmp_path)
    admission.validate_o7_admission(**built.bindings())
    plan = gate_module.bootstrap_plan(
        admission.gate_plan_for(built.inputs, built.permission),
        permission_digest=gate_module.digest(built.permission),
    )
    gate_path = tmp_path / "gate"
    claim = admission.reservation_claim(built.inputs, gate_path=gate_path, gate_plan=plan)
    envelope = {
        "permissionDigest": gate_module.digest(built.permission),
        "issuedAt": built.permission["issuedAt"],
        "expiresAt": built.permission["expiresAt"],
        "limits": dict(claim["budget"]),
        "concurrency": 1,
        "scopes": list(claim["locks"]),
    }
    ticket = reservations.Ledger(built.ledger).reserve(envelope, claim, plan)
    assert ticket["reservation"] in reservations.Ledger(built.ledger).snapshot()["reservations"]
    gate_module.create(gate_path, plan)
    gate = CredentialGate(gate_path)
    receipts = []
    for slot in gate_module.bootstrap_management_ids():
        receipt = gate.management_dispatch(
            "observation",
            slot,
            lambda _deadline, slot=slot: {
                "status": 200,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": {"slot": slot, "fixture": True},
            },
        )
        receipts.append(receipt)
    assert [row["body"]["slot"] for row in receipts] == list(gate_module.bootstrap_management_ids())
    snapshot = gate.snapshot()
    assert snapshot["managementUsed"] == ["observation:" + slot for slot in gate_module.bootstrap_management_ids()]
    assert snapshot["managementEvents"][0]["bodyDigest"] == gate_module.digest(receipts[0]["body"])
    assert "fixture" not in (gate_path / "state.json").read_text()


def test_every_binding_a_slot_carries_is_either_observed_earlier_or_minted() -> None:
    plan = _plan()
    job = plan["jobs"][gate_module.JOB]
    available = set(gate_module.MINTED_BINDINGS)
    for op in job["observation"] + job["recovery"]:
        used = {
            value.removeprefix("$binding:")
            for value in _leaves(op["body"])
            if isinstance(value, str) and value.startswith("$binding:")
        }
        missing = used - available
        assert not missing, (op["kind"], missing)
        available |= set(op["binds"])


def _leaves(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _leaves(value)
    elif isinstance(node, list):
        for value in node:
            yield from _leaves(value)
    else:
        yield node


def test_the_shared_gate_admits_the_plan() -> None:
    plan = _plan()
    assert plan["jobs"][gate_module.JOB]["resources"] == plan["accountResources"]
    assert plan["accountResources"] == [
        f"projects/{PROJECT}/auth/accounts/fireemu-cred-{NONCE[:8]}-0",
        f"projects/{PROJECT}/auth/accounts/fireemu-cred-{NONCE[:8]}-1",
        f"projects/{PROJECT}/auth/accounts/custom-{NONCE}",
    ]


def test_gate_rejects_an_account_resource_with_another_accounts_email(tmp_path: Path) -> None:
    plan = _plan(signing=False)
    address = next(
        operation
        for operation in plan["jobs"][gate_module.JOB]["recovery"]
        if operation["kind"] == "address-absence" and operation["account"] == "acct0"
    )
    address["body"] = {"email": [gate_module.owned_email(NONCE, 1)]}
    with pytest.raises(ValueError, match="address binding differs"):
        gate_module.create(tmp_path / "gate", plan)


def test_a_hosted_run_reaches_every_case_cleans_up_and_finishes(tmp_path, monkeypatch) -> None:
    gate, rows, failure, problems, tracker, budget, service = _hosted_run(tmp_path, monkeypatch)
    assert failure is None and problems == []
    assert set(rows) == {case["id"] for case in observation_cases()}
    assert shadow._agreement(list(rows.values()))["unexpected"] == []
    assert cleanup_report(tracker)["cleanupComplete"] is True
    _preflight(gate, "recovery")
    gate.finish()
    snapshot = gate.snapshot()
    plan = snapshot["plan"]
    creation_events = [
        event for event in snapshot["events"]
        if event.get("authEvidence", {}).get("creationOutcome") == "created"
    ]
    assert creation_events and all(
        event["authEvidence"].get("uid")
        and event["authEvidence"].get("resource")
        == gate_module.account_resource(
            plan["project"], plan["nonce"], event["authEvidence"]["account"]
        )
        for event in creation_events
    )
    assert account_evidence(snapshot) == {
        "createdAccounts": 3,
        "deletedAccounts": 3,
        "uidAbsenceReadbacks": 3,
        "addressAbsenceReadbacks": 2,
        "routesAbsent": sorted(plan["accountResources"]),
        "complete": True,
    }
    assert snapshot["total"] == 42 + 7
    assert budget["requests"] == 42
    assert service["accounts"] == {}
    # The journal holds the plan and digests, never a credential this run received.
    journal = (tmp_path / "gate" / "state.json").read_text()
    for token in _tokens_issued(service):
        assert token not in journal
    assert shadow.PASSWORD not in journal
    assert "$binding:" in journal


def _tokens_issued(service: dict) -> list[str]:
    return list(service["issuedSecrets"])


def test_a_run_without_a_signer_reaches_only_the_non_signing_cases(tmp_path, monkeypatch) -> None:
    gate, rows, failure, problems, tracker, budget, _ = _hosted_run(tmp_path, monkeypatch, signing=False)
    assert failure is None and problems == []
    assert set(rows) == set(gate_module.runnable_case_ids(False))
    assert len(rows) == 8
    _preflight(gate, "recovery", signing=False)
    gate.finish()
    assert account_evidence(gate.snapshot())["createdAccounts"] == 2
    record, _exit_code = shadow.finish_record(
        rows=rows, tracker=tracker, budget=budget, failure=None,
        shutdown={"exitCode": 0, "processStopped": True, "remainingChildren": 0,
                  "outputDrainerStopped": True, "failures": []},
        source_binding={"commit": "a" * 40, "artifactSha256": "b" * 64},
        signing=False,
    )
    not_run = [row for row in record["receipt"]["rows"] if row["errorCode"] == "NOT_RUN"]
    assert len(not_run) == 11
    assert {row["notRunReason"] for row in not_run} == {shadow.SIGNING_ABSENT_REASON}
    assert record["receipt"]["recordingComplete"] is False


def test_a_value_the_run_never_observed_cannot_ride_in_a_bound_slot(tmp_path, monkeypatch) -> None:
    plan = _plan()
    plan["permissionExpiresAt"] = time.time() + 3600
    gate_module.create(tmp_path / "gate", plan)
    gate = CredentialGate(tmp_path / "gate")
    gate.claim()
    _preflight(gate, "observation")
    service = _service()
    transmit = _transmit(service)
    # The first slot is the sign-up; its password is minted on first use.
    email = gate_module.owned_email(NONCE, 0)
    declared = gate.next_operation(False)
    sign_up = {"email": email, "password": "minted-secret", "returnSecureToken": True}
    status, body = gate.dispatch_runtime(
        "identitytoolkit.googleapis.com/v1/accounts:signUp?key=$apiKey",
        sign_up,
        owner=False, recovery=False,
        send=lambda: transmit(declared, sign_up, 5),
    )
    assert status == 200
    # The second slot carries the refresh token the sign-up returned, and no other.
    with pytest.raises(ValueError, match="runtime binding differs"):
        gate.dispatch_runtime(
            "securetoken.googleapis.com/v1/token?key=$apiKey",
            {"grant_type": "refresh_token", "refresh_token": "not-the-issued-one"},
            owner=False, recovery=False, send=lambda: (200, {}),
        )
    # A request off the frozen order is refused before any send.
    with pytest.raises(ValueError, match="outside closed scenario"):
        gate.dispatch_runtime(
            "identitytoolkit.googleapis.com/v1/accounts:lookup?key=$apiKey",
            {"idToken": body["idToken"]},
            owner=False, recovery=False, send=lambda: (200, {}),
        )
    assert len(service["sent"]) == 1


def test_a_cookie_minted_for_another_subject_still_fails_when_hosted(tmp_path, monkeypatch) -> None:
    _gate, rows, failure, problems, *_ = _hosted_run(
        tmp_path, monkeypatch, service=_service(cookie_subject="uid-impostor")
    )
    assert failure is None and problems == []
    unexpected = shadow._agreement(list(rows.values()))["unexpected"]
    assert [item["caseId"] for item in unexpected] == ["session-cookie-claim-composition"]
