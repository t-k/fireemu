import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

import action_codes_gate as gate
import shared_gate

NONCE = "a" * 32
PROJECT = "fireemu-35fe6"


def _claim(handle):
    def receipt(slot):
        if slot == "oauth-tokeninfo":
            body = {
                "kind": "request-byte-token-attestation-v1",
                "principalDigest": "0" * 64,
                "requiredScopeVerified": True,
                "identityMode": "verified-email",
                "identityVerified": True,
                "oauthClientVerified": True,
                "expiresInSeconds": 480,
                "remainingSecondsAtVerification": 480,
                "requiredSeconds": 480,
                "complete": True,
                "workerReaped": True,
            }
        else:
            body = {"kind": "auth-project-readback-v1", "projectId": PROJECT, "authorized": True}
        return {"status": 200, "complete": True, "workerReaped": True, "bodyKind": "json", "body": body}

    handle.management_dispatch("observation", "oauth-tokeninfo", lambda _: receipt("oauth-tokeninfo"))
    handle.management_dispatch("observation", "auth-project-readback", lambda _: receipt("auth-project-readback"))
    handle.claim()


def test_gate_plan_is_full_action_matrix_and_two_nonce_resources():
    plan = gate.gate_plan(PROJECT, NONCE)
    job = plan["jobs"][gate.JOB]
    assert len(job["observation"]) == 26
    assert len(job["recovery"]) == 6
    assert len(job["resources"]) == 2
    assert all(f"projects/{PROJECT}/auth/accounts/" in item for item in job["resources"])
    assert all(NONCE in item for item in job["resources"])
    assert plan["observationRequests"] == 28
    assert plan["dataRequests"] == 32
    assert [slot["id"] for slot in plan["management"]["observation"]] == [
        "oauth-tokeninfo", "auth-project-readback"
    ]


def test_shared_gate_accepts_typed_action_plan_in_temporary_directory(tmp_path):
    plan = gate.gate_plan(PROJECT, NONCE)
    path = tmp_path / "gate"
    shared_gate.create(path, plan)
    state = json.loads((path / "state.json").read_bytes())
    assert state["planDigest"] == gate.plan_digest(plan)
    assert state["jobs"][gate.JOB]["observation"] == 0


def test_registered_signup_uids_admit_only_the_intentional_observation_delete(tmp_path):
    plan = gate.gate_plan(PROJECT, NONCE)
    path = tmp_path / "gate"
    gate.create(path, plan)
    handle = gate.ActionGate(path, gate.JOB)
    _claim(handle)
    operations = plan["jobs"][gate.JOB]["observation"]
    for index, operation in enumerate(operations[:24]):
        if operation["kind"] == "sign-up":
            suffix = "a" if operation["account"] == "accountA" else "b"
            body = {"localId": "uid-" + suffix, "idToken": "token-" + suffix, "refreshToken": "refresh-" + suffix}
            status = 200
        elif operation["id"] == "account-b-delete":
            body, status = {}, 200
        elif operation["id"] in {"reset-link-generate", "verify-link-generate", "email-link-generate", "email-link-generate-second", "reset-link-generate-second", "deleted-user-link-generate"}:
            body, status = {"oobCode": "code-" + operation["id"]}, 200
        else:
            body, status = {}, 200
        if operation["id"] == "account-b-delete":
            state = json.loads((path / "state.json").read_bytes())
            assert handle._allow_observation_auth_delete(state, state["jobs"][gate.JOB], operation, index)
            assert shared_gate._action_observation_delete_plan_allowed(plan, state["jobs"][gate.JOB], operation)
        handle.dispatch(operation, False, lambda status=status, body=body: (status, body))
    state = json.loads((path / "state.json").read_bytes())
    account = state["jobs"][gate.JOB]["authAccounts"]["accountB"]
    assert isinstance(account["createEvent"], int)
    assert isinstance(account["deletedEvent"], int)
    assert account["deletedEvent"] > account["createEvent"]


def test_gate_rejects_foreign_resource_or_nonce(tmp_path):
    plan = gate.gate_plan(PROJECT, NONCE)
    plan["jobs"][gate.JOB]["resources"][0] = "projects/foreign/auth/accounts/" + NONCE + "-a"
    with pytest.raises(ValueError):
        shared_gate.create(tmp_path / "gate", plan)


def test_incomplete_signup_is_unknown_held_and_not_refused(tmp_path):
    plan = gate.gate_plan(PROJECT, NONCE)
    path = tmp_path / "gate"
    gate.create(path, plan)
    handle = gate.ActionGate(path, gate.JOB)
    _claim(handle)
    signup = plan["jobs"][gate.JOB]["observation"][0]
    handle.dispatch(signup, False, lambda: (200, {"localId": "uid-a"}))
    state = json.loads((path / "state.json").read_bytes())
    event = state["events"][0]
    record = state["jobs"][gate.JOB]["authAccounts"]["accountA"]
    assert event["creationOutcome"] == "unknown"
    assert event["authEvidence"]["creationOutcome"] == "unknown"
    assert record["creationOutcome"] == "unknown"
    assert record["resource"] == signup["resource"]
    assert record["createEvent"] == 0
    assert "uid" not in record


def test_action_delete_predicate_does_not_union_invoking_job_bindings():
    plan = gate.gate_plan(PROJECT, NONCE)
    original = plan["jobs"][gate.JOB]
    other = deepcopy(original)
    other["accountBindings"]["accountB"]["resource"] = "projects/foreign/auth/accounts/foreign"
    plan["jobs"]["other"] = other
    operation = original["observation"][23]
    invoking = {"resources": list(original["resources"])}
    assert not shared_gate._action_observation_delete_plan_allowed(plan, invoking, operation)


def _dispatch_observation_prefix(handle, plan, stop=23):
    for operation in plan["jobs"][gate.JOB]["observation"][:stop]:
        if operation["kind"] == "sign-up":
            suffix = "a" if operation["account"] == "accountA" else "b"
            result = (200, {"localId": "uid-" + suffix, "idToken": "token-" + suffix, "refreshToken": "refresh-" + suffix})
        elif operation["id"] in {"reset-link-generate", "verify-link-generate", "email-link-generate", "email-link-generate-second", "reset-link-generate-second", "deleted-user-link-generate"}:
            result = (200, {"oobCode": "code-" + operation["id"]})
        else:
            result = (200, {})
        handle.dispatch(operation, False, lambda result=result: result)


def test_action_delete_requires_declared_account_binding_and_signup_digest(tmp_path):
    plan = gate.gate_plan(PROJECT, NONCE)
    path = tmp_path / "gate"
    gate.create(path, plan)
    handle = gate.ActionGate(path, gate.JOB)
    _claim(handle)
    _dispatch_observation_prefix(handle, plan)
    state = json.loads((path / "state.json").read_bytes())
    operation = plan["jobs"][gate.JOB]["observation"][23]
    forged = dict(operation, resource=plan["jobs"][gate.JOB]["resources"][0])
    assert not handle._allow_observation_auth_delete(state, state["jobs"][gate.JOB], forged, 23)
    account = state["jobs"][gate.JOB]["authAccounts"]["accountB"]
    assert account["requestDigest"] == state["events"][account["createEvent"]]["requestDigest"]
    assert state["events"][account["createEvent"]]["authEvidence"]["uid"] == account["uid"]


def test_action_delete_reordered_or_replayed_is_rejected(tmp_path):
    plan = gate.gate_plan(PROJECT, NONCE)
    path = tmp_path / "gate"
    gate.create(path, plan)
    handle = gate.ActionGate(path, gate.JOB)
    _claim(handle)
    with pytest.raises(ValueError, match="closed scenario|execution schedule"):
        handle.dispatch(plan["jobs"][gate.JOB]["observation"][23], False, lambda: (200, {}))

    _dispatch_observation_prefix(handle, plan)
    delete = plan["jobs"][gate.JOB]["observation"][23]
    handle.dispatch(delete, False, lambda: (200, {}))
    with pytest.raises(ValueError):
        handle.dispatch(delete, False, lambda: (200, {}))


def test_action_delete_400_is_terminal_error_not_absence(tmp_path):
    plan = gate.gate_plan(PROJECT, NONCE)
    path = tmp_path / "gate"
    gate.create(path, plan)
    handle = gate.ActionGate(path, gate.JOB)
    _claim(handle)
    _dispatch_observation_prefix(handle, plan)
    delete = plan["jobs"][gate.JOB]["observation"][23]
    handle.dispatch(delete, False, lambda: (400, {"error": {"message": "permission denied"}}))
    state = json.loads((path / "state.json").read_bytes())
    account = state["jobs"][gate.JOB]["authAccounts"]["accountB"]
    assert "deletedEvent" not in account
    assert "absenceProofs" not in state["jobs"][gate.JOB] or account["resource"] not in state["jobs"][gate.JOB]["absenceProofs"]
