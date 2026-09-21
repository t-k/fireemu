import json
import sys
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


def test_gate_plan_is_full_action_matrix_and_two_nonce_resources():
    plan = gate.gate_plan(PROJECT, NONCE)
    job = plan["jobs"][gate.JOB]
    assert len(job["observation"]) == 26
    assert len(job["recovery"]) == 6
    assert len(job["resources"]) == 2
    assert all(f"projects/{PROJECT}/auth/accounts/" in item for item in job["resources"])
    assert all(NONCE in item for item in job["resources"])
    assert plan["observationRequests"] == 26
    assert plan["dataRequests"] == 32


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
    handle.claim()
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
