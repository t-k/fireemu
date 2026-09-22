"""Offline tests for the parent-linked Auth custom-UID recovery contract."""

from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from broad_contract import digest

import credential_recovery as recovery


def _provenance() -> dict:
    values = {
        recovery.WORKER_ENTRY: "a" * 64,
        recovery.TRANSPORT_ENTRY: "b" * 64,
        recovery.LAUNCHER_ENTRY: "c" * 64,
    }
    return {
        "sourceCommit": "1" * 40,
        "sourceInputs": values,
        "worker": {"path": recovery.WORKER_ENTRY, "sha256": values[recovery.WORKER_ENTRY]},
        "transport": {"path": recovery.TRANSPORT_ENTRY, "sha256": values[recovery.TRANSPORT_ENTRY]},
        "launcher": {"path": recovery.LAUNCHER_ENTRY, "sha256": values[recovery.LAUNCHER_ENTRY]},
    }


def _parent() -> dict:
    nonce = "0123456789abcdef0123456789abcdef"
    uid = f"custom-{nonce}"
    operation = {
        "service": "auth",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
        "body": {"token": "$binding:customToken", "returnSecureToken": True},
        "form": False,
        "owner": False,
        "kind": "custom-sign-in",
        "account": "custom",
        "binds": {"customUid": "localId"},
        "resource": f"projects/fireemu-35fe6/auth/accounts/{uid}",
    }
    plan = {
        "campaignId": recovery.CAMPAIGN,
        "project": "fireemu-35fe6",
        "nonce": nonce,
        "sourceCommit": "1" * 40,
        "sourceInputs": _provenance()["sourceInputs"],
        "jobs": {"auth-credential": {"observation": [operation], "recovery": []}},
    }
    event = {
        "job": "auth-credential",
        "phase": "observation",
        "index": 0,
        "requestDigest": digest(operation),
        "completed": False,
        "creationOutcome": "unknown",
    }
    return {
        "state": "held",
        "ticket": {"reservation": "parent-ticket", "claimDigest": "parent-claim"},
        "claim": {
            "campaignId": recovery.CAMPAIGN,
            "claimDigest": "parent-claim",
            "gatePlanDigest": digest(plan),
            "nonceDigest": digest(nonce),
            "gatePath": "/tmp/auth-parent-gate",
        },
        "plan": plan,
        "gate": {
            "plan": plan,
            "jobs": {"auth-credential": {"inflight": False}},
            "events": [event],
            "coordinatorInflight": False,
        },
        "receipt": {"kind": "auth-credential-acquisition-receipt-v1", "failure": "collection-incomplete"},
        "responsibility": {"custom": {"state": "unknown", "uid": None}},
    }


def _authorities(plan: dict) -> tuple[dict, dict, dict]:
    permission = {
        "kind": recovery.PERMISSION_KIND,
        "campaignId": recovery.CAMPAIGN,
        "parentClaimDigest": plan["parent"]["claimDigest"],
        "planDigest": plan["planDigest"],
        "nonceDigest": plan["recoveryNonceDigest"],
        "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"],
        "budget": copy.deepcopy(recovery.CHILD_BUDGET),
        "ownerIdentity": "owner@example.invalid",
        "recoveryOwner": "recovery@example.invalid",
        "issuedAt": 1000.0,
        "expiresAt": 1300.0,
    }
    o7 = {
        "kind": recovery.O7_KIND,
        "status": "approved",
        "campaignId": recovery.CAMPAIGN,
        "planDigest": plan["planDigest"],
        "permissionDigest": digest(permission),
        "nonceDigest": plan["recoveryNonceDigest"],
        "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"],
        "issuedAt": 1000.0,
        "expiresAt": 1300.0,
    }
    o8 = {
        "kind": recovery.O8_KIND,
        "status": "issued",
        "campaignId": recovery.CAMPAIGN,
        "planDigest": plan["planDigest"],
        "permissionDigest": digest(permission),
        "nonceDigest": plan["recoveryNonceDigest"],
        "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"],
        "capabilityDigest": "d" * 64,
        "oneShot": True,
        "consumed": False,
        "issuedAt": 1001.0,
        "expiresAt": 1300.0,
    }
    return permission, o7, o8


def _plan() -> tuple[dict, dict]:
    parent = _parent()
    plan = recovery.compile_recovery_plan(
        parent,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        provenance=_provenance(),
        now=1000.0,
        deadline_seconds=180,
    )
    permission, o7, o8 = _authorities(plan)
    plan["permissionDigest"] = digest(permission)
    plan["o7Digest"] = digest(o7)
    plan["o8Digest"] = digest(o8)
    recovery.validate_authority_bundle(plan, permission=permission, o7=o7, o8=o8, now=1001.0)
    return parent, plan


def test_compile_binds_exact_custom_uid_and_one_read_only_lookup() -> None:
    parent, plan = _plan()
    operation = plan["operations"][0]
    assert operation["body"] == {"localId": [f"custom-{parent['plan']['nonce']}"]}
    assert operation["kind"] == "recovery-custom-uid-lookup"
    assert operation["method"] == "POST"
    assert len(plan["operations"]) == 1
    assert plan["budget"] == recovery.CHILD_BUDGET
    assert plan["deadlineSeconds"] == 180
    assert "email" not in repr(plan)
    assert all(op["method"] != "DELETE" for op in plan["operations"])


def test_compile_refuses_parent_that_is_not_held_or_custom_event_changed() -> None:
    parent = _parent()
    parent["state"] = "released"
    with pytest.raises(recovery.RecoveryRefusal, match="parent.*held"):
        recovery.compile_recovery_plan(parent, recovery_nonce="f" * 32, provenance=_provenance())

    parent = _parent()
    parent["gate"]["events"][0]["requestDigest"] = "0" * 64
    with pytest.raises(recovery.RecoveryRefusal, match="custom.*event"):
        recovery.compile_recovery_plan(parent, recovery_nonce="f" * 32, provenance=_provenance())


def test_fresh_authority_must_bind_child_and_parent_provenance() -> None:
    _parent_value, plan = _plan()
    permission, o7, o8 = _authorities(plan)
    o8["consumed"] = True
    with pytest.raises(recovery.RecoveryRefusal, match="O8"):
        recovery.validate_authority_bundle(plan, permission=permission, o7=o7, o8=o8, now=1001.0)


class _Ledger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    def begin_auth_recovery_extension(self, *args, **kwargs):
        self.calls.append(("begin", args, kwargs))
        return {"child": "ticket", "parentReservation": "parent-ticket"}

    def settle_auth_recovery_child(self, *args, **kwargs):
        self.calls.append(("settle", args, kwargs))
        return {"child": "ticket", "state": "settled"}

    def close_after_auth_recovery_child(self, *args, **kwargs):
        self.calls.append(("close", args, kwargs))
        return {"state": "closed-after-recovery-child"}


def test_begin_uses_auth_child_api_and_does_not_touch_parent() -> None:
    parent, plan = _plan()
    permission, o7, o8 = _authorities(plan)
    ledger = _Ledger()
    ticket = recovery.begin_child(
        ledger,
        parent_ticket=parent["ticket"],
        parent=parent,
        plan=plan,
        permission=permission,
        o7=o7,
        o8=o8,
        now=1001.0,
    )
    assert ticket["child"] == "ticket"
    assert [name for name, _args, _kwargs in ledger.calls] == ["begin"]
    assert parent["state"] == "held"


@pytest.mark.parametrize(
    "answer",
    [
        (200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}),
    ],
)
def test_empty_uid_lookup_is_typed_and_is_the_only_send(answer) -> None:
    _parent_value, plan = _plan()
    calls = []

    def send(operation, timeout):
        calls.append((operation, timeout))
        return answer

    result = recovery.execute_lookup(plan, send=send, now=lambda: 1001.0)
    assert result["disposition"] == "typed-empty"
    assert result["lookupCount"] == 1
    assert len(calls) == 1
    assert result["response"]["users"] == 0
    assert "custom-" not in repr(result)


@pytest.mark.parametrize(
    "answer,reason",
    [
        ((200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": [{"localId": "x"}]}), "present"),
        ((200, {"users": []}), "malformed"),
        ((200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": ["bad"]}), "ambiguous"),
    ],
)
def test_non_empty_malformed_and_ambiguous_answers_refuse_without_second_send(answer, reason) -> None:
    _parent_value, plan = _plan()
    calls = []

    def send(operation, timeout):
        calls.append(operation)
        return answer

    with pytest.raises(recovery.RecoveryRefusal, match=reason):
        recovery.execute_lookup(plan, send=send, now=lambda: 1001.0)
    assert len(calls) == 1


def test_timeout_refuses_without_settlement() -> None:
    _parent_value, plan = _plan()
    with pytest.raises(recovery.RecoveryRefusal, match="timeout"):
        recovery.execute_lookup(
            plan,
            send=lambda _operation, _timeout: (_ for _ in ()).throw(TimeoutError()),
            now=lambda: 1001.0,
        )


def test_settle_and_close_is_only_available_for_typed_empty() -> None:
    parent, plan = _plan()
    ledger = _Ledger()
    response_digest = digest({"kind": "identitytoolkit#GetAccountInfoResponse", "users": []})
    result = {
        "disposition": "typed-empty",
        "lookupCount": 1,
        "status": 200,
        "responseDigest": response_digest,
        "response": {"kind": "identitytoolkit#GetAccountInfoResponse", "users": 0},
        "receiptDigest": hashlib.sha256(repr((plan["planDigest"], response_digest)).encode()).hexdigest(),
    }
    outcome = recovery.settle_and_close(
        ledger,
        parent_ticket=parent["ticket"],
        child_ticket={"child": "ticket"},
        parent=parent,
        plan=plan,
        result=result,
    )
    assert outcome["state"] == "closed-after-recovery-child"
    assert [name for name, _args, _kwargs in ledger.calls] == ["settle", "close"]

    ledger = _Ledger()
    with pytest.raises(recovery.RecoveryRefusal, match="typed-empty"):
        recovery.settle_and_close(
            ledger,
            parent_ticket=parent["ticket"],
            child_ticket={"child": "ticket"},
            parent=parent,
            plan=plan,
            result={"disposition": "present"},
        )
    assert ledger.calls == []


def test_diagnostic_projection_is_secret_free_and_typed() -> None:
    projection = recovery.custom_sign_in_diagnostic(
        200,
        {"localId": "uid", "isNewUser": False, "idToken": "secret", "refreshToken": "secret"},
    )
    assert projection == {
        "status": 200,
        "bodyType": "object",
        "localId": "present",
        "isNewUser": "boolean-false",
        "tokens": {"idToken": "present", "refreshToken": "present"},
    }
    assert "secret" not in repr(projection)
