"""Shared Auth-resource admission and cleanup tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "production-admission"))

import reservations
from broad_contract import digest
from shared_gate import Gate, create


def _auth_plan(resource: str = "projects/demo/auth/accounts/acct-0") -> dict:
    operation = {
        "service": "auth",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/projects/demo/accounts:lookup",
        "body": {"localId": ["uid-0"]},
        "form": False,
        "owner": True,
        "kind": "uid-absence",
        "account": "acct0",
        "resource": resource,
    }
    return {
        "contract": "shared-local-v1",
        "campaignId": "AUTH-CREDENTIAL-TOKENS-01",
        "nonce": "a" * 32,
        "project": "demo",
        "jobSlots": 1,
        "requestSeconds": 1,
        "wallSeconds": 30,
        "recoverySeconds": 10,
        "intervalSeconds": 0.25,
        "observationRequests": 0,
        "requestCostMicrousd": 1,
        "costMicrousd": 1,
        "jobs": {
            "auth-credential": {
                "observation": [],
                "recovery": [operation],
                "resources": [resource],
            }
        },
    }


def test_auth_account_resource_maps_to_project_scoped_write() -> None:
    resource = "projects/demo/auth/accounts/fireemu-cred-abcdef01-0"
    assert reservations._resource_scope(resource) == (
        "project",
        "demo",
        "auth",
        "accounts",
        "fireemu-cred-abcdef01-0",
    )


@pytest.mark.parametrize(
    "resource",
    [
        "projects/demo/auth/accounts",
        "projects/demo/auth/accounts/a/b",
        "projects/demo/auth/users/a",
        "projects/demo/auth/accounts/..",
        "projects/demo/auth/accounts/a b",
        "projects/demo/auth/accounts/" + "a" * 129,
        "identitytoolkit.googleapis.com/v1/projects/demo/accounts:delete",
    ],
)
def test_auth_resource_parser_rejects_routes_tenant_escapes_and_malformed_names(resource: str) -> None:
    with pytest.raises((TypeError, ValueError), match="canonical (Auth account|Firestore) resource"):
        reservations._resource_scope(resource)


def test_auth_resource_lock_coverage_is_project_and_account_bound() -> None:
    resource = "projects/demo/auth/accounts/fireemu-cred-abcdef01-0"
    assert reservations._resource_scope(resource)[:3] == ("project", "demo", "auth")
    namespace = {"key": "project/demo/auth/accounts/*", "mode": "WRITE"}
    foreign = {"key": "project/other/auth/accounts/*", "mode": "WRITE"}
    assert reservations._ancestor(reservations._scope(namespace), reservations._resource_scope(resource))
    assert not reservations._ancestor(reservations._scope(foreign), reservations._resource_scope(resource))


def test_auth_resource_scope_never_conflicts_with_firestore_document() -> None:
    auth = {"key": "project/demo/auth/accounts/a", "mode": "WRITE"}
    firestore = {"key": "project/demo/firestore/(default)/documents/a", "mode": "WRITE"}
    assert reservations.conflicts(auth, firestore) is False


def test_auth_lookup_empty_users_is_a_typed_absence_and_finishes(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    create(path, plan)
    gate = Gate(path, "auth-credential")
    gate.claim()
    operation = plan["jobs"]["auth-credential"]["recovery"][0]
    gate.dispatch(operation, True, lambda: (200, {"users": []}))
    gate.finish()
    snapshot = gate.snapshot()
    assert snapshot["jobs"]["auth-credential"]["absent"] == [operation["resource"]]


def test_auth_cleanup_route_without_declared_account_resource_is_refused_without_send(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    plan["jobs"]["auth-credential"]["recovery"][0]["resource"] = "projects/other/auth/accounts/acct-0"
    with pytest.raises(ValueError, match="outside assigned resources|canonical Auth account"):
        create(path, plan)
    assert not path.exists()
