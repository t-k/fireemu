"""Shared Auth-resource admission and cleanup tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "production-admission"))

import reservations
from broad_contract import digest
from shared_gate import Gate, create, validate_absence_proofs


def _auth_plan(resource: str = "projects/demo/auth/accounts/acct-0") -> dict:
    operation = {
        "service": "auth",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/projects/demo/accounts:lookup",
        "body": {"localId": ["$binding:acct0Uid"]},
        "form": False,
        "owner": True,
        "kind": "uid-absence",
        "account": "acct0",
        "resource": resource,
        "uidBinding": "acct0Uid",
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
                "accountBindings": {
                    "acct0": {"resource": resource, "uidBinding": "acct0Uid"}
                },
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
    with pytest.raises(
        ValueError, match="outside assigned resources|canonical Auth account|binding differs"
    ):
        create(path, plan)
    assert not path.exists()


def test_auth_account_binding_map_accepts_the_frozen_resource_and_uid_binding(tmp_path: Path) -> None:
    plan = _auth_plan()
    create(tmp_path / "gate", plan)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda plan: plan["jobs"]["auth-credential"]["accountBindings"]["acct0"].update(
                resource="projects/demo/auth/accounts/other"
            ),
            "resource",
        ),
        (
            lambda plan: plan["jobs"]["auth-credential"]["recovery"][0].update(
                uidBinding="otherUid"
            ),
            "binding",
        ),
        (
            lambda plan: plan["jobs"]["auth-credential"]["recovery"][0].update(
                resource="projects/demo/auth/accounts/other"
            ),
            "resource",
        ),
    ],
)
def test_auth_account_binding_mutations_are_refused_before_creation(
    tmp_path: Path, mutation, message: str
) -> None:
    plan = _auth_plan()
    mutation(plan)
    with pytest.raises(ValueError, match=message):
        create(tmp_path / "gate", plan)


def test_auth_account_binding_alias_collision_is_refused(tmp_path: Path) -> None:
    plan = _auth_plan()
    plan["jobs"]["auth-credential"]["accountBindings"]["other"] = {
        "resource": "projects/demo/auth/accounts/other",
        "uidBinding": "acct0Uid",
    }
    with pytest.raises(ValueError, match="injective|binding"):
        create(tmp_path / "gate", plan)


def test_auth_legacy_plan_without_binding_map_keeps_the_derived_binding_contract(
    tmp_path: Path,
) -> None:
    plan = _auth_plan()
    plan["jobs"]["auth-credential"].pop("accountBindings")
    plan["jobs"]["auth-credential"]["recovery"][0].pop("uidBinding")
    create(tmp_path / "gate", plan)


def test_auth_legacy_plan_cannot_override_its_derived_uid_binding(tmp_path: Path) -> None:
    plan = _auth_plan()
    plan["jobs"]["auth-credential"].pop("accountBindings")
    with pytest.raises(ValueError, match="requires account map"):
        create(tmp_path / "gate", plan)


def test_auth_digest_only_adoption_cannot_authorize_a_delete(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    plan["costMicrousd"] = 3
    lookup = plan["jobs"]["auth-credential"]["recovery"][0]
    delete = dict(
        lookup,
        kind="delete",
        path="identitytoolkit.googleapis.com/v1/projects/demo/accounts:delete",
        body={"localId": "$binding:acct0Uid"},
    )
    plan["jobs"]["auth-credential"]["recovery"] = [delete, lookup]
    create(path, plan)
    gate = Gate(path, "auth-credential")
    gate.claim()
    state = gate.snapshot()
    state["events"] = [
        {
            "job": "auth-credential",
            "phase": "observation",
            "completed": False,
            "creationOutcome": "created",
            "settledBy": {
                "kind": "address-readback-present",
                "responseDigest": "a" * 64,
            },
        }
    ]
    state["jobs"]["auth-credential"]["authAccounts"] = {
        "acct0": {
            "uid": "uid-0",
            "resource": "projects/demo/auth/accounts/acct-0",
            "createEvent": 0,
        }
    }
    reservations._save(path, state)
    with pytest.raises(ValueError, match="creation ownership"):
        gate.dispatch(delete, True, lambda: pytest.fail("forged delete was sent"))


def test_auth_plan_cannot_bind_absence_to_a_literal_or_foreign_uid(tmp_path: Path) -> None:
    plan = _auth_plan()
    operation = plan["jobs"]["auth-credential"]["recovery"][0]
    operation["body"] = {"localId": ["foreign-uid"]}
    with pytest.raises(ValueError, match="canonical Auth UID binding"):
        create(tmp_path / "gate", plan)


def test_auth_plan_cannot_use_a_lookup_route_from_another_project(tmp_path: Path) -> None:
    plan = _auth_plan()
    operation = plan["jobs"]["auth-credential"]["recovery"][0]
    operation["path"] = "identitytoolkit.googleapis.com/v1/projects/other/accounts:lookup"
    with pytest.raises(ValueError, match="canonical Auth UID binding or lookup route"):
        create(tmp_path / "gate", plan)


def test_auth_delete_requires_a_recorded_creation_before_send(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    plan["costMicrousd"] = 2
    lookup = plan["jobs"]["auth-credential"]["recovery"][0]
    delete = dict(lookup, kind="delete", path="identitytoolkit.googleapis.com/v1/projects/demo/accounts:delete", body={"localId": "$binding:acct0Uid"})
    plan["jobs"]["auth-credential"]["recovery"] = [delete, lookup]
    create(path, plan)
    gate = Gate(path, "auth-credential")
    gate.claim()
    with pytest.raises(ValueError, match="creation ownership"):
        gate.dispatch(delete, True, lambda: pytest.fail("unowned Auth delete was sent"))
    assert gate.snapshot()["events"] == []


def test_auth_delete_rejects_forged_cross_resource_creation_record(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    delete = dict(
        plan["jobs"]["auth-credential"]["recovery"][0],
        kind="delete",
        path="identitytoolkit.googleapis.com/v1/projects/demo/accounts:delete",
        body={"localId": "$binding:acct0Uid"},
    )
    plan["jobs"]["auth-credential"]["recovery"] = [delete]
    create(path, plan)
    gate = Gate(path, "auth-credential")
    gate.claim()
    state = gate.snapshot()
    state["jobs"]["auth-credential"]["authAccounts"] = {
        "acct0": {
            "uid": "acct1-uid",
            "resource": "projects/demo/auth/accounts/acct-1",
            "createEvent": 0,
        }
    }
    reservations._save(path, state)
    with pytest.raises(ValueError, match="creation ownership"):
        gate.dispatch(delete, True, lambda: pytest.fail("forged Auth delete was sent"))
    assert gate.snapshot()["events"] == []


def test_auth_observation_delete_is_rejected_before_send(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    delete = dict(
        plan["jobs"]["auth-credential"]["recovery"][0],
        kind="delete",
        path="identitytoolkit.googleapis.com/v1/projects/demo/accounts:delete",
        body={"localId": "$binding:acct0Uid"},
    )
    plan["observationRequests"] = 1
    plan["jobs"]["auth-credential"]["observation"] = [delete]
    plan["jobs"]["auth-credential"]["recovery"] = []
    plan["recoverySeconds"] = 1
    with pytest.raises(ValueError, match="observation.*delete|destructive Auth"):
        create(path, plan)
    assert not path.exists()


def test_auth_email_only_lookup_is_supplemental_not_account_absence(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    operation = plan["jobs"]["auth-credential"]["recovery"][0]
    operation["kind"] = "address-absence"
    operation["body"] = {"email": ["foreign@example.com"]}
    create(path, plan)
    gate = Gate(path, "auth-credential")
    gate.claim()
    gate.dispatch(operation, True, lambda: (200, {"users": []}))
    snapshot = gate.snapshot()
    assert snapshot["jobs"]["auth-credential"].get("absenceProofs", {}) == {}
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()


def test_auth_recovery_binding_cannot_cross_accounts(tmp_path: Path) -> None:
    plan = _auth_plan()
    operation = plan["jobs"]["auth-credential"]["recovery"][0]
    operation["body"] = {"localId": ["$binding:acct1Uid"]}
    with pytest.raises(ValueError, match="canonical Auth UID binding"):
        create(tmp_path / "gate", plan)


def test_auth_lookup_with_a_user_is_not_absence_and_stops_the_gate(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    create(path, plan)
    gate = Gate(path, "auth-credential")
    gate.claim()
    operation = plan["jobs"]["auth-credential"]["recovery"][0]
    with pytest.raises(ValueError, match="typed Auth absence required"):
        gate.dispatch(operation, True, lambda: (200, {"users": [{"localId": "uid-0"}]}))
    assert gate.snapshot()["stopped"] is False
    assert gate.snapshot()["jobs"]["auth-credential"]["stopped"] is True


def test_auth_lookup_for_a_different_uid_is_outside_the_frozen_request(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    create(path, plan)
    gate = Gate(path, "auth-credential")
    gate.claim()
    operation = dict(plan["jobs"]["auth-credential"]["recovery"][0])
    operation["body"] = {"localId": ["foreign-uid"]}
    with pytest.raises(ValueError, match="request outside closed scenario"):
        gate.dispatch(operation, True, lambda: pytest.fail("foreign UID was sent"))
    assert gate.snapshot()["events"] == []


def test_auth_typed_absence_proof_is_required_for_finish(tmp_path: Path) -> None:
    path = tmp_path / "gate"
    plan = _auth_plan()
    create(path, plan)
    gate = Gate(path, "auth-credential")
    gate.claim()
    operation = plan["jobs"]["auth-credential"]["recovery"][0]
    gate.dispatch(operation, True, lambda: (200, {"users": []}))
    state = gate.snapshot()
    state["jobs"]["auth-credential"]["absenceProofs"].clear()
    reservations._save(path, state)
    with pytest.raises(ValueError, match="typed cleanup absence evidence incomplete"):
        validate_absence_proofs(gate.snapshot(), "auth-credential")


def test_auth_gate_and_temporary_ledger_release_after_typed_cleanup(tmp_path: Path) -> None:
    plan = _auth_plan()
    gate_path = tmp_path / "gate"
    ledger = reservations.Ledger.create(tmp_path / "ledger")
    claim = {
        "campaignId": "AUTH-CREDENTIAL-TOKENS-01",
        "manifestDigest": digest("manifest"),
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str(gate_path.resolve()),
        "gatePlanDigest": digest(plan),
        "gateJob": "auth-credential",
        "locks": [{"key": "project/demo/auth/accounts/acct-0", "mode": "WRITE"}],
        "budget": {"requests": 1, "accounts": 1, "resources": 1, "costMicrousd": 1},
        "durationSeconds": 30,
    }
    envelope = {
        "permissionDigest": digest("permission"),
        "issuedAt": 1,
        "expiresAt": 10_000_000_000,
        "limits": {"requests": 2, "accounts": 1, "resources": 1, "costMicrousd": 2},
        "concurrency": 1,
        "scopes": [{"key": "project/demo", "mode": "EXCLUSIVE"}],
    }
    ticket = ledger.reserve(envelope, claim, plan, now=2)
    create(gate_path, plan)
    gate = Gate(gate_path, "auth-credential")
    gate.claim()
    operation = plan["jobs"]["auth-credential"]["recovery"][0]
    gate.dispatch(operation, True, lambda: (200, {"users": []}))
    gate.finish()
    ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
