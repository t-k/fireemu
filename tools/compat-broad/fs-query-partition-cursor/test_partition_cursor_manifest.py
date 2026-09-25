"""Contract tests for the campaign manifest and its closed production admission."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from partition_cursor_case import OBSERVATION_COUNT, RECOVERY_COUNT, compile_plan
from partition_cursor_manifest import (
    BLOCKERS,
    ROOT,
    admission_status,
    bound_manifest,
    manifest,
    source_inputs,
    validate_manifest,
    validate_permission,
)

NONCE = "c" * 32


def test_the_manifest_is_preparation_only() -> None:
    value = manifest()
    assert value["status"] == "PREPARATION_ONLY"
    assert value["productionReady"] is False
    assert value["productionExecuted"] is False
    assert value["blockers"] == list(BLOCKERS)


def test_the_manifest_freezes_the_lane_source_inputs() -> None:
    inputs = source_inputs()
    assert manifest()["sourceInputs"] == inputs
    for relative, sha in inputs.items():
        path = ROOT / relative
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha


def test_every_lane_module_is_a_frozen_input() -> None:
    directory = Path(__file__).resolve().parent
    modules = {
        str(path.relative_to(ROOT))
        for path in directory.glob("*.py")
        if not path.name.startswith("test_") and path.name != "conftest.py"
    }
    assert modules <= set(source_inputs())


def test_the_manifest_declares_the_bounded_wire_and_resource_budget() -> None:
    budget = manifest()["budget"]
    assert budget["requestUpperBound"] == OBSERVATION_COUNT + RECOVERY_COUNT
    assert budget["documentUpperBound"] == 21
    assert budget["documentUpperBound"] < 200
    assert budget["writeUpperBound"] == 42
    assert budget["concurrencyUpperBound"] == 1
    assert budget["costCeilingUsd"] < 1


def test_the_manifest_states_that_no_index_deployment_is_required() -> None:
    preconditions = manifest()["ownerPreconditions"]
    assert preconditions["requiredCompositeIndexes"] == []
    assert preconditions["indexFile"] == "conformance/firestore.indexes.json"
    assert preconditions["indexFileChangeRequired"] is False
    assert preconditions["deliberatelyUnindexed"] == ["partition-order-non-name"]


def test_the_manifest_records_why_the_collection_group_is_nonce_unique() -> None:
    value = manifest()
    assert value["isolation"]["partitionParent"] == "database"
    assert value["isolation"]["collectionGroup"] == "nonce-unique"


def test_a_bound_manifest_carries_one_compiled_case() -> None:
    value = bound_manifest("demo-project", "(default)", NONCE)
    assert value["observationCase"] == compile_plan("demo-project", "(default)", NONCE)
    assert value["caseDigest"] == value["observationCase"]["planDigest"]
    validate_manifest(value)


def test_validate_manifest_rejects_drift() -> None:
    value = bound_manifest("demo-project", "(default)", NONCE)
    value["budget"]["costCeilingUsd"] = 100
    with pytest.raises(ValueError):
        validate_manifest(value)


def test_validate_manifest_rejects_a_foreign_case() -> None:
    value = bound_manifest("demo-project", "(default)", NONCE)
    value["observationCase"]["nonce"] = "d" * 32
    with pytest.raises(ValueError):
        validate_manifest(value)


@pytest.mark.parametrize("value", [None, [], "manifest", {}])
def test_validate_manifest_rejects_a_non_manifest(value) -> None:
    with pytest.raises((TypeError, ValueError)):
        validate_manifest(value)


def test_admission_is_closed_and_cannot_be_opened() -> None:
    status = admission_status(compile_plan("demo-project", "(default)", NONCE))
    assert status["productionReady"] is False
    assert status["blockers"] == list(BLOCKERS)
    with pytest.raises(PermissionError):
        status["admit"]()


def test_admission_rejects_a_drifted_plan() -> None:
    plan = compile_plan("demo-project", "(default)", NONCE)
    plan["observation"].pop()
    with pytest.raises(ValueError):
        admission_status(plan)


@pytest.mark.parametrize(
    "permission",
    [
        None,
        {},
        {"expiresAt": float("nan")},
        {"expiresAt": float("inf")},
        {"expiresAt": 1, "ownerConfirmed": True},
        {"expiresAt": 2**40, "owner": "someone", "costAccepted": True},
    ],
)
def test_no_permission_is_accepted_while_the_blockers_stand(permission) -> None:
    with pytest.raises((TypeError, ValueError)):
        validate_permission(permission)


def test_the_manifest_has_no_production_transport_entry_point() -> None:
    import partition_cursor_manifest as module

    source = Path(module.__file__).read_text()
    for forbidden in ("http://", "https://", "urlopen", "socket", "subprocess"):
        assert forbidden not in source


def test_the_checked_in_preparation_record_matches_the_current_lane() -> None:
    from partition_cursor_manifest import EVIDENCE

    assert EVIDENCE.is_file(), "run partition_cursor_manifest.write_evidence()"
    assert json.loads(EVIDENCE.read_bytes()) == json.loads(json.dumps(manifest()))


def test_the_owner_preconditions_name_a_minimal_permission_set() -> None:
    preconditions = manifest()["ownerPreconditions"]
    assert preconditions["minimalPermissions"] == [
        "datastore.entities.create",
        "datastore.entities.get",
        "datastore.entities.list",
        "datastore.entities.delete",
    ]
    assert not any(
        permission.startswith(("datastore.indexes", "datastore.databases"))
        for permission in preconditions["minimalPermissions"]
    )
    assert preconditions["permissionNotes"]
