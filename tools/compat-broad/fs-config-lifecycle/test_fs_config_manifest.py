from __future__ import annotations

import json

import pytest
from fs_config_lifecycle.cases import DROPPED_CASES, cases_digest, compile_cases
from fs_config_lifecycle.manifest import (
    FORBIDDEN_PERMISSIONS,
    HARD_CEILING_MICROUSD,
    MAX_REQUESTS,
    POLL_ATTEMPTS,
    REQUIRED_PERMISSIONS,
    compile_manifest,
    lock_scopes,
    validate_manifest,
)

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def test_a_manifest_needs_a_full_length_lowercase_hexadecimal_nonce() -> None:
    for bad in ("", "abc", "A" * 32, NONCE[:-1]):
        with pytest.raises(ValueError):
            compile_manifest(bad)
    assert compile_manifest(NONCE)


def test_the_manifest_is_preparation_only_and_carries_no_permission() -> None:
    manifest = compile_manifest(NONCE)
    assert manifest["status"] == "PREPARATION_ONLY"
    assert manifest["productionExecuted"] is False
    assert manifest["ownerApproval"] is None
    assert manifest["credentials"] == "none acquired; none referenced"


def test_frozen_inputs_bind_the_matrix_the_cases_and_the_pinned_discovery() -> None:
    manifest = compile_manifest(NONCE)
    frozen = manifest["frozenInputs"]
    assert frozen["casesDigest"] == cases_digest(NONCE)
    assert len(frozen["matrixDigest"]) == 64
    assert len(frozen["discoverySha256"]) == 64
    assert frozen["nonceDigest"] != NONCE
    assert NONCE not in json.dumps(frozen)


def test_the_manifest_records_the_scope_decision_that_dropped_thirteen_cases() -> None:
    manifest = compile_manifest(NONCE)
    assert manifest["caseCount"] == 12
    assert manifest["scopeDecision"]["decidedOn"] == "2026-09-18"
    assert manifest["scopeDecision"]["droppedCases"] == list(DROPPED_CASES)
    assert len(manifest["scopeDecision"]["droppedCases"]) == 13
    assert "managed-infrastructure" in manifest["scopeDecision"]["reason"]


def test_the_budget_is_enforced_and_re_derived_from_the_request_bound() -> None:
    budget = compile_manifest(NONCE)["budget"]
    assert budget["estimatedCostUsd"] == 0.0
    assert budget["estimatedCostMicrousd"] == 0
    assert budget["hardCeilingMicrousd"] == HARD_CEILING_MICROUSD == 1_000_000
    assert budget["hardCeilingUsd"] == 1.0
    assert (
        budget["reservedMicrousd"] == MAX_REQUESTS * budget["requestAllowanceMicrousd"]
    )
    assert budget["reservedMicrousd"] < budget["hardCeilingMicrousd"]
    assert budget["basis"]
    # Derivation: 1 preflight + 2 controls + 2 steps x 5 + 1 listing + 6 operations
    # x 16 polls + 2 recovery reverts and verifies + 5 reconciliation reads.
    derived = 1 + 2 + 2 * 5 + 1 + budget["maxOperations"] * POLL_ATTEMPTS + 4 + 5
    assert budget["maxOperations"] == 6
    assert budget["maxAccounts"] == 1
    assert derived <= budget["maxRequests"] == MAX_REQUESTS
    assert budget["maxRequests"] >= len(compile_cases(NONCE))
    assert budget["maxWallSeconds"] <= 1200
    assert 0 < budget["recoveryReserveSeconds"] < budget["maxWallSeconds"]
    assert budget["maxCreatedDatabases"] == 0
    assert budget["maxPatchedFieldConfigurations"] == 2
    assert budget["maxDocumentOperations"] == 0
    assert budget["enforced"] is True
    assert budget["enforcedBy"].endswith("lifecycle_gate.py")


def test_the_permission_envelope_names_no_database_lifecycle_permission() -> None:
    envelope = compile_manifest(NONCE)["permissionEnvelope"]
    assert set(envelope["required"]) == set(REQUIRED_PERMISSIONS)
    assert set(envelope["forbidden"]) == set(FORBIDDEN_PERMISSIONS)
    assert not set(envelope["required"]) & set(envelope["forbidden"])
    for permission in envelope["required"]:
        assert not permission.startswith("datastore.entities.")
        assert permission not in {
            "datastore.databases.create",
            "datastore.databases.delete",
            "datastore.databases.update",
        }
    for permission in (
        "datastore.databases.create",
        "datastore.databases.delete",
        "datastore.entities.get",
    ):
        assert permission in envelope["forbidden"]
    assert "datastore.indexes.update" in envelope["required"]


def test_owner_preconditions_and_abort_rules_are_explicit_and_non_empty() -> None:
    manifest = compile_manifest(NONCE)
    assert len(manifest["ownerPreconditions"]) >= 4
    joined = " ".join(manifest["ownerPreconditions"]).lower()
    assert "exclusive" in joined
    assert "projection digest" in joined
    assert len(manifest["abortRules"]) >= 4
    text = json.dumps(manifest["ownerPreconditions"] + manifest["abortRules"]).lower()
    for topic in ("credential", "wall", "unrecovered", "held", "retry", "nonce"):
        assert topic in text
    assert "billing plan" not in text
    assert "delete protection" not in text


def test_the_cleanup_contract_covers_every_mutating_case_and_forbids_a_partial_exit() -> (
    None
):
    manifest = compile_manifest(NONCE)
    cleanup = manifest["cleanup"]
    recoverable = [case["id"] for case in compile_cases(NONCE) if case["mutates"]]
    assert {entry["createdBy"] for entry in cleanup["ledger"]} == set(recoverable)
    for entry in cleanup["ledger"]:
        assert entry["recovered"] is False
        assert entry["revertCase"]
        assert entry["kind"] == "fieldConfig"
    assert cleanup["order"][0] == "revert-field-configurations"
    assert cleanup["order"][-1] == "write-final-ledger"
    assert "reconcile-database-enumeration" in cleanup["order"]
    assert "reconcile-field-listings" in cleanup["order"]
    assert "delete-created-database" not in cleanup["order"]
    assert cleanup["completionRequires"]
    assert cleanup["unrecoveredResourcesFailTheRun"] is True
    assert cleanup["reconciliation"]["comparesAgainst"] == "OC-02"
    assert cleanup["reconciliation"]["failsClosed"] is True


def test_lock_scopes_hold_exclusive_on_each_patched_field_and_read_around_it() -> None:
    locks = lock_scopes(NONCE)
    assert compile_manifest(NONCE)["lockScopes"] == locks
    exclusive = [lock for lock in locks if lock["mode"] == "EXCLUSIVE"]
    assert len(exclusive) == 2
    for lock in exclusive:
        assert lock["key"].startswith(
            "project/fireemu-35fe6/firestore/(default)/fields/"
        )
        assert NONCE[:12] in lock["key"]
    assert {lock["key"] for lock in locks if lock["mode"] == "READ"} == {
        "project/fireemu-35fe6/firestore/(default)/database",
        "project/fireemu-35fe6/firestore/(default)/indexes",
        "project/fireemu-35fe6/identity",
    }
    assert not any(lock["mode"] == "WRITE" for lock in locks)
    assert "documents" not in json.dumps(locks)


def test_the_operation_poll_is_bounded_and_resumable() -> None:
    poll = compile_manifest(NONCE)["operationPolling"]
    assert poll["maxAttemptsPerOperation"] >= 1
    assert poll["deadlineSeconds"] <= 900
    assert poll["initialBackoffSeconds"] < poll["maxBackoffSeconds"]
    assert poll["maxOperations"] == 6
    assert poll["onDeadline"] == "abort-and-run-recovery"
    checkpoint = poll["checkpoint"]
    assert checkpoint["writtenAfterEveryPoll"] is True
    assert checkpoint["fsyncBeforeContinuing"] is True
    assert checkpoint["resumeFrom"] == "owned-resource-ledger"
    assert checkpoint["path"]


def test_the_manifest_never_names_the_oracle_api_key_or_any_secret() -> None:
    serialized = json.dumps(compile_manifest(NONCE)).lower()
    for secret in ("api_key", "apikey", "password", "bearer", "secret", "token"):
        assert secret not in serialized


def test_validation_rejects_a_mutated_budget_ledger_or_nonce() -> None:
    manifest = compile_manifest(NONCE)
    assert validate_manifest(manifest, NONCE)
    assert not validate_manifest({}, NONCE)
    assert not validate_manifest(manifest, "b" * 32)
    raised = json.loads(json.dumps(manifest))
    raised["budget"]["hardCeilingUsd"] = 100.0
    assert not validate_manifest(raised, NONCE)
    emptied = json.loads(json.dumps(manifest))
    emptied["cleanup"]["ledger"] = []
    assert not validate_manifest(emptied, NONCE)
    executed = json.loads(json.dumps(manifest))
    executed["productionExecuted"] = True
    assert not validate_manifest(executed, NONCE)


def test_the_manifest_states_the_release_gap_and_never_claims_a_message_shape() -> None:
    unresolved = " ".join(compile_manifest(NONCE)["unresolved"])
    assert "locators only" in unresolved
    assert "never a message shape" in unresolved
    assert "release" in unresolved
    assert "shared_gate.create" in unresolved
