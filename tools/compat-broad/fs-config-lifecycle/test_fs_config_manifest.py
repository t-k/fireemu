from __future__ import annotations

import json

import pytest
from fs_config_lifecycle.cases import cases_digest, compile_cases
from fs_config_lifecycle.manifest import (
    FORBIDDEN_PERMISSIONS,
    REQUIRED_PERMISSIONS,
    compile_manifest,
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


def test_the_budget_stays_far_below_one_dollar_and_declares_its_basis() -> None:
    budget = compile_manifest(NONCE)["budget"]
    assert budget["estimatedCostUsd"] == 0.0
    assert budget["hardCeilingUsd"] <= 1.0
    assert budget["estimatedCostUsd"] < budget["hardCeilingUsd"]
    assert budget["basis"]
    assert budget["maxRequests"] >= len(compile_cases(NONCE))
    assert budget["maxWallSeconds"] <= 1800
    assert budget["maxCreatedDatabases"] == 1
    assert budget["maxDocumentOperations"] == 0
    assert budget["enforced"] is False


def test_the_permission_envelope_excludes_every_document_and_billing_permission() -> (
    None
):
    envelope = compile_manifest(NONCE)["permissionEnvelope"]
    assert set(envelope["required"]) == set(REQUIRED_PERMISSIONS)
    assert set(envelope["forbidden"]) == set(FORBIDDEN_PERMISSIONS)
    assert not set(envelope["required"]) & set(envelope["forbidden"])
    for permission in envelope["required"]:
        assert not permission.startswith("datastore.entities.")
    assert "datastore.entities.get" in envelope["forbidden"]


def test_owner_preconditions_and_abort_rules_are_explicit_and_non_empty() -> None:
    manifest = compile_manifest(NONCE)
    assert len(manifest["ownerPreconditions"]) >= 4
    joined = " ".join(manifest["ownerPreconditions"]).lower()
    assert "exclusive use" in joined
    assert len(manifest["abortRules"]) >= 4
    text = json.dumps(manifest["ownerPreconditions"] + manifest["abortRules"]).lower()
    for topic in ("billing", "free", "delete protection", "abort", "retry"):
        assert topic in text


def test_the_cleanup_contract_covers_every_mutating_case_and_forbids_a_partial_exit() -> (
    None
):
    manifest = compile_manifest(NONCE)
    cleanup = manifest["cleanup"]
    recoverable = [
        case["id"]
        for case in compile_cases(NONCE)
        if case["mutates"] or case["possiblyAllocates"]
    ]
    assert {entry["createdBy"] for entry in cleanup["ledger"]} == set(recoverable)
    assert any(entry["conditional"] for entry in cleanup["ledger"])
    for entry in cleanup["ledger"]:
        assert entry["recovered"] is False
        assert entry["revertCase"]
    assert cleanup["order"]
    assert cleanup["completionRequires"]
    assert cleanup["unrecoveredResourcesFailTheRun"] is True
    assert "reconcile-database-enumeration" in cleanup["order"]
    assert cleanup["order"].index("reconcile-database-enumeration") == (
        len(cleanup["order"]) - 2
    )
    assert cleanup["reconciliation"]["comparesAgainst"] == "OC-02"
    assert cleanup["reconciliation"]["failsClosed"] is True
    reconciliation_text = json.dumps(cleanup["reconciliation"]).lower()
    assert "fsconfig-" in reconciliation_text


def test_the_operation_poll_is_bounded_and_resumable() -> None:
    poll = compile_manifest(NONCE)["operationPolling"]
    assert poll["maxAttemptsPerOperation"] >= 1
    assert poll["deadlineSeconds"] <= 900
    assert poll["initialBackoffSeconds"] < poll["maxBackoffSeconds"]
    assert poll["onDeadline"] == "abort-and-run-cleanup"
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


def test_every_allocating_case_is_in_the_ledger_or_covered_by_reconciliation() -> None:
    manifest = compile_manifest(NONCE)
    cleanup = manifest["cleanup"]
    tracked = {entry["createdBy"] for entry in cleanup["ledger"]}
    for case in compile_cases(NONCE):
        if not case["method"].endswith("databases.create"):
            continue
        assert case["id"] in tracked, case["id"]
        entry = next(e for e in cleanup["ledger"] if e["createdBy"] == case["id"])
        assert entry["revertCase"]
    assert cleanup["reconciliation"]["failsClosed"] is True
