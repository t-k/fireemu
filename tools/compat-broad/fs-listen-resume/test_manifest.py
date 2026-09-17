import copy

import pytest
from manifest import CASE_ID, compile_plan, digest, validate_plan


def test_plan_is_deterministic_and_binds_owned_nonce_resources():
    first = compile_plan("0123456789abcdef0123456789abcdef")
    second = compile_plan("0123456789abcdef0123456789abcdef")
    assert first == second
    assert first["caseId"] == CASE_ID == "FS-LISTEN-SDK-002"
    assert first["owner"]["collection"] == "o6_resume_0123456789abcdef0123456789abcdef"
    assert [item["path"] for item in first["ownedResources"]] == [
        "o6_resume_0123456789abcdef0123456789abcdef/one",
        "o6_resume_0123456789abcdef0123456789abcdef/two",
    ]
    assert first["limits"] == {
        "maxRuns": 3,
        "maxDurationSeconds": 120,
        "maxConcurrency": 1,
        "maxDocuments": 2,
        "maxOperations": 32,
        "maxSnapshots": 6,
        "estimatedCostUsd": 1,
        "hardCostCeilingUsd": 10,
    }
    assert validate_plan(first)
    assert digest(first) == digest(copy.deepcopy(first))


@pytest.mark.parametrize("nonce", ["", "abc", "Z" * 32, "0" * 31 + "!"])
def test_plan_rejects_non_128_bit_hex_nonce(nonce):
    with pytest.raises(ValueError, match="nonce"):
        compile_plan(nonce)


def test_plan_digest_changes_when_bound_input_changes():
    plan = compile_plan("a" * 32)
    changed = copy.deepcopy(plan)
    changed["limits"]["maxSnapshots"] = 5
    assert digest(plan) != digest(changed)
    assert not validate_plan(changed)


def test_plan_validation_rejects_operation_drift():
    plan = compile_plan("6" * 32)
    plan["operations"][4]["revision"] = 99
    assert not validate_plan(plan)


def test_operations_fit_the_frozen_budget_and_include_ordered_cleanup():
    plan = compile_plan("b" * 32)
    operations = plan["operations"]
    assert len(operations) <= plan["limits"]["maxOperations"]
    assert [item["kind"] for item in operations] == [
        "create",
        "listen",
        "update",
        "interrupt",
        "update",
        "create",
        "reconnect",
        "unsubscribe",
        "delete",
        "delete",
        "absence",
        "absence",
    ]
    assert operations[-2]["path"].endswith("/one")
    assert operations[-1]["path"].endswith("/two")
