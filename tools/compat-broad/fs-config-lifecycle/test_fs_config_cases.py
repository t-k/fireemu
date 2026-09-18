from __future__ import annotations

import json

import pytest
from fs_config_lifecycle.cases import (
    CASE_KINDS,
    OWNED_DATABASE_PREFIX,
    compile_cases,
    owned_resources,
    validate_cases,
)
from fs_config_lifecycle.surface_matrix import build_matrix

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def test_a_case_plan_needs_a_full_length_lowercase_hexadecimal_nonce() -> None:
    for bad in ("", "abc", "A" * 32, "g" * 32, NONCE[:-1], NONCE + "0"):
        with pytest.raises(ValueError):
            compile_cases(bad)
    assert compile_cases(NONCE)


def test_every_case_names_a_method_the_classification_matrix_already_covers() -> None:
    known = {row["locator"] for row in build_matrix()["methods"]}
    for case in compile_cases(NONCE):
        assert case["method"] in known


def test_case_kinds_are_closed_and_controls_and_negatives_both_exist() -> None:
    cases = compile_cases(NONCE)
    kinds = {case["kind"] for case in cases}
    assert kinds <= set(CASE_KINDS)
    assert "control" in kinds
    assert "negative" in kinds
    assert "observation" in kinds


def test_every_mutating_case_declares_a_revert_and_every_negative_mutates_nothing() -> (
    None
):
    for case in compile_cases(NONCE):
        if case["kind"] == "negative":
            assert case["mutates"] is False
            assert case["expectedProductionOutcome"] == "refusal"
        if case["mutates"]:
            assert case["revertedBy"], case["id"]
        else:
            assert case["revertedBy"] is None


def test_every_declared_revert_is_itself_a_case_in_the_same_plan() -> None:
    cases = compile_cases(NONCE)
    ids = {case["id"] for case in cases}
    for case in cases:
        if case["revertedBy"]:
            assert case["revertedBy"] in ids
            revert = next(c for c in cases if c["id"] == case["revertedBy"])
            assert revert["isRevertOf"] == case["id"]


def test_every_addressed_resource_lives_inside_the_owned_nonce_namespace() -> None:
    cases = compile_cases(NONCE)
    for case in cases:
        for resource in case["resources"]:
            if NONCE[:12] in resource or resource == "(default)":
                continue
            assert case["kind"] == "negative", case["id"]
            assert case["namespaceExemptReason"], case["id"]


def test_the_owned_ledger_lists_exactly_the_resources_a_run_must_recover() -> None:
    cases = compile_cases(NONCE)
    ledger = owned_resources(cases)
    assert ledger
    for entry in ledger:
        assert entry["revertCase"]
        assert entry["kind"] in {"database", "fieldConfig"}
    databases = [e for e in ledger if e["kind"] == "database"]
    assert len(databases) == 1
    assert databases[0]["name"].startswith(OWNED_DATABASE_PREFIX)


def test_no_case_reads_or_writes_a_document_so_no_storage_is_billed() -> None:
    for case in compile_cases(NONCE):
        assert ".documents." not in case["method"]
        assert "entities" not in json.dumps(case)


def test_expected_local_results_cite_the_classification_not_an_observation() -> None:
    matrix = {row["locator"]: row for row in build_matrix()["methods"]}
    for case in compile_cases(NONCE):
        expected = case["expectedLocal"]
        assert expected["outcome"] in {"served", "not-served"}
        assert expected["basis"] == "classification-matrix"
        row = matrix[case["method"]]
        if expected["outcome"] == "served":
            assert row["local"]["status"] in {"implemented", "partial"}
        else:
            assert row["local"]["status"] in {"not-implemented", "local-extension-only"}


def test_production_outcomes_are_declared_expectations_not_recorded_results() -> None:
    for case in compile_cases(NONCE):
        assert case["productionObserved"] is False
        assert case["expectedProductionOutcome"] in {"success", "refusal"}


def test_a_different_nonce_gives_a_disjoint_resource_namespace() -> None:
    def owned(nonce: str) -> set[str]:
        return {
            resource
            for case in compile_cases(nonce)
            for resource in case["resources"]
            if case["kind"] != "negative"
        }

    assert owned(NONCE) & owned("f" * 32) == {"(default)"}


def test_validation_rejects_drift_a_missing_revert_and_an_unknown_kind() -> None:
    cases = compile_cases(NONCE)
    assert validate_cases(cases, NONCE)
    assert not validate_cases([], NONCE)
    assert not validate_cases(cases, "b" * 32)
    truncated = json.loads(json.dumps(cases))[:-1]
    assert not validate_cases(truncated, NONCE)
    retyped = json.loads(json.dumps(cases))
    retyped[0]["kind"] = "smoke"
    assert not validate_cases(retyped, NONCE)
