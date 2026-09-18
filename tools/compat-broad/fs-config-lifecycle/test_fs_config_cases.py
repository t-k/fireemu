from __future__ import annotations

import json

import pytest
from fs_config_lifecycle.cases import (
    BODY_KEYS,
    CASE_KINDS,
    OWNED_DATABASE_PREFIX,
    compile_cases,
    declared_request_keys,
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
    assert "cleanup" in kinds


def test_every_conditional_cleanup_case_reverts_a_negative_create() -> None:
    cases = {case["id"]: case for case in compile_cases(NONCE)}
    cleanups = [case for case in cases.values() if case["kind"] == "cleanup"]
    assert len(cleanups) == 3
    for case in cleanups:
        assert case["conditional"] is True
        assert case["method"].endswith("databases.delete")
        origin = cases[case["isRevertOf"]]
        assert origin["kind"] == "negative"
        assert origin["method"].endswith("databases.create")


def test_a_negative_case_is_expected_to_be_refused_and_never_expected_to_mutate() -> (
    None
):
    for case in compile_cases(NONCE):
        if case["kind"] == "negative":
            assert case["mutates"] is False
            assert case["expectedProductionOutcome"] == "refusal"


def test_a_case_that_could_allocate_or_mutate_always_names_its_revert() -> None:
    for case in compile_cases(NONCE):
        recoverable = case["mutates"] or case["possiblyAllocates"]
        if recoverable:
            assert case["revertedBy"], case["id"]
        else:
            assert case["revertedBy"] is None, case["id"]


def test_every_create_call_counts_as_possibly_allocating_even_when_refused() -> None:
    for case in compile_cases(NONCE):
        if case["method"].endswith("databases.create"):
            assert case["possiblyAllocates"] is True, case["id"]


def test_every_request_key_is_a_parameter_or_body_the_pinned_discovery_declares() -> (
    None
):
    for case in compile_cases(NONCE):
        allowed = declared_request_keys(case["method"])
        assert set(case["request"]) <= allowed, (
            case["id"],
            set(case["request"]) - allowed,
        )


def test_a_body_key_is_only_used_where_discovery_declares_a_request_body() -> None:
    for method, key in BODY_KEYS.items():
        assert key in declared_request_keys(method)
    for case in compile_cases(NONCE):
        key = BODY_KEYS.get(case["method"])
        if key is None:
            assert not any(
                isinstance(value, dict) for value in case["request"].values()
            )


def test_the_negative_creates_vary_only_the_database_identifier() -> None:
    cases = {case["id"]: case for case in compile_cases(NONCE)}
    reference = cases["OC-03"]["request"]["database"]
    for case_id in ("OC-08", "OC-09", "OC-10"):
        request = cases[case_id]["request"]
        assert request["database"] == reference, case_id
        assert request["parent"] == cases["OC-03"]["request"]["parent"]
        assert request["databaseId"] != cases["OC-03"]["request"]["databaseId"]


def test_the_exemption_revert_never_sets_an_output_only_field() -> None:
    cases = {case["id"]: case for case in compile_cases(NONCE)}
    revert = cases["OC-20"]["request"]
    assert revert["field"]["indexConfig"] == {}
    assert "usesAncestorConfig" not in json.dumps(revert)


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
            assert case["kind"] in {"negative", "cleanup"}, case["id"]
            assert case["namespaceExemptReason"], case["id"]


def test_the_owned_ledger_covers_every_case_that_could_leave_a_resource() -> None:
    cases = compile_cases(NONCE)
    ledger = owned_resources(cases)
    recoverable = {
        case["id"] for case in cases if case["mutates"] or case["possiblyAllocates"]
    }
    assert {entry["createdBy"] for entry in ledger} == recoverable
    for entry in ledger:
        assert entry["revertCase"]
        assert entry["kind"] in {"database", "fieldConfig"}
        assert isinstance(entry["conditional"], bool)
    databases = [e for e in ledger if e["kind"] == "database"]
    assert len(databases) == 4
    expected = [e for e in databases if not e["conditional"]]
    assert len(expected) == 1
    assert expected[0]["name"].startswith(OWNED_DATABASE_PREFIX)
    assert all(e["conditional"] for e in databases if e is not expected[0])


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
            if case["kind"] not in {"negative", "cleanup"}
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
