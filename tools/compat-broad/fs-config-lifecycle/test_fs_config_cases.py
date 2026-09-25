from __future__ import annotations

import json

import pytest
from fs_config_lifecycle.cases import (
    BODY_KEYS,
    CASE_KINDS,
    DROPPED_CASES,
    EXECUTION_ORDER,
    LOCKED_STEPS,
    compile_cases,
    declared_request_keys,
    locked_steps,
    owned_resources,
    validate_cases,
)
from fs_config_lifecycle.surface_matrix import build_matrix

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
IN_SCOPE = (
    "OC-01",
    "OC-02",
    "OC-13",
    "OC-14",
    "OC-15",
    "OC-16",
    "OC-17",
    "OC-18",
    "OC-19",
    "OC-20",
    "OC-21",
    "OC-22",
)


def test_a_case_plan_needs_a_full_length_lowercase_hexadecimal_nonce() -> None:
    for bad in ("", "abc", "A" * 32, "g" * 32, NONCE[:-1], NONCE + "0"):
        with pytest.raises(ValueError):
            compile_cases(bad)
    assert compile_cases(NONCE)


def test_the_plan_carries_exactly_the_twelve_in_scope_cases() -> None:
    assert [case["id"] for case in compile_cases(NONCE)] == list(IN_SCOPE)


def test_every_managed_database_lifecycle_case_is_dropped_by_the_owner_decision() -> (
    None
):
    """OC-03..12 and OC-23..25 created or deleted a named database (2026-09-18)."""
    dropped = set(DROPPED_CASES)
    assert dropped == {f"OC-{n:02d}" for n in (*range(3, 13), 23, 24, 25)}
    assert not dropped & set(IN_SCOPE)
    for case in compile_cases(NONCE):
        assert not case["method"].endswith("databases.create")
        assert not case["method"].endswith("databases.delete")


def test_every_case_names_a_method_the_classification_matrix_already_covers() -> None:
    known = {row["locator"] for row in build_matrix()["methods"]}
    for case in compile_cases(NONCE):
        assert case["method"] in known


def test_case_kinds_are_closed_and_only_controls_and_observations_remain() -> None:
    cases = compile_cases(NONCE)
    kinds = {case["kind"] for case in cases}
    assert set(CASE_KINDS) == {"control", "observation"}
    assert kinds == set(CASE_KINDS)


def test_a_mutating_case_always_names_its_revert_and_the_revert_names_it_back() -> None:
    cases = compile_cases(NONCE)
    by_id = {case["id"] for case in cases}
    for case in cases:
        if case["mutates"]:
            assert case["revertedBy"] in by_id, case["id"]
            revert = next(c for c in cases if c["id"] == case["revertedBy"])
            assert revert["isRevertOf"] == case["id"]
            assert revert["mutates"] is False
        else:
            assert case["revertedBy"] is None, case["id"]


def test_exactly_two_cases_mutate_and_both_patch_a_nonce_owned_field() -> None:
    mutating = [case for case in compile_cases(NONCE) if case["mutates"]]
    assert [case["id"] for case in mutating] == ["OC-14", "OC-18"]
    for case in mutating:
        assert case["method"].endswith("collectionGroups.fields.patch")
        assert NONCE[:12] in case["resources"][0]
        assert "/databases/(default)/" in case["resources"][0]


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


def test_the_exemption_revert_never_sets_an_output_only_field() -> None:
    cases = {case["id"]: case for case in compile_cases(NONCE)}
    revert = cases["OC-20"]["request"]
    assert revert["field"]["indexConfig"] == {}
    assert "usesAncestorConfig" not in json.dumps(revert)


def test_every_addressed_resource_is_the_default_database_or_nonce_owned() -> None:
    for case in compile_cases(NONCE):
        for resource in case["resources"]:
            assert resource == "(default)" or NONCE[:12] in resource, case["id"]


def test_the_owned_ledger_lists_exactly_the_two_field_configurations() -> None:
    cases = compile_cases(NONCE)
    ledger = owned_resources(cases)
    assert [entry["createdBy"] for entry in ledger] == ["OC-14", "OC-18"]
    for entry in ledger:
        assert entry["kind"] == "fieldConfig"
        assert entry["revertCase"]
        assert entry["recovered"] is False
        assert entry["conditional"] is False


def test_locked_steps_bind_baseline_apply_readback_revert_and_lock_key() -> None:
    steps = locked_steps(NONCE)
    assert [step["id"] for step in steps] == [step["id"] for step in LOCKED_STEPS]
    cases = {case["id"]: case for case in compile_cases(NONCE)}
    for step in steps:
        for role in ("baseline", "apply", "readback", "revert"):
            assert step[role] in cases, (step["id"], role)
        assert cases[step["apply"]]["mutates"] is True
        assert cases[step["apply"]]["revertedBy"] == step["revert"]
        assert cases[step["baseline"]]["resources"] == [step["resource"]]
        assert step["lockKey"].startswith(
            "project/fireemu-35fe6/firestore/(default)/fields/"
        )
        assert NONCE[:12] in step["lockKey"]
        assert step["lockMode"] == "EXCLUSIVE"
    assert steps[0]["poll"] == "OC-22"


def test_the_execution_order_covers_every_case_once_and_reverts_after_readback() -> (
    None
):
    ids = [case["id"] for case in compile_cases(NONCE)]
    assert sorted(EXECUTION_ORDER) == sorted(ids)
    for step in LOCKED_STEPS:
        order = [
            EXECUTION_ORDER.index(step[r])
            for r in ("baseline", "apply", "readback", "revert")
        ]
        assert order == sorted(order)
    assert EXECUTION_ORDER[:2] == ("OC-01", "OC-02")


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
            assert "refusalReason" not in expected
        elif "refusalReason" in expected:
            assert row["local"]["status"] == "partial"
            assert expected["refusalReason"]
        else:
            assert row["local"]["status"] in {"not-implemented", "local-extension-only"}


def test_the_index_config_patches_are_expected_to_be_refused_locally() -> None:
    """OC-18 and OC-20 drive updateMask=indexConfig, which the local runtime refuses."""
    refused = {
        case["id"]
        for case in compile_cases(NONCE)
        if "refusalReason" in case["expectedLocal"]
    }
    assert refused == {"OC-18", "OC-20"}
    for case in compile_cases(NONCE):
        if case["id"] in refused:
            assert case["expectedLocal"]["outcome"] == "not-served"
            assert "UNIMPLEMENTED" in case["expectedLocal"]["refusalReason"]
        if case["id"] in {"OC-14", "OC-16"}:
            assert case["expectedLocal"]["outcome"] == "served"


def test_production_outcomes_are_declared_expectations_not_recorded_results() -> None:
    for case in compile_cases(NONCE):
        assert case["productionObserved"] is False
        assert case["expectedProductionOutcome"] == "success"


def test_a_different_nonce_gives_a_disjoint_resource_namespace() -> None:
    def owned(nonce: str) -> set[str]:
        return {
            resource for case in compile_cases(nonce) for resource in case["resources"]
        }

    assert owned(NONCE) & owned("f" * 32) == {"(default)"}


def test_validation_rejects_drift_a_missing_case_and_an_unknown_kind() -> None:
    cases = compile_cases(NONCE)
    assert validate_cases(cases, NONCE)
    assert not validate_cases([], NONCE)
    assert not validate_cases(cases, "b" * 32)
    truncated = json.loads(json.dumps(cases))[:-1]
    assert not validate_cases(truncated, NONCE)
    retyped = json.loads(json.dumps(cases))
    retyped[0]["kind"] = "smoke"
    assert not validate_cases(retyped, NONCE)
