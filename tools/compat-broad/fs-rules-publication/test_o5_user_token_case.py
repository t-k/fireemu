from __future__ import annotations

import copy

import pytest
from o5_user_token_case import (
    OK,
    PERMISSION_DENIED,
    UNAUTHENTICATED,
    compile_case,
    validate_case,
)

PROJECT = "fireemu-35fe6"
NONCE = "a" * 32


def case() -> dict:
    return compile_case(PROJECT, "(default)", NONCE)


def test_case_is_preparation_only_and_claims_nothing() -> None:
    plan = case()
    assert plan["status"] == "PREPARATION_ONLY"
    assert plan["productionExecuted"] is False
    assert plan["productionReady"] is False


def test_matrix_covers_every_required_condition() -> None:
    plan = case()
    assert set(plan["conditions"]) == {
        "atomic-multiwrite",
        "credential-refusal",
        "custom-claim",
        "exists",
        "get",
        "getAfter",
        "principal-separation",
        "request-auth-null",
        "ruleset-transition",
        "tenant",
    }


def test_every_condition_has_a_control_or_negative_row() -> None:
    plan = case()
    roles: dict[str, set[str]] = {}
    for row in plan["observation"]:
        roles.setdefault(row["condition"], set()).add(row["role"])
    for condition, present in roles.items():
        assert present & {"control", "negative", "poststate"}, condition


def test_principal_separation_uses_three_distinct_principals() -> None:
    plan = case()
    separation = [
        row for row in plan["observation"] if row["condition"] == "principal-separation"
    ]
    principals = {row["principal"] for row in separation}
    assert {"owner-a", "other-b", "anonymous-c"} <= principals
    denied = {
        row["principal"]
        for row in separation
        if row["expect"]["status"] == PERMISSION_DENIED
    }
    assert denied == {"other-b", "anonymous-c"}


def test_request_auth_null_is_explicit_in_both_directions() -> None:
    plan = case()
    rows = {
        row["caseId"]: row
        for row in plan["observation"]
        if row["condition"] == "request-auth-null"
    }
    assert (
        rows["a-unauthenticated-allowed-by-explicit-null-clause"]["expect"]["status"]
        == OK
    )
    assert (
        rows["a-authenticated-denied-by-explicit-null-clause"]["expect"]["status"]
        == PERMISSION_DENIED
    )


def test_credential_refusal_is_distinguished_from_rules_denial() -> None:
    plan = case()
    refusals = [
        row for row in plan["observation"] if row["condition"] == "credential-refusal"
    ]
    assert len(refusals) == 3
    assert {row["expect"]["status"] for row in refusals} == {UNAUTHENTICATED}


def test_ruleset_transition_changes_only_the_owner_clause() -> None:
    plan = case()
    source_a = plan["rulesets"]["A"]["source"]
    source_b = plan["rulesets"]["B"]["source"]
    differing = [
        (left, right)
        for left, right in zip(
            source_a.splitlines(), source_b.splitlines(), strict=True
        )
        if left != right
    ]
    assert len(differing) == 1
    assert "allow get" in differing[0][0]
    transition = [
        row for row in plan["observation"] if row["condition"] == "ruleset-transition"
    ]
    assert [row["expect"]["status"] for row in transition] == [
        PERMISSION_DENIED,
        OK,
        OK,
    ]


def test_atomic_multiwrite_refusal_has_a_poststate_row() -> None:
    plan = case()
    rows = [
        row for row in plan["observation"] if row["condition"] == "atomic-multiwrite"
    ]
    assert [row["role"] for row in rows] == ["primary", "poststate"]
    assert rows[0]["expect"]["status"] == PERMISSION_DENIED
    assert rows[1]["expect"]["status"] == OK


def test_operations_never_carry_a_credential_value() -> None:
    plan = case()
    for row in plan["observation"]:
        assert set(row["credential"]) == {"class", "ref"}
        assert "idToken" not in row
        assert "authorization" not in row


def test_document_paths_are_valid_and_scoped() -> None:
    plan = case()
    for resource in plan["ownedResources"]:
        suffix = resource.split("/documents/", 1)[1]
        assert len(suffix.split("/")) % 2 == 0
        assert resource.startswith(plan["ownedScope"] + "/")


def test_rules_reference_the_same_paths_the_matrix_targets() -> None:
    plan = case()
    source = plan["rulesets"]["A"]["source"]
    for entry in plan["fixtures"]:
        assert f"cases/{entry['document']}" in source


def test_rules_path_segment_does_not_start_with_a_digit() -> None:
    plan = compile_case(PROJECT, "(default)", "0" * 32)
    segment = plan["ownedScope"].split("/documents/", 1)[1].split("/")[1]
    assert not segment[0].isdigit()


@pytest.mark.parametrize(
    "project,database,nonce,tenant",
    [
        ("bad/project", "(default)", NONCE, "t-tenant"),
        (PROJECT, "bad/database", NONCE, "t-tenant"),
        (PROJECT, "(default)", "short", "t-tenant"),
        ("A", "(default)", NONCE, "t-tenant"),
        (PROJECT, "(default)", NONCE, "no"),
        (PROJECT, "(default)", NONCE, "bad/tenant"),
        (PROJECT, "(default)", "A" * 32, "t-tenant"),
    ],
)
def test_malformed_identity_rejected(project, database, nonce, tenant) -> None:
    with pytest.raises(ValueError):
        compile_case(project, database, nonce, tenant)


@pytest.mark.parametrize(
    "mutation", ["status", "expect", "principal", "digest", "contract"]
)
def test_case_drift_rejected(mutation) -> None:
    plan = copy.deepcopy(case())
    if mutation == "status":
        plan["productionReady"] = True
    elif mutation == "expect":
        plan["observation"][1]["expect"]["status"] = OK
    elif mutation == "principal":
        plan["observation"][1]["principal"] = "owner-a"
    elif mutation == "digest":
        plan["planDigest"] = "0" * 64
    else:
        plan["contract"] = "other"
    with pytest.raises(ValueError):
        validate_case(plan)


def test_validate_rejects_non_mappings() -> None:
    for value in (None, [], "plan", 3):
        with pytest.raises(ValueError):
            validate_case(value)
