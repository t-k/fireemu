from __future__ import annotations

import copy

import pytest
from o5_user_token_case import (
    OK,
    OWNER_FIELD,
    PERMISSION_DENIED,
    UNAUTHENTICATED,
    compile_case,
    principal_actions,
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
        "credential-revocation",
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


def test_request_auth_null_separates_anonymous_from_unauthenticated() -> None:
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
    # An implementation that wrongly treats an anonymous principal as an absent
    # principal would allow this row, so the two are separated here.
    assert rows["a-anonymous-denied-by-explicit-null-clause"]["principal"] == (
        "anonymous-c"
    )
    assert (
        rows["a-anonymous-denied-by-explicit-null-clause"]["expect"]["status"]
        == PERMISSION_DENIED
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


def test_atomic_multiwrite_refusal_proves_its_poststate() -> None:
    plan = case()
    rows = [
        row for row in plan["observation"] if row["condition"] == "atomic-multiwrite"
    ]
    assert [row["role"] for row in rows] == ["primary", "poststate"]
    assert rows[0]["expect"]["status"] == PERMISSION_DENIED
    updated = next(
        write for write in rows[0]["writes"] if write["document"] == "multiwrite-x"
    )
    assert updated["fields"]["generation"] == "updated"
    # The post-state row pins the pre-commit value, so an applied half is visible.
    assert rows[1]["expect"]["fields"]["generation"] == "initial"


def test_getafter_control_does_not_reuse_documents_from_earlier_rows() -> None:
    plan = case()
    rows = [row for row in plan["observation"] if row["condition"] == "getAfter"]
    primary, control = rows
    primary_documents = set(primary["targets"]) | set(primary["createdDocuments"])
    control_documents = set(control["targets"]) | set(control["createdDocuments"])
    assert primary_documents & control_documents == set()
    # The guard the control rule reads is never created by any row.
    guard = "getafter-control-guard"
    assert all(guard not in row["createdDocuments"] for row in plan["observation"])
    assert any(entry.endswith(guard) for entry in plan["neverCreatedDocuments"])
    assert guard in plan["rulesets"]["A"]["source"]


def test_no_row_creates_a_document_an_earlier_row_already_created() -> None:
    plan = case()
    seen: set[str] = set()
    fixtures = {entry["document"] for entry in plan["fixtures"]}
    for row in plan["observation"]:
        for document in row["createdDocuments"]:
            assert document not in seen
            assert document not in fixtures
            seen.add(document)


def test_every_touched_document_has_a_frozen_payload() -> None:
    plan = case()
    fixtures = {entry["document"]: entry["fields"] for entry in plan["fixtures"]}
    created = {
        write["document"]: write["fields"]
        for row in plan["observation"]
        for write in row["writes"]
        if write["operation"] == "create"
    }
    for row in plan["observation"]:
        for document in row["targets"]:
            assert document in fixtures or document in created
        for write in row["writes"]:
            assert write["fields"]


def test_rules_read_a_field_the_fixtures_actually_carry() -> None:
    plan = case()
    assert f"resource.data.{OWNER_FIELD}" in plan["rulesets"]["A"]["source"]
    owned = next(entry for entry in plan["fixtures"] if entry["document"] == "owned-a")
    assert OWNER_FIELD in owned["fields"]
    assert owned["fields"][OWNER_FIELD] == {"$principal": "owner-a"}
    assert plan["fieldResolution"]["ownerField"] == OWNER_FIELD


def test_principal_references_resolve_to_owned_accounts() -> None:
    plan = case()
    accounts = {entry["ref"] for entry in plan["ownedAccounts"]}
    assert accounts == {
        "owner-a",
        "other-b",
        "anonymous-c",
        "tenant-d",
        "revoked-e",
        "disabled-f",
        "deleted-g",
    }
    for entry in plan["fixtures"]:
        for value in entry["fields"].values():
            if isinstance(value, dict):
                assert value["$principal"] in accounts


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
    "mutation", ["status", "expect", "principal", "digest", "contract", "payload"]
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
    elif mutation == "payload":
        plan["fixtures"][0]["fields"][OWNER_FIELD] = {"$principal": "nobody"}
    else:
        plan["contract"] = "other"
    with pytest.raises(ValueError):
        validate_case(plan)


def test_validate_rejects_non_mappings() -> None:
    for value in (None, [], "plan", 3):
        with pytest.raises(ValueError):
            validate_case(value)


def test_revocation_rows_state_the_local_decision_and_a_production_hypothesis() -> None:
    """RULES-REVOKE-005 phase 1.

    Each revocation principal is accepted first (the positive control), then
    the administrator action is performed by the collector as a step, then the
    same token is presented again. The compiled status of that second row is
    what the local runtime currently decides: refused before Rules
    evaluation. Production is expected to keep accepting the token until it
    expires; that is a hypothesis carried on the row, never an observation,
    and a real comparison is expected to name these rows.
    """
    plan = case()
    rows = [
        row
        for row in plan["observation"]
        if row["condition"] == "credential-revocation"
    ]
    assert [(row["principal"], row["role"]) for row in rows] == [
        ("revoked-e", "control"),
        ("revoked-e", "primary"),
        ("disabled-f", "control"),
        ("disabled-f", "primary"),
        ("deleted-g", "control"),
        ("deleted-g", "primary"),
        ("revoked-expired-token", "control"),
    ]
    assert all(row["ruleset"] == "A" for row in rows)
    assert all(row["targets"] == ["exists-guarded"] for row in rows)
    for accepted, refused in (rows[0:2], rows[2:4], rows[4:6]):
        assert accepted["expect"]["status"] == "OK"
        assert "principalAction" not in accepted
        assert accepted["expect"]["productionHypothesis"]["status"] == "OK"
        assert refused["expect"]["status"] == "UNAUTHENTICATED"
        assert refused["expect"]["productionHypothesis"]["status"] == "OK"
        assert "revocation" in refused["expect"]["productionHypothesis"]["basis"]
        assert refused["principalAction"]["ref"] == refused["principal"]
        assert refused["index"] == accepted["index"] + 1
    assert [a["action"] for a in principal_actions(plan)] == [
        "revoke",
        "disable",
        "delete",
    ]
    assert [a["beforeIndex"] for a in principal_actions(plan)] == [
        rows[1]["index"],
        rows[3]["index"],
        rows[5]["index"],
    ]
    control = rows[6]
    assert control["expect"]["status"] == "UNAUTHENTICATED"
    assert control["expect"]["productionHypothesis"]["status"] == "UNAUTHENTICATED"
    assert control["credential"]["class"] == "user-id-token"


def test_revocation_principals_are_owned_accounts_with_a_post_sign_in_action() -> None:
    plan = case()
    actions = {entry["ref"]: entry.get("postSignIn") for entry in plan["ownedAccounts"]}
    assert actions["revoked-e"] == "revoke"
    assert actions["disabled-f"] == "disable"
    assert actions["deleted-g"] == "delete"
    assert all(
        actions[ref] is None
        for ref in ("owner-a", "other-b", "anonymous-c", "tenant-d")
    )
    for entry in plan["ownedAccounts"]:
        if entry.get("postSignIn"):
            assert entry["tenant"] is None
            assert entry["claims"] == {}
    principals = {row["ref"]: row for row in plan["principals"]}
    assert principals["revoked-expired-token"]["account"] is False
    assert principals["revoked-expired-token"]["kind"] == "expired-id-token"


def test_the_revocation_target_admits_any_authenticated_principal() -> None:
    plan = case()
    for label in ("A", "B"):
        source = plan["rulesets"][label]["source"]
        assert "exists-guarded {" in source
        clause = source.split("exists-guarded {", 1)[1].split("}", 1)[0]
        assert "request.auth != null" in clause
        assert "request.auth.uid" not in clause
