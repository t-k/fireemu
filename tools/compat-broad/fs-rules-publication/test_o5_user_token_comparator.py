from __future__ import annotations

import copy

import pytest
from o5_user_token_case import compile_case
from o5_user_token_collector import ROLE_LOCAL_SHADOW, ROLE_PRODUCTION, collect
from o5_user_token_comparator import (
    EXPECTED_NONDETERMINISM,
    INDETERMINATE,
    MATCH,
    SEMANTIC_MISMATCH,
    compare,
)
from test_o5_user_token_collector import Transport

PROJECT = "fireemu-35fe6"
NONCE = "d" * 32


def case() -> dict:
    return compile_case(PROJECT, "(default)", NONCE)


def bundle(plan: dict, role: str, run_id: str, **kwargs) -> dict:
    return collect(plan, Transport(plan, **kwargs), role=role, run_id=run_id)


def pair(plan: dict) -> tuple[dict, dict]:
    return (
        bundle(plan, ROLE_PRODUCTION, "production-1"),
        bundle(plan, ROLE_LOCAL_SHADOW, "local-1"),
    )


def test_agreeing_runs_match_every_row_without_promoting_anything() -> None:
    plan = case()
    production, local = pair(plan)
    result = compare(production, local, plan)
    assert result["errors"] == []
    assert result["classification"] == MATCH
    assert len(result["rows"]) == len(plan["observation"])
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False
    assert set(result["conditions"]) == set(plan["conditions"])


def test_a_differing_rules_decision_is_a_semantic_mismatch() -> None:
    plan = case()
    production, local = pair(plan)
    production["rows"][1]["observed"]["status"] = "OK"
    result = compare(production, local, plan)
    assert result["classification"] == SEMANTIC_MISMATCH
    mismatched = [
        row for row in result["rows"] if row["classification"] == SEMANTIC_MISMATCH
    ]
    assert [row["reason"] for row in mismatched] == ["status"]
    assert result["conditions"]["principal-separation"] == SEMANTIC_MISMATCH


def test_both_sides_agreeing_on_the_wrong_status_is_still_a_mismatch() -> None:
    plan = case()
    production, local = pair(plan)
    for side in (production, local):
        side["rows"][1]["observed"]["status"] = "OK"
    result = compare(production, local, plan)
    assert result["classification"] == SEMANTIC_MISMATCH
    assert result["rows"][1]["reason"] == "expected-status"


def test_server_assigned_values_are_expected_nondeterminism() -> None:
    plan = case()
    production, local = pair(plan)
    production["rows"][0]["observed"]["fields"] = {"caseId": "x", "updateTime": "t1"}
    local["rows"][0]["observed"]["fields"] = {"caseId": "x", "updateTime": "t2"}
    result = compare(production, local, plan)
    assert result["rows"][0]["classification"] == EXPECTED_NONDETERMINISM
    assert result["classification"] == EXPECTED_NONDETERMINISM


def test_a_differing_business_field_is_a_mismatch_not_nondeterminism() -> None:
    plan = case()
    production, local = pair(plan)
    production["rows"][0]["observed"]["fields"] = {"caseId": "x", "ownerUid": "one"}
    local["rows"][0]["observed"]["fields"] = {"caseId": "x", "ownerUid": "two"}
    result = compare(production, local, plan)
    assert result["rows"][0]["classification"] == SEMANTIC_MISMATCH


def test_a_local_bundle_cannot_stand_in_for_the_production_side() -> None:
    plan = case()
    local = bundle(plan, ROLE_LOCAL_SHADOW, "local-1")
    forged = copy.deepcopy(local)
    forged["productionExecuted"] = True
    result = compare(forged, local, plan)
    assert result["classification"] == INDETERMINATE
    assert result["rows"] == []
    assert any("role-mismatch" in error for error in result["errors"])


def test_a_bundle_cannot_be_compared_with_itself() -> None:
    plan = case()
    production = bundle(plan, ROLE_PRODUCTION, "shared-run")
    local = bundle(plan, ROLE_LOCAL_SHADOW, "shared-run")
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "self-comparison" in result["errors"]


def test_a_bundle_claiming_authority_is_refused() -> None:
    plan = case()
    production, local = pair(plan)
    production["productionReady"] = True
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert any("claims-authority" in error for error in result["errors"])


def test_incomplete_recording_or_cleanup_is_refused() -> None:
    plan = case()
    production, local = pair(plan)
    production["cleanup"]["cleanupComplete"] = False
    assert compare(production, local, plan)["classification"] == INDETERMINATE
    production, local = pair(plan)
    local["recordingComplete"] = False
    assert compare(production, local, plan)["classification"] == INDETERMINATE


def test_a_case_digest_mismatch_is_refused() -> None:
    plan = case()
    production, local = pair(plan)
    production["planDigest"] = "0" * 64
    result = compare(production, local, plan)
    assert any("case-digest-drift" in error for error in result["errors"])


def test_row_identity_and_principal_drift_are_refused() -> None:
    plan = case()
    production, local = pair(plan)
    production["rows"][2]["credentialRef"] = "owner-a"
    assert compare(production, local, plan)["classification"] == INDETERMINATE
    production, local = pair(plan)
    production["rows"][2]["caseId"] = "other"
    assert compare(production, local, plan)["classification"] == INDETERMINATE


def test_a_failed_row_is_indeterminate_and_dominates_a_clean_row() -> None:
    plan = case()
    production, local = pair(plan)
    production["rows"][0]["failure"] = "transport:TimeoutError"
    result = compare(production, local, plan)
    assert result["rows"][0]["classification"] == INDETERMINATE
    assert result["classification"] == INDETERMINATE


@pytest.mark.parametrize("bad", [None, [], "bundle", {}, {"contract": "other"}])
def test_malformed_bundles_are_refused(bad) -> None:
    plan = case()
    _, local = pair(plan)
    assert compare(bad, local, plan)["classification"] == INDETERMINATE
    assert compare(local, bad, plan)["classification"] == INDETERMINATE


def test_a_malformed_plan_is_refused_before_any_row() -> None:
    plan = case()
    production, local = pair(plan)
    result = compare(production, local, {"project": []})
    assert result["classification"] == INDETERMINATE
    assert result["rows"] == []
