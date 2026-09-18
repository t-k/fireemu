from __future__ import annotations

import copy

import pytest
from o5_user_token_case import compile_case
from o5_user_token_collector import ROLE_LOCAL_SHADOW, ROLE_PRODUCTION, collect
from o5_user_token_comparator import (
    CLASSIFICATIONS,
    INDETERMINATE,
    REQUIRED_ACQUISITION_BINDINGS,
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


def fully_bound(plan: dict) -> tuple[dict, dict]:
    """Two bundles carrying every binding the unlock conditions name."""
    production, local = pair(plan)
    for side, label in ((production, "production"), (local, "local")):
        side["acquisition"] = {
            name: f"{label}-{name}" for name in REQUIRED_ACQUISITION_BINDINGS
        }
    return production, local


def test_the_comparator_has_exactly_one_classification() -> None:
    assert CLASSIFICATIONS == (INDETERMINATE,)


def test_two_agreeing_runs_are_still_indeterminate() -> None:
    plan = case()
    production, local = pair(plan)
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert result["rows"] == []
    assert result["promotionReady"] is False
    assert result["productionObserved"] is False
    assert "positive-classification-locked-pending-review" in result["errors"]


def test_a_locally_collected_bundle_labelled_production_never_agrees() -> None:
    """The regression the earlier O5 review asked for.

    Collecting the same matrix twice locally and passing ``role`` as the
    production role is the cheapest forgery. It must not reach agreement.
    """
    plan = case()
    forged = bundle(plan, ROLE_PRODUCTION, "local-run-relabelled")
    local = bundle(plan, ROLE_LOCAL_SHADOW, "local-run")
    result = compare(forged, local, plan)
    assert result["classification"] == INDETERMINATE
    assert result["rows"] == []
    assert any("missing-acquisition-bindings" in error for error in result["errors"])


def test_even_fully_bound_bundles_stay_indeterminate() -> None:
    plan = case()
    production, local = fully_bound(plan)
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert result["errors"] == ["positive-classification-locked-pending-review"]
    assert result["unlockConditions"]


@pytest.mark.parametrize("missing", REQUIRED_ACQUISITION_BINDINGS)
def test_a_missing_binding_is_named(missing) -> None:
    plan = case()
    production, local = fully_bound(plan)
    del production["acquisition"][missing]
    result = compare(production, local, plan)
    assert f"production-user-token:missing-binding:{missing}" in result["errors"]


def test_a_bundle_without_any_binding_is_refused() -> None:
    plan = case()
    production, local = pair(plan)
    result = compare(production, local, plan)
    for role in ("production-user-token", "local-fireemu-shadow"):
        assert f"{role}:missing-acquisition-bindings" in result["errors"]


def test_a_wrong_role_is_named() -> None:
    plan = case()
    local = bundle(plan, ROLE_LOCAL_SHADOW, "local-1")
    forged = copy.deepcopy(local)
    forged["productionExecuted"] = True
    result = compare(forged, local, plan)
    assert any("role-mismatch" in error for error in result["errors"])


def test_a_bundle_cannot_be_compared_with_itself() -> None:
    plan = case()
    production = bundle(plan, ROLE_PRODUCTION, "shared-run")
    local = bundle(plan, ROLE_LOCAL_SHADOW, "shared-run")
    assert "self-comparison" in compare(production, local, plan)["errors"]


def test_a_bundle_claiming_authority_is_named() -> None:
    plan = case()
    production, local = fully_bound(plan)
    production["productionReady"] = True
    result = compare(production, local, plan)
    assert any("claims-authority" in error for error in result["errors"])


def test_incomplete_recording_or_cleanup_is_named() -> None:
    plan = case()
    production, local = fully_bound(plan)
    production["cleanup"]["cleanupComplete"] = False
    assert any(
        "cleanup-incomplete" in e for e in compare(production, local, plan)["errors"]
    )
    production, local = fully_bound(plan)
    local["recordingComplete"] = False
    assert any(
        "recording-incomplete" in e for e in compare(production, local, plan)["errors"]
    )


def test_a_case_digest_mismatch_is_named() -> None:
    plan = case()
    production, local = fully_bound(plan)
    production["planDigest"] = "0" * 64
    assert any(
        "case-digest-drift" in error
        for error in compare(production, local, plan)["errors"]
    )


def test_row_identity_and_principal_drift_are_named() -> None:
    plan = case()
    production, local = fully_bound(plan)
    production["rows"][2]["credentialRef"] = "owner-a"
    assert any(
        "principal-drift" in error
        for error in compare(production, local, plan)["errors"]
    )
    production, local = fully_bound(plan)
    production["rows"][2]["caseId"] = "other"
    assert any(
        "row-identity" in error for error in compare(production, local, plan)["errors"]
    )


@pytest.mark.parametrize("bad", [None, [], "bundle", {}, {"contract": "other"}])
def test_malformed_bundles_are_refused(bad) -> None:
    plan = case()
    _, local = pair(plan)
    assert compare(bad, local, plan)["classification"] == INDETERMINATE
    assert compare(local, bad, plan)["classification"] == INDETERMINATE


def test_a_malformed_plan_is_refused_before_any_binding_check() -> None:
    plan = case()
    production, local = pair(plan)
    result = compare(production, local, {"project": []})
    assert result["classification"] == INDETERMINATE
    assert result["rows"] == []
    assert len(result["errors"]) == 1


def test_no_success_vocabulary_exists_in_the_module() -> None:
    import o5_user_token_comparator as module

    source = module.__doc__ or ""
    assert not hasattr(module, "MATCH")
    assert not hasattr(module, "EXPECTED_NONDETERMINISM")
    assert not hasattr(module, "SEMANTIC_MISMATCH")
    assert "no positive classification" in source
