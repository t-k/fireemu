"""Contract tests for the observation cases, campaign manifest, and comparator."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from mfa_cases import (
    CAMPAIGN_ID,
    CASE_IDS,
    SAMPLED_AGES_SECONDS,
    observation_cases,
    owned_accounts,
)
from mfa_comparator import compare
from mfa_manifest import compile_campaign, validate_campaign
from mfa_provenance import compute_provenance, repository_root

NONCE = "0123456789abcdef0123456789abcdef"


def test_the_blocking_conditions_each_have_cases() -> None:
    cases = observation_cases()
    families = {case["family"] for case in cases}
    assert families == {
        "pending-age-causality",
        "totp-lifecycle",
        "enrollment-session-age",
        "interaction",
    }
    assert SAMPLED_AGES_SECONDS == (300, 450, 600)
    for age in SAMPLED_AGES_SECONDS:
        assert f"age-{age}s-start" in CASE_IDS
        assert f"age-{age}s-finalize" in CASE_IDS
        assert f"age-{age}s-same-account-fresh-control" in CASE_IDS
        assert f"totp-enroll-session-age-{age}s" in CASE_IDS
    for endpoint in (
        "accounts/mfaEnrollment:start",
        "accounts/mfaEnrollment:finalize",
        "accounts/mfaEnrollment:withdraw",
        "accounts/mfaSignIn:start",
        "accounts/mfaSignIn:finalize",
    ):
        assert any(case["endpoint"] == endpoint for case in cases), endpoint


def test_the_fresh_same_account_control_shares_its_aged_case_account() -> None:
    by_id = {case["id"]: case for case in observation_cases()}
    for age in SAMPLED_AGES_SECONDS:
        aged = by_id[f"age-{age}s-start"]
        control = by_id[f"age-{age}s-same-account-fresh-control"]
        assert control["account"] == aged["account"]
        assert control["basis"] == "control" and control["ageSeconds"] == 0
        assert aged["basis"] == "diagnostic"


def test_no_case_claims_a_production_expectation() -> None:
    for case in observation_cases():
        assert case["productionExpectation"] == "unobserved"
        assert case["expectedLocal"]["basis"] == "source-read"
        assert case["source"] is not None


def test_negative_cases_expect_a_refusal_and_controls_expect_success() -> None:
    for case in observation_cases():
        if case["basis"] == "negative":
            assert case["expectedLocal"]["status"] >= 400
            assert case["expectedLocal"]["errorCode"]
        if case["basis"] == "control":
            assert case["expectedLocal"]["status"] == 200


def test_the_manifest_is_deterministic_and_validates_itself() -> None:
    plan = compile_campaign(NONCE)
    assert plan == compile_campaign(NONCE)
    assert validate_campaign(plan) is True
    assert plan["campaignId"] == CAMPAIGN_ID
    assert plan["status"] == "PREPARED_UNOBSERVED"
    assert plan["productionExecuted"] is False and plan["productionAllowed"] is False
    assert plan["caseCount"] == len(CASE_IDS)
    assert len(plan["owner"]["accounts"]) == len(owned_accounts())
    # The nonce is the ownership marker, so it is expected in the namespace and emails.
    assert plan["owner"]["namespace"].endswith(NONCE)
    assert plan["owner"]["nonceDigest"] != NONCE


def test_the_manifest_rejects_a_malformed_nonce_or_another_project() -> None:
    for bad in ("", "short", "G" * 32, NONCE.upper(), 1234):
        with pytest.raises(ValueError):
            compile_campaign(bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        compile_campaign(NONCE, project="some-other-project")


def test_an_altered_manifest_fails_validation() -> None:
    for mutation in (
        lambda plan: plan.update(productionAllowed=True),
        lambda plan: plan.update(productionExecuted=True),
        lambda plan: plan["limits"].update(maxRequests=10_000),
        lambda plan: plan["cases"].pop(),
        lambda plan: plan["owner"].update(nonceDigest="0" * 64),
        lambda plan: plan["cleanupContract"].update(residueAllowed=1),
    ):
        plan = compile_campaign(NONCE)
        mutation(plan)
        assert validate_campaign(plan) is False


def test_the_budget_stays_well_under_one_dollar_and_reserves_recovery() -> None:
    limits = compile_campaign(NONCE)["limits"]
    assert limits["enforced"] is True
    assert limits["estimatedCostUsd"] < 1.0
    assert limits["hardCostCeilingUsd"] < 1.0
    assert (
        limits["maxWallSeconds"]
        > max(SAMPLED_AGES_SECONDS) + limits["recoveryReserveSeconds"]
    )
    assert limits["maxOwnedAccounts"] >= len(owned_accounts())


def test_the_permission_envelope_names_only_identity_endpoints() -> None:
    envelope = compile_campaign(NONCE)["permissionEnvelope"]
    assert all(
        endpoint.startswith(("accounts", "projects"))
        for endpoint in envelope["allowedEndpoints"]
    )
    assert envelope["configurationMutation"]["restoreRequired"] is True
    assert any("Firestore" in item for item in envelope["forbidden"])
    assert len(compile_campaign(NONCE)["ownerPreconditions"]) >= 5


def receipt(side: str, root: Path | None = None) -> dict:
    return {
        "campaignId": CAMPAIGN_ID,
        "side": side,
        "recordingComplete": True,
        "productionExecuted": False,
        "provenance": compute_provenance(root or repository_root()),
        "worktree": {"commit": "a" * 40, "clean": True, "resolved": True},
        "rows": [
            {"id": identifier, "status": 200, "errorCode": None, "outcome": "observed"}
            for identifier in CASE_IDS
        ],
        "recovery": {
            "cleanupVerified": True,
            "remainingOwnedResources": 0,
            "configurationRestored": True,
        },
    }


def test_a_bound_preparation_pair_is_preparation_only_and_never_a_match() -> None:
    result = compare(receipt("local"), receipt("production"))
    assert result["classification"] == "PREPARATION_ONLY"
    assert result["productionExecuted"] is False
    assert result["rowDifferences"] == []


def test_self_comparison_and_forged_provenance_are_indeterminate(
    tmp_path: Path,
) -> None:
    local = receipt("local")
    assert compare(local, local)["classification"] == "INDETERMINATE"
    forged = receipt("production")
    forged["provenance"]["digest"] = "f" * 64
    result = compare(receipt("local"), forged)
    assert result["classification"] == "INDETERMINATE"
    assert "provenance does not match the worktree" in result["productionProblems"]


def test_incomplete_recording_cleanup_or_worktree_is_indeterminate() -> None:
    for mutation in (
        lambda record: record.update(recordingComplete=False),
        lambda record: record["recovery"].update(cleanupVerified=False),
        lambda record: record["recovery"].update(remainingOwnedResources=1),
        lambda record: record["recovery"].update(configurationRestored=False),
        lambda record: record["worktree"].update(clean=False),
        lambda record: record["worktree"].update(resolved=False),
        lambda record: record["rows"].pop(),
        lambda record: record["rows"].append(copy.deepcopy(record["rows"][0])),
        lambda record: record["rows"][0].update(status=True),
        lambda record: record["rows"][0].update(outcome="maybe"),
        lambda record: record.update(side="local"),
    ):
        production = receipt("production")
        mutation(production)
        assert (
            compare(receipt("local"), production)["classification"] == "INDETERMINATE"
        )


def test_a_real_row_difference_is_reported_only_for_an_executed_production_side() -> (
    None
):
    local = receipt("local")
    production = receipt("production")
    production["rows"][2].update(status=400, errorCode="INVALID_MFA_PENDING_CREDENTIAL")
    assert compare(local, production)["classification"] == "PREPARATION_ONLY"
    production["productionExecuted"] = True
    result = compare(local, production)
    assert result["classification"] == "DIFF"
    assert [row["id"] for row in result["rowDifferences"]] == [CASE_IDS[2]]


def test_dynamic_and_secret_values_never_create_a_difference() -> None:
    local = receipt("local")
    production = receipt("production")
    production["productionExecuted"] = True
    for index, record in enumerate((local, production)):
        record["rows"][1]["localId"] = f"uid-{index}"
        record["rows"][1]["mfaEnrollmentId"] = f"enrollment-{index}"
        record["rows"][1]["sharedSecretKey"] = f"SECRET_{index}"
        record["rows"][1]["verificationCode"] = f"{index}23456"
        record["rows"][1]["idToken"] = f"TOKEN_{index}"
        record["rows"][1]["pendingAgeSeconds"] = 300.0 + index
    result = compare(local, production)
    assert result["classification"] == "EXPECTED_NONDETERMINISM"
    assert result["rowDifferences"] == []
    assert result["nondeterministicRows"] == [CASE_IDS[1]]
    serialized = json.dumps(result)
    for material in ("SECRET_0", "SECRET_1", "TOKEN_0", "TOKEN_1", "023456", "123456"):
        assert material not in serialized


def test_identical_executed_receipts_reach_agreement() -> None:
    local = receipt("local")
    production = receipt("production")
    production["productionExecuted"] = True
    result = compare(local, production)
    assert result["classification"] == "MATCH"
    assert result["rowDifferences"] == [] and result["nondeterministicRows"] == []


def test_a_differing_error_code_alone_is_a_real_difference() -> None:
    local = receipt("local")
    production = receipt("production")
    production["productionExecuted"] = True
    production["rows"][3].update(status=400, errorCode="SESSION_EXPIRED")
    local["rows"][3].update(status=400, errorCode="INVALID_SESSION_INFO")
    result = compare(local, production)
    assert result["classification"] == "DIFF"
    assert result["rowDifferences"][0]["local"]["errorCode"] == "INVALID_SESSION_INFO"
    assert result["rowDifferences"][0]["production"]["errorCode"] == "SESSION_EXPIRED"
