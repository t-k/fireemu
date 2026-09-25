"""Contract tests for the observation cases, campaign manifest, and comparator."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from mfa_cases import (
    AGED_PENDING_SAMPLES,
    CAMPAIGN_ID,
    CASE_IDS,
    REFUSAL_DIRECTION_CONTROL_AGE_SECONDS,
    SAMPLED_AGES_SECONDS,
    critical_path_seconds,
    observation_cases,
    owned_accounts,
    serial_aging_seconds,
)
from mfa_collector import digest
from mfa_comparator import compare
from mfa_manifest import compile_campaign, validate_campaign
from mfa_provenance import compute_provenance, repository_root

NONCE = "0123456789abcdef0123456789abcdef"
RUNTIME_ANCHOR = {
    "artifactSha256": "a" * 64,
    "executionCommit": "a" * 40,
    "configurationDigest": "b" * 64,
    "runId": "campaign-run-1",
}


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


def test_the_only_finite_selector_preserves_the_full_catalog_and_exact_closure() -> None:
    full = compile_campaign(NONCE)
    selected = compile_campaign(NONCE, selector="pending-age-300-v1")
    assert [case["id"] for case in selected["cases"]] == list(CASE_IDS)
    assert selected["caseCount"] == 33
    assert selected["selector"] == {
        "name": "pending-age-300-v1",
        "caseIds": [
            "age-300s-start",
            "age-300s-finalize",
            "age-300s-same-account-fresh-control",
        ],
        "accountRoles": ["pending-age-300"],
        "observedAgeSeconds": 301,
        "dataRequests": 11,
        "recoveryRequests": 4,
        "managementRequests": 6,
        "declaredRequests": 22,
        "maxWallSeconds": 1200,
        "criticalPathSeconds": 301,
        "slackSeconds": 119,
        "requestContingency": {
            "resumeTokeninfoRequests": 3,
            "abandonTokeninfoRequests": 1,
            "restoreFallbackRequests": 4,
        },
    }
    assert "selector" not in full
    assert validate_campaign(selected) is True
    with pytest.raises(ValueError, match="unsupported MFA selector"):
        compile_campaign(NONCE, selector="age-450s")


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


def test_the_budget_covers_the_real_critical_path_and_the_reserve() -> None:
    limits = compile_campaign(NONCE)["limits"]
    assert limits["enforced"] is True
    assert limits["estimatedCostUsd"] < 1.0
    assert limits["hardCostCeilingUsd"] < 1.0
    assert limits["maxOwnedAccounts"] >= len(owned_accounts())
    assert limits["criticalPathSeconds"] == critical_path_seconds()
    assert limits["serialAgingSeconds"] == serial_aging_seconds()
    needed = (
        limits["criticalPathSeconds"]
        + limits["provisioningSeconds"]
        + limits["recoveryReserveSeconds"]
    )
    assert limits["maxWallSeconds"] >= needed


def test_the_serial_reading_of_the_schedule_would_not_fit_the_budget() -> None:
    # This is why the concurrent acquisition schedule is contractual rather than advisory:
    # acquiring each aged resource immediately before its own wait costs the serial total.
    limits = compile_campaign(NONCE)["limits"]
    assert limits["serialAgingSeconds"] > limits["maxWallSeconds"]
    assert limits["serialAgingSeconds"] > limits["criticalPathSeconds"]


def test_the_aged_cases_are_listed_in_non_decreasing_due_order() -> None:
    offsets = [
        case["dueOffsetSeconds"]
        for case in observation_cases()
        if case["dueOffsetSeconds"]
    ]
    assert offsets == sorted(offsets)
    assert max(offsets) == REFUSAL_DIRECTION_CONTROL_AGE_SECONDS


def test_the_manifest_declares_the_concurrent_acquisition_schedule() -> None:
    schedule = compile_campaign(NONCE)["agingSchedule"]
    assert schedule["mode"] == "concurrent-acquisition"
    assert schedule["acquireAtOriginSeconds"] == 0
    assert schedule["agedPendingSamplesSeconds"] == list(AGED_PENDING_SAMPLES)
    assert schedule["agedSessionSamplesSeconds"] == list(SAMPLED_AGES_SECONDS)
    scheduled = {row["case"] for row in schedule["dueOffsetsSeconds"]}
    assert scheduled == {
        case["id"] for case in observation_cases() if case["dueOffsetSeconds"]
    }


def test_an_already_refused_age_is_carried_as_a_refusal_direction_control() -> None:
    by_id = {case["id"]: case for case in observation_cases()}
    control = by_id[f"age-{REFUSAL_DIRECTION_CONTROL_AGE_SECONDS}s-start"]
    assert control["basis"] == "control"
    assert "refusal direction" in control["obligation"]
    assert REFUSAL_DIRECTION_CONTROL_AGE_SECONDS not in SAMPLED_AGES_SECONDS


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
        "campaign": compile_campaign(NONCE),
        "side": side,
        "recordingComplete": True,
        "productionExecuted": False,
        "provenance": compute_provenance(root or repository_root()),
        "worktree": {"commit": "a" * 40, "clean": True, "resolved": True},
        "runtimeIdentity": dict(RUNTIME_ANCHOR),
        "rows": [
            {"id": identifier, "status": 200, "errorCode": None, "outcome": "observed"}
            for identifier in CASE_IDS
        ],
        "recovery": {
            "cleanupVerified": True,
            "remainingOwnedResources": 0,
            "configurationRestored": True,
            "runId": RUNTIME_ANCHOR["runId"],
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
    approved(production)
    result = compare(local, production, runtime_anchor=dict(RUNTIME_ANCHOR))
    assert result["classification"] == "DIFF"
    assert [row["id"] for row in result["rowDifferences"]] == [CASE_IDS[2]]


def test_dynamic_and_secret_values_never_create_a_difference() -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    for index, record in enumerate((local, production)):
        record["rows"][1]["localId"] = f"uid-{index}"
        record["rows"][1]["mfaEnrollmentId"] = f"enrollment-{index}"
        record["rows"][1]["sharedSecretKey"] = f"SECRET_{index}"
        record["rows"][1]["verificationCode"] = f"{index}23456"
        record["rows"][1]["idToken"] = f"TOKEN_{index}"
        record["rows"][1]["pendingAgeSeconds"] = 300.0 + index
    result = compare(local, production, runtime_anchor=dict(RUNTIME_ANCHOR))
    assert result["classification"] == "EXPECTED_NONDETERMINISM"
    assert result["rowDifferences"] == []
    assert result["nondeterministicRows"] == [CASE_IDS[1]]
    serialized = json.dumps(result)
    for material in ("SECRET_0", "SECRET_1", "TOKEN_0", "TOKEN_1", "023456", "123456"):
        assert material not in serialized


def approved(record: dict) -> dict:
    """Attach owner approval bound to this receipt's own manifest and nonce."""
    campaign = record["campaign"]
    record["productionExecuted"] = True
    record["ownerApproval"] = {
        "approvedBy": "project owner",
        "manifestDigest": digest(campaign),
        "nonceDigest": campaign["owner"]["nonceDigest"],
        "grant": "one-run",
    }
    return record


def test_identical_executed_and_approved_receipts_reach_agreement() -> None:
    result = compare(
        receipt("local"),
        approved(receipt("production")),
        runtime_anchor=dict(RUNTIME_ANCHOR),
    )
    assert result["classification"] == "MATCH"
    assert result["rowDifferences"] == [] and result["nondeterministicRows"] == []


def test_asserting_production_execution_without_approval_is_indeterminate() -> None:
    production = receipt("production")
    production["productionExecuted"] = True
    result = compare(receipt("local"), production)
    assert result["classification"] == "INDETERMINATE"
    assert (
        "production execution is asserted without owner approval evidence"
        in result["productionProblems"]
    )


def test_an_approval_bound_to_another_manifest_or_nonce_cannot_reach_agreement() -> (
    None
):
    for mutation in (
        lambda approval, campaign: approval.update(manifestDigest="0" * 64),
        lambda approval, campaign: approval.update(nonceDigest="0" * 64),
        lambda approval, campaign: approval.update(grant="unlimited"),
        lambda approval, campaign: approval.update(approvedBy="  "),
    ):
        production = approved(receipt("production"))
        mutation(production["ownerApproval"], production["campaign"])
        assert (
            compare(receipt("local"), production)["classification"] == "INDETERMINATE"
        )


def test_a_receipt_without_a_recompilable_manifest_is_indeterminate() -> None:
    for mutation in (
        lambda record: record.pop("campaign"),
        lambda record: record.update(campaign={}),
        lambda record: record["campaign"]["limits"].update(maxRequests=10_000),
        lambda record: record["campaign"].update(productionAllowed=True),
    ):
        production = approved(receipt("production"))
        mutation(production)
        result = compare(receipt("local"), production)
        assert result["classification"] == "INDETERMINATE"


def test_two_sides_that_ran_different_manifests_cannot_be_compared() -> None:
    production = approved(receipt("production"))
    production["campaign"] = compile_campaign("1" * 32)
    production["campaign"]["cases"][0]["obligation"] = "changed"
    result = compare(receipt("local"), production)
    assert result["classification"] == "INDETERMINATE"


def test_a_different_nonce_alone_does_not_block_a_comparison() -> None:
    # Each side owns its own accounts, so the per-run owner block legitimately differs.
    production = receipt("production")
    production["campaign"] = compile_campaign("1" * 32)
    production["rows"] = [
        {"id": case["id"], "status": 200, "errorCode": None, "outcome": "observed"}
        for case in production["campaign"]["cases"]
    ]
    approved(production)
    assert (
        compare(
            receipt("local"),
            production,
            runtime_anchor=dict(RUNTIME_ANCHOR),
        )["classification"]
        == "MATCH"
    )


def test_a_differing_error_code_alone_is_a_real_difference() -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    production["rows"][3].update(status=400, errorCode="SESSION_EXPIRED")
    local["rows"][3].update(status=400, errorCode="INVALID_SESSION_INFO")
    result = compare(local, production, runtime_anchor=dict(RUNTIME_ANCHOR))
    assert result["classification"] == "DIFF"
    assert result["rowDifferences"][0]["local"]["errorCode"] == "INVALID_SESSION_INFO"
    assert result["rowDifferences"][0]["production"]["errorCode"] == "SESSION_EXPIRED"


def test_a_differing_error_message_is_a_difference_not_nondeterminism() -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    for index, record in enumerate((local, production)):
        record["rows"][4]["message"] = f"prose variant {index}"
        record["rows"][4]["stage"] = f"stage-{index}"
        record["rows"][4]["usage"] = f"usage-{index}"
    result = compare(local, production, runtime_anchor=dict(RUNTIME_ANCHOR))
    assert result["classification"] == "DIFF"
    assert [row["id"] for row in result["rowDifferences"]] == [CASE_IDS[4]]


def test_the_declared_order_is_the_order_that_yields_second_factor_exists() -> None:
    """The factor-limit row only refuses while exactly one TOTP factor is enrolled."""
    order = list(CASE_IDS)
    limit = order.index("second-factor-limit")
    enrolled = order.index("totp-enroll-retry-same-session")
    readback = order.index("totp-enroll-factor-readback")
    withdrawn = order.index("totp-withdraw")
    assert enrolled < readback < limit < withdrawn
    by_id = {case["id"]: case for case in observation_cases()}
    assert by_id["second-factor-limit"]["expectedLocal"] == {
        "status": 400,
        "errorCode": "SECOND_FACTOR_EXISTS",
        "basis": "source-read",
    }
    assert by_id["second-factor-limit"]["account"] == by_id["totp-withdraw"]["account"]


def test_the_serial_cost_counts_each_aged_resource_once() -> None:
    from mfa_cases import TOTP_STEP_ROLLOVER_SECONDS

    # Three rows share one aged pending credential; the wait happens once, not three times.
    assert serial_aging_seconds() == (
        sum(AGED_PENDING_SAMPLES)
        + sum(SAMPLED_AGES_SECONDS)
        + TOTP_STEP_ROLLOVER_SECONDS
    )
    rows_with_offsets = [
        case["dueOffsetSeconds"]
        for case in observation_cases()
        if case["dueOffsetSeconds"]
    ]
    assert serial_aging_seconds() < sum(rows_with_offsets)


def test_the_refusal_direction_control_is_what_makes_the_budget_2700() -> None:
    from mfa_cases import TOTP_STEP_ROLLOVER_SECONDS

    limits = compile_campaign(NONCE)["limits"]
    without_control = max(SAMPLED_AGES_SECONDS) + TOTP_STEP_ROLLOVER_SECONDS
    assert without_control == 630
    assert limits["criticalPathSeconds"] == (
        REFUSAL_DIRECTION_CONTROL_AGE_SECONDS + TOTP_STEP_ROLLOVER_SECONDS
    )
    assert limits["criticalPathSeconds"] > without_control
