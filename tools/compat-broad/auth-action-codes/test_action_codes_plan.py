"""The frozen case matrix and campaign manifest of the OOB action-code lane."""

from __future__ import annotations

import copy
import json

import pytest
from action_codes_plan import (
    CAMPAIGN_ID,
    CONTRACT,
    NONCE_TEMPLATE,
    SECRET_FIELDS,
    STAGE_IDS,
    campaign_cases,
    campaign_manifest,
    compiled_methods,
    proposal,
    validate_proposal,
)

NONCE = "0123456789abcdef" * 2


def test_campaign_identity_matches_the_recorded_auth_backlog_entry() -> None:
    manifest = campaign_manifest(NONCE)
    assert (
        manifest["campaignId"] == CAMPAIGN_ID == "AUTH-ACTION-OOB-DELIVERY-BOUNDARY-01"
    )
    assert manifest["contract"] == CONTRACT == "auth-action-codes-v1"
    assert manifest["productionExecutable"] is False
    assert manifest["productionExecuted"] is False
    assert manifest["sourceBinding"] == {"commit": None, "artifactSha256": None}
    assert all(value is None for value in manifest["ownerInputs"].values())


def test_nonce_must_be_fresh_hexadecimal_and_names_every_owned_resource() -> None:
    with pytest.raises(ValueError, match="hexadecimal"):
        campaign_manifest("not-a-nonce")
    with pytest.raises(ValueError, match="hexadecimal"):
        campaign_manifest(NONCE.upper())
    manifest = campaign_manifest(NONCE)
    assert manifest["nonce"] == NONCE
    assert manifest["nonceStatus"] == "syntax-only; freshness and ownership unverified"
    for account in manifest["ownedAccounts"].values():
        assert NONCE in account["email"]
        assert account["email"].endswith("@example.invalid")
    # The template manifest keeps the placeholder instead of a usable namespace.
    assert campaign_manifest()["nonce"] == NONCE_TEMPLATE


def test_authorized_project_is_an_explicit_canonical_plan_input() -> None:
    authorized = campaign_manifest(NONCE, project="fireemu-authorized")
    assert authorized["localProject"] == "fireemu-authorized"
    assert authorized["permissionEnvelope"]["projectId"] == "fireemu-authorized"
    assert campaign_manifest(NONCE)["localProject"] == "demo-auth-action"
    assert authorized != campaign_manifest(NONCE)


@pytest.mark.parametrize("project", ["", "bad project", "../escape", 42])
def test_authorized_project_rejects_noncanonical_values(project) -> None:
    with pytest.raises(ValueError, match="project"):
        campaign_manifest(NONCE, project=project)


def test_every_stage_is_ordered_typed_and_bounded() -> None:
    manifest = campaign_manifest(NONCE)
    assert [stage["id"] for stage in manifest["stages"]] == list(STAGE_IDS)
    assert len(set(STAGE_IDS)) == len(STAGE_IDS)
    for stage in manifest["stages"]:
        assert stage["method"] == "POST"
        assert stage["basis"] in {"control", "diagnostic", "setup"}
        assert stage["routeClass"] in {"admin", "end-user"}
        assert stage["group"] in {
            "setup",
            "password-reset",
            "verify-email",
            "email-link",
            "deleted-user",
            "unknown-email",
        }
        assert stage["productionExpectation"] == "UNOBSERVED"
        assert isinstance(stage["expectedLocal"]["status"], int)
        assert stage["delivery"] in {
            "none",
            "suppressed-by-returnOobLink",
        }


def test_matrix_covers_the_declared_finite_conditions() -> None:
    manifest = campaign_manifest(NONCE)
    stages = {stage["id"]: stage for stage in manifest["stages"]}
    # Lookup before consumption, consumption, reuse, wrong code, deleted user,
    # password-change transition and refused password policy are all present.
    assert stages["reset-code-lookup"]["expectedLocal"]["status"] == 200
    assert stages["reset-consume"]["expectedLocal"]["status"] == 200
    assert stages["reset-reuse"]["expectedLocal"]["errorMessage"] == "INVALID_OOB_CODE"
    assert (
        stages["reset-wrong-code"]["expectedLocal"]["errorMessage"]
        == "INVALID_OOB_CODE"
    )
    assert stages["reset-weak-password"]["expectedLocal"]["status"] == 400
    assert stages["reset-weak-password-retry"]["expectedLocal"]["status"] == 200
    assert stages["reset-after-password-change"]["basis"] == "diagnostic"
    assert stages["reset-after-delete"]["group"] == "deleted-user"
    assert stages["verify-apply"]["group"] == "verify-email"
    assert stages["email-link-signin"]["group"] == "email-link"
    assert stages["link-generate-unknown-email"]["group"] == "unknown-email"
    controls = {
        stage["id"] for stage in manifest["stages"] if stage["basis"] == "control"
    }
    assert {
        "reset-wrong-code",
        "verify-wrong-code",
        "email-link-mismatched-email",
    } <= controls


def test_expiry_is_declared_unobserved_instead_of_waited_for() -> None:
    manifest = campaign_manifest(NONCE)
    assert "expiry" not in {stage["group"] for stage in manifest["stages"]}
    expiry = [
        row for row in manifest["unobservedConditions"] if row["id"] == "code-expiry"
    ]
    assert len(expiry) == 1
    assert expiry[0]["reason"].startswith("The published lifetime")
    assert (
        expiry[0]["wouldRequire"]
        == "an out-of-band wait outside this campaign envelope"
    )


def test_out_of_scope_cases_are_named_and_never_admitted() -> None:
    cases = campaign_cases()
    accepted = [case for case in cases if case.get("admission") == "accepted"]
    outside = [case for case in cases if case.get("admission") == "outside"]
    assert len(accepted) == 6
    assert {case["id"] for case in outside} >= {
        "action-code/expiry",
        "action-code/delivered-email",
        "action-code/tenant",
        "action-code/blocking-function",
        "action-code/continue-url-redirect",
        "action-code/sdk",
    }
    for case in outside:
        assert case["reason"]


def test_budget_is_bounded_and_far_below_one_dollar() -> None:
    manifest = campaign_manifest(NONCE)
    budget = manifest["budget"]
    assert budget["observationRequests"] == len(STAGE_IDS) + 2
    assert budget["recoveryRequests"] == len(manifest["recovery"])
    assert budget["maxConcurrency"] == 1
    assert budget["requestRatePerSecondMax"] == 4
    assert budget["requestRateEnforced"] is True
    assert budget["planningCeilingUsd"] <= 0.05
    assert budget["expectedMeteredUsd"] == 0.0
    assert budget["deliveredMessages"] == 0
    assert budget["wallSeconds"] <= 300
    assert budget["recoverySeconds"] <= 180


def test_recovery_proves_absence_by_address_not_by_runtime_identifier() -> None:
    manifest = campaign_manifest(NONCE)
    owned = set(manifest["ownedAccounts"])
    rows = {row["id"]: row for row in manifest["recovery"]}
    assert list(rows) == [
        "recover-discover",
        "recover-delete-accountA",
        "recover-delete-accountB",
        "recover-uid-absence-accountA",
        "recover-uid-absence-accountB",
        "recover-absence",
    ]
    # Email discovery is batched, but only an immutable create UID authorizes a
    # delete or UID absence proof.
    for identifier in ("recover-discover", "recover-absence"):
        row = rows[identifier]
        assert row["operationType"] == "auth-lookup"
        assert row["selector"] == "email"
        assert row["body"]["email"] == [
            "$binding:" + name + ".email" for name in sorted(owned)
        ]
    assert {rows["recover-delete-" + name]["account"] for name in owned} == owned
    assert {rows["recover-uid-absence-" + name]["account"] for name in owned} == owned
    assert all(row["routeClass"] == "admin" for row in manifest["recovery"])


def test_recovery_budget_is_the_frozen_observation_plus_six_rows() -> None:
    manifest = campaign_manifest(NONCE)
    assert len(manifest["stages"]) + len(manifest["recovery"]) == 32
    assert manifest["budget"]["observationRequests"] == 28
    assert manifest["budget"]["recoveryRequests"] == 6
    rows = {row["id"]: row for row in manifest["recovery"]}
    for name in ("accountA", "accountB"):
        assert rows["recover-uid-absence-" + name]["selector"] == "localId"
        assert rows["recover-uid-absence-" + name]["body"] == {
            "localId": "$binding:" + name + ".localId"
        }


def test_the_permission_envelope_names_a_least_privilege_role() -> None:
    manifest = campaign_manifest(NONCE)
    permission = manifest["permissionEnvelope"]
    assert permission["role"] == "roles/firebaseauth.admin"
    assert permission["scope"] == "https://www.googleapis.com/auth/identitytoolkit"
    assert permission["projectScope"] == "the single approved project"
    assert any("cloud-platform" in row for row in permission["notRequired"])
    assert permission["methods"] == [
        "accounts:" + method for method in compiled_methods(NONCE)
    ]
    assert manifest["ownerInputs"]["credentialRole"] is None


def test_the_reserved_address_domain_is_a_stated_owner_assumption() -> None:
    manifest = campaign_manifest(NONCE)
    assumption = [
        row for row in manifest["ownerPreconditions"] if "example.invalid" in row
    ]
    assert len(assumption) == 1
    assert "fail" in assumption[0].lower()


def test_no_stage_body_or_manifest_text_carries_a_secret_value() -> None:
    manifest = campaign_manifest(NONCE)
    serialized = json.dumps(manifest)
    for field in SECRET_FIELDS:
        assert '"' + field + '": "' not in serialized.replace(
            '"' + field + '": "$binding:', '"redacted-binding": "'
        )
    for stage in manifest["stages"]:
        for key, value in stage["body"].items():
            if key in SECRET_FIELDS:
                assert value.startswith("$binding:")


def test_proposal_is_frozen_against_drift_and_owner_inputs() -> None:
    assert validate_proposal(proposal()) is True
    changed = copy.deepcopy(proposal())
    changed["planTemplate"]["ownerInputs"]["owner"] = "someone"
    with pytest.raises(ValueError, match="drift or owner inputs"):
        validate_proposal(changed)
    changed = copy.deepcopy(proposal())
    changed["planTemplate"]["productionExecutable"] = True
    with pytest.raises(ValueError):
        validate_proposal(changed)
