"""Contract tests for the inert AUTH-CREDENTIAL campaign manifest."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from credential_cases import observation_cases
from credential_collector import BOUND_MODULES
from credential_plan import (
    BUDGET,
    FROZEN_MODULES,
    PERMISSION_ENVELOPE,
    STATUS,
    campaign_manifest,
    cases_digest,
    validate_permission,
)

NONCE = "0" * 32


def test_manifest_is_inert_and_unbound() -> None:
    manifest = campaign_manifest(NONCE)
    assert manifest["status"] == STATUS == "PREPARATION"
    assert manifest["productionExecuted"] is False
    assert manifest["productionAllowed"] is False
    assert manifest["sourceBinding"] == {"commit": None, "artifactSha256": None}
    assert manifest["nonceStatus"].startswith("syntax-only")
    assert (
        "Production-unobserved conditions reduced by this package: 0."
        in manifest["unresolved"]
    )


def test_manifest_carries_no_request_plan_or_credential() -> None:
    serialized = json.dumps(campaign_manifest(NONCE))
    for forbidden in ("googleapis.com", "Bearer", "AIza", "fireemu-35fe6", "127.0.0.1"):
        assert forbidden not in serialized
    assert "operations" not in campaign_manifest(NONCE)


def test_nonce_syntax_is_neither_freshness_nor_permission() -> None:
    with pytest.raises(ValueError, match="hexadecimal"):
        campaign_manifest("not-a-nonce")
    assert campaign_manifest(NONCE) == campaign_manifest(NONCE)


def test_budget_is_enforced_and_well_under_one_dollar() -> None:
    manifest = campaign_manifest(NONCE)
    assert manifest["budget"] == BUDGET
    assert BUDGET["enforced"] is True
    assert 0 < BUDGET["maxCostUsd"] <= 0.05
    assert manifest["costBasis"]


def test_frozen_inputs_cover_every_module_and_change_with_the_cases() -> None:
    manifest = campaign_manifest(NONCE)
    assert set(manifest["frozenInputs"]["modules"]) == set(FROZEN_MODULES)
    assert "ABSENT" not in manifest["frozenInputs"]["modules"].values()
    assert manifest["frozenInputs"]["casesSha256"] == cases_digest()
    assert len(cases_digest()) == 64
    assert manifest["caseCount"] == len(observation_cases())


def test_owner_preconditions_name_the_custom_token_signing_blocker() -> None:
    preconditions = " ".join(campaign_manifest(NONCE)["ownerPreconditions"])
    assert "custom tokens" in preconditions
    assert "unsigned" in preconditions
    assert "nonce" in preconditions


def test_cleanup_contract_requires_a_readback_and_cannot_be_downgraded() -> None:
    contract = " ".join(campaign_manifest(NONCE)["cleanupContract"])
    assert "readback" in contract or "reads back" in contract
    assert "warning" in contract


def test_failure_rehearsal_covers_the_unpinnable_boundary() -> None:
    rehearsal = campaign_manifest(NONCE)["failureRehearsal"]
    ids = [line.split(":", 1)[0] for line in rehearsal]
    assert set(ids) == {
        "budget-exhausted",
        "privileged-call-refused",
        "cleanup-refused",
        "process-killed",
        "boundary-unpinned",
        "deadline-exceeded",
        "boundary-control-unrelated",
    }
    assert any("EXPECTED_NONDETERMINISM" in line for line in rehearsal)


def test_this_package_grants_no_permission() -> None:
    assert PERMISSION_ENVELOPE["grantedHere"] is False
    manifest = campaign_manifest(NONCE)
    assert manifest["permissionEnvelope"]["grantedHere"] is False
    # The manifest itself is not an acceptable permission.
    assert validate_permission(manifest, manifest)


def test_permission_shape_check_rejects_an_incomplete_grant() -> None:
    manifest = campaign_manifest(NONCE)
    assert validate_permission(None, manifest) == ["permission must be an object"]
    assert "kind must be owner-execution-permission" in validate_permission(
        {}, manifest
    )
    grant = {field: "supplied" for field in PERMISSION_ENVELOPE["requiredFields"]}
    grant["kind"] = PERMISSION_ENVELOPE["kind"]
    grant["campaignId"] = manifest["campaignId"]
    grant["nonce"] = "1" * 32
    assert validate_permission(grant, manifest) == []
    grant["nonce"] = NONCE
    assert validate_permission(grant, manifest) == [
        "permission may not reuse the manifest nonce"
    ]


def test_a_well_formed_permission_is_still_not_production_execution() -> None:
    manifest = campaign_manifest(NONCE)
    grant = {field: "supplied" for field in PERMISSION_ENVELOPE["requiredFields"]}
    grant.update(
        kind=PERMISSION_ENVELOPE["kind"],
        campaignId=manifest["campaignId"],
        nonce="2" * 32,
    )
    assert validate_permission(grant, manifest) == []
    assert campaign_manifest(NONCE)["productionExecuted"] is False


def test_the_manifest_and_the_collector_bind_the_same_modules() -> None:
    # Two lists that must agree would drift; the manifest reuses the collector's.
    assert FROZEN_MODULES is BOUND_MODULES
    assert set(campaign_manifest(NONCE)["frozenInputs"]["modules"]) == set(
        BOUND_MODULES
    )
