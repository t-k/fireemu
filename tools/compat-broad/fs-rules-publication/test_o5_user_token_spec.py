from __future__ import annotations

import json
from pathlib import Path

from o5_user_token_campaign import OWNER_PRECONDITIONS, PERMISSION_ENVELOPE, budget
from o5_user_token_case import CAMPAIGN, compile_case

SPEC = (
    Path(__file__).resolve().parents[3]
    / "spec"
    / "compatibility"
    / "fs-rules-user-token-matrix.json"
)

TEMPLATE_PROJECT = "template-project"
TEMPLATE_NONCE = "0" * 32


def spec() -> dict:
    return json.loads(SPEC.read_text())


def test_the_checked_in_matrix_is_the_compiled_matrix() -> None:
    plan = compile_case(TEMPLATE_PROJECT, "(default)", TEMPLATE_NONCE)
    assert spec()["observationCase"] == plan


def test_the_checked_in_budget_and_envelope_match_the_campaign_module() -> None:
    document = spec()
    plan = compile_case(TEMPLATE_PROJECT, "(default)", TEMPLATE_NONCE)
    assert document["budget"] == budget(plan)
    assert document["permissionEnvelope"] == PERMISSION_ENVELOPE
    assert document["ownerPreconditions"] == list(OWNER_PRECONDITIONS)


def test_the_checked_in_matrix_claims_no_production_evidence() -> None:
    document = spec()
    assert document["campaignId"] == CAMPAIGN
    assert document["status"] == "PREPARATION_ONLY"
    assert document["productionExecuted"] is False
    assert document["productionReady"] is False


def test_the_checked_in_identities_are_placeholders() -> None:
    case = spec()["observationCase"]
    assert case["project"] == TEMPLATE_PROJECT
    assert case["nonce"] == TEMPLATE_NONCE
