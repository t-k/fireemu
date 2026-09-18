"""The comparator contract: what may be compared, and what may never agree."""

from __future__ import annotations

import copy

import pytest
from action_codes_comparator import INFORMATIONAL_FIELDS, SEMANTIC_FIELDS, compare
from action_codes_plan import (
    CAMPAIGN_ID,
    CONTRACT,
    STAGE_IDS,
    campaign_manifest,
    manifest_digest,
)

NONCE = "abcdef0123456789" * 2
DIGEST = manifest_digest(campaign_manifest(NONCE))


def receipt(side: str) -> dict:
    return {
        "contract": CONTRACT,
        "campaignId": CAMPAIGN_ID,
        "side": side,
        "nonce": NONCE,
        "manifestDigest": DIGEST,
        "sourceBinding": {"commit": "a" * 40, "artifactSha256": "b" * 64},
        "permissionReference": None
        if side == "local"
        else "owner-permission-2026-09-18",
        "recordingComplete": True,
        "cleanupComplete": True,
        "remainingAccounts": 0,
        "deleteFailures": 0,
        "productionExecuted": side == "production",
        "stages": [
            {
                "id": stage,
                "status": 200,
                "keys": ["email", "kind"],
                "errorCode": None,
                "errorMessage": None,
            }
            for stage in STAGE_IDS
        ],
    }


def pair(**production_changes) -> dict:
    local = receipt("local")
    production = receipt("production")
    for key, value in production_changes.items():
        production[key] = value
    return compare(local, production)


def test_a_bound_complete_pair_that_agrees_is_a_match() -> None:
    result = pair()
    assert result["classification"] == "MATCH"
    assert result["productionCompared"] is True
    assert result["comparedStages"] == len(STAGE_IDS)
    assert result["differingStages"] == []


def test_a_typed_difference_is_a_semantic_mismatch_not_an_agreement() -> None:
    production = receipt("production")
    production["stages"][7]["status"] = 400
    production["stages"][7]["errorCode"] = "EXPIRED_OOB_CODE"
    result = compare(receipt("local"), production)
    assert result["classification"] == "SEMANTIC_MISMATCH"
    assert result["differingStages"] == [STAGE_IDS[7]]
    difference = result["stages"][7]["differences"]
    assert difference["status"] == {"local": 200, "production": 400}
    assert difference["errorCode"] == {"local": None, "production": "EXPIRED_OOB_CODE"}


def test_field_presence_differences_are_semantic() -> None:
    production = receipt("production")
    production["stages"][0]["keys"] = ["email", "kind", "mfaInfo"]
    result = compare(receipt("local"), production)
    assert result["classification"] == "SEMANTIC_MISMATCH"
    assert "keys" in result["stages"][0]["differences"]


def test_message_prose_and_code_length_stay_visible_without_forcing_a_verdict() -> None:
    production = receipt("production")
    production["stages"][3]["errorMessage"] = "The action code is invalid."
    production["stages"][2]["oobCodeLength"] = 54
    local = receipt("local")
    local["stages"][2]["oobCodeLength"] = 24
    result = compare(local, production)
    assert result["classification"] == "MATCH"
    assert result["stages"][3]["informational"]["errorMessage"] == {
        "local": None,
        "production": "The action code is invalid.",
    }
    assert result["stages"][2]["informational"]["oobCodeLength"] == {
        "local": 24,
        "production": 54,
    }
    assert set(SEMANTIC_FIELDS) & set(INFORMATIONAL_FIELDS) == set()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("recordingComplete", False),
        ("cleanupComplete", False),
        ("remainingAccounts", 1),
        ("deleteFailures", 1),
        ("manifestDigest", "c" * 64),
        ("campaignId", "AUTH-OTHER-01"),
        ("contract", "auth-action-codes-v0"),
        ("side", "local"),
        ("permissionReference", None),
        ("stages", []),
    ],
)
def test_an_incomplete_or_unbound_production_receipt_is_indeterminate(
    field, value
) -> None:
    result = pair(**{field: value})
    assert result["classification"] == "INDETERMINATE"
    assert result["productionCompared"] is False
    assert result["reason"]


def test_an_unbound_local_source_cannot_be_compared() -> None:
    local = receipt("local")
    local["sourceBinding"] = {"commit": None, "artifactSha256": None}
    result = compare(local, receipt("production"))
    assert result["classification"] == "INDETERMINATE"
    assert result["reason"] == "local source binding is incomplete"


def test_a_preparation_receipt_from_this_package_is_never_promoted() -> None:
    from action_codes_collector import collect

    class Empty:
        def send(self, method, url, headers, body):
            return 200, {"kind": "identitytoolkit#Response"}

    local = collect(
        origin="http://127.0.0.1:9099",
        project="demo-auth-action",
        nonce=NONCE,
        send=Empty().send,
    )
    result = compare(local, copy.deepcopy(local))
    assert result["classification"] == "INDETERMINATE"
    assert result["productionCompared"] is False


def test_the_same_object_on_both_sides_is_never_a_match() -> None:
    shared = receipt("local")
    assert compare(shared, shared)["classification"] == "INDETERMINATE"


def test_stage_order_and_membership_must_agree_before_any_verdict() -> None:
    production = receipt("production")
    production["stages"] = list(reversed(production["stages"]))
    assert compare(receipt("local"), production)["classification"] == "INDETERMINATE"
    production = receipt("production")
    production["stages"].pop()
    assert compare(receipt("local"), production)["classification"] == "INDETERMINATE"


def test_a_receipt_carrying_a_secret_key_is_refused_outright() -> None:
    production = receipt("production")
    production["stages"][0]["oobCode"] = "leaked-code"
    result = compare(receipt("local"), production)
    assert result["classification"] == "INDETERMINATE"
    assert result["reason"] == "receipt carries a secret field"
    assert "leaked-code" not in str(result)
