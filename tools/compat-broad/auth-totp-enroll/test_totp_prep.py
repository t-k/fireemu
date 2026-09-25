from __future__ import annotations

import copy
import json

import pytest
from totp_comparator import compare
from totp_plan import CAMPAIGN_ID, STAGE_IDS, campaign_manifest


def receipt(side: str) -> dict:
    return {
        "caseId": CAMPAIGN_ID,
        "side": side,
        "sourceBinding": {"commit": "a" * 40, "artifactSha256": "b" * 64},
        "recordingComplete": True,
        "stages": [
            {
                "id": stage,
                "response": {
                    "status": 400 if stage == "wrong-code" else 200,
                    "errorCode": "INVALID_TOTP" if stage == "wrong-code" else None,
                },
            }
            for stage in STAGE_IDS
        ],
        "state": {
            "afterWrong": {"pendingSession": True, "factorCount": 0},
            "afterSuccess": {"pendingSession": False, "factorCount": 1},
        },
        "recovery": {
            "ownerVerified": True,
            "cleanupVerified": True,
            "remainingAccounts": 0,
        },
    }


def test_manifest_is_only_unbound_logical_preparation() -> None:
    manifest = campaign_manifest("a" * 32)
    assert manifest["status"] == "PREPARATION"
    assert manifest["productionExecuted"] is False
    assert manifest["productionAllowed"] is False
    assert manifest["sourceBinding"] == {"commit": None, "artifactSha256": None}
    assert manifest["limits"]["enforced"] is False
    assert (
        manifest["uniqueObligation"]
        == "same TOTP session after wrong-code retry and after successful replay, with account and factor readback"
    )
    assert len(manifest["existingControls"]) == 3
    assert [stage["id"] for stage in manifest["stages"]] == list(STAGE_IDS)
    assert all(
        not ({"method", "path", "body", "cleanupComplete", "ownedOnly"} & set(stage))
        for stage in manifest["stages"]
    )
    assert "operations" not in manifest


def test_nonce_syntax_is_not_freshness_or_binding() -> None:
    with pytest.raises(ValueError, match="hexadecimal nonce"):
        campaign_manifest("old")
    first = campaign_manifest("a" * 32)
    second = campaign_manifest("a" * 32)
    assert first == second
    assert first["nonceStatus"] == "syntax-only; freshness and ownership unverified"


def test_identical_or_incomplete_receipts_fail_closed() -> None:
    local = receipt("local")
    assert compare(local, local)["classification"] == "INDETERMINATE"
    assert compare(local, receipt("production"))["classification"] == "INDETERMINATE"
    for mutation in (
        lambda x: x.pop("sourceBinding"),
        lambda x: x.update(recordingComplete=False),
        lambda x: x["stages"].pop(),
        lambda x: x["stages"].append(copy.deepcopy(x["stages"][-1])),
        lambda x: x.update(side="local"),
    ):
        production = receipt("production")
        mutation(production)
        assert compare(local, production)["classification"] == "INDETERMINATE"


def test_observed_differences_never_become_agreement() -> None:
    local = receipt("local")
    for mutation in (
        lambda x: x["stages"][2]["response"].update(status=401),
        lambda x: x["state"]["afterWrong"].update(pendingSession=False),
        lambda x: x["state"]["afterSuccess"].update(factorCount=2),
    ):
        production = receipt("production")
        mutation(production)
        assert compare(local, production)["classification"] == "INDETERMINATE"
    production = receipt("production")
    production["recovery"]["remainingAccounts"] = 1
    assert compare(local, production)["receiptStatus"] == "INCOMPLETE"
    production = receipt("production")
    production["recovery"]["cleanupVerified"] = False
    assert compare(local, production)["classification"] == "INDETERMINATE"


def test_serialized_outputs_do_not_contain_secret_material() -> None:
    local = receipt("local")
    production = receipt("production")
    for record in (local, production):
        record["stages"][1]["response"]["totpSecret"] = "RAW_SECRET_123"
        record["stages"][1]["response"]["otp"] = "123456"
        record["stages"][1]["response"]["password"] = "RAW_PASSWORD_123"
        record["stages"][1]["response"]["idToken"] = "RAW_TOKEN_123"
        record["stages"][1]["response"]["refreshToken"] = "RAW_REFRESH_123"
        record["stages"][1]["response"]["sessionInfo"] = "RAW_SESSION_123"
    result = json.dumps(compare(local, production))
    manifest = json.dumps(campaign_manifest("a" * 32))
    for material in (
        "RAW_SECRET_123",
        "123456",
        "RAW_PASSWORD_123",
        "RAW_TOKEN_123",
        "RAW_REFRESH_123",
        "RAW_SESSION_123",
    ):
        assert material not in result + manifest
    assert compare(local, production)["classification"] == "INDETERMINATE"


def test_secret_only_difference_is_not_semantic_mismatch() -> None:
    local, production = receipt("local"), receipt("production")
    local["stages"][1]["response"]["totpSecret"] = "SECRET_ONE"
    production["stages"][1]["response"]["totpSecret"] = "SECRET_TWO"
    assert compare(local, production)["classification"] == "INDETERMINATE"


def test_boolean_status_and_cleanup_count_are_not_typed_receipts() -> None:
    local, production = receipt("local"), receipt("production")
    production["stages"][1]["response"]["status"] = True
    production["state"]["afterSuccess"]["factorCount"] = 2
    assert compare(local, production)["receiptStatus"] == "INCOMPLETE"
    production = receipt("production")
    production["recovery"]["remainingAccounts"] = False
    production["state"]["afterSuccess"]["factorCount"] = 2
    assert compare(local, production)["receiptStatus"] == "INCOMPLETE"


def test_forged_source_binding_cannot_enable_semantic_comparison() -> None:
    local, production = receipt("local"), receipt("production")
    for record in (local, production):
        record["sourceBinding"] = {"commit": "x" * 40, "artifactSha256": "x" * 64}
    production["state"]["afterSuccess"]["factorCount"] = 2
    assert compare(local, production)["classification"] == "INDETERMINATE"
