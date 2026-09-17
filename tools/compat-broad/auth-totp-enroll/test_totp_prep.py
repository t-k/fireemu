from __future__ import annotations

import copy

import pytest
from totp_comparator import compare
from totp_plan import campaign_manifest
from totp_shadow import TotpShadow


def test_manifest_is_bounded_and_fail_closed() -> None:
    manifest = campaign_manifest("a" * 32)

    assert manifest["campaignId"] == "AUTH-MFA-TOTP-ENROLL-RETRY-01"
    assert manifest["status"] == "PREPARED_NOT_READY"
    assert manifest["productionExecuted"] is False
    assert manifest["gate"]["productionAuthorization"] is False
    assert manifest["limits"] == {"maxRequests": 15, "maxWallSeconds": 600, "maxCostUsd": 2.0}
    assert manifest["nonce"] == "a" * 32
    assert len(manifest["operations"]) == 15
    assert all(operation["origin"] == "loopback-only" for operation in manifest["operations"])


def test_wrong_otp_keeps_pending_enrollment_for_correct_retry_and_replay_fails() -> None:
    shadow = TotpShadow("user-1", secret="JBSWY3DPEHPK3PXP", now=1_700_000_000)

    start = shadow.start(email_verified=True)
    wrong = shadow.finalize(start["sessionId"], "000000")
    correct = shadow.current_code(start["sessionId"])
    success = shadow.finalize(start["sessionId"], correct)
    replay = shadow.finalize(start["sessionId"], correct)

    assert wrong == {"status": 400, "error": {"code": "INVALID_TOTP"}}
    assert success["status"] == 200
    assert success["enrollment"]["id"]
    assert replay == {"status": 400, "error": {"code": "SESSION_ALREADY_FINALIZED"}}
    assert shadow.state() == {"pendingSessions": 0, "enrollments": 1, "codeConsumptions": 1, "events": 2}


def test_unverified_email_and_wrong_namespace_do_not_create_state() -> None:
    shadow = TotpShadow("user-1", secret="JBSWY3DPEHPK3PXP", now=1_700_000_000)

    assert shadow.start(email_verified=False) == {
        "status": 400,
        "error": {"code": "EMAIL_NOT_VERIFIED"},
    }
    assert shadow.start(email_verified=True, tenant="other") == {
        "status": 400,
        "error": {"code": "TENANT_MISMATCH"},
    }
    assert shadow.state() == {"pendingSessions": 0, "enrollments": 0, "codeConsumptions": 0, "events": 0}


def test_comparator_redacts_secret_otp_and_tokens_and_keeps_failures_distinct() -> None:
    left = {
        "recordingComplete": True,
        "cleanupComplete": True,
        "rows": [{"stage": "start", "status": 200, "body": {"secret": "abc", "idToken": "token"}}],
    }
    right = copy.deepcopy(left)
    right["rows"][0]["body"] = {"secret": "xyz", "idToken": "other"}
    assert compare(left, right)["classification"] == "MATCH"

    right["rows"][0]["status"] = 401
    assert compare(left, right)["classification"] == "DIFF"
    right = copy.deepcopy(left)
    right["cleanupComplete"] = False
    assert compare(left, right)["classification"] == "CLEANUP_DIFF"
    right = copy.deepcopy(left)
    right["recordingComplete"] = False
    assert compare(left, right)["classification"] == "INCONCLUSIVE"


def test_plan_rejects_reused_or_unbounded_nonce() -> None:
    with pytest.raises(ValueError, match="fresh hexadecimal"):
        campaign_manifest("old")
