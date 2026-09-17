from __future__ import annotations

import copy
import json

import pytest
from totp_comparator import compare
from totp_plan import campaign_manifest
from totp_shadow import TotpShadow, run


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
    start = next(operation for operation in manifest["operations"] if operation["stage"] == "C1-start")
    finalize = next(operation for operation in manifest["operations"] if operation["stage"] == "C3-correct-code")
    assert start["path"] == "/v2/accounts/mfaEnrollment:start"
    assert start["body"] == {"idToken": "$owned:idToken", "totpEnrollmentInfo": {}}
    assert finalize["path"] == "/v2/accounts/mfaEnrollment:finalize"
    assert finalize["body"] == {
        "idToken": "$owned:idToken",
        "totpVerificationInfo": {
            "sessionInfo": "$owned:sessionInfo",
            "verificationCode": "$classified:correct",
            "displayName": "O2 TOTP",
        },
    }
    assert all("{freshNonce}" not in repr(operation) for operation in manifest["operations"])


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


def test_malformed_otp_is_typed_refusal_and_pending_state_is_retained() -> None:
    shadow = TotpShadow("user-1", secret="JBSWY3DPEHPK3PXP", now=1_700_000_000)
    start = shadow.start(email_verified=True)

    assert shadow.finalize(start["sessionId"], "12") == {
        "status": 400,
        "error": {"code": "INVALID_TOTP_FORMAT"},
    }
    assert shadow.state()["pendingSessions"] == 1


def test_comparator_redacts_secret_otp_and_tokens_and_keeps_failures_distinct() -> None:
    left = {
        "recordingComplete": True,
        "cleanupComplete": True,
        "rows": [{"stage": "start", "status": 200, "body": {"secret": "abc", "idToken": "token"}}],
    }
    right = copy.deepcopy(left)
    right["rows"][0]["body"] = {"secret": "xyz", "idToken": "other"}
    assert compare(left, right)["classification"] == "EXPECTED_NONDETERMINISM"

    right["rows"][0]["status"] = 401
    assert compare(left, right)["classification"] == "SEMANTIC_MISMATCH"
    right = copy.deepcopy(left)
    right["cleanupComplete"] = False
    assert compare(left, right)["classification"] == "INDETERMINATE"
    right = copy.deepcopy(left)
    right["recordingComplete"] = False
    assert compare(left, right)["classification"] == "INCONCLUSIVE"


def test_comparator_never_matches_missing_rows_or_incomplete_cleanup() -> None:
    base = {"recordingComplete": True, "cleanupComplete": True, "rows": [{"status": 200}]}
    assert compare(base, {**base, "rows": []})["classification"] == "SEMANTIC_MISMATCH"
    assert compare(base, {**base, "cleanupComplete": False})["classification"] == "INDETERMINATE"


def test_session_ids_remain_unique_after_a_session_is_consumed() -> None:
    shadow = TotpShadow("user-1", secret="JBSWY3DPEHPK3PXP", now=1_700_000_000)
    first = shadow.start(email_verified=True)
    shadow.finalize(first["sessionId"], shadow.current_code(first["sessionId"]))
    second = shadow.start(email_verified=True)
    assert second["sessionId"] != first["sessionId"]


def test_shadow_writes_owned_recovery_receipt_and_readback(tmp_path) -> None:
    output = tmp_path / "shadow"
    result = run(output, nonce="c" * 32)

    receipt = json.loads((output / "recovery-receipt.json").read_text())
    assert result["cleanupComplete"] is True
    assert receipt == {
        "complete": True,
        "owner": "uid-" + "c" * 32,
        "deleted": True,
        "remainingState": {"pendingSessions": 0, "enrollments": 0, "codeConsumptions": 1, "events": 2},
    }


def test_plan_rejects_reused_or_unbounded_nonce() -> None:
    with pytest.raises(ValueError, match="fresh hexadecimal"):
        campaign_manifest("old")
