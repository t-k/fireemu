"""Contract tests for the bounded, credential-safe collector support library."""

from __future__ import annotations

import ast
import base64
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import credential_collector as collector
from credential_cases import observation_cases

SECRET = "eyJzZWNyZXQiOiJyYXctdG9rZW4ifQ.RAW_TOKEN_MATERIAL.sig"


def _jwt(payload: dict, alg: str = "none") -> str:
    def segment(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    signature = "" if alg == "none" else "c2lnbmF0dXJl"
    return f"{segment({'alg': alg, 'typ': 'JWT'})}.{segment(payload)}.{signature}"


# --- transport ---------------------------------------------------------------


def test_collector_carries_no_network_transport() -> None:
    tree = ast.parse((HERE / "credential_collector.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (
        imported & {"urllib", "http", "requests", "socket", "ssl", "subprocess", "os"}
    )
    assert collector.PERFORMS_REQUESTS is False


# --- redaction ---------------------------------------------------------------


def test_publishable_projection_drops_every_secret_value_and_digest() -> None:
    record = {
        "idToken": SECRET,
        "refreshToken": SECRET,
        "sessionCookie": SECRET,
        "customToken": SECRET,
        "password": "hunter22",
        "authorization": "Bearer owner",
        "apiKey": "AIzaRAW",
        "status": 200,
        "nested": {"access_token": SECRET, "expires_in": "3600"},
        "list": [{"id_token": SECRET}],
    }
    published = collector.publishable(record)
    serialized = json.dumps(published)
    for material in ("RAW_TOKEN_MATERIAL", "hunter22", "Bearer owner", "AIzaRAW"):
        assert material not in serialized
    assert published["idToken"] == {"present": True, "type": "string"}
    assert published["nested"]["access_token"] == {"present": True, "type": "string"}
    assert published["list"][0]["id_token"] == {"present": True, "type": "string"}
    assert published["status"] == 200
    assert published["nested"]["expires_in"] == "3600"
    # A digest of a secret is still derived from it and is never published.
    assert "sha256" not in serialized


def test_a_boolean_or_number_under_a_secret_key_is_kept_because_it_cannot_be_a_token() -> (
    None
):
    # A masked boolean would make a failed assertion indistinguishable from a held one.
    published = collector.publishable(
        {
            "idTokenReturned": False,
            "refreshTokenReturned": True,
            "tokenCount": 2,
            "idToken": SECRET,
        }
    )
    assert published["idTokenReturned"] is False
    assert published["refreshTokenReturned"] is True
    assert published["tokenCount"] == 2
    assert published["idToken"] == {"present": True, "type": "string"}


def test_a_member_that_merely_contains_a_secret_fragment_survives() -> None:
    # "assertions" contains "assertion" but holds the case's own boolean results.
    record = {"assertions": {"authTimePreserved": True}, "assertion": "RAW_SAML_BLOB"}
    published = collector.publishable(record)
    assert published["assertions"] == {"authTimePreserved": True}
    assert published["assertion"] == {"present": True, "type": "string"}
    assert "RAW_SAML_BLOB" not in json.dumps(published)


def test_absent_and_null_secrets_are_distinguishable_from_present_ones() -> None:
    assert collector.publishable({"idToken": None})["idToken"] == {
        "present": False,
        "type": "null",
    }
    assert "refreshToken" not in collector.publishable({"idToken": None})


def test_secret_digest_is_available_for_the_private_receipt_only() -> None:
    digest = collector.secret_digest(SECRET)
    assert len(digest) == 64 and digest == collector.secret_digest(SECRET)
    assert digest != collector.secret_digest(SECRET + "x")
    with pytest.raises(ValueError, match="non-empty"):
        collector.secret_digest("")


def test_argv_and_log_guards_refuse_secret_material() -> None:
    with pytest.raises(collector.SecretLeak):
        collector.assert_no_secret(["--token", SECRET], [SECRET])
    with pytest.raises(collector.SecretLeak):
        collector.assert_no_secret("starting with idToken=" + SECRET, [SECRET])
    collector.assert_no_secret(["--case", "refresh-preserves-auth-time"], [SECRET])
    assert collector.safe_log("sent " + SECRET, [SECRET]) == "sent [REDACTED]"


# --- claim shapes ------------------------------------------------------------


def test_claim_shape_reports_names_types_and_the_trust_root() -> None:
    token = _jwt(
        {"sub": "uid-1", "auth_time": 100, "iat": 100, "exp": 3700, "role": "tester"}
    )
    shape = collector.claim_shape(token)
    assert shape["trustRoot"] == "unsigned-emulator"
    assert shape["claimTypes"] == {
        "auth_time": "int",
        "exp": "int",
        "iat": "int",
        "role": "string",
        "sub": "string",
    }
    assert shape["times"] == {"auth_time": 100, "exp": 3700, "iat": 100}
    assert shape["issuer"] is None
    assert "token" not in shape and SECRET not in json.dumps(shape)


def test_signed_production_token_is_recorded_as_a_different_trust_root() -> None:
    token = _jwt(
        {"sub": "uid-1", "iat": 1, "iss": "https://securetoken.google.com/p"},
        alg="RS256",
    )
    shape = collector.claim_shape(token)
    assert shape["trustRoot"] == "signed"
    assert shape["issuer"] == "https://securetoken.google.com/p"
    # Signature bytes never reach the record.
    assert "c2lnbmF0dXJl" not in json.dumps(shape)


def test_claim_shape_never_publishes_a_string_claim_value_it_was_not_told_to() -> None:
    token = _jwt(
        {"sub": "uid-1", "iat": 1, "email": "probe@example.com", "role": "tester"}
    )
    shape = collector.claim_shape(token)
    assert "probe@example.com" not in json.dumps(shape)
    assert collector.claim_shape(token, reveal=("role",))["claimValues"] == {
        "role": "tester"
    }
    with pytest.raises(ValueError, match="reveal"):
        collector.claim_shape(token, reveal=("email",))


def test_malformed_token_fails_closed() -> None:
    for bad in ("", "not-a-jwt", "a.b", "a." + "!" * 5 + ".c"):
        with pytest.raises(ValueError):
            collector.claim_shape(bad)


# --- owned resources and cleanup ---------------------------------------------


def test_owned_identifiers_carry_the_run_nonce_prefix() -> None:
    tracker = collector.new_tracker("a" * 32)
    email = collector.owned_email(tracker, 0)
    assert email.startswith("fireemu-cred-aaaaaaaa-0@")
    assert collector.owned_email(tracker, 1) != email
    with pytest.raises(ValueError, match="hexadecimal"):
        collector.new_tracker("short")


def test_cleanup_is_incomplete_until_every_owned_account_is_absent() -> None:
    tracker = collector.new_tracker("b" * 32)
    collector.track_account(tracker, "uid-1", collector.owned_email(tracker, 0))
    collector.track_account(tracker, "uid-2", collector.owned_email(tracker, 1))
    assert collector.cleanup_report(tracker)["cleanupComplete"] is False
    collector.mark_deleted(tracker, "uid-1", uid_absent=True, email_absent=True)
    assert collector.cleanup_report(tracker)["cleanupComplete"] is False
    # Deletion without a readback is not cleanup.
    collector.mark_deleted(tracker, "uid-2", uid_absent=True, email_absent=False)
    report = collector.cleanup_report(tracker)
    assert report["cleanupComplete"] is False
    assert report["remainingAccounts"] == 1
    collector.mark_deleted(tracker, "uid-2", uid_absent=True, email_absent=True)
    report = collector.cleanup_report(tracker)
    assert report["cleanupComplete"] is True
    assert report["remainingAccounts"] == 0
    assert report["ownedAccounts"] == 2


def test_untracked_account_cannot_be_marked_deleted() -> None:
    tracker = collector.new_tracker("c" * 32)
    with pytest.raises(KeyError):
        collector.mark_deleted(
            tracker, "uid-unknown", uid_absent=True, email_absent=True
        )


def test_cleanup_report_carries_no_account_identifier() -> None:
    tracker = collector.new_tracker("d" * 32)
    collector.track_account(tracker, "uid-secret", collector.owned_email(tracker, 0))
    assert "uid-secret" not in json.dumps(collector.cleanup_report(tracker))


# --- budget ------------------------------------------------------------------


def test_budget_is_enforced_not_merely_declared() -> None:
    budget = collector.new_budget(
        max_requests=2, max_wall_seconds=10, max_cost_usd=0.05
    )
    collector.charge_request(budget, elapsed_seconds=1.0)
    collector.charge_request(budget, elapsed_seconds=1.0)
    with pytest.raises(collector.BudgetExceeded, match="request"):
        collector.charge_request(budget, elapsed_seconds=1.0)
    assert budget["enforced"] is True


def test_wall_clock_budget_stops_the_run() -> None:
    budget = collector.new_budget(
        max_requests=10, max_wall_seconds=2, max_cost_usd=0.05
    )
    with pytest.raises(collector.BudgetExceeded, match="wall"):
        collector.charge_request(budget, elapsed_seconds=3.0)


def test_budget_ceiling_stays_well_under_one_dollar() -> None:
    with pytest.raises(ValueError, match="ceiling"):
        collector.new_budget(max_requests=10, max_wall_seconds=10, max_cost_usd=1.0)


# --- receipt -----------------------------------------------------------------


def test_receipt_requires_every_case_and_a_complete_cleanup() -> None:
    tracker = collector.new_tracker("e" * 32)
    rows = [
        {"caseId": case["id"], "status": 200, "errorCode": None, "assertions": {}}
        for case in observation_cases()
    ]
    receipt = collector.build_receipt(
        side="local",
        rows=rows,
        tracker=tracker,
        budget=collector.new_budget(60, 600, 0.05),
    )
    # A run that owned no account never signed anybody in, so it is not complete.
    assert receipt["recordingComplete"] is False
    assert receipt["productionExecuted"] is False
    assert [row["caseId"] for row in receipt["rows"]] == [
        case["id"] for case in observation_cases()
    ]

    collector.track_account(tracker, "uid-1", collector.owned_email(tracker, 0))
    collector.mark_deleted(tracker, "uid-1", uid_absent=True, email_absent=True)
    complete = collector.build_receipt(
        side="local",
        rows=rows,
        tracker=tracker,
        budget=collector.new_budget(60, 600, 0.05),
    )
    assert complete["recordingComplete"] is True
    assert complete["cleanup"]["cleanupComplete"] is True


def test_receipt_rejects_a_missing_or_reordered_row() -> None:
    tracker = collector.new_tracker("f" * 32)
    rows = [
        {"caseId": case["id"], "status": 200, "errorCode": None, "assertions": {}}
        for case in observation_cases()
    ]
    with pytest.raises(ValueError, match="rows"):
        collector.build_receipt(
            side="local",
            rows=rows[:-1],
            tracker=tracker,
            budget=collector.new_budget(60, 600, 0.05),
        )
    with pytest.raises(ValueError, match="rows"):
        collector.build_receipt(
            side="local",
            rows=list(reversed(rows)),
            tracker=tracker,
            budget=collector.new_budget(60, 600, 0.05),
        )


def test_receipt_side_must_be_declared() -> None:
    tracker = collector.new_tracker("a" * 32)
    rows = [
        {"caseId": case["id"], "status": 200, "errorCode": None, "assertions": {}}
        for case in observation_cases()
    ]
    with pytest.raises(ValueError, match="side"):
        collector.build_receipt(
            side="either",
            rows=rows,
            tracker=tracker,
            budget=collector.new_budget(60, 600, 0.05),
        )
