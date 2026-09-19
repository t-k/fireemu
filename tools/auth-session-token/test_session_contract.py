"""Bounded model checks distinguish observation from claimed conformance."""

import importlib.util
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("session_contract.py")
    assert path.exists(), "Session observation contract required"
    spec = importlib.util.spec_from_file_location("session_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixed_grid_has_no_retry_until_rejection():
    c = contract()
    assert c.OFFSETS == (0, 10000, 30000)
    assert c.DEADLINE_MS == 45000
    assert len(c.SAMPLES) == 18
    assert len(c.CASES) == 32
    assert c.may_start(44999)
    assert not c.may_start(45000)
    for invalid in (True, -1, 1.2):
        assert not c.may_start(invalid)


def test_identity_error_and_secret_projections_are_distinct():
    c = contract()
    good = {
        "users": [
            {
                "localId": "uid",
                "email": "email",
                "validSince": "123",
                "passwordHash": "SECRET",
            }
        ]
    }
    row = c.response(200, good, "lookup", "uid", "email")
    assert row["outcome"] == "accepted"
    assert "SECRET" not in str(row)
    assert c.response(200, good, "lookup", "other", "email")["outcome"] == "unexpected"
    assert (
        c.response(
            400, {"error": {"message": "TOKEN_EXPIRED"}}, "lookup", "uid", "email"
        )["outcome"]
        == "auth-rejected"
    )
    assert (
        c.response(
            429,
            {"error": {"message": "TOO_MANY_ATTEMPTS_TRY_LATER"}},
            "lookup",
            "uid",
            "email",
        )["outcome"]
        == "unexpected"
    )
    assert (
        c.response(400, {"error": {"message": "SECRET"}}, "lookup", "uid", "email")[
            "error"
        ]
        == "OTHER"
    )
    c.validate_response(row, "lookup")
    for key, value in (
        ("outcome", "auth-rejected"),
        ("idToken", "SECRET"),
        ("httpStatus", True),
    ):
        with pytest.raises(ValueError):
            c.validate_response({**row, key: value}, "lookup")


def test_unverified_jwt_metadata_is_bounded_and_not_a_signature_claim():
    import base64
    import json

    c = contract()

    def token(payload):
        return (
            "e30."
            + base64.urlsafe_b64encode(json.dumps(payload).encode())
            .decode()
            .rstrip("=")
            + ".unused"
        )

    assert c.token_time(token({"iat": 123, "auth_time": 120, "sub": "SECRET"})) == {
        "iat": 123,
        "authTime": 120,
    }
    for payload in (
        {"iat": True, "auth_time": 120},
        {"iat": -1, "auth_time": 0},
        {},
        {"iat": 1, "auth_time": 2},
    ):
        assert c.token_time(token(payload)) is None
    assert c.token_time("SECRET") is None


def test_late_missing_and_failed_controls_are_inconclusive():
    c = contract()
    result = c.response(
        400, {"error": {"message": "TOKEN_EXPIRED"}}, "lookup", "uid", "email"
    )
    assert c.sample_quality(result, None, 0, 100, 0, "a-id") == "observed"
    assert c.sample_quality(result, None, 0, 100, 0, "changed-id") == "inconclusive"
    assert c.sample_quality(result, None, 2500, 2600, 0, "a-id") == "late"
    assert c.sample_quality(result, None, 44000, 46000, 30000, "a-id") == "late"
    assert (
        c.sample_quality(
            c.unavailable("lookup", "not-sampled"), None, 45000, 45000, 30000, "a-id"
        )
        == "inconclusive"
    )


def test_accepted_refresh_does_not_imply_usable_issued_id_token():
    c = contract()
    accepted = {"outcome": "accepted"}
    refused = {"outcome": "auth-rejected"}
    assert c.sample_quality(accepted, refused, 0, 100, 0, "a-refresh") == "observed"
    assert (
        c.sample_quality(accepted, refused, 0, 100, 0, "changed-refresh")
        == "inconclusive"
    )
    assert c.sample_quality(accepted, None, 0, 100, 0, "a-refresh") == "inconclusive"


def test_transport_and_not_sampled_are_never_auth_rejection():
    c = contract()
    for kind in ("token", "lookup", "refresh", "delete", "absence"):
        for outcome in ("transport-failure", "not-sampled"):
            row = c.unavailable(kind, outcome)
            c.validate_response(row, kind)
            assert row["outcome"] != "auth-rejected"
            with pytest.raises(ValueError):
                c.validate_response({**row, "outcome": "auth-rejected"}, kind)


def test_deadline_model_never_becomes_observed_by_waiting_longer():
    c = contract()
    accepted = {"outcome": "accepted"}
    refused = {"outcome": "auth-rejected"}
    for offset in c.OFFSETS:
        for start in (offset, offset + 2000, offset + 2001, 44999, 45000, 60000):
            for primary in (accepted, refused):
                quality = c.sample_quality(
                    primary, None, start, start + 1, offset, "a-id"
                )
                assert (quality == "observed") is (
                    start >= offset
                    and start - offset <= 2000
                    and start + 1 <= c.DEADLINE_MS
                )
