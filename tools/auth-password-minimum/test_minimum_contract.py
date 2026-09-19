"""Finite partitions and mutations for the password transition observation oracle."""

import importlib.util
import json
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("minimum_contract.py")
    assert path.exists(), "Password observation contract is required"
    spec = importlib.util.spec_from_file_location("minimum_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixed_transition_cases_and_token_sources():
    c = contract()
    assert c.CASES == (
        "signup",
        "baseline-signin",
        "minimum-password-change",
        "changed-token-lookup",
        "old-password-rejected",
        "unchanged-state",
        "new-password-signin",
        "new-password-lookup",
        "changed-token-refresh",
        "refreshed-lookup",
        "delete",
        "deleted-account-absent",
    )
    assert c.TOKEN_CASES == {
        "signup",
        "baseline-signin",
        "minimum-password-change",
        "new-password-signin",
        "changed-token-refresh",
    }


def test_selected_state_preserves_presence_type_and_value():
    c = contract()
    values = [{}, {"photoUrl": None}, {"photoUrl": ""}, {"photoUrl": "x"}]
    assert len({c.selected_state(value) for value in values}) == len(values)
    assert c.selected_state({"disabled": False}) != c.selected_state({"disabled": 0})
    assert c.selected_state({"localId": "one"}) != c.selected_state({"localId": "two"})
    assert c.selected_state(
        {"passwordHash": "SECRET", "lastLoginAt": "1"}
    ) == c.selected_state({})


@pytest.mark.parametrize("seconds", [None, "1", "3600", "999999"])
def test_token_expiry_partitions_and_secret_redaction(seconds):
    c = contract()
    raw = {
        "idToken": "SECRET-ID",
        "refreshToken": "SECRET-REFRESH",
        "localId": "uid",
        "email": "email",
        "expiresIn": seconds,
        "passwordHash": "SECRET-HASH",
    }
    checks = {"httpOk": True, **c.tokens(raw, "uid", "email")}
    row = {
        "id": "minimum-password-change",
        "httpStatus": 200,
        "checks": checks,
        "passed": all(checks.values()),
        "expirySeconds": c.expiry_seconds(raw),
    }
    c.validate_case(row, "minimum-password-change")
    assert row["passed"] is (seconds == "3600")
    assert "SECRET" not in json.dumps(row)
    with pytest.raises(ValueError):
        c.validate_case({**row, "passed": not row["passed"]}, "minimum-password-change")
    with pytest.raises(ValueError):
        c.validate_case({**row, "password": "SECRET"}, "minimum-password-change")


def test_failed_identity_or_status_cannot_pass():
    c = contract()
    raw = {
        "idToken": "token",
        "refreshToken": "token",
        "localId": "wrong",
        "email": "email",
        "expiresIn": "3600",
    }
    assert c.tokens(raw, "uid", "email")["uidMatches"] is False
    for name in c.CASES:
        row = {
            "id": name,
            "httpStatus": 400 if name == "old-password-rejected" else 200,
            "checks": dict.fromkeys(c.CHECKS[name], True),
            "passed": True,
        }
        if name in c.TOKEN_CASES:
            row["expirySeconds"] = "3600"
        c.validate_case(row, name)
        with pytest.raises(ValueError):
            c.validate_case({**row, "httpStatus": 500}, name)
        for key in c.CHECKS[name]:
            changed = {**row, "checks": {**row["checks"], key: False}}
            with pytest.raises(ValueError):
                c.validate_case(changed, name)


def test_same_email_different_uid_is_not_owned():
    c = contract()
    with pytest.raises(ValueError):
        c.owned(
            [{"email": "email", "localId": "other", "displayName": "marker"}],
            "email",
            "marker",
            "uid",
        )
