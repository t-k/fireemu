"""Successful controls must not be confused with matching rejections."""

import pytest
from disabled_contract import CASES, validate_row


def test_diagnostic_errors_are_classified_without_arbitrary_text():
    from disabled_contract import error_code

    for code in (
        "INVALID_REFRESH_TOKEN",
        "USER_NOT_FOUND",
        "USER_DISABLED",
        "TOKEN_EXPIRED",
    ):
        assert error_code({"error": {"message": code}}) == code
    assert (
        error_code({"error": {"message": "secret token value"}}) == "UNCLASSIFIED_ERROR"
    )


def test_success_and_diagnostic_rejection_are_distinct():
    assert len(CASES) == 18
    for name in CASES:
        row = {
            "id": name,
            "httpStatus": 400,
            "outcome": "refused",
            "observedError": "USER_DISABLED",
            "checks": {},
            "expirySeconds": None,
            "elapsedMs": 1,
        }
        if name.startswith("disabled-a-") or name in {
            "reenabled-a-id",
            "reenabled-a-refresh",
        }:
            validate_row(row, name)
        else:
            with pytest.raises(ValueError):
                validate_row(row, name)


def test_unknown_error_and_secret_fields_are_rejected():
    row = {
        "id": "disabled-a-id",
        "httpStatus": 400,
        "outcome": "refused",
        "observedError": "secret text",
        "checks": {},
        "expirySeconds": None,
        "elapsedMs": 1,
    }
    with pytest.raises(ValueError):
        validate_row(row, row["id"])
    row["observedError"] = "USER_DISABLED"
    row["idToken"] = "secret"
    with pytest.raises(ValueError):
        validate_row(row, row["id"])


def test_revoked_error_suffix_is_classified_but_never_retained():
    from disabled_contract import error_code

    assert (
        error_code({"error": {"message": "TOKEN_EXPIRED : credentials revoked"}})
        == "TOKEN_EXPIRED"
    )
    assert (
        error_code({"error": {"message": "USER_DISABLED : private diagnostic"}})
        == "USER_DISABLED"
    )
    for value in (
        None,
        {},
        {"error": None},
        {"error": {"message": 3}},
        {"error": {"message": "UNKNOWN : private diagnostic"}},
    ):
        assert error_code(value) == "UNCLASSIFIED_ERROR"
