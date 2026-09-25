"""Diagnostic held-credential rows may be refused; every other row must be accepted."""

import pytest
from revocation_contract import (
    CASES,
    DIAGNOSTIC,
    FINALIZE_CHECKS,
    complete,
    error_code,
    validate_row,
)


def test_errors_are_classified_without_arbitrary_text():
    for code in (
        "INVALID_MFA_PENDING_CREDENTIAL",
        "TOKEN_EXPIRED",
        "OPERATION_NOT_ALLOWED",
    ):
        assert error_code({"error": {"message": code}}) == code
        assert error_code({"error": {"message": code + " : private detail"}}) == code
    for value in (None, {}, {"error": {"message": "secret token value"}}):
        assert error_code(value) == "UNCLASSIFIED_ERROR"


def refused(name):
    return {
        "id": name,
        "httpStatus": 400,
        "outcome": "refused",
        "observedError": "INVALID_MFA_PENDING_CREDENTIAL",
        "checks": {},
        "elapsedMs": 1,
        "skipped": False,
    }


def test_only_held_credential_rows_may_be_refused_or_skipped():
    assert len(CASES) == 8 and len(DIAGNOSTIC) == 4
    for name in CASES:
        if name in DIAGNOSTIC:
            validate_row(refused(name), name)
            validate_row(
                {
                    **refused(name),
                    "httpStatus": None,
                    "outcome": "skipped",
                    "observedError": None,
                    "skipped": True,
                },
                name,
            )
        else:
            with pytest.raises(ValueError):
                validate_row(refused(name), name)


def test_accepted_finalize_rows_carry_claim_checks_and_no_secrets():
    checks = dict.fromkeys(FINALIZE_CHECKS, True)
    row = {
        "id": "baseline-a-fresh-finalize",
        "httpStatus": 200,
        "outcome": "accepted",
        "observedError": None,
        "checks": checks,
        "elapsedMs": 1,
        "skipped": False,
    }
    validate_row(row, row["id"])
    with pytest.raises(ValueError):
        validate_row(
            {**row, "id": "revoked-a-held-finalize"}, "revoked-a-held-finalize"
        )
    validate_row(
        {
            **row,
            "id": "revoked-a-held-finalize",
            "checks": {**checks, "authTimeAtOrAfterValidSince": True},
        },
        "revoked-a-held-finalize",
    )
    with pytest.raises(ValueError):
        validate_row({**row, "checks": {**checks, "derivedLookup": False}}, row["id"])
    with pytest.raises(ValueError):
        validate_row({**row, "idToken": "secret"}, row["id"])


def test_complete_requires_restore_and_cleanup():
    assert complete({}) is False
    assert complete({"status": "observed", "cases": [], "failure": "X"}) is False
