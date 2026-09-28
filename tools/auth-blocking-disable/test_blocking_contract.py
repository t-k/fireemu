"""Hook rows may be refused; readback and control rows must be accepted; completion needs
the function removed, the configuration restored and a consistent token chain."""

import json

import blocking_recorder as recorder
import pytest
from blocking_contract import (
    CASES,
    DIAGNOSTIC,
    FINALIZE_CHECKS,
    SIGNIN_CHECKS,
    complete,
    error_code,
    validate_row,
)


def accepted(name, checks):
    return {
        "id": name,
        "httpStatus": 200,
        "outcome": "accepted",
        "observedError": None,
        "checks": checks,
        "elapsedMs": 1,
        "skipped": False,
    }


def refused(name, error="USER_DISABLED"):
    return {
        **accepted(name, {}),
        "httpStatus": 400,
        "outcome": "refused",
        "observedError": error,
    }


def skipped(name):
    return {
        **accepted(name, {}),
        "httpStatus": None,
        "outcome": "skipped",
        "skipped": True,
    }


REFRESH = {
    "noError": True,
    "idTokenPresent": True,
    "refreshTokenPresent": True,
    "uidMatches": True,
    "expiryIsPositiveInteger": True,
    "expiryMatchesOneHour": True,
    "bearerType": True,
    "derivedLookup": True,
}


def complete_report():
    finalize = dict.fromkeys(FINALIZE_CHECKS, True)
    signin = dict.fromkeys(SIGNIN_CHECKS, True)
    rows = {
        "baseline-b-fresh-finalize": accepted("baseline-b-fresh-finalize", finalize),
        "hook-c-first-signin": accepted("hook-c-first-signin", signin),
        "hook-c-token-lookup": accepted("hook-c-token-lookup", {"ownerMatches": True}),
        "hook-c-token-refresh": accepted("hook-c-token-refresh", REFRESH),
        "hook-c-disabled-readback": accepted(
            "hook-c-disabled-readback", {"disabledPersisted": True}
        ),
        "hook-c-second-signin": refused("hook-c-second-signin"),
        "hook-a-first-finalize": accepted("hook-a-first-finalize", finalize),
        "hook-a-token-lookup": accepted("hook-a-token-lookup", {"ownerMatches": True}),
        "hook-a-token-refresh": accepted("hook-a-token-refresh", REFRESH),
        "hook-a-disabled-readback": accepted(
            "hook-a-disabled-readback", {"disabledPersisted": True}
        ),
        "hook-a-second-signin": refused("hook-a-second-signin"),
        "final-b-fresh-finalize": accepted("final-b-fresh-finalize", finalize),
    }
    return {
        "status": "observed",
        "cases": [rows[name] for name in CASES],
        "setup": {"a": True, "b": True, "c": True},
        "hook": {"deployed": True, "triggerReadback": True},
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
        "functionRemoved": True,
        "configRestored": True,
        "configDigestMatches": True,
    }


def with_rows(report, **replacements):
    report["cases"] = [replacements.get(r["id"], r) for r in report["cases"]]
    return report


def test_complete_report_is_complete():
    assert complete(complete_report())


def test_errors_are_classified_without_arbitrary_text():
    assert (
        error_code({"error": {"message": "USER_DISABLED : private"}}) == "USER_DISABLED"
    )
    assert error_code({"error": {"message": "secret token"}}) == "UNCLASSIFIED_ERROR"


def test_only_diagnostic_rows_may_be_refused():
    assert len(CASES) == 12 and len(DIAGNOSTIC) == 8
    for name in CASES:
        if name in DIAGNOSTIC:
            validate_row(refused(name), name)
        else:
            with pytest.raises(ValueError):
                validate_row(refused(name), name)


def test_readback_records_the_flag_as_seen_but_nothing_else():
    for seen in (True, False):
        validate_row(
            accepted("hook-c-disabled-readback", {"disabledPersisted": seen}),
            "hook-c-disabled-readback",
        )
    with pytest.raises(ValueError):
        validate_row(
            accepted("hook-c-disabled-readback", {"disabledPersisted": "yes"}),
            "hook-c-disabled-readback",
        )
    with pytest.raises(ValueError):
        validate_row(refused("hook-c-disabled-readback"), "hook-c-disabled-readback")


def test_completion_requires_removal_restore_and_a_consistent_chain():
    for key in ("functionRemoved", "configRestored", "configDigestMatches"):
        assert complete({**complete_report(), key: False}) is False
    for key in ("functionRemovalFailure", "configRestoreFailure", "cleanupFailure"):
        assert complete({**complete_report(), key: "X"}) is False
    # A refused first step must skip the token rows, and an accepted one must not.
    report = with_rows(
        complete_report(), **{"hook-c-first-signin": refused("hook-c-first-signin")}
    )
    assert complete(report) is False
    report = with_rows(
        report,
        **{
            "hook-c-token-lookup": skipped("hook-c-token-lookup"),
            "hook-c-token-refresh": skipped("hook-c-token-refresh"),
        },
    )
    assert complete(report)
    report = with_rows(
        complete_report(), **{"hook-a-token-refresh": skipped("hook-a-token-refresh")}
    )
    assert complete(report) is False


def test_note_keeps_only_classified_diagnostics():
    report = {}
    recorder.note(
        report,
        "signInWithPassword",
        400,
        {"error": {"message": "USER_DISABLED : secret-value-42"}},
    )
    assert report["lastError"] == "USER_DISABLED"
    assert "secret-value-42" not in json.dumps(report)


def test_restore_body_uses_the_values_read():
    original = {
        "mfa": {"state": "DISABLED"},
        "phoneNumber": None,
        "smsRegionConfig": {"allowlistOnly": {}},
        "blockingFunctions": {"forwardInboundCredentials": {}},
    }
    body = recorder.restore_body(original)
    assert body["blockingFunctions"] == {"forwardInboundCredentials": {}}
    assert body["signIn"]["phoneNumber"] == {"enabled": False, "testPhoneNumbers": {}}
    assert recorder.restored(
        {
            "mfa": {"state": "DISABLED"},
            "signIn": {"phoneNumber": {}},
            "smsRegionConfig": {"allowlistOnly": {}},
            "blockingFunctions": {"forwardInboundCredentials": {}},
        },
        original,
    )
    assert not recorder.restored(
        {
            "mfa": {"state": "DISABLED"},
            "signIn": {},
            "smsRegionConfig": {"allowlistOnly": {}},
            "blockingFunctions": {"triggers": {"beforeSignIn": {"functionUri": "x"}}},
        },
        original,
    )
