"""Contract tests for the local shadow's pure parts.

The live shadow is exercised separately against a `fireemu` binary built from this
checkout; these tests cover the decisions that must hold before a process is started.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import credential_shadow as shadow
from credential_cases import observation_cases
from credential_collector import claim_shape, new_budget


def test_transport_refuses_a_target_outside_the_loopback_interface() -> None:
    budget = new_budget(10, 10, 0.0)
    for base in (
        "http://identitytoolkit.googleapis.com",
        "http://10.0.0.1:9099",
        "http://example.com:80",
    ):
        with pytest.raises(shadow.ShadowError, match="non-loopback"):
            shadow.post(budget, base, "/accounts:signUp", {})
    assert budget["requests"] == 0


def test_loopback_hosts_are_the_only_permitted_targets() -> None:
    assert set(shadow.LOOPBACK_HOSTS) == {"127.0.0.1", "localhost", "[::1]"}


def test_custom_token_is_unsigned_and_decodes_to_the_given_payload() -> None:
    payload = {
        "aud": shadow.CUSTOM_TOKEN_AUDIENCE,
        "uid": "u1",
        "claims": {"role": "tester"},
        "iat": 1,
        "exp": 2,
    }
    token = shadow.unsigned_jwt(payload)
    assert token.endswith(".")
    header, body, signature = token.split(".")
    assert signature == ""
    assert json.loads(base64.urlsafe_b64decode(header + "==")) == {
        "alg": "none",
        "typ": "JWT",
    }
    assert (
        json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))) == payload
    )
    assert claim_shape(token)["trustRoot"] == "unsigned-emulator"


def test_error_code_drops_the_trailing_detail_and_tolerates_a_success_body() -> None:
    assert (
        shadow.error_code({"error": {"message": "TOKEN_EXPIRED : credentials revoked"}})
        == "TOKEN_EXPIRED"
    )
    assert (
        shadow.error_code({"error": {"message": "INVALID_DURATION"}})
        == "INVALID_DURATION"
    )
    assert shadow.error_code({"idToken": "x"}) is None
    assert shadow.error_code({"error": "not-an-object"}) is None


def test_a_missing_case_is_recorded_as_not_run_rather_than_passing() -> None:
    rows = [
        {"caseId": case["id"], "status": 0, "errorCode": "NOT_RUN", "assertions": {}}
        for case in observation_cases()
    ]
    agreement = shadow._agreement(rows)
    assert agreement["cases"] == len(observation_cases())
    assert len(agreement["unexpected"]) == len(observation_cases())


def test_agreement_requires_every_declared_assertion_to_hold() -> None:
    rows = []
    for case in observation_cases():
        expected = case["expectedLocal"]
        rows.append(
            {
                "caseId": case["id"],
                "status": expected["status"],
                "errorCode": expected["errorCode"],
                "assertions": {name: True for name in expected["assertions"]},
            }
        )
    assert shadow._agreement(rows)["unexpected"] == []

    for case in observation_cases():
        if not case["expectedLocal"]["assertions"]:
            continue
        weakened = [dict(row) for row in rows]
        for row in weakened:
            if row["caseId"] == case["id"]:
                row["assertions"] = {
                    **row["assertions"],
                    case["expectedLocal"]["assertions"][0]: False,
                }
        problems = shadow._agreement(weakened)["unexpected"]
        assert [item["caseId"] for item in problems] == [case["id"]]
        break


def test_an_unset_assertion_is_not_treated_as_held() -> None:
    rows = [
        {
            "caseId": case["id"],
            "status": case["expectedLocal"]["status"],
            "errorCode": case["expectedLocal"]["errorCode"],
            "assertions": {},
        }
        for case in observation_cases()
    ]
    failing = {item["caseId"] for item in shadow._agreement(rows)["unexpected"]}
    assert failing == {
        case["id"]
        for case in observation_cases()
        if case["expectedLocal"]["assertions"]
    }


def test_the_shadow_never_claims_production() -> None:
    source = (HERE / "credential_shadow.py").read_text()
    assert (
        "googleapis.com/v1" in source
    )  # the local adapter routes on the full host prefix
    assert (
        "https://identitytoolkit.googleapis.com" in source
    )  # the custom-token audience only
    assert '"productionExecuted": False' in source
