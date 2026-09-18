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
from credential_collector import (
    BudgetExceeded,
    build_receipt,
    claim_shape,
    cleanup_report,
    new_budget,
    new_tracker,
    owned_email,
    track_account,
)
from credential_plan import BUDGET


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


# --- cleanup must prove absence, not infer it --------------------------------


def _tracker_with(uid: str, email: str | None) -> dict:
    tracker = new_tracker("a" * 32)
    track_account(tracker, uid, email)
    return tracker


def _stub(responses: list[tuple[int, dict]]):
    calls: list[tuple[str, dict]] = []

    def poster(budget, base, path, body, *, owner=False):
        calls.append((path, body))
        return responses[min(len(calls) - 1, len(responses) - 1)]

    poster.calls = calls
    return poster


def test_an_absent_account_needs_a_200_lookup_with_an_empty_result() -> None:
    tracker = _tracker_with("uid-1", owned_email(_tracker_with("uid-1", None), 0))
    poster = _stub([(200, {}), (200, {}), (200, {})])
    shadow.cleanup(
        "http://127.0.0.1:1", new_budget(30, 60, 0.0), tracker, poster=poster
    )
    report = cleanup_report(tracker)
    assert report["cleanupComplete"] is True
    assert report["remainingAccounts"] == 0


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_a_refused_lookup_is_never_read_as_a_completed_cleanup(status: int) -> None:
    email = owned_email(new_tracker("a" * 32), 0)
    tracker = _tracker_with("uid-1", email)
    # A refusal body carries no `users` member; inferring absence from that would
    # report a live account as deleted.
    poster = _stub([(200, {}), (status, {"error": {"message": "PERMISSION_DENIED"}})])
    shadow.cleanup(
        "http://127.0.0.1:1", new_budget(30, 60, 0.0), tracker, poster=poster
    )
    report = cleanup_report(tracker)
    assert report["cleanupComplete"] is False
    assert report["remainingAccounts"] == 1


def test_a_refused_delete_is_never_read_as_a_completed_cleanup() -> None:
    email = owned_email(new_tracker("a" * 32), 0)
    tracker = _tracker_with("uid-1", email)
    poster = _stub([(403, {"error": {"message": "PERMISSION_DENIED"}}), (200, {})])
    shadow.cleanup(
        "http://127.0.0.1:1", new_budget(30, 60, 0.0), tracker, poster=poster
    )
    assert cleanup_report(tracker)["cleanupComplete"] is False


def test_a_lookup_that_still_returns_the_account_is_not_absence() -> None:
    email = owned_email(new_tracker("a" * 32), 0)
    tracker = _tracker_with("uid-1", email)
    poster = _stub([(200, {}), (200, {"users": [{"localId": "uid-1"}]})])
    shadow.cleanup(
        "http://127.0.0.1:1", new_budget(30, 60, 0.0), tracker, poster=poster
    )
    assert cleanup_report(tracker)["cleanupComplete"] is False


def test_an_addressless_account_skips_the_address_lookup_entirely() -> None:
    tracker = _tracker_with("uid-custom", None)
    poster = _stub([(200, {}), (200, {})])
    shadow.cleanup(
        "http://127.0.0.1:1", new_budget(30, 60, 0.0), tracker, poster=poster
    )
    paths = [path for path, _ in poster.calls]
    assert paths == ["/accounts:delete", "/accounts:lookup"]
    assert cleanup_report(tracker)["cleanupComplete"] is True
    assert cleanup_report(tracker)["addressReadbacks"] == 0


def test_a_cleanup_failure_keeps_the_receipt_incomplete() -> None:
    email = owned_email(new_tracker("a" * 32), 0)
    tracker = _tracker_with("uid-1", email)
    poster = _stub([(200, {}), (429, {"error": {"message": "RESOURCE_EXHAUSTED"}})])
    shadow.cleanup(
        "http://127.0.0.1:1", new_budget(30, 60, 0.0), tracker, poster=poster
    )
    rows = [
        {"caseId": case["id"], "status": 200, "errorCode": None, "assertions": {}}
        for case in observation_cases()
    ]
    receipt = build_receipt(
        side="local", rows=rows, tracker=tracker, budget=new_budget(60, 600, 0.05)
    )
    assert receipt["recordingComplete"] is False


# --- a stopped run still records what it observed -----------------------------


def test_budget_exhaustion_keeps_the_rows_already_observed() -> None:
    first = observation_cases()[0]["id"]

    def runner(base, budget, tracker, rows):
        rows[first] = {
            "caseId": first,
            "status": 200,
            "errorCode": None,
            "assertions": {},
        }
        raise BudgetExceeded("request budget exhausted")

    rows, failure = shadow.collect(
        "http://127.0.0.1:1",
        new_budget(1, 1, 0.0),
        new_tracker("a" * 32),
        runner=runner,
    )
    assert first in rows
    assert failure is not None and "BudgetExceeded" in failure


@pytest.mark.parametrize(
    "error",
    [
        BudgetExceeded("wall-clock budget exhausted"),
        shadow.ShadowError("sign-up failed"),
        ValueError("token is not a three-segment JWT"),
        KeyError("id_token"),
    ],
)
def test_every_stop_condition_is_recorded_rather_than_raised(error: Exception) -> None:
    def runner(base, budget, tracker, rows):
        rows["x"] = {"caseId": "x"}
        raise error

    rows, failure = shadow.collect(
        "http://127.0.0.1:1",
        new_budget(5, 5, 0.0),
        new_tracker("a" * 32),
        runner=runner,
    )
    assert rows == {"x": {"caseId": "x"}}
    assert failure is not None and type(error).__name__ in failure


def test_a_stopped_run_writes_a_record_with_the_missing_cases_marked_not_run(
    tmp_path,
) -> None:
    first = observation_cases()[0]["id"]
    partial = {
        first: {"caseId": first, "status": 200, "errorCode": None, "assertions": {}}
    }
    tracker = new_tracker("a" * 32)
    record, exit_code = shadow.finish_record(
        rows=partial,
        tracker=tracker,
        budget=new_budget(60, 600, 0.0),
        failure="BudgetExceeded: request budget exhausted",
        shutdown={"exitCode": 0, "processStopped": True, "remainingChildren": 0},
        source_binding={"commit": None, "artifactSha256": "c" * 64},
    )
    assert exit_code == 1
    assert record["failure"].startswith("BudgetExceeded")
    by_id = {row["caseId"]: row for row in record["receipt"]["rows"]}
    assert by_id[first]["status"] == 200
    assert by_id[observation_cases()[-1]["id"]]["errorCode"] == "NOT_RUN"
    assert len(record["receipt"]["rows"]) == len(observation_cases())
    assert record["receipt"]["recordingComplete"] is False
    assert record["productionExecuted"] is False


def test_the_shadow_budget_cannot_drift_from_the_declared_campaign_budget() -> None:
    budget = shadow.shadow_budget()
    assert budget["maxRequests"] == BUDGET["maxRequests"] == 60
    assert budget["maxWallSeconds"] == BUDGET["maxWallSeconds"]
    # A local run spends nothing, so its cost ceiling is zero rather than the campaign's.
    assert budget["maxCostUsd"] == 0.0
    assert budget["enforced"] is True
