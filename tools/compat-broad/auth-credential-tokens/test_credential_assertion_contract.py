"""Assertion evidence completeness, using the complete real comparator.

Every receipt here is SYNTHETIC. The synthetic binding only gets finite unit-test
inputs to the comparison boundary; it establishes no acquisition, native runtime,
production request, signature, source provenance, or cleanup observation.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from credential_cases import SAME_SECOND_CASE_ID, control_members, observation_cases
from credential_comparator import compare

CASES = observation_cases()
MEASURED = [case["id"] for case in CASES if case["expectedLocal"]["assertions"]]
REFRESH = "refresh-preserves-auth-time"
COOKIE = "session-cookie-claim-composition"
ABOVE = "revocation-newer-session-accepted"


def synthetic_pair() -> tuple[dict, dict]:
    rows = []
    for case in CASES:
        # Local expectations generate a convenient TEST fixture, never a real
        # production oracle. Tests below deliberately change these values.
        row = {
            "caseId": case["id"],
            "status": case["expectedLocal"]["status"],
            "errorCode": case["expectedLocal"]["errorCode"],
            "assertions": {name: True for name in case["expectedLocal"]["assertions"]},
            "trustRoot": "unsigned-emulator",
            **control_members(case),
        }
        if (row["assertions"].get("idTokenReturned") is True
                or row["assertions"].get("sessionCookieReturned") is True
                or case["group"] == "claim-precedence"):
            # This synthetic fixture supplies the measured claim projection too.
            row["claims"] = {"claimNames": ["sub"],
                             "claimTypes": {"sub": "string"}, "firebase": None}
        if case["id"] == SAME_SECOND_CASE_ID:
            row.update(boundaryPinned=True,
                       boundarySeconds={"authTime": 1800000000, "validSince": 1800000000})
        rows.append(row)
    left = {
        "side": "local", "productionExecuted": False, "recordingComplete": True,
        "collectorBinding": {"unitTestFixture": "not-production-provenance"},
        "cleanup": {"cleanupComplete": True, "remainingAccounts": 0,
                    "ownedAccounts": 2, "addressReadbacks": 2},
        "rows": rows,
    }
    right = copy.deepcopy(left)
    right.update(side="production", productionExecuted=True)
    for row in right["rows"]:
        row["trustRoot"] = "signed"
    return left, right


def select(receipt: dict, case_id: str) -> dict:
    return next(row for row in receipt["rows"] if row["caseId"] == case_id)


def classes(pair: tuple[dict, dict]) -> dict[str, str]:
    report = compare(*pair)
    assert report["reason"] == "classified"
    assert report["parityEstablished"] is False
    return {row["caseId"]: row["classification"] for row in report["rows"]}


@pytest.mark.parametrize("side", ["local", "production", "both"])
@pytest.mark.parametrize("case_id", MEASURED)
def test_missing_declared_measurement_is_indeterminate_on_either_side(case_id, side):
    pair = synthetic_pair()
    selected = pair if side == "both" else (pair[0 if side == "local" else 1],)
    for receipt in selected:
        row = select(receipt, case_id)
        del row["assertions"][next(iter(row["assertions"]))]
    got = classes(pair)
    assert got[case_id] == "INDETERMINATE"
    affected = {case_id}
    if case_id == ABOVE:
        affected.add(SAME_SECOND_CASE_ID)
        assert got[SAME_SECOND_CASE_ID] == "INDETERMINATE"
    assert all(value == "MATCH" for key, value in got.items() if key not in affected)


def test_empty_successes_do_not_turn_an_unmeasured_campaign_into_matches():
    pair = synthetic_pair()
    for receipt in pair:
        for row in receipt["rows"]:
            row["assertions"] = {}
    got = classes(pair)
    assert all(got[case_id] == "INDETERMINATE" for case_id in MEASURED)
    assert all(value == "MATCH" for key, value in got.items() if key not in MEASURED)
    assert len(MEASURED) == 10


@pytest.mark.parametrize("change", ["rename", "add"])
def test_identical_extra_or_renamed_checks_are_not_the_declared_measurements(change):
    pair = synthetic_pair()
    for receipt in pair:
        checks = select(receipt, COOKIE)["assertions"]
        if change == "rename":
            checks["cookieSubjectMatchesIdTokne"] = checks.pop("cookieSubjectMatchesIdToken")
        else:
            checks["unregisteredMeasurement"] = True
    assert classes(pair)[COOKIE] == "INDETERMINATE"


@pytest.mark.parametrize("side", [0, 1])
def test_extra_check_is_not_mistaken_for_a_semantic_difference(side):
    pair = synthetic_pair()
    select(pair[side], REFRESH)["assertions"]["newCheck"] = False
    assert classes(pair)[REFRESH] == "INDETERMINATE"


def test_actual_false_measurements_are_not_missing_and_can_agree():
    pair = synthetic_pair()
    for receipt in pair:
        for row in receipt["rows"]:
            row["assertions"] = dict.fromkeys(row["assertions"], False)
    got = classes(pair)
    # Equal false measurements remain comparable data, but a failed account
    # lookup is not a positive control that can place the same-second boundary.
    assert got[SAME_SECOND_CASE_ID] == "INDETERMINATE"
    assert all(value == "MATCH" for key, value in got.items() if key != SAME_SECOND_CASE_ID)


def test_actual_false_measurement_on_one_side_is_a_difference():
    pair = synthetic_pair()
    select(pair[1], REFRESH)["assertions"]["authTimePreserved"] = False
    assert classes(pair)[REFRESH] == "DIFFERENT"


def test_order_of_measurements_is_not_semantic():
    pair = synthetic_pair()
    row = select(pair[1], COOKIE)
    row["assertions"] = dict(reversed(list(row["assertions"].items())))
    assert classes(pair)[COOKIE] == "MATCH"


@pytest.mark.parametrize("status,code", [(400, "TOKEN_EXPIRED"), (403, "PERMISSION_DENIED"), (503, "UNAVAILABLE")])
def test_identical_explicit_refusals_need_not_describe_an_unissued_token(status, code):
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, COOKIE).update(status=status, errorCode=code, assertions={})
    assert classes(pair)[COOKIE] == "MATCH"


def test_production_refusal_against_local_success_remains_different():
    pair = synthetic_pair()
    select(pair[1], COOKIE).update(status=400, errorCode="TOKEN_EXPIRED", assertions={})
    assert classes(pair)[COOKIE] == "DIFFERENT"


def test_two_explicit_refusal_codes_are_still_compared():
    pair = synthetic_pair()
    for receipt, code in zip(pair, ("TOKEN_EXPIRED", "INVALID_ID_TOKEN"), strict=True):
        select(receipt, COOKIE).update(status=400, errorCode=code, assertions={})
    assert classes(pair)[COOKIE] == "DIFFERENT"


def test_partial_refusal_measurements_are_not_accepted_as_a_complete_set():
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, COOKIE).update(status=400, errorCode="TOKEN_EXPIRED",
                                       assertions={"sessionCookieReturned": False})
    assert classes(pair)[COOKIE] == "INDETERMINATE"


@pytest.mark.parametrize("status,code", [(200, "TOKEN_EXPIRED"), (400, None), (400, ""), (302, "REDIRECT")])
def test_missing_success_checks_cannot_hide_behind_an_incomplete_refusal(status, code):
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, COOKIE).update(status=status, errorCode=code, assertions={})
    assert classes(pair)[COOKIE] == "INDETERMINATE"


@pytest.mark.parametrize("status", [201, 204])
def test_unexpected_success_status_does_not_make_measurements_optional(status):
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, COOKIE).update(status=status, assertions={})
    assert classes(pair)[COOKIE] == "INDETERMINATE"


def test_complete_measured_service_difference_is_not_overruled_by_local_expectations():
    pair = synthetic_pair()
    select(pair[1], REFRESH).update(status=400, errorCode="UNEXPECTED_REFUSAL")
    assert classes(pair)[REFRESH] == "DIFFERENT"


def test_negative_case_with_no_declared_measurements_remains_comparable():
    pair = synthetic_pair()
    case_id = "custom-token-expired-rejected"
    for receipt in pair:
        # Agreement is recorded as data even when it contradicts expectedLocal.
        select(receipt, case_id).update(status=200, errorCode=None, assertions={})
    assert classes(pair)[case_id] == "MATCH"


@pytest.mark.parametrize("checks", [None, [], "missing", {"authTimePreserved": 1}])
def test_non_object_or_non_boolean_measurements_fail_without_exception(checks):
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, REFRESH)["assertions"] = checks
    assert classes(pair)[REFRESH] == "INDETERMINATE"


def test_missing_assertions_member_is_indeterminate():
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, REFRESH).pop("assertions")
    assert classes(pair)[REFRESH] == "INDETERMINATE"


def test_incomplete_control_invalidates_even_an_unpinned_boundary():
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, ABOVE)["assertions"] = {}
        select(receipt, SAME_SECOND_CASE_ID)["boundaryPinned"] = False
    got = classes(pair)
    assert got[ABOVE] == got[SAME_SECOND_CASE_ID] == "INDETERMINATE"


def test_unpinned_fully_measured_boundary_preserves_expected_nondeterminism():
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, SAME_SECOND_CASE_ID)["boundaryPinned"] = False
    assert classes(pair)[SAME_SECOND_CASE_ID] == "EXPECTED_NONDETERMINISM"


def test_pinned_refusal_boundary_still_compares_against_local_acceptance():
    pair = synthetic_pair()
    select(pair[1], SAME_SECOND_CASE_ID).update(status=400, errorCode="TOKEN_EXPIRED", assertions={})
    assert classes(pair)[SAME_SECOND_CASE_ID] == "DIFFERENT"


def test_original_receipts_and_case_definitions_are_not_filled_in_or_mutated():
    pair = synthetic_pair()
    select(pair[0], REFRESH)["assertions"].pop("authTimePreserved")
    before = copy.deepcopy(pair)
    case_before = copy.deepcopy(CASES)
    classes(pair)
    assert pair == before
    assert CASES == case_before == observation_cases()


@pytest.mark.parametrize("failure", ["cleanup", "binding", "not-run", "recording"])
def test_new_measurement_gate_does_not_bypass_existing_evidence_gates(failure):
    pair = synthetic_pair()
    if failure == "cleanup":
        pair[1]["cleanup"]["cleanupComplete"] = False
    elif failure == "binding":
        pair[1]["collectorBinding"] = {"unitTestFixture": "other"}
    elif failure == "recording":
        pair[1]["recordingComplete"] = False
    else:
        select(pair[1], REFRESH)["errorCode"] = "NOT_RUN"
    report = compare(*pair)
    got = {row["caseId"]: row["classification"] for row in report["rows"]}
    assert got[REFRESH] == "INDETERMINATE"
    if failure != "not-run":
        assert set(got.values()) == {"INDETERMINATE"}


def test_result_exposes_classification_only_not_row_payloads():
    pair = synthetic_pair()
    select(pair[0], REFRESH)["assertions"].pop("authTimePreserved")
    report = compare(*pair)
    assert all(set(row) == {"caseId", "classification"} for row in report["rows"])
    assert "not-production-provenance" not in json.dumps(report)
    assert report["parityEstablished"] is False
