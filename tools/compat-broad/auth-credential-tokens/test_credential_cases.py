"""Contract tests for the AUTH-CREDENTIAL observation case list."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from credential_cases import (
    ASSERTION_NAMES,
    CAMPAIGN_ID,
    CASE_GROUPS,
    CASE_KINDS,
    SAME_SECOND_CASE_ID,
    SIGNING_DEPENDENT_CASE_COUNT,
    case_by_id,
    observation_cases,
)


def test_campaign_identity_is_stable() -> None:
    assert CAMPAIGN_ID == "AUTH-CREDENTIAL-TOKENS-01"
    assert observation_cases() == observation_cases()


def test_case_identifiers_are_unique_and_ordered_by_group() -> None:
    cases = observation_cases()
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids))
    groups = [case["group"] for case in cases]
    assert set(groups) == set(CASE_GROUPS)
    # Groups appear in one contiguous run each, so a partial run is visibly partial.
    assert [
        group
        for index, group in enumerate(groups)
        if index == 0 or groups[index - 1] != group
    ] == list(CASE_GROUPS)


def test_every_case_declares_a_known_kind_and_typed_local_expectation() -> None:
    for case in observation_cases():
        assert case["kind"] in CASE_KINDS
        assert case["group"] in CASE_GROUPS
        expected = case["expectedLocal"]
        assert type(expected["status"]) is int
        if case["kind"] == "negative":
            assert expected["errorCode"] is not None, case["id"]
        if expected["errorCode"] is None:
            assert expected["status"] == 200
            assert expected["assertions"]
        else:
            # A refusal is described by its code alone; no claim shape is asserted.
            assert type(expected["errorCode"]) is str and expected["errorCode"]
            assert expected["status"] >= 400
            assert expected["assertions"] == []
        assert set(expected["assertions"]) <= set(ASSERTION_NAMES)


def test_no_case_carries_a_url_host_or_credential_field() -> None:
    forbidden = {
        "url",
        "host",
        "apiKey",
        "key",
        "token",
        "password",
        "bearer",
        "serviceAccount",
        "projectId",
    }
    serialized = json.dumps(observation_cases())
    for case in observation_cases():
        assert not (forbidden & set(case))
    assert "googleapis.com" not in serialized
    assert "fireemu-35fe6" not in serialized


def test_production_side_is_unobserved_everywhere() -> None:
    for case in observation_cases():
        assert case["production"] == "UNOBSERVED"


def test_same_second_boundary_is_the_only_declared_nondeterminism() -> None:
    cases = observation_cases()
    flagged = [case["id"] for case in cases if case["nondeterminism"] != "NONE"]
    assert flagged == [SAME_SECOND_CASE_ID]
    assert case_by_id(SAME_SECOND_CASE_ID)["nondeterminism"] == "SAME_SECOND_BOUNDARY"


def test_same_second_observation_has_a_control_on_either_side() -> None:
    boundary = case_by_id(SAME_SECOND_CASE_ID)
    controls = boundary["boundaryControls"]
    assert set(controls) == {"below", "above"}
    below, above = case_by_id(controls["below"]), case_by_id(controls["above"])
    assert below["kind"] == "control" and above["kind"] == "control"
    assert below["group"] == above["group"] == boundary["group"] == "revocation"
    # The lower control must be refused and the upper control accepted, or the
    # boundary case proves nothing about where the boundary sits.
    assert below["expectedLocal"]["status"] >= 400
    assert above["expectedLocal"]["status"] == 200


def test_session_cookie_duration_bounds_are_covered_on_both_sides() -> None:
    durations = {
        case["id"]: case["input"].get("validDurationSeconds")
        for case in observation_cases()
        if case["group"] == "session-cookie"
    }
    assert durations["session-cookie-min-duration-accepted"] == 300
    assert durations["session-cookie-below-min-rejected"] == 299
    assert durations["session-cookie-max-duration-accepted"] == 1209600
    assert durations["session-cookie-above-max-rejected"] == 1209601
    assert durations["session-cookie-default-duration"] is None


def test_cases_already_observed_elsewhere_name_their_prior_evidence() -> None:
    covered = [case for case in observation_cases() if case["coveredElsewhere"]]
    assert covered, "the lane must say which rows repeat existing evidence"
    for case in covered:
        assert case["kind"] in {"control", "negative"}
        for reference in case["coveredElsewhere"]:
            assert reference.startswith("docs/compatibility/")


def test_new_conditions_do_not_repeat_existing_published_evidence() -> None:
    fresh = [
        case["id"]
        for case in observation_cases()
        if not case["coveredElsewhere"] and case["kind"] == "observation"
    ]
    assert set(fresh) == {
        "refresh-preserves-auth-time",
        "revocation-same-second-session",
        "session-cookie-default-duration",
        "session-cookie-claim-composition",
        "custom-token-developer-claims-present",
        "claim-precedence-session-over-account",
    }


def test_unknown_case_identifier_fails_closed() -> None:
    try:
        case_by_id("no-such-case")
    except KeyError:
        return
    raise AssertionError("unknown case id must raise")


def test_every_case_declares_whether_it_depends_on_production_token_signing() -> None:
    for case in observation_cases():
        assert type(case["requiresSigning"]) is bool, case["id"]


def test_the_signing_dependent_set_is_exactly_the_groups_built_on_a_custom_token() -> (
    None
):
    dependent = {case["id"] for case in observation_cases() if case["requiresSigning"]}
    # The session-cookie group derives its ID token from the custom-token session, so it
    # cannot run without production RS256 signing either.
    expected_groups = {"session-cookie", "custom-token", "claim-precedence"}
    assert dependent == {
        case["id"] for case in observation_cases() if case["group"] in expected_groups
    }
    assert len(dependent) == SIGNING_DEPENDENT_CASE_COUNT == 11
    assert len(observation_cases()) - len(dependent) == 6


def test_the_boundary_row_asserts_pinning_rather_than_a_timestamp_comparison() -> None:
    boundary = case_by_id(SAME_SECOND_CASE_ID)
    assert boundary["expectedLocal"]["assertions"] == [
        "acceptedResponse",
        "boundaryPinnedFromServerValues",
    ]
    assert "authTimePreserved" not in boundary["expectedLocal"]["assertions"]
    assert "boundaryPinnedFromServerValues" in ASSERTION_NAMES
