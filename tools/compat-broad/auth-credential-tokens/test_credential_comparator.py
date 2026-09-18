"""Contract tests for the AUTH-CREDENTIAL comparison contract."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from credential_cases import SAME_SECOND_CASE_ID, case_by_id, observation_cases
from credential_collector import (
    build_receipt,
    mark_deleted,
    new_budget,
    new_tracker,
    owned_email,
    track_account,
)
from credential_comparator import CONTRACT, DIAGNOSTIC_MEMBERS, compare

SOURCE_BINDING = {"commit": "a" * 40, "artifactSha256": "b" * 64}


def _row(case: dict) -> dict:
    expected = case["expectedLocal"]
    row = {
        "caseId": case["id"],
        "status": expected["status"],
        "errorCode": expected["errorCode"],
        "assertions": {name: True for name in expected["assertions"]},
        "trustRoot": "unsigned-emulator",
    }
    if case["nondeterminism"] == "SAME_SECOND_BOUNDARY":
        row["boundaryPinned"] = False
    return row


def _cleaned_tracker(seed: str) -> dict:
    tracker = new_tracker(seed * 32)
    for index, uid in enumerate(("uid-1", "uid-2")):
        track_account(tracker, uid, owned_email(tracker, index))
        mark_deleted(tracker, uid, uid_absent=True, email_absent=True)
    return tracker


def _receipt(side: str, *, production_executed: bool | None = None) -> dict:
    """Build a receipt the way a real run does, through the collector itself.

    Hand-built receipt literals hid a defect once: the comparator required a member the
    collector never wrote, so no real pair could be compared. Going through
    `build_receipt` keeps the two sides of that seam honest.
    """
    rows = [_row(case) for case in observation_cases()]
    if side == "production":
        for row in rows:
            row["trustRoot"] = "signed"
    executed = (
        side == "production" if production_executed is None else production_executed
    )
    return build_receipt(
        side=side,
        rows=rows,
        tracker=_cleaned_tracker("a"),
        budget=new_budget(60, 600, 0.05),
        source_binding=dict(SOURCE_BINDING),
        production_executed=executed,
    )


# --- each side must place the boundary for itself ------------------------------

BOUNDARY_SECONDS = {"authTime": 1_800_000_000, "validSince": 1_800_000_000}


def _pinned_pair(**boundary: object) -> tuple[dict, dict]:
    local, production = _receipt("local"), _receipt("production")
    for receipt in (local, production):
        for row in receipt["rows"]:
            if row["caseId"] == SAME_SECOND_CASE_ID:
                row["boundaryPinned"] = True
                row["boundarySeconds"] = dict(BOUNDARY_SECONDS)
                row.update(boundary)
    return local, production


def _set_row(receipts: tuple[dict, ...], case_id: str, **members: object) -> None:
    for receipt in receipts:
        for row in receipt["rows"]:
            if row["caseId"] == case_id:
                row.update(members)


def _classifications(report: dict) -> dict[str, str]:
    return {row["caseId"]: row["classification"] for row in report["rows"]}


def test_contract_is_named_and_never_claims_parity() -> None:
    report = compare(_receipt("local"), _receipt("production"))
    assert report["contract"] == CONTRACT
    assert report["parityEstablished"] is False


def test_agreeing_bound_receipts_classify_every_ordinary_row_as_match() -> None:
    report = compare(_receipt("local"), _receipt("production"))
    assert report["productionCompared"] is True
    classes = _classifications(report)
    ordinary = {
        case_id: value
        for case_id, value in classes.items()
        if case_id != SAME_SECOND_CASE_ID
    }
    assert set(ordinary.values()) == {"MATCH"}
    assert report["summary"]["match"] == len(ordinary)


def test_unpinned_same_second_boundary_is_expected_nondeterminism_not_a_match() -> None:
    report = compare(_receipt("local"), _receipt("production"))
    assert _classifications(report)[SAME_SECOND_CASE_ID] == "EXPECTED_NONDETERMINISM"
    assert report["summary"]["expectedNondeterminism"] == 1
    assert report["summary"]["match"] == len(observation_cases()) - 1


def test_pinned_same_second_boundary_can_match_or_differ() -> None:
    local, production = _pinned_pair()
    assert _classifications(compare(local, production))[SAME_SECOND_CASE_ID] == "MATCH"

    _set_row(
        (production,),
        SAME_SECOND_CASE_ID,
        status=400,
        errorCode="TOKEN_EXPIRED",
        assertions={},
    )
    assert (
        _classifications(compare(local, production))[SAME_SECOND_CASE_ID] == "DIFFERENT"
    )


def test_boundary_needs_one_side_pinned_on_both_receipts() -> None:
    local, production = _receipt("local"), _receipt("production")
    for row in local["rows"]:
        if row["caseId"] == SAME_SECOND_CASE_ID:
            row["boundaryPinned"] = True
    assert (
        _classifications(compare(local, production))[SAME_SECOND_CASE_ID]
        == "EXPECTED_NONDETERMINISM"
    )


def test_boundary_is_indeterminate_when_the_sides_disagree_on_a_control() -> None:
    controls = case_by_id(SAME_SECOND_CASE_ID)["boundaryControls"]
    for control in controls.values():
        local, production = _pinned_pair()
        # The control holds on the local side and fails on the production side, so the
        # two sides placed the boundary in different places.
        _set_row((production,), control["case"], status=503, errorCode="UNAVAILABLE")
        classes = _classifications(compare(local, production))
        assert classes[control["case"]] == "DIFFERENT"
        assert classes[SAME_SECOND_CASE_ID] == "INDETERMINATE"


def test_trust_root_difference_alone_is_never_a_semantic_difference() -> None:
    local, production = _receipt("local"), _receipt("production")
    assert {row["trustRoot"] for row in local["rows"]} != {
        row["trustRoot"] for row in production["rows"]
    }
    report = compare(local, production)
    assert report["summary"]["different"] == 0
    assert report["trustRoots"] == {
        "local": ["unsigned-emulator"],
        "production": ["signed"],
    }


def test_an_unexecuted_production_side_makes_every_row_indeterminate() -> None:
    report = compare(
        _receipt("local"), _receipt("production", production_executed=False)
    )
    assert report["productionCompared"] is False
    assert set(_classifications(report).values()) == {"INDETERMINATE"}
    assert report["reason"] == "production-unobserved"


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda r: r.update(recordingComplete=False), "incomplete-recording"),
        (lambda r: r["cleanup"].update(cleanupComplete=False), "incomplete-cleanup"),
        (lambda r: r["cleanup"].update(remainingAccounts=1), "incomplete-cleanup"),
        (lambda r: r["rows"].pop(), "row-set-mismatch"),
        (lambda r: r["rows"].reverse(), "row-set-mismatch"),
        (lambda r: r.update(side="local"), "side-mismatch"),
        (
            lambda r: r.update(
                collectorBinding={"commit": "c" * 40, "collectorSha256": "d" * 64}
            ),
            "collector-binding-mismatch",
        ),
        (lambda r: r.pop("collectorBinding"), "collector-binding-mismatch"),
    ],
)
def test_an_invalid_pair_fails_closed_with_a_named_reason(
    mutation, reason: str
) -> None:
    production = _receipt("production")
    mutation(production)
    report = compare(_receipt("local"), production)
    assert report["productionCompared"] is False
    assert report["reason"] == reason
    assert set(_classifications(report).values()) == {"INDETERMINATE"}


def test_a_receipt_carrying_raw_credential_material_is_refused() -> None:
    production = _receipt("production")
    production["rows"][0]["idToken"] = "eyJhbGciOiJub25lIn0.RAW.sig"
    report = compare(_receipt("local"), production)
    assert report["reason"] == "credential-material-present"
    assert "RAW" not in json.dumps(report)


def test_comparing_a_receipt_with_itself_is_not_evidence() -> None:
    local = _receipt("local")
    report = compare(local, local)
    assert report["productionCompared"] is False
    assert report["reason"] == "side-mismatch"


def test_report_carries_no_row_payload_beyond_classification() -> None:
    report = compare(_receipt("local"), _receipt("production"))
    for row in report["rows"]:
        assert set(row) == {"caseId", "classification"}


def test_mutating_the_inputs_does_not_change_an_existing_report() -> None:
    local, production = _receipt("local"), _receipt("production")
    before = copy.deepcopy(compare(local, production))
    production["rows"][0]["status"] = 500
    assert before == compare(_receipt("local"), _receipt("production"))


def test_absolute_server_times_are_retained_but_never_compared() -> None:
    local, production = _receipt("local"), _receipt("production")
    local["rows"][0]["diagnostics"] = {"iat": 1_700_000_000}
    production["rows"][0]["diagnostics"] = {"iat": 1_800_000_000}
    for row in production["rows"]:
        if row["caseId"] == SAME_SECOND_CASE_ID:
            row["boundarySeconds"] = {"authTime": 5, "validSince": 5}
    report = compare(local, production)
    assert report["summary"]["different"] == 0
    assert set(DIAGNOSTIC_MEMBERS) == {"diagnostics", "boundarySeconds"}


def test_a_collector_built_pair_is_comparable_end_to_end() -> None:
    local, production = _receipt("local"), _receipt("production")
    assert "collectorBinding" in local and "collectorBinding" in production
    report = compare(local, production)
    assert report["reason"] == "classified"
    assert report["productionCompared"] is True
    assert report["summary"]["indeterminate"] == 0


def test_a_receipt_from_a_different_collector_build_is_refused() -> None:
    local, production = _receipt("local"), _receipt("production")
    production["collectorBinding"]["modules"]["credential_cases.py"] = "0" * 64
    assert compare(local, production)["reason"] == "collector-binding-mismatch"


def test_a_jwt_hidden_under_a_module_named_key_is_refused() -> None:
    production = _receipt("production")
    production["collectorBinding"]["modules"]["refresh_token.py"] = (
        "eyJhbGciOiJub25lIn0.RAW_TOKEN_MATERIAL.sig"
    )
    report = compare(_receipt("local"), production)
    assert report["reason"] == "credential-material-present"
    assert "RAW_TOKEN_MATERIAL" not in json.dumps(report)


def test_a_pinned_boundary_with_holding_controls_is_compared() -> None:
    local, production = _pinned_pair()
    assert _classifications(compare(local, production))[SAME_SECOND_CASE_ID] == "MATCH"


def test_both_sides_accepting_the_older_session_does_not_place_the_boundary() -> None:
    below = case_by_id(SAME_SECOND_CASE_ID)["boundaryControls"]["below"]["case"]
    pair = _pinned_pair()
    # Both sides make the same mistake, so the controls still agree with each other.
    _set_row(pair, below, status=200, errorCode=None)
    classes = _classifications(compare(*pair))
    assert classes[below] == "MATCH"
    assert classes[SAME_SECOND_CASE_ID] == "INDETERMINATE"


def test_both_sides_refusing_the_newer_session_does_not_place_the_boundary() -> None:
    above = case_by_id(SAME_SECOND_CASE_ID)["boundaryControls"]["above"]["case"]
    pair = _pinned_pair()
    _set_row(pair, above, status=400, errorCode="TOKEN_EXPIRED", assertions={})
    classes = _classifications(compare(*pair))
    assert classes[above] == "MATCH"
    assert classes[SAME_SECOND_CASE_ID] == "INDETERMINATE"


def test_a_control_refused_by_the_service_rather_than_the_rule_does_not_hold() -> None:
    below = case_by_id(SAME_SECOND_CASE_ID)["boundaryControls"]["below"]["case"]
    pair = _pinned_pair()
    # A 503 is the service failing, not the older session being refused.
    _set_row(pair, below, status=503, errorCode="UNAVAILABLE")
    assert _classifications(compare(*pair))[SAME_SECOND_CASE_ID] == "INDETERMINATE"


@pytest.mark.parametrize(
    "seconds",
    [
        {"authTime": 100, "validSince": 102},
        {"authTime": 100, "validSince": None},
        {"authTime": 100},
        {"authTime": None, "validSince": None},
        "1800000000",
    ],
)
def test_a_boundary_pinned_against_inconsistent_seconds_is_not_pinned(seconds) -> None:
    local, production = _pinned_pair()
    _set_row((production,), SAME_SECOND_CASE_ID, boundarySeconds=seconds)
    assert (
        _classifications(compare(local, production))[SAME_SECOND_CASE_ID]
        == "EXPECTED_NONDETERMINISM"
    )


def test_a_boundary_second_reported_as_a_whole_number_string_still_pins() -> None:
    local, production = _pinned_pair()
    _set_row(
        (production,),
        SAME_SECOND_CASE_ID,
        boundarySeconds={"authTime": 1_800_000_000, "validSince": "1800000000"},
    )
    assert _classifications(compare(local, production))[SAME_SECOND_CASE_ID] == "MATCH"
