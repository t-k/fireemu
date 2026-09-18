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
from credential_comparator import CONTRACT, DIAGNOSTIC_MEMBERS, compare

COLLECTOR_BINDING = {"commit": "a" * 40, "collectorSha256": "b" * 64}


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


def _receipt(side: str, *, production_executed: bool | None = None) -> dict:
    rows = [_row(case) for case in observation_cases()]
    if side == "production":
        for row in rows:
            row["trustRoot"] = "signed"
    return {
        "side": side,
        "productionExecuted": side == "production"
        if production_executed is None
        else production_executed,
        "recordingComplete": True,
        "collectorBinding": dict(COLLECTOR_BINDING),
        "cleanup": {
            "ownedAccounts": 2,
            "remainingAccounts": 0,
            "cleanupComplete": True,
        },
        "rows": rows,
    }


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
    local, production = _receipt("local"), _receipt("production")
    for receipt in (local, production):
        for row in receipt["rows"]:
            if row["caseId"] == SAME_SECOND_CASE_ID:
                row["boundaryPinned"] = True
    assert _classifications(compare(local, production))[SAME_SECOND_CASE_ID] == "MATCH"

    for row in production["rows"]:
        if row["caseId"] == SAME_SECOND_CASE_ID:
            row["status"], row["errorCode"], row["assertions"] = (
                400,
                "TOKEN_EXPIRED",
                {},
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


def test_boundary_is_indeterminate_when_a_neighbouring_control_did_not_hold() -> None:
    controls = case_by_id(SAME_SECOND_CASE_ID)["boundaryControls"]
    for control_id in controls.values():
        local, production = _receipt("local"), _receipt("production")
        for receipt in (local, production):
            for row in receipt["rows"]:
                if row["caseId"] == SAME_SECOND_CASE_ID:
                    row["boundaryPinned"] = True
        for row in production["rows"]:
            if row["caseId"] == control_id:
                row["status"] = 503
        classes = _classifications(compare(local, production))
        assert classes[control_id] == "DIFFERENT"
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
