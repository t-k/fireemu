"""Contract tests for the AUTH-CREDENTIAL comparison contract."""

from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import credential_comparator as comparator
from credential_cases import (
    SAME_SECOND_CASE_ID,
    case_by_id,
    control_members,
    observation_cases,
)
from credential_collector import (
    build_receipt,
    claim_set,
    claim_shape,
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
        **control_members(case),
    }
    if (row["assertions"].get("idTokenReturned") is True
            or row["assertions"].get("sessionCookieReturned") is True
            or case["group"] == "claim-precedence"):
        # Synthetic token, passed through the actual collector projection. No
        # signature verification or production observation is claimed by a fixture.
        def segment(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
        token = segment({"alg": "none"}) + "." + segment({"sub": "fixture-user"}) + "."
        row["claims"] = claim_set(claim_shape(token))
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
        budget=new_budget(60, 600, 0.05, started_monotonic=0.0),
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


# --- claim-set hygiene: the local-only session marker is never a difference --------

PRODUCTION_CLAIMS = {
    "claimNames": ["aud", "auth_time", "exp", "firebase", "iat", "iss", "sub", "user_id"],
    "claimTypes": {
        "aud": "string",
        "auth_time": "int",
        "exp": "int",
        "firebase": "object",
        "iat": "int",
        "iss": "string",
        "sub": "string",
        "user_id": "string",
    },
    "firebase": {
        "claimNames": ["identities", "sign_in_provider"],
        "claimTypes": {"identities": "object", "sign_in_provider": "string"},
    },
}


def _local_claims_with_epoch() -> dict:
    claims = json.loads(json.dumps(PRODUCTION_CLAIMS))
    claims["firebase"]["claimNames"] = sorted(
        [*claims["firebase"]["claimNames"], "fireemu_session_epoch"]
    )
    claims["firebase"]["claimTypes"]["fireemu_session_epoch"] = "string"
    return claims


def test_a_local_token_with_the_session_epoch_matches_a_production_token_without_it() -> (
    None
):
    local = _local_claims_with_epoch()
    assert local != PRODUCTION_CLAIMS
    assert comparator.compare_claim_sets(local, PRODUCTION_CLAIMS) == "MATCH"
    assert comparator.compare_claim_sets(PRODUCTION_CLAIMS, local) == "MATCH"
    # Stripping is a projection for comparison; the inputs are left as recorded.
    assert "fireemu_session_epoch" in local["firebase"]["claimNames"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["claimNames"].append("email"),
        lambda c: c["claimTypes"].update({"auth_time": "string"}),
        lambda c: c["firebase"]["claimNames"].append("tenant"),
        lambda c: c["firebase"]["claimTypes"].update({"sign_in_provider": "null"}),
        lambda c: c.update({"firebase": None}),
        lambda c: c["claimNames"].remove("user_id"),
    ],
)
def test_any_other_claim_difference_is_a_semantic_mismatch(mutate) -> None:
    local = _local_claims_with_epoch()
    mutate(local)
    assert comparator.compare_claim_sets(local, PRODUCTION_CLAIMS) == "SEMANTIC_MISMATCH"


def test_a_top_level_claim_with_the_same_name_is_not_stripped() -> None:
    # Only `firebase.fireemu_session_epoch` is local-only. A claim of that name at the
    # top level is not the marker and stays a difference.
    local = json.loads(json.dumps(PRODUCTION_CLAIMS))
    local["claimNames"] = sorted([*local["claimNames"], "fireemu_session_epoch"])
    local["claimTypes"]["fireemu_session_epoch"] = "string"
    assert comparator.compare_claim_sets(local, PRODUCTION_CLAIMS) == "SEMANTIC_MISMATCH"


@pytest.mark.parametrize("bad", [None, [], "claims", {"claimNames": float("nan")}])
def test_a_malformed_claim_set_never_matches(bad) -> None:
    assert comparator.compare_claim_sets(bad, PRODUCTION_CLAIMS) == "SEMANTIC_MISMATCH"
    assert comparator.compare_claim_sets(PRODUCTION_CLAIMS, bad) == "SEMANTIC_MISMATCH"


def test_row_claim_sets_are_compared_with_the_epoch_stripped() -> None:
    local, production = _receipt("local"), _receipt("production")
    case_id = "refresh-preserves-auth-time"
    _set_row((local,), case_id, claims=_local_claims_with_epoch())
    _set_row((production,), case_id, claims=json.loads(json.dumps(PRODUCTION_CLAIMS)))
    assert _classifications(compare(local, production))[case_id] == "MATCH"
    # Any other claim difference on the row is still a difference.
    differing = json.loads(json.dumps(PRODUCTION_CLAIMS))
    differing["claimNames"] = sorted([*differing["claimNames"], "email"])
    differing["claimTypes"]["email"] = "string"
    _set_row((production,), case_id, claims=differing)
    assert _classifications(compare(local, production))[case_id] == "DIFFERENT"


# --- the fresh control on a refusal row must hold on both sides ---------------------


@pytest.mark.parametrize(
    "case_id",
    ["refresh-after-password-reset-rejected", "refresh-after-explicit-valid-since-rejected"],
)
def test_a_refusal_row_whose_fresh_control_did_not_hold_is_indeterminate(case_id) -> None:
    local, production = _receipt("local"), _receipt("production")
    assert _classifications(compare(local, production))[case_id] == "MATCH"
    for control in (
        {"status": 400, "errorCode": "TOKEN_EXPIRED"},
        {"status": 200, "errorCode": "TOKEN_EXPIRED"},
        {"status": "200", "errorCode": None},
        None,
    ):
        for side in (local, production):
            weakened = json.loads(json.dumps(side))
            _set_row((weakened,), case_id, freshSessionRefresh=control)
            other = production if side is local else local
            pair = (weakened, other) if side is local else (other, weakened)
            assert _classifications(compare(*pair))[case_id] == "INDETERMINATE", control


def test_the_refusal_code_itself_is_still_compared_when_the_control_holds() -> None:
    local, production = _receipt("local"), _receipt("production")
    case_id = "refresh-after-password-reset-rejected"
    # Production answering TOKEN_EXPIRED where the local runtime answers
    # INVALID_REFRESH_TOKEN is the finding this row exists to record.
    _set_row((production,), case_id, errorCode="TOKEN_EXPIRED")
    assert _classifications(compare(local, production))[case_id] == "DIFFERENT"
