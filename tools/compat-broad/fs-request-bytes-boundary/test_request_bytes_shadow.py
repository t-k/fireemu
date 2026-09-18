"""Offline tests for the request-byte local shadow classification.

These tests use synthetic collector results. They start no emulator, build no
artifact and send no request.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from request_bytes_campaign import BASELINE_COMPARISON_FIELDS, LOCAL_EXPECTATION
from request_bytes_run_fixture import (
    EXPECTED_MESSAGE,
    TYPED_400,
    TYPED_400_NO_MESSAGE,
    TYPED_400_OTHER_MESSAGE,
    TYPED_413,
    UNTYPED_413,
    run_collector,
)
from request_bytes_shadow import classify_local_result, shadow_gates

REFUSAL_400 = {
    "httpStatus": 400,
    "errorCode": 400,
    "errorStatus": "INVALID_ARGUMENT",
    "message": "Request payload size exceeds the limit: 10485760 bytes.",
    "classification": "expected",
}

REFUSAL_413 = {
    "httpStatus": 413,
    "errorCode": 413,
    "errorStatus": "INVALID_ARGUMENT",
    "classification": "semantic-discrepancy",
}

BASELINE = {
    "completed": True,
    "cleanupComplete": True,
    "resourceAbsence": True,
    "failures": [],
    "overRefusal": REFUSAL_400,
}


def test_observed_baseline_matches_the_expected_production_shape() -> None:
    verdict = classify_local_result(dict(BASELINE))
    assert verdict["classification"] == "local-shape-matches-production-expectation"
    assert verdict["matchesBaseline"] is True
    assert verdict["expectedClassification"] == LOCAL_EXPECTATION["classification"]
    assert verdict["productionRefusalExpectation"] == "400 INVALID_ARGUMENT"
    assert verdict["differenceMasked"] is False


def test_the_baseline_names_the_enforcement_source() -> None:
    verdict = classify_local_result(dict(BASELINE))
    assert "API_REQUEST_BYTES" in verdict["enforcementSource"]
    assert "strict profile" in verdict["localEnforcement"]


def test_agreement_with_the_documented_shape_is_not_confirmation_of_it() -> None:
    verdict = classify_local_result(dict(BASELINE))
    assert "not confirmation of it" in verdict["summary"]


def test_a_legacy_413_is_now_reported_as_a_lost_shape() -> None:
    """The emulator profile's refusal from a strict build is a regression."""
    verdict = classify_local_result({**BASELINE, "overRefusal": REFUSAL_413})
    assert verdict["classification"] == "local-boundary-enforced-shape-differs"
    assert verdict["matchesBaseline"] is False
    assert "regression" in verdict["summary"]


def test_an_accepted_over_probe_is_reported_as_an_unenforced_boundary(
    tmp_path,
) -> None:
    result = run_collector(tmp_path / "accepted", over=None)
    verdict = classify_local_result(result)
    assert verdict["classification"] == "local-boundary-not-enforced"
    assert verdict["matchesBaseline"] is False


@pytest.mark.parametrize(
    "result",
    [
        pytest.param({**BASELINE, "resourceAbsence": False}, id="cleanup-incomplete"),
        pytest.param({**BASELINE, "completed": False}, id="not-completed"),
        pytest.param(
            {**BASELINE, "failures": ["under:commit-proof-missing"]},
            id="failure-alongside-refusal",
        ),
        pytest.param({**BASELINE, "overRefusal": None}, id="clean-run-without-refusal"),
        pytest.param(
            {**BASELINE, "overRefusal": {"httpStatus": 500}}, id="unexpected-code"
        ),
        pytest.param(
            {**BASELINE, "overRefusal": {"httpStatus": 429}}, id="resource-exhausted"
        ),
        pytest.param({**BASELINE, "overRefusal": "413"}, id="refusal-not-an-object"),
        pytest.param(
            {
                "completed": False,
                "resourceAbsence": False,
                "failures": ["over:unexpected-success"],
            },
            id="accepted-but-not-cleaned-up",
        ),
        pytest.param(
            {
                "completed": False,
                "resourceAbsence": True,
                "failures": ["over:unexpected-success", "under:commit-proof-missing"],
            },
            id="accepted-with-extra-failure",
        ),
    ],
)
def test_unexpected_local_outcomes_are_shadow_failures(result: dict) -> None:
    assert classify_local_result(result)["classification"] == "shadow-failure"


def test_malformed_results_are_rejected_rather_than_classified() -> None:
    with pytest.raises(TypeError):
        classify_local_result(["not", "an", "object"])
    with pytest.raises(TypeError):
        classify_local_result({"failures": "over:unexpected-success"})


def test_classification_never_claims_production() -> None:
    verdict = classify_local_result(dict(BASELINE))
    assert verdict["productionExecuted"] is False
    assert verdict["formalCompatibilityClaim"] is False


def test_gates_pass_on_a_recognised_outcome_with_full_absence() -> None:
    verdict = classify_local_result(dict(BASELINE))
    gates = shadow_gates(dict(BASELINE), verdict, source_bound=True)
    assert gates == {"recordingComplete": True, "stateValidation": True}


def test_gates_fail_when_the_source_binding_broke() -> None:
    verdict = classify_local_result(dict(BASELINE))
    gates = shadow_gates(dict(BASELINE), verdict, source_bound=False)
    assert gates["stateValidation"] is False


def test_gates_fail_on_a_shadow_failure() -> None:
    result = {**BASELINE, "overRefusal": {"httpStatus": 500}}
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert verdict["classification"] == "shadow-failure"
    assert gates["stateValidation"] is False


def test_gates_fail_when_resources_were_left_behind() -> None:
    result = {**BASELINE, "resourceAbsence": False, "cleanupComplete": False}
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert gates == {"recordingComplete": False, "stateValidation": False}


def test_an_unenforced_boundary_validates_state_but_is_not_a_complete_recording(
    tmp_path,
) -> None:
    """The collector cannot report cleanupComplete while it holds a failure.

    `over:unexpected-success` is itself a failure, and `cleanupComplete` is
    `absence and not failures`, so the enforcement-regression outcome always
    arrives with `recordingComplete` false even though every resource was
    removed. The shadow still validates state, so the supervisor records the
    regression instead of discarding the run.
    """
    result = run_collector(tmp_path / "accepted", over=None)
    assert result["failures"] == ["over:unexpected-success"]
    assert result["cleanupComplete"] is False
    assert result["resourceAbsence"] is True
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert verdict["classification"] == "local-boundary-not-enforced"
    assert gates["stateValidation"] is True
    assert gates["recordingComplete"] is False


# --- Round trips against results the collector actually produced --------------


def test_round_trip_typed_400_is_the_observed_baseline(tmp_path) -> None:
    result = run_collector(tmp_path / "typed400", over=TYPED_400)
    assert result["completed"] is True
    assert result["failures"] == []
    assert result["overRefusal"]["classification"] == "expected"
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert verdict["classification"] == "local-shape-matches-production-expectation"
    assert verdict["matchesBaseline"] is True
    assert gates == {"recordingComplete": True, "stateValidation": True}


def test_round_trip_typed_413_is_a_lost_shape_not_a_pass(tmp_path) -> None:
    result = run_collector(tmp_path / "typed413", over=TYPED_413)
    assert result["overRefusal"]["classification"] == "semantic-discrepancy"
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert verdict["classification"] == "local-boundary-enforced-shape-differs"
    assert verdict["matchesBaseline"] is False
    # The run is still internally sound, so the regression is recorded rather
    # than thrown away; it simply is not the baseline.
    assert gates == {"recordingComplete": True, "stateValidation": True}


def test_round_trip_untyped_refusal_is_its_own_outcome(tmp_path) -> None:
    result = run_collector(tmp_path / "untyped", over=UNTYPED_413)
    assert "overRefusal" not in result
    untyped = result["untypedOverRefusal"]
    assert untyped["classification"] == "untyped-transport-refusal"
    assert untyped["httpStatus"] == 413
    assert untyped["contentType"].startswith("text/html")
    assert untyped["refusalShapeProven"] is False
    assert untyped["grantsCleanupOwnership"] is False
    assert untyped["recoveryAuthority"] == "read-only"
    verdict = classify_local_result(result)
    assert verdict["classification"] == "local-untyped-transport-refusal"
    assert verdict["untypedOverRefusal"] == untyped
    # Nothing was written, and nothing was deleted on an unproven refusal.
    assert result["resourceAbsence"] is True


def test_an_untyped_refusal_never_becomes_a_typed_one(tmp_path) -> None:
    result = run_collector(tmp_path / "untyped", over=UNTYPED_413)
    assert result.get("overRefusal") is None
    assert result["completed"] is False
    # The unproven refusal costs the commit proof and then refuses every
    # version-bound delete for want of a creation proof. No DELETE is sent.
    assert result["failures"][0] == "over:commit-proof-missing"
    assert len(result["failures"]) == 18
    assert all(
        entry.endswith(":creation-and-current-version-not-proven")
        for entry in result["failures"][1:]
    )


def test_the_collector_records_the_untyped_body_verbatim(tmp_path) -> None:
    import base64
    import hashlib

    result = run_collector(tmp_path / "untyped", over=UNTYPED_413)
    untyped = result["untypedOverRefusal"]
    raw = UNTYPED_413["body"].encode()
    assert untyped["bodyBytes"] == len(raw)
    assert untyped["bodySha256"] == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(untyped["bodyBase64"]) == raw
    assert untyped["bodyTruncated"] is False


# --- The refusal shape is compared field by field -----------------------------
#
# Each of these drives the real collector from a raw response body, so the
# message travels the same path a production run would use: wire bytes, receipt,
# collector `overRefusal`, classification.


def test_round_trip_matching_message_is_the_baseline(tmp_path) -> None:
    result = run_collector(tmp_path / "match", over=TYPED_400)
    assert result["overRefusal"]["message"] == EXPECTED_MESSAGE
    verdict = classify_local_result(result)
    assert verdict["classification"] == "local-shape-matches-production-expectation"
    assert verdict["matchesBaseline"] is True
    assert verdict["refusalFieldMismatches"] == []


def test_round_trip_different_wording_is_not_a_match(tmp_path) -> None:
    """The reviewer's case: right status and code, someone else's message."""
    result = run_collector(tmp_path / "other", over=TYPED_400_OTHER_MESSAGE)
    assert result["overRefusal"]["httpStatus"] == 400
    assert result["overRefusal"]["errorCode"] == 400
    assert result["overRefusal"]["message"] == "The request is too large."
    verdict = classify_local_result(result)
    assert verdict["matchesBaseline"] is False
    assert verdict["classification"] == "local-boundary-enforced-shape-differs"
    assert [item["field"] for item in verdict["refusalFieldMismatches"]] == ["message"]
    assert "message" in verdict["summary"]


def test_round_trip_missing_message_is_not_a_match(tmp_path) -> None:
    """The reviewer's other case: no message at all must not pass."""
    result = run_collector(tmp_path / "none", over=TYPED_400_NO_MESSAGE)
    assert result["overRefusal"]["message"] is None
    verdict = classify_local_result(result)
    assert verdict["matchesBaseline"] is False
    assert verdict["classification"] == "local-boundary-enforced-shape-differs"
    assert [item["field"] for item in verdict["refusalFieldMismatches"]] == ["message"]


@pytest.mark.parametrize(
    "over",
    [
        pytest.param(TYPED_400_OTHER_MESSAGE, id="different-wording"),
        pytest.param(TYPED_400_NO_MESSAGE, id="missing-message"),
        pytest.param(TYPED_413, id="legacy-413"),
    ],
)
def test_a_shape_difference_keeps_the_recording_and_recovery_facts(
    tmp_path, over
) -> None:
    """Only matchesBaseline goes false; the run is still sound and recorded."""
    result = run_collector(tmp_path / "differs", over=over)
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert verdict["matchesBaseline"] is False
    assert result["resourceAbsence"] is True
    assert result["cleanupComplete"] is True
    assert gates == {"recordingComplete": True, "stateValidation": True}


def test_the_recorded_message_is_bound_to_the_response_digest(tmp_path) -> None:
    import hashlib
    import json

    result = run_collector(tmp_path / "bound", over=TYPED_400)
    refusal = result["overRefusal"]
    raw = json.dumps(TYPED_400["body"], separators=(",", ":")).encode()
    assert refusal["responseSha256"] == hashlib.sha256(raw).hexdigest()
    assert refusal["responseBytes"] == len(raw)
    assert json.loads(raw)["error"]["message"] == refusal["message"]


def test_every_declared_comparison_field_is_actually_compared() -> None:
    """A field named in the contract but never compared is the original defect."""
    from request_bytes_shadow import refusal_field_mismatches

    expected = LOCAL_EXPECTATION["observedRefusal"]
    for field in BASELINE_COMPARISON_FIELDS:
        altered = {key: expected[key] for key in BASELINE_COMPARISON_FIELDS}
        altered[field] = "definitely-not-the-expected-value"
        assert [item["field"] for item in refusal_field_mismatches(altered)] == [field]
