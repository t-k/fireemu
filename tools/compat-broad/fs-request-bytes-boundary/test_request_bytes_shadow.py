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

from request_bytes_campaign import LOCAL_EXPECTATION
from request_bytes_shadow import classify_local_result, shadow_gates

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
    "overRefusal": REFUSAL_413,
}


def test_observed_baseline_is_an_enforced_boundary_with_a_different_shape() -> None:
    verdict = classify_local_result(dict(BASELINE))
    assert verdict["classification"] == "local-boundary-enforced-shape-differs"
    assert verdict["matchesBaseline"] is True
    assert verdict["expectedClassification"] == LOCAL_EXPECTATION["classification"]
    assert verdict["productionRefusalExpectation"] == "400 INVALID_ARGUMENT"
    assert verdict["differenceMasked"] is False


def test_the_baseline_names_the_enforcement_source() -> None:
    verdict = classify_local_result(dict(BASELINE))
    assert "MAX_REST_BODY_BYTES" in verdict["enforcementSource"]
    assert verdict["localEnforcement"] == "transport body cap"


def test_a_typed_400_marks_the_baseline_stale() -> None:
    verdict = classify_local_result(
        {
            **BASELINE,
            "overRefusal": {
                "httpStatus": 400,
                "errorCode": 400,
                "errorStatus": "INVALID_ARGUMENT",
                "classification": "expected",
            },
        }
    )
    assert verdict["classification"] == "local-shape-matches-production-expectation"
    assert verdict["matchesBaseline"] is False


def test_an_accepted_over_probe_is_reported_as_an_unenforced_boundary() -> None:
    verdict = classify_local_result(
        {
            "completed": False,
            "cleanupComplete": False,
            "resourceAbsence": True,
            "failures": ["over:unexpected-success"],
        }
    )
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


def test_an_unenforced_boundary_still_validates_state_when_cleaned_up() -> None:
    result = {
        "completed": False,
        "cleanupComplete": True,
        "resourceAbsence": True,
        "failures": ["over:unexpected-success"],
    }
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert verdict["classification"] == "local-boundary-not-enforced"
    assert gates["stateValidation"] is True
