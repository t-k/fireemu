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
from request_bytes_shadow import classify_local_result

PENDING = {
    "completed": False,
    "cleanupComplete": False,
    "resourceAbsence": True,
    "failures": ["over:unexpected-success"],
}


def test_pending_implementation_is_an_expected_difference() -> None:
    verdict = classify_local_result(dict(PENDING))
    assert verdict["classification"] == "expected-local-difference"
    assert verdict["localEnforcement"] == "implementation pending"
    assert verdict["differenceMasked"] is False
    assert verdict["observedFailures"] == LOCAL_EXPECTATION["expectedCollectorFailures"]


def test_a_local_refusal_marks_the_expectation_stale() -> None:
    verdict = classify_local_result(
        {
            "completed": True,
            "cleanupComplete": True,
            "resourceAbsence": True,
            "failures": [],
            "overRefusal": {
                "httpStatus": 400,
                "errorCode": 400,
                "errorStatus": "INVALID_ARGUMENT",
                "classification": "expected",
            },
        }
    )
    assert verdict["classification"] == "local-enforcement-observed"
    assert verdict["overRefusal"]["httpStatus"] == 400


@pytest.mark.parametrize(
    "result",
    [
        pytest.param({**PENDING, "resourceAbsence": False}, id="cleanup-incomplete"),
        pytest.param({**PENDING, "failures": []}, id="no-failure-recorded"),
        pytest.param(
            {
                **PENDING,
                "failures": ["over:unexpected-success", "under:commit-proof-missing"],
            },
            id="extra-failure",
        ),
        pytest.param(
            {**PENDING, "failures": ["under:commit-proof-missing"]}, id="wrong-failure"
        ),
        pytest.param(
            {**PENDING, "overRefusal": {"httpStatus": 400}}, id="refusal-with-failures"
        ),
        pytest.param(
            {
                "completed": True,
                "cleanupComplete": True,
                "resourceAbsence": True,
                "failures": [],
            },
            id="clean-run-without-a-refusal",
        ),
        pytest.param(
            {
                "completed": False,
                "resourceAbsence": True,
                "failures": [],
                "overRefusal": {"httpStatus": 413},
            },
            id="refusal-but-not-completed",
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
    verdict = classify_local_result(dict(PENDING))
    assert verdict["productionExecuted"] is False
    assert verdict["formalCompatibilityClaim"] is False
