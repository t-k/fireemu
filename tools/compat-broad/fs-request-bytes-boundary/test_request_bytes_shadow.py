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
from request_bytes_run_fixture import (
    TYPED_400,
    TYPED_413,
    UNTYPED_413,
    run_collector,
)
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


def test_round_trip_typed_413_is_the_observed_baseline(tmp_path) -> None:
    result = run_collector(tmp_path / "typed413", over=TYPED_413)
    assert result["completed"] is True
    assert result["failures"] == []
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert verdict["classification"] == "local-boundary-enforced-shape-differs"
    assert verdict["matchesBaseline"] is True
    assert gates == {"recordingComplete": True, "stateValidation": True}


def test_round_trip_typed_400_marks_the_baseline_stale(tmp_path) -> None:
    result = run_collector(tmp_path / "typed400", over=TYPED_400)
    assert result["overRefusal"]["classification"] == "expected"
    verdict = classify_local_result(result)
    gates = shadow_gates(result, verdict, source_bound=True)
    assert verdict["classification"] == "local-shape-matches-production-expectation"
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
