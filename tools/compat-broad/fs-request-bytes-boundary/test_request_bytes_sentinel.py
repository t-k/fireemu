"""Contracts for the single exploratory 16 MiB request-byte sentinel."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from request_bytes_compiler import (
    DOCUMENT_SAFETY_MARGIN,
    RAW_16MIB_OVER_BYTES,
    RAW_16MIB_OVER_CASE_ID,
    compact_utf8,
    compile_request_bytes_sentinel_plan,
    validate_request_bytes_sentinel_plan,
)
from request_bytes_campaign import (
    compile_request_bytes_sentinel_campaign,
    validate_request_bytes_sentinel_campaign,
)

NONCE = "a" * 32


def test_sentinel_compiles_one_exactly_sized_twenty_document_commit() -> None:
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)

    assert plan["caseId"] == RAW_16MIB_OVER_CASE_ID
    assert plan["catalogId"] == "FS-LIMIT-API-REQUEST-BYTES"
    assert plan["metricStatus"] == "observation hypothesis"
    assert len(plan["probes"]) == 1
    probe = plan["probes"][0]
    assert probe["label"] == "raw-16mib-over"
    assert probe["bodyBytes"] == RAW_16MIB_OVER_BYTES == 16_777_217
    assert len(compact_utf8(probe["body"])) == RAW_16MIB_OVER_BYTES
    assert len(probe["resources"]) == 20
    assert len(plan["ownedResources"]) == 20
    assert len(probe["body"]["writes"]) == 20
    assert all(
        row["currentDocument"] == {"exists": False}
        for row in probe["body"]["writes"]
    )
    assert sum(
        write["update"]["name"].endswith(tuple(f"payload-{i:02d}" for i in range(19)))
        for write in probe["body"]["writes"]
    ) == 19
    assert all(
        doc["logicalBytes"] < DOCUMENT_SAFETY_MARGIN
        for doc in plan["documents"].values()
    )
    assert probe["expected"]["outcome"] == "capture-without-semantic-expectation"
    assert plan["bounds"]["observationRequests"] == 41
    assert plan["bounds"]["recoveryRequests"] == 60
    assert plan["bounds"]["totalRequestBound"] == 101
    validate_request_bytes_sentinel_plan(plan)


def test_sentinel_validator_rejects_body_scope_and_semantic_expectation_drift() -> None:
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["probes"][0]["body"]["writes"][1]["update"]["fields"]["blob"][
        "stringValue"
    ] += "x"
    with pytest.raises(ValueError, match="byte length"):
        validate_request_bytes_sentinel_plan(plan)

    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["recovery"][0]["resource"] = (
        "projects/foreign/databases/(default)/documents/foreign/victim"
    )
    with pytest.raises(ValueError):
        validate_request_bytes_sentinel_plan(plan)

    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["probes"][0]["expected"]["productionExpectation"] = "refused"
    with pytest.raises(ValueError, match="outcome-neutral"):
        validate_request_bytes_sentinel_plan(plan)


def test_sentinel_validator_rejects_create_precondition_and_schedule_drift() -> None:
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["probes"][0]["body"]["writes"][0]["currentDocument"] = {"exists": True}
    with pytest.raises(ValueError, match="exists-false"):
        validate_request_bytes_sentinel_plan(plan)

    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["executionSchedule"].reverse()
    with pytest.raises(ValueError):
        validate_request_bytes_sentinel_plan(plan)


def test_sentinel_campaign_is_finite_costed_and_does_not_predict_outcome() -> None:
    campaign = compile_request_bytes_sentinel_campaign("demo", "(default)", NONCE)

    assert campaign["caseIds"] == [RAW_16MIB_OVER_CASE_ID]
    case = campaign["cases"][0]
    assert case["id"] == RAW_16MIB_OVER_CASE_ID
    assert case["requestBytes"] == RAW_16MIB_OVER_BYTES
    assert case["outcomeExpectation"] == "unknown"
    assert "productionExpectation" not in case
    assert campaign["accounting"] == {
        "documentReads": 80,
        "documentWrites": 20,
        "documentDeletes": 20,
        "dataRequests": 101,
        "managementRequests": 7,
        "httpRequests": 108,
        "uploadedBytes": RAW_16MIB_OVER_BYTES,
    }
    assert campaign["cost"]["estimatedCostMicrousd"] == 88
    assert campaign["budget"]["maxRequestBytes"] == RAW_16MIB_OVER_BYTES
    assert campaign["transportDeadlineSeconds"] == 80
    assert campaign["budget"]["recoveryWindow"]["reserveDeletes"] == 20
    validate_request_bytes_sentinel_campaign(campaign)


def test_sentinel_campaign_validator_rejects_outcome_and_budget_drift() -> None:
    campaign = compile_request_bytes_sentinel_campaign("demo", "(default)", NONCE)
    campaign["cases"][0]["outcomeExpectation"] = "refused"
    with pytest.raises(ValueError, match="outcome-neutral"):
        validate_request_bytes_sentinel_campaign(campaign)

    campaign = compile_request_bytes_sentinel_campaign("demo", "(default)", NONCE)
    campaign["budget"]["maxDeletes"] = 19
    with pytest.raises(ValueError, match="budget"):
        validate_request_bytes_sentinel_campaign(campaign)
