"""Fixed Query Explain campaign contract and production boundary fixtures."""

import copy
import json

import pytest

from broad_contract import digest
from campaign_explain import (
    binding,
    campaign_manifest,
    manifest,
    validate_manifest,
)


def test_manifest_is_exactly_six_owned_explain_cases():
    value = manifest()
    assert value["kind"] == "production-campaign-explain-01-v1"
    assert value["status"] == "prepared-offline"
    assert value["productionExecutable"] is True
    assert value["template"]["nonce"] == "{freshNonce}"
    assert value["template"]["wallSeconds"] <= 1200
    assert value["template"]["costMicrousd"] < 100_000
    assert len(value["cases"]) == 6
    assert {case["method"] for case in value["cases"]} == {
        "runQuery",
        "runAggregationQuery",
    }
    assert {case["mode"] for case in value["cases"]} == {
        "plan-only",
        "analyze",
        "empty-analyze",
    }


def test_manifest_rejects_nonce_or_case_drift():
    value = manifest()
    changed = copy.deepcopy(value)
    changed["template"]["jobs"]["query-explain"]["observation"][4]["method"] = "GET"
    with pytest.raises(ValueError, match="manifest drift"):
        validate_manifest(changed)

    with pytest.raises(ValueError, match="fresh hexadecimal namespace"):
        campaign_manifest("old-nonce")


def test_manifest_binds_metadata_and_recovery_budget():
    plan = campaign_manifest("a" * 32)
    assert len(plan["management"]["observation"]) == 6
    assert len(plan["management"]["recovery"]) == 6
    assert plan["observationRequests"] == 18
    assert plan["recoveryRequests"] == 12
    assert plan["totalRequests"] == 30
    assert plan["recoveryRequestIds"] == [
        "recovery:access-command",
        "recovery:tokeninfo",
        "recovery:project",
        "recovery:database",
        "recovery:auth",
        "recovery:key",
    ]


def test_checked_in_manifest_and_binding_are_stable():
    path = __import__("pathlib").Path(__file__).parents[2] / "spec/compatibility/broad-runs/prod-campaign-explain-01.json"
    assert json.loads(path.read_bytes()) == manifest()
    assert binding()["manifestDigest"] == digest(manifest())


@pytest.mark.parametrize(
    "field",
    ["observerSha256", "configurationDigest", "databaseProjectionContractDigest"],
)
def test_environment_baseline_drift_fails_closed(field):
    value = manifest()
    value["environment"][field] = "drift"
    with pytest.raises(ValueError, match="environment baseline drift"):
        validate_manifest(value)


def test_comparator_contract_retains_mismatch_and_indeterminate():
    from shared_production_pair import compare_campaign_rows

    rows = manifest()["template"]["jobs"]["query-explain"]["stepIds"]
    base = {
        "recordingComplete": True,
        "collectionComplete": True,
        "cleanupComplete": True,
        "stateValidation": True,
        "principalEvidence": {
            "job": "query-explain",
            "nonce": "a" * 32,
            "localOrigins": {"auth": "http://127.0.0.1:18081", "firestore": "http://127.0.0.1:18082"},
            "planDigest": digest({**campaign_manifest("a" * 32), "localOrigins": {"auth": "http://127.0.0.1:18081", "firestore": "http://127.0.0.1:18082"}}),
            "dispatch": {"observation": [], "recovery": []},
        },
        "rows": [{"id": row, "request": {}} for row in rows],
        "cleanup": [],
    }
    changed = copy.deepcopy(base)
    changed["rows"][0]["body"] = {"error": {"status": "FAILED_PRECONDITION"}}
    result = compare_campaign_rows(base, changed, rows)
    assert result["compatibility"] == "indeterminate"
