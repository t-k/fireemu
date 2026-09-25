"""Round trip the shipped shadow receipt through the shipped comparator.

These checks iterate the comparator's required inputs, not the receipt's own
keys, so widening the contract without widening the collector breaks the build.
"""

import json
from pathlib import Path

from o6_listen_resume import observation
from o6_listen_resume.campaign import STATUS_PREPARED, compile_campaign
from o6_listen_resume.observation import (
    BOUND_SOURCES,
    compare_observations,
    receipt_errors,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = REPO_ROOT / "spec/compatibility/fs-listen-sdk-local-shadow.json"
CAMPAIGN = REPO_ROOT / "spec/compatibility/fs-listen-sdk-local-shadow-campaign.json"


def _receipt():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def _campaign_record():
    return json.loads(CAMPAIGN.read_text(encoding="utf-8"))


def test_the_shipped_receipt_passes_the_shipped_comparator_admission():
    errors = receipt_errors(
        _campaign_record()["campaign"], _receipt(), side="local", base_dir=REPO_ROOT
    )
    assert errors == []


def test_the_receipt_carries_every_source_the_contract_binds():
    declared = _receipt()["sourceDigests"]
    assert set(declared) == set(BOUND_SOURCES)
    for relative in BOUND_SOURCES:
        assert declared[relative] != "missing", relative


def test_the_receipt_carries_every_field_the_production_branch_requires():
    receipt = _receipt()
    # The production branch reads these in addition to the local ones. The
    # collector must emit them even on a local run, or no collector could ever
    # satisfy the contract it ships with.
    for field in ("permission", "sdkResolved", "transportTimeline", "campaignDigest"):
        assert field in receipt, field
    assert receipt["sdkResolved"] == _campaign_record()["campaign"]["sdk"]


def test_a_production_shaped_copy_of_the_shipped_receipt_is_admitted():
    record = _campaign_record()
    prepared = compile_campaign(
        record["nonce"], permission="o6-listen-sdk-0f1e2d3c4b5a6978"
    )
    assert prepared["status"] == STATUS_PREPARED
    receipt = _receipt()
    receipt["campaignDigest"] = observation.campaign_digest(prepared)
    receipt["productionExecuted"] = True
    receipt["environment"] = {**receipt["environment"], "kind": "production-oracle"}
    receipt["permission"] = prepared["permission"]
    errors = receipt_errors(prepared, receipt, side="production", base_dir=REPO_ROOT)
    assert errors == []


def test_the_shipped_receipt_compared_against_itself_is_refused_not_matched():
    campaign = _campaign_record()["campaign"]
    result = compare_observations(campaign, _receipt(), _receipt(), base_dir=REPO_ROOT)
    assert result["promotionReady"] is False
    assert "production:production-not-executed" in result["errors"]
