import copy
from pathlib import Path

import pytest
from o6_listen_resume import cases
from o6_listen_resume.campaign import campaign_digest, compile_campaign
from o6_listen_resume.observation import (
    INDETERMINATE,
    MATCH,
    REFUSED,
    SCHEMA,
    SEMANTIC_MISMATCH,
    compare_observations,
    compute_source_digests,
    receipt_errors,
)

NONCE = "0123456789abcdef0123456789abcdef"
PERMISSION = "o6-listen-sdk-0f1e2d3c4b5a6978"
REPO_ROOT = Path(__file__).resolve().parents[3]


def _case_row(case):
    return {
        "caseId": case["caseId"],
        "role": case["role"],
        "comparison": case["comparison"],
        "complete": True,
        "failures": [],
        "observed": copy.deepcopy(case["expectedLocal"]),
        "rawEventCount": len(case["expectedLocal"]),
        "invariantViolations": [],
        "listenersClosed": True,
        "comparedFields": list(case["comparedFields"]),
    }


def _receipt(campaign, *, side):
    receipt = {
        "schema": SCHEMA,
        "caseId": campaign["caseId"],
        "campaignDigest": campaign_digest(campaign),
        "catalogDigest": cases.catalog_digest(),
        "sourceDigests": compute_source_digests(REPO_ROOT),
        "productionExecuted": side == "production",
        "environment": {
            "kind": "production-oracle" if side == "production" else "local-fireemu",
            "node": "24.14.0",
        },
        "budget": {"exhausted": False, "used": {}, "limits": {}},
        "cleanup": {"complete": True, "rows": []},
        "complete": True,
        "cases": [_case_row(case) for case in cases.CASES],
    }
    if side == "production":
        receipt["permission"] = campaign["permission"]
        receipt["sdkResolved"] = dict(campaign["sdk"])
        receipt["transportTimeline"] = [
            {"kind": "connect", "atMs": 0},
            {"kind": "disconnect", "atMs": 1000},
            {"kind": "reconnect", "atMs": 1500},
        ]
    return receipt


@pytest.fixture
def prepared():
    return compile_campaign(NONCE, permission=PERMISSION)


def test_bound_sources_exist_and_hash_to_hex(prepared):
    digests = compute_source_digests(REPO_ROOT)
    assert digests
    for relative, value in digests.items():
        assert value != "missing", relative
        assert len(value) == 64


def test_matching_receipts_from_both_sides_reach_match(prepared):
    result = compare_observations(
        prepared,
        _receipt(prepared, side="local"),
        _receipt(prepared, side="production"),
        base_dir=REPO_ROOT,
    )
    assert result["errors"] == []
    assert result["classification"] == MATCH
    assert result["acquisitionValidated"] is True
    assert result["promotionReady"] is True
    assert len(result["rows"]) == len(cases.CASES)
    assert {row["classification"] for row in result["rows"]} == {MATCH}


def test_a_local_receipt_alone_can_never_reach_match(prepared):
    result = compare_observations(
        prepared, _receipt(prepared, side="local"), None, base_dir=REPO_ROOT
    )
    assert result["classification"] == INDETERMINATE
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False
    assert "production:not-observed" in result["errors"]


def test_the_same_receipt_on_both_sides_is_refused_as_a_production_claim(prepared):
    local = _receipt(prepared, side="local")
    result = compare_observations(
        prepared, local, copy.deepcopy(local), base_dir=REPO_ROOT
    )
    assert result["classification"] == INDETERMINATE
    assert "production:production-not-executed" in result["errors"]


def test_flipping_the_production_marker_does_not_manufacture_evidence(prepared):
    forged = _receipt(prepared, side="local")
    forged["productionExecuted"] = True
    forged["environment"]["kind"] = "production-oracle"
    result = compare_observations(
        prepared, _receipt(prepared, side="local"), forged, base_dir=REPO_ROOT
    )
    assert result["classification"] == INDETERMINATE
    assert "production:permission-binding" in result["errors"]
    assert "production:transport-timeline-missing" in result["errors"]


def test_an_unprepared_campaign_cannot_admit_a_production_receipt():
    blocked = compile_campaign(NONCE)
    production = _receipt(blocked, side="production")
    production["permission"] = None
    result = compare_observations(
        blocked, _receipt(blocked, side="local"), production, base_dir=REPO_ROOT
    )
    assert result["classification"] == INDETERMINATE
    assert "production:campaign-not-prepared" in result["errors"]


def test_a_differing_event_sequence_is_a_semantic_mismatch(prepared):
    production = _receipt(prepared, side="production")
    production["cases"][0]["observed"][0]["exists"] = False
    result = compare_observations(
        prepared, _receipt(prepared, side="local"), production, base_dir=REPO_ROOT
    )
    assert result["classification"] == SEMANTIC_MISMATCH
    assert result["promotionReady"] is False
    mismatched = [
        row for row in result["rows"] if row["classification"] == SEMANTIC_MISMATCH
    ]
    assert [row["caseId"] for row in mismatched] == [cases.CASES[0]["caseId"]]
    assert mismatched[0]["localDigest"] != mismatched[0]["productionDigest"]


def test_a_case_with_no_events_is_indeterminate_not_a_match(prepared):
    production = _receipt(prepared, side="production")
    local = _receipt(prepared, side="local")
    production["cases"][0]["observed"] = []
    local["cases"][0]["observed"] = []
    result = compare_observations(prepared, local, production, base_dir=REPO_ROOT)
    assert result["classification"] == INDETERMINATE
    row = result["rows"][0]
    assert row["classification"] == INDETERMINATE
    assert "local-no-events" in row["reasons"]


def test_an_invariant_violation_blocks_a_match(prepared):
    production = _receipt(prepared, side="production")
    production["cases"][4]["invariantViolations"] = [
        {"invariant": "no-event-after-unsubscribe", "detail": "leak"}
    ]
    result = compare_observations(
        prepared, _receipt(prepared, side="local"), production, base_dir=REPO_ROOT
    )
    assert result["classification"] == INDETERMINATE
    row = next(r for r in result["rows"] if r["caseId"] == cases.CASES[4]["caseId"])
    assert "production-invariant-violation" in row["reasons"]


def test_a_listener_leak_blocks_a_match(prepared):
    production = _receipt(prepared, side="production")
    production["cases"][0]["listenersClosed"] = False
    result = compare_observations(
        prepared, _receipt(prepared, side="local"), production, base_dir=REPO_ROOT
    )
    assert result["rows"][0]["classification"] == INDETERMINATE
    assert "production-listener-leak" in result["rows"][0]["reasons"]


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (
            lambda r: r.update(cleanup={"complete": False, "rows": []}),
            "cleanup-unproven",
        ),
        (
            lambda r: r.update(budget={"exhausted": True, "used": {}, "limits": {}}),
            "budget-unproven",
        ),
        (lambda r: r.update(complete=False), "receipt-incomplete"),
        (lambda r: r.update(campaignDigest="0" * 64), "campaign-binding"),
        (lambda r: r.update(catalogDigest="0" * 64), "catalog-binding"),
        (lambda r: r.update(sourceDigests={"a": "b"}), "source-digest-drift"),
        (lambda r: r.pop("sourceDigests"), "source-digests-missing"),
        (lambda r: r["cases"].pop(), "case-coverage"),
        (lambda r: r.update(schema="other"), "receipt-schema"),
    ],
)
def test_receipt_admission_rejects_unproven_receipts(prepared, mutate, expected):
    receipt = _receipt(prepared, side="local")
    mutate(receipt)
    assert expected in receipt_errors(
        prepared, receipt, side="local", base_dir=REPO_ROOT
    )


def test_a_receipt_carrying_secret_material_is_rejected(prepared):
    receipt = _receipt(prepared, side="local")
    receipt["environment"]["idToken"] = "eyJhbGciOiJIUzI1NiJ9.payload"
    assert "secret-material" in receipt_errors(
        prepared, receipt, side="local", base_dir=REPO_ROOT
    )


def test_a_redacted_placeholder_is_not_treated_as_secret_material(prepared):
    receipt = _receipt(prepared, side="local")
    receipt["environment"]["password"] = "[redacted]"
    assert "secret-material" not in receipt_errors(
        prepared, receipt, side="local", base_dir=REPO_ROOT
    )


def test_an_out_of_order_transport_timeline_is_rejected(prepared):
    production = _receipt(prepared, side="production")
    production["transportTimeline"] = [
        {"kind": "connect", "atMs": 1000},
        {"kind": "disconnect", "atMs": 10},
        {"kind": "reconnect", "atMs": 1500},
    ]
    assert "transport-timeline-unordered" in receipt_errors(
        prepared, production, side="production", base_dir=REPO_ROOT
    )


def test_a_tampered_campaign_is_refused_before_any_row_is_compared(prepared):
    broken = copy.deepcopy(prepared)
    broken["budget"]["hardCostCeilingUsd"] = 1000
    result = compare_observations(
        broken, _receipt(prepared, side="local"), None, base_dir=REPO_ROOT
    )
    assert result["classification"] == REFUSED
    assert result["errors"] == ["campaign-invalid"]
    assert result["rows"] == []


def test_the_comparison_always_reports_the_paths_it_did_not_observe(prepared):
    result = compare_observations(
        prepared,
        _receipt(prepared, side="local"),
        _receipt(prepared, side="production"),
        base_dir=REPO_ROOT,
    )
    assert set(result["unobservedPaths"]) == {
        "browser-webchannel",
        "android-sdk",
        "apple-sdk",
        "tenant-isolation",
        "raw-resume-token",
    }


def test_metadata_only_differences_are_ignored_where_a_case_declares_them_uncompared(
    prepared,
):
    production = _receipt(prepared, side="production")
    for row, case in zip(production["cases"], cases.CASES, strict=True):
        if "fromCache" in case["comparedFields"]:
            continue
        for event in row["observed"]:
            event["fromCache"] = True
    result = compare_observations(
        prepared, _receipt(prepared, side="local"), production, base_dir=REPO_ROOT
    )
    assert result["classification"] == MATCH


def test_a_semantic_field_difference_is_never_ignored(prepared):
    production = _receipt(prepared, side="production")
    production["cases"][4]["observed"][0]["changes"] = []
    result = compare_observations(
        prepared, _receipt(prepared, side="local"), production, base_dir=REPO_ROOT
    )
    assert result["classification"] == SEMANTIC_MISMATCH
