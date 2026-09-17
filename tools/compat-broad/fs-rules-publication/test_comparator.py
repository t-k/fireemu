from __future__ import annotations

import copy

from comparator import compare_receipts
from compiler import compile_plan
from local_shadow import shadow_receipt


def _production_receipt(plan):
    value = shadow_receipt(plan)
    value["productionExecuted"] = True
    value["rows"][0]["requestId"] = "prod-request"
    value["rows"][0]["timestamp"] = "2026-09-18T01:02:03Z"
    return value


def test_comparator_excludes_request_ids_and_timestamps_but_never_promotes() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    result = compare_receipts(_production_receipt(plan), shadow_receipt(plan), plan)
    assert result["classification"] == "EXPECTED_NONDETERMINISM"
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False


def test_comparator_rejects_admin_or_local_token_evidence() -> None:
    plan = compile_plan("demo", "(default)", "b" * 32)
    production = _production_receipt(plan)
    production["credentialKind"] = "admin-rest"
    result = compare_receipts(production, shadow_receipt(plan), plan)
    assert result["classification"] == "INDETERMINATE"
    assert "wrong-credential-kind" in result["errors"]


def test_comparator_reports_denied_body_leak_and_plan_drift() -> None:
    plan = compile_plan("demo", "(default)", "c" * 32)
    production = _production_receipt(plan)
    production["rows"][3]["body"] = {"document": "secret"}
    result = compare_receipts(production, shadow_receipt(plan), plan)
    assert "denied-body-leak" in result["errors"]
    drifted = copy.deepcopy(plan)
    drifted["nonce"] = "d" * 32
    result = compare_receipts(shadow_receipt(plan), shadow_receipt(plan), drifted)
    assert "plan-drift" in result["errors"]
