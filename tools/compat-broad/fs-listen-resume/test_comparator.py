import copy

from comparator import compare_receipts
from manifest import compile_plan
from shadow import run_shadow


def test_shadow_receipts_match_after_normalizing_nonsemantic_fields():
    plan = compile_plan("c" * 32)
    left = run_shadow(plan)
    right = copy.deepcopy(left)
    for event in right["events"]:
        event["readTime"] = "2026-09-18T01:02:03.000Z"
        event["resumeToken"] = "raw-token-must-not-be-compared"
    result = compare_receipts(plan, left, right)
    assert result["classification"] == "MATCH"
    assert result["semanticOnly"] is True
    assert result["promotionReady"] is False


def test_duplicate_revision_is_a_semantic_mismatch():
    plan = compile_plan("d" * 32)
    left = run_shadow(plan)
    right = copy.deepcopy(left)
    right["events"].insert(4, copy.deepcopy(right["events"][3]))
    right["collector"]["eventCount"] = len(right["events"])
    assert compare_receipts(plan, left, right)["classification"] == "SEMANTIC_MISMATCH"


def test_missing_collector_event_is_indeterminate():
    plan = compile_plan("e" * 32)
    left = run_shadow(plan)
    right = copy.deepcopy(left)
    right["events"].pop()
    right["collector"]["complete"] = False
    result = compare_receipts(plan, left, right)
    assert result["classification"] == "INDETERMINATE"
    assert result["errors"] == ["collector-incomplete"]


def test_transport_failure_is_indeterminate_even_when_ledgers_differ():
    plan = compile_plan("f" * 32)
    left = run_shadow(plan)
    right = copy.deepcopy(left)
    right["transport"]["interruptionObserved"] = False
    right["events"][-1]["revision"] = 99
    result = compare_receipts(plan, left, right)
    assert result["classification"] == "INDETERMINATE"
    assert "transport-interruption-unobserved" in result["errors"]


def test_reset_and_negative_error_codes_are_compared_semantically():
    plan = compile_plan("1" * 32)
    left = run_shadow(plan, scenario="negative")
    right = copy.deepcopy(left)
    assert compare_receipts(plan, left, right)["classification"] == "MATCH"
    right["events"][-1]["errorCode"] = "OK"
    assert compare_receipts(plan, left, right)["classification"] == "SEMANTIC_MISMATCH"


def test_foreign_resource_or_plan_drift_is_indeterminate():
    plan = compile_plan("2" * 32)
    receipt = run_shadow(plan)
    foreign = copy.deepcopy(receipt)
    foreign["events"][0]["document"] = "o6_resume_foreign/one"
    result = compare_receipts(plan, receipt, foreign)
    assert result["classification"] == "INDETERMINATE"
    assert "foreign-resource" in result["errors"]


def test_future_production_marker_does_not_change_semantic_kernel_result():
    plan = compile_plan("5" * 32)
    shadow = run_shadow(plan)
    production = copy.deepcopy(shadow)
    production["productionExecuted"] = True
    assert compare_receipts(plan, production, shadow)["classification"] == "MATCH"
