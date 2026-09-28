import copy

from o6_listen_resume.comparator import compare_receipts
from o6_listen_resume.manifest import compile_plan
from o6_listen_resume.shadow import run_shadow


def test_two_shadow_preparations_never_match_or_emit_rows():
    plan = compile_plan("c" * 32)
    result = compare_receipts(plan, run_shadow(plan), run_shadow(plan))
    assert result["classification"] == "PREPARATION_ONLY"
    assert result["rows"] == []
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False


def test_production_marker_and_observation_fields_are_rejected():
    plan = compile_plan("d" * 32)
    receipt = run_shadow(plan)
    marked = copy.deepcopy(receipt)
    marked["productionExecuted"] = True
    result = compare_receipts(plan, marked, receipt)
    assert result["classification"] == "PREPARATION_ONLY"
    assert "production-executed" in result["errors"]
    observed = copy.deepcopy(receipt)
    observed["collector"] = {"complete": True}
    assert "observed-fields" in compare_receipts(plan, observed, receipt)["errors"]


def test_receipt_drift_stays_preparation_only_without_semantic_rows():
    plan = compile_plan("e" * 32)
    left = run_shadow(plan)
    right = copy.deepcopy(left)
    right["expectedLogicalEvents"].pop()
    result = compare_receipts(plan, left, right)
    assert result["classification"] == "PREPARATION_ONLY"
    assert result["rows"] == []
    assert result["errors"] == ["preparation-only"]


def test_invalid_plan_is_rejected():
    plan = compile_plan("f" * 32)
    plan["operations"][0]["kind"] = "update"
    receipt = run_shadow(compile_plan("f" * 32))
    result = compare_receipts(plan, receipt, receipt)
    assert result["classification"] == "PREPARATION_ONLY"
    assert result["errors"] == ["plan-invalid"]
