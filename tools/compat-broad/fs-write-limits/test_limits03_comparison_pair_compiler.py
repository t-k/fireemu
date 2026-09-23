"""Real compiler pair checks with synthetic responses and no network access."""

from __future__ import annotations

import copy

import comparator_03 as comparator
import pytest
from comparator_03 import compare_rows
from compiler_03 import compile_limits_plan, dispatched_operations


@pytest.fixture(scope="module")
def plans():
    return {
        part: compile_limits_plan("demo-pair", "(default)", "f" * 32, part)
        for part in ("A", "B")
    }


def _journal(plan):
    return [
        {
            "index": index,
            "request": copy.deepcopy(operation),
            "complete": True,
            "failure": None,
            "status": 400,
            "body": {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
        }
        for index, operation in enumerate(dispatched_operations(plan))
    ]


@pytest.mark.parametrize("left,right", [("A", "B"), ("B", "A")])
def test_real_compiler_rejects_a_cross_part_pair(plans, left, right):
    p, q = plans[left], plans[right]
    result = compare_rows(p, _journal(p), q, _journal(q))
    assert result["classification"] == "INDETERMINATE"
    assert result["structuralClassification"] == "INDETERMINATE"
    assert result["rows"] == []
    assert result["errors"]
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False


@pytest.mark.parametrize("part", ["A", "B"])
def test_real_compiler_accepts_a_matching_part_pair(plans, part):
    plan = plans[part]
    rows = _journal(plan)
    result = compare_rows(plan, rows, plan, copy.deepcopy(rows))
    assert result["classification"] == "MATCH"
    assert len(result["rows"]) == len(rows)
    assert result["promotionReady"] is False


def test_deep_response_json_fails_closed(plans):
    plan = plans["A"]
    rows = _journal(plan)
    other = copy.deepcopy(rows)
    body = {"deep": []}
    for _ in range(1100):
        body = [body]
    rows[0]["body"] = body

    result = compare_rows(plan, rows, plan, other)
    assert result["classification"] == "INDETERMINATE"
    assert result["structuralClassification"] == "INDETERMINATE"
    assert result["rows"] == []
    assert result["errors"] == ["RecursionError"]


def test_recursion_failure_after_a_row_is_compared_discards_partial_rows(
    plans, monkeypatch
):
    plan = plans["A"]
    rows = _journal(plan)
    comparisons = 0
    exact = comparator._exact

    def fail_on_second_comparison(left, right):
        nonlocal comparisons
        if isinstance(left, dict) and set(left) == {"status", "body", "metadata"}:
            comparisons += 1
            if comparisons == 2:
                raise RecursionError("simulated nested response")
        return exact(left, right)

    monkeypatch.setattr(comparator, "_exact", fail_on_second_comparison)
    result = compare_rows(plan, rows, plan, copy.deepcopy(rows))
    assert comparisons == 2
    assert result["classification"] == "INDETERMINATE"
    assert result["structuralClassification"] == "INDETERMINATE"
    assert result["rows"] == []
    assert result["errors"] == ["RecursionError"]
