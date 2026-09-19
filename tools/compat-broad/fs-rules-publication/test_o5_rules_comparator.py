from __future__ import annotations

import pytest
from o5_rules_case import compile_plan
from o5_rules_comparator import compare_receipts


@pytest.mark.parametrize(
    "production,local",
    [
        ({}, {}),
        ({"productionExecuted": True}, {}),
        (None, []),
        ({"cleanup": {"lock": None}}, {}),
    ],
)
def test_uncollected_or_malformed_receipts_remain_indeterminate(
    production, local
) -> None:
    plan = compile_plan("demo-project", "(default)", "a" * 32)
    result = compare_receipts(production, local, plan)
    assert result["classification"] == "INDETERMINATE"
    assert result["status"] == "PREPARATION_ONLY"
    assert result["productionExecuted"] is False
    assert result["productionReady"] is False
    assert result["rows"] == []


def test_malformed_plan_remains_indeterminate() -> None:
    assert (
        compare_receipts({}, {}, {"project": []})["classification"] == "INDETERMINATE"
    )


def test_complete_production_shaped_input_still_has_no_semantic_result() -> None:
    plan = compile_plan("demo-project", "(default)", "c" * 32)
    rows = [
        {
            "index": index,
            "request": operation,
            "status": operation["expect"]["status"],
            "complete": True,
        }
        for index, operation in enumerate(plan["observation"])
    ]
    fake = {"productionExecuted": True, "rows": rows, "cleanup": {"complete": True}}
    result = compare_receipts(fake, fake, plan)
    assert result["classification"] == "INDETERMINATE"
    assert result["rows"] == []
    assert result["productionExecuted"] is False
