from __future__ import annotations

import pytest

from comparator import compare_receipts
from compiler import compile_plan


@pytest.mark.parametrize(
    "production,local",
    [({}, {}), ({"productionExecuted": True}, {}), (None, []), ({"cleanup": {"lock": None}}, {})],
)
def test_uncollected_or_malformed_receipts_remain_indeterminate(production, local) -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    result = compare_receipts(production, local, plan)
    assert result["classification"] == "INDETERMINATE"
    assert result["status"] == "PREPARATION_ONLY"
    assert result["productionExecuted"] is False
    assert result["productionReady"] is False
    assert result["rows"] == []


def test_malformed_plan_remains_indeterminate() -> None:
    assert compare_receipts({}, {}, {"project": []})["classification"] == "INDETERMINATE"
