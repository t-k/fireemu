from __future__ import annotations

from o5_rules_case import compile_plan
from o5_rules_shadow import shadow_receipt, validate_shadow


def test_shadow_is_only_a_preparation_case() -> None:
    plan = compile_plan("demo-project", "(default)", "a" * 32)
    case = shadow_receipt(plan)
    assert validate_shadow(case, plan)
    assert case["status"] == "PREPARATION_ONLY"
    assert case["productionExecuted"] is False
    assert case["productionReady"] is False
    assert "cleanup" not in case
    assert "credentialKind" not in case
    assert [row["expectedStatus"] for row in case["observations"]] == [
        "success",
        "success",
        "success",
        "permission-denied",
        "success",
        "permission-denied",
    ]


def test_shadow_rejects_malformed_case() -> None:
    plan = compile_plan("demo-project", "(default)", "b" * 32)
    assert not validate_shadow({"status": "MATCH"}, plan)
