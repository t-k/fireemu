from __future__ import annotations

import copy

import pytest
from o5_rules_case import compile_plan, validate_plan


def test_case_is_finite_and_not_executable() -> None:
    plan = compile_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert plan["status"] == "PREPARATION_ONLY"
    assert plan["productionExecuted"] is False
    assert plan["productionReady"] is False
    assert [op["expect"]["status"] for op in plan["observation"]] == [
        "success",
        "success",
        "success",
        "permission-denied",
        "success",
        "permission-denied",
    ]
    assert len(plan["ownedDocument"].split("/documents/")[1].split("/")) % 2 == 0
    assert len(plan["publicDocument"].split("/documents/")[1].split("/")) % 2 == 0
    for label, path in (
        ("owned", plan["ownedDocument"]),
        ("public", plan["publicDocument"]),
    ):
        assert (
            f"match /{path.split('/documents/')[1]}" in plan["rulesets"]["A"]["source"]
        )
        assert (
            f"match /{path.split('/documents/')[1]}" in plan["rulesets"]["B"]["source"]
        )
    assert "recovery" not in plan
    assert "nonceReservation" not in plan
    assert "budget" not in plan
    assert "recovery" not in plan["rulesets"]


@pytest.mark.parametrize(
    "project,database,nonce",
    [
        ("bad/project", "(default)", "a" * 32),
        ("demo-project", "bad/database", "a" * 32),
        ("demo-project", "(default)", "short"),
        ("A", "(default)", "a" * 32),
        ("demo-project", "_", "a" * 32),
        ("demo-project", "-bad", "a" * 32),
    ],
)
def test_invalid_identity_rejected(project, database, nonce) -> None:
    with pytest.raises(ValueError):
        compile_plan(project, database, nonce)


def test_drift_rejected() -> None:
    plan = compile_plan("demo-project", "(default)", "a" * 32)
    changed = copy.deepcopy(plan)
    changed["observation"][3]["expect"]["status"] = "success"
    with pytest.raises(ValueError):
        validate_plan(changed)
