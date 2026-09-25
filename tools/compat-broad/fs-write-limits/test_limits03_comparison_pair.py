"""Comparator input-pair controls; no production evidence is created here."""

from __future__ import annotations

import copy

import comparator_03 as comparator
import pytest


@pytest.fixture
def plans(monkeypatch):
    calls = []

    def compile_plan(project, database, nonce, part):
        calls.append((project, database, nonce, part))
        count = 3 if project == "long-plan" else 2
        resource = f"projects/{project}/databases/{database}/documents/items/{nonce}"
        operations = [
            {"method": "GET", "path": f"/v1/{resource}", "body": None}
            for _ in range(count)
        ]
        return {
            "part": part,
            "nonce": nonce,
            "documents": {"doc": {"resource": resource}},
            "requests": [{"kind": "typed-readback"} for _ in operations],
            "localGatePlan": {"jobs": {"limits": {"observation": operations}}},
        }

    monkeypatch.setattr(comparator, "compile_limits_plan", compile_plan)
    monkeypatch.setattr(
        comparator,
        "dispatched_operations",
        lambda plan: copy.deepcopy(
            plan["localGatePlan"]["jobs"]["limits"]["observation"]
        ),
    )

    def pair(part="A", project="demo", n=2):
        plan = compile_plan(project, "(default)", "a" * 32, part)
        rows = [
            {
                "index": i,
                "request": operation,
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"name": plan["documents"]["doc"]["resource"]},
            }
            for i, operation in enumerate(comparator.dispatched_operations(plan))
        ]
        return plan, rows

    return pair, calls


def _indeterminate(result):
    assert result["classification"] == "INDETERMINATE"
    assert result["structuralClassification"] == "INDETERMINATE"
    assert result["rows"] == []
    assert result["errors"]
    assert result["semanticOnly"] is True
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False


@pytest.mark.parametrize("left,right", [("A", "B"), ("B", "A")])
def test_valid_different_parts_are_not_comparable(plans, left, right):
    pair, calls = plans
    p, rows = pair(part=left)
    q, other = pair(part=right)
    calls.clear()
    _indeterminate(comparator.compare_rows(p, rows, q, other))
    assert len(calls) == 2


@pytest.mark.parametrize("side", [0, 1])
def test_same_part_with_different_validated_row_counts_is_indeterminate(plans, side):
    pair, _ = plans
    pairs = [pair(), pair(project="long-plan")]
    if side == 0:
        pairs.reverse()
    _indeterminate(comparator.compare_rows(*pairs[0], *pairs[1]))


@pytest.mark.parametrize("side", [0, 1])
def test_empty_document_map_is_indeterminate(plans, side):
    pair, _ = plans
    pairs = [pair(), pair()]
    pairs[side][0]["documents"] = {}
    _indeterminate(comparator.compare_rows(*pairs[0], *pairs[1]))


@pytest.mark.parametrize("side", [0, 1])
def test_observations_must_be_a_list(plans, side):
    pair, _ = plans
    pairs = [pair(), pair()]
    plan, rows = pairs[side]
    pairs[side] = plan, tuple(rows)
    _indeterminate(comparator.compare_rows(*pairs[0], *pairs[1]))


@pytest.mark.parametrize("part", ["A", "B"])
def test_matching_valid_pair_remains_comparable(plans, part):
    pair, _ = plans
    plan, rows = pair(part=part)
    result = comparator.compare_rows(plan, rows, plan, copy.deepcopy(rows))
    assert result["classification"] == "MATCH"
    assert result["structuralClassification"] == "MATCH"
    assert len(result["rows"]) == len(rows)
    assert result["promotionReady"] is False
