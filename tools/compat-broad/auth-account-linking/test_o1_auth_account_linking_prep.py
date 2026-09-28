from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from o1_auth_account_linking_comparator import compare
from o1_auth_account_linking_compiler import (
    CASE_ID,
    compile_case,
    validate_plan,
)


def test_preparation_references_existing_v10_case_without_execution_authority():
    plan = compile_case()
    assert plan["parentCase"] == {
        "path": "spec/compatibility/broad-runs/auth-settings-sdk-next-v10.json",
        "id": CASE_ID,
    }
    assert plan["status"] == "PREPARATION_ONLY"
    assert plan["productionExecuted"] is False
    assert plan["productionAllowed"] is False
    assert plan["bindings"] == {
        "source": "UNBOUND",
        "artifact": "UNBOUND",
        "configuration": "UNBOUND",
        "sdk": "UNBOUND",
    }
    assert plan["observations"]["allowDuplicateEmailsFalse"] == "LOCAL_ONLY"
    assert plan["observations"]["allowDuplicateEmailsTrue"] == "UNOBSERVED"
    assert plan["observations"]["production"] == "UNOBSERVED"
    assert "operations" not in plan
    assert "campaign" not in plan
    validate_plan(plan)


def test_parent_reference_points_to_frozen_v10_case():
    parent = compile_case()["parentCase"]
    root = HERE.parents[2]
    case_ids = [
        case["id"] for case in json.loads((root / parent["path"]).read_text())["cases"]
    ]
    assert case_ids.count(parent["id"]) == 1


@pytest.mark.parametrize("field", ["source", "artifact", "configuration", "sdk"])
def test_claimed_binding_is_rejected(field: str):
    changed = copy.deepcopy(compile_case())
    changed["bindings"][field] = "BOUND"
    with pytest.raises(ValueError, match="preparation-only"):
        validate_plan(changed)


@pytest.mark.parametrize(
    "receipt",
    [
        {},
        {"operations": []},
        {"operations": [{"id": "provider-collision"}]},
        {"operations": [{"id": "provider-collision"}] * 2},
        {"operations": [{"id": "readback-a"}, {"id": "signup-a"}]},
        {"transport": "ok", "failure": "timeout"},
        {"side": "unknown", "cleanup": {"complete": True}, "after": {}},
        {"sourceCommit": "b" * 40, "artifactSha256": "a" * 64},
    ],
)
def test_synthetic_or_incomplete_receipts_are_indeterminate(receipt: dict):
    result = compare(receipt, copy.deepcopy(receipt))
    assert result["classification"] == "INDETERMINATE"
    assert result["status"] == "PREPARATION_ONLY"
    assert result["productionCompared"] is False


def test_conflicting_synthetic_receipts_cannot_claim_semantic_mismatch():
    assert (
        compare({"outcome": "accepted"}, {"outcome": "refused"})["classification"]
        == "INDETERMINATE"
    )
