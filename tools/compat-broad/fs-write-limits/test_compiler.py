from __future__ import annotations

import pytest

from compiler import (
    FIELD_VALUE_MAX,
    DOCUMENT_MAX,
    compile_limits_plan,
    document_size_bytes,
    nested_depth,
)


def test_compiler_is_deterministic_and_nonce_isolation() -> None:
    first = compile_limits_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert first == compile_limits_plan("fireemu-35fe6", "(default)", "a" * 32)
    other = compile_limits_plan("fireemu-35fe6", "(default)", "b" * 32)
    assert first["requests"][0]["path"] != other["requests"][0]["path"]
    assert all("a" * 32 not in str(item) for item in other["requests"])


def test_exact_document_uses_official_name_formula_and_boundary() -> None:
    plan = compile_limits_plan("fireemu-35fe6", "(default)", "a" * 32)
    exact = plan["documents"]["exact-document-boundary"]
    assert exact["logicalBytes"] == DOCUMENT_MAX
    assert max(exact["fieldValueBytes"].values()) <= FIELD_VALUE_MAX
    assert document_size_bytes(exact["resource"], exact["fields"]) == DOCUMENT_MAX
    over = plan["documents"]["over-document-boundary"]
    assert over["logicalBytes"] == DOCUMENT_MAX + 1


def test_nested_cases_are_catalog_depth_boundaries() -> None:
    plan = compile_limits_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert nested_depth(plan["documents"]["exact-nested-boundary"]["fields"]) == 20
    assert nested_depth(plan["documents"]["over-nested-boundary"]["fields"]) == 21


def test_plan_is_bounded_and_contains_typed_absence_create_readback_cleanup() -> None:
    plan = compile_limits_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert len(plan["requests"]) == 28
    kinds = [request["kind"] for request in plan["requests"]]
    assert kinds[0:4] == ["preflight-typed-absence"] * 4
    assert "create-only-commit" in kinds
    assert kinds[-1] == "cleanup-verify-absence"
    assert kinds.count("cleanup-conditional-delete") == 4
    assert plan["budgetAccounting"]["requestUpperBound"] == len(plan["requests"])
    assert plan["budgetAccounting"]["requestUpperBound"] > 24
    assert plan["budgetAccounting"]["responseUpperBoundBytes"] <= 8388608
    assert plan["budgetAccounting"]["recoverySeconds"] >= 159
    patch = next(item for item in plan["requests"] if item["kind"] == "create-only-commit")
    assert patch["path"].startswith("/v1/projects/") and "?currentDocument.exists=false" in patch["path"]
    assert set(patch["body"]) == {"name", "fields"}
    assert patch["body"]["fields"]["_sharedOwner"]["referenceValue"] == patch["body"]["name"]


@pytest.mark.parametrize("project,database,nonce", [("", "(default)", "a" * 32), ("p", "bad/name", "a" * 32), ("p", "(default)", "A" * 32)])
def test_malformed_target_is_rejected(project: str, database: str, nonce: str) -> None:
    with pytest.raises(ValueError):
        compile_limits_plan(project, database, nonce)
