from __future__ import annotations

import pytest
from compiler import (
    DOCUMENT_MAX,
    FIELD_VALUE_MAX,
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
    assert "create-only-patch" in kinds
    assert kinds[-1] == "cleanup-verify-absence"
    assert kinds.count("cleanup-conditional-delete") == 4
    assert plan["budgetAccounting"]["requestUpperBound"] == len(plan["requests"])
    assert plan["budgetAccounting"]["requestUpperBound"] > 24
    assert plan["budgetAccounting"]["responseUpperBoundBytes"] > 8388608
    assert plan["budgetAccounting"]["recoverySeconds"] >= 159
    patch = next(
        item for item in plan["requests"] if item["kind"] == "create-only-patch"
    )
    assert (
        patch["path"].startswith("/v1/projects/")
        and "?currentDocument.exists=false" in patch["path"]
    )
    assert set(patch["body"]) == {"name", "fields"}
    assert (
        patch["body"]["fields"]["_sharedOwner"]["referenceValue"]
        == patch["body"]["name"]
    )


def test_management_observation_reads_inherited_baseline_before_applying_exemption():
    from compiler_03 import MANAGEMENT_OBSERVATION_IDS

    assert list(MANAGEMENT_OBSERVATION_IDS) == [
        "oauth-tokeninfo",
        "project",
        "database",
        "index-lifecycle-before",
        "index-lifecycle-apply",
        "index-lifecycle-poll",
        "index-lifecycle-after",
        "index-exemption",
        "auth",
    ]


@pytest.mark.parametrize(
    "project,database,nonce",
    [
        ("", "(default)", "a" * 32),
        ("p", "bad/name", "a" * 32),
        ("p", "(default)", "A" * 32),
    ],
)
def test_malformed_target_is_rejected(project: str, database: str, nonce: str) -> None:
    with pytest.raises(ValueError):
        compile_limits_plan(project, database, nonce)


def test_each_negative_is_followed_by_both_controls_before_the_next_write():
    rows = compile_limits_plan("demo-app", "(default)", "a" * 32)["requests"]
    for index, row in enumerate(rows):
        if row["method"] == "PATCH" and not row["expect"]["positive"]:
            assert rows[index + 1]["kind"] == "typed-readback"
            assert [r["kind"] for r in rows[index + 2 : index + 4]] == [
                "unchanged-control-readback"
            ] * 2


def test_every_possible_document_response_has_a_full_body_allowance():
    import json

    plan = compile_limits_plan("demo-app", "(default)", "a" * 32)
    for row in plan["requests"]:
        if row["method"] in ("GET", "PATCH"):
            resource = row["path"].split("?", 1)[0].removeprefix("/v1/")
            document = next(
                d for d in plan["documents"].values() if d["resource"] == resource
            )
            size = len(
                json.dumps({"name": resource, "fields": document["fields"]}).encode()
            )
            assert row["responseByteLimit"] >= size + 1024
    assert plan["budgetAccounting"]["responseUpperBoundBytes"] == sum(
        r["responseByteLimit"] for r in plan["requests"]
    )


def test_cleanup_uses_gate_capture_indices_not_literal_version_placeholders():
    plan = compile_limits_plan("demo-app", "(default)", "a" * 32)
    recovery = plan["requests"][-12:]
    for index in range(0, 12, 3):
        read, delete, absent = recovery[index : index + 3]
        assert delete["versionFrom"] == index
        assert "?" not in delete["path"]
        assert read["path"] == delete["path"] == absent["path"]
        assert read["expect"]["statuses"] == [200, 404]


def test_independent_boundary_arithmetic_and_document_path_parity():
    import base64

    plan = compile_limits_plan("demo-app", "(default)", "a" * 32)
    for label, expected in [
        ("exact-document-boundary", 1048576),
        ("over-document-boundary", 1048577),
    ]:
        doc = plan["documents"][label]
        parts = doc["resource"].split("/documents/")[1].split("/")
        assert len(parts) % 2 == 0
        name_bytes = 16 + sum(len(s.encode()) + 1 for s in parts)
        payload = base64.b64decode(doc["fields"]["blob"]["bytesValue"], validate=True)
        assert len(payload) <= 1048487
        assert (
            2 * name_bytes
            + 32
            + len("_sharedOwner")
            + 1
            + len("blob")
            + 1
            + len(payload)
            == expected
        )


@pytest.mark.parametrize(
    "value", [None, 1, "", "a?b", "a#b", "a%b", "a b", ".", "..", "a\nb"]
)
def test_targets_and_nonce_reject_unsafe_values(value):
    for args in [
        (value, "(default)", "a" * 32),
        ("demo-app", value, "a" * 32),
        ("demo-app", "(default)", value),
    ]:
        with pytest.raises(ValueError):
            compile_limits_plan(*args)


def test_compiled_local_allocation_is_accepted_by_existing_gate(tmp_path):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from shared_gate import Gate, create

    plan = compile_limits_plan("demo-app", "(default)", "a" * 32)
    allocation = plan["localGatePlan"]
    gate_path = tmp_path / "gate"
    create(gate_path, allocation)
    gate = Gate(gate_path, "limits")
    assert gate.snapshot()["reservedRecovery"] == 12
    assert allocation["observationRequests"] == 16
    for phase in ("observation", "recovery"):
        for operation in allocation["jobs"]["limits"][phase]:
            assert set(operation) <= {
                "service",
                "method",
                "path",
                "body",
                "privileged",
                "form",
                "versionFrom",
            }
            assert {"service", "method", "path", "body", "privileged", "form"} <= set(
                operation
            )
    assert plan["budgetAccounting"]["legacyTransportCompatible"] is False
    assert plan["budgetAccounting"]["productionReady"] is False
