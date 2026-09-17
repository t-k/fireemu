from __future__ import annotations

import copy


from compiler import compile_plan
from local_shadow import shadow_receipt, validate_shadow


def test_shadow_covers_allow_deny_public_and_cleanup_contract() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    receipt = shadow_receipt(plan)
    assert validate_shadow(receipt, plan)
    assert [row["status"] for row in receipt["rows"]] == [
        "success",
        "success",
        "success",
        "permission-denied",
        "success",
        "permission-denied",
    ]


def test_shadow_rejects_successful_denied_read_or_incomplete_cleanup() -> None:
    plan = compile_plan("demo", "(default)", "b" * 32)
    receipt = shadow_receipt(plan)
    changed = copy.deepcopy(receipt)
    changed["rows"][3]["status"] = "success"
    assert not validate_shadow(changed, plan)


def test_shadow_rejects_unknown_status_and_malformed_row() -> None:
    plan = compile_plan("demo", "(default)", "c" * 32)
    changed = shadow_receipt(plan)
    changed["rows"][0]["status"] = "maybe"
    assert not validate_shadow(changed, plan)
    changed = shadow_receipt(plan)
    changed["rows"][0] = None
    assert not validate_shadow(changed, plan)
    changed = shadow_receipt(plan)
    changed["cleanup"]["documents"] = []
    assert not validate_shadow(changed, plan)
