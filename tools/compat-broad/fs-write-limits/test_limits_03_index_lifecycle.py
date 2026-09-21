from __future__ import annotations

from limits_03_index_lifecycle import (
    build_index_lifecycle_plan,
    execute_production,
    run_loopback_index_lifecycle,
)
import pytest


def test_plan_binds_actual_baseline_and_counts_every_index_lifecycle_call() -> None:
    baseline = {
        "name": "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*",
        "indexConfig": {
            "indexes": [{"order": "ASCENDING", "queryScope": "COLLECTION_GROUP"}],
            "usesAncestorConfig": False,
            "ancestorField": "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*",
        },
        "ttlConfig": {"state": "ENABLED"},
    }

    plan = build_index_lifecycle_plan(baseline)

    assert plan["fieldName"] == baseline["name"]
    assert plan["before"] == baseline
    assert plan["afterPatch"]["indexConfig"] == {"indexes": []}
    assert plan["restorePatch"]["indexConfig"] == {}
    assert plan["afterPatch"]["ttlConfig"] == baseline["ttlConfig"]
    assert plan["restorePatch"]["ttlConfig"] == baseline["ttlConfig"]
    assert plan["updateMask"] == "indexConfig"
    assert plan["budget"]["minimumRequests"] == 7
    assert plan["budget"]["maximumRequests"] == 23
    assert plan["budget"]["requestCostMicrousd"] == 100
    assert plan["budget"]["maximumCostMicrousd"] == 2300


def test_loopback_lifecycle_patches_polls_reads_and_restores_exact_baseline() -> None:
    baseline = {
        "name": "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*",
        "indexConfig": {
            "indexes": [{"order": "DESCENDING", "queryScope": "COLLECTION"}],
            "usesAncestorConfig": False,
            "ancestorField": "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*",
        },
        "ttlConfig": {"state": "ENABLED"},
    }

    receipt = run_loopback_index_lifecycle(build_index_lifecycle_plan(baseline))

    assert receipt["success"] is True
    assert receipt["restored"] is True
    assert receipt["finalField"] == baseline
    assert receipt["budget"]["requests"] == 7
    assert receipt["budget"]["costMicrousd"] == 700
    assert [event["kind"] for event in receipt["events"]] == [
        "read-before",
        "patch-after",
        "poll-after",
        "read-after",
        "patch-restore",
        "poll-restore",
        "read-restored",
    ]


def test_lifecycle_holds_on_bounded_poll_timeout_and_has_no_production_escape() -> None:
    baseline = {
        "name": "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*",
        "indexConfig": {"indexes": [], "usesAncestorConfig": True},
        "ttlConfig": {"state": "ENABLED", "duration": "86400s"},
    }
    plan = build_index_lifecycle_plan(baseline, poll_limit=2)

    receipt = run_loopback_index_lifecycle(plan, operation_polls_before_done=2)

    assert receipt["success"] is False
    assert receipt["heldOnFailure"] is True
    assert receipt["restored"] is False
    assert receipt["budget"]["requests"] == 4
    with pytest.raises(RuntimeError, match="O8/Ledger"):
        execute_production(plan)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "name": value["name"].replace("fireemu-35fe6", "other")},
        lambda value: {**value, "indexConfig": {"indexes": "not-a-list"}},
    ],
)
def test_plan_refuses_nonactual_or_malformed_baseline(mutation) -> None:
    baseline = {
        "name": "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*",
        "indexConfig": {"indexes": [], "usesAncestorConfig": True},
    }

    with pytest.raises(ValueError, match="baseline|index configuration"):
        build_index_lifecycle_plan(mutation(baseline))
