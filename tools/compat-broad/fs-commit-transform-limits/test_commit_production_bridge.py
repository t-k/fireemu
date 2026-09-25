import copy

import pytest
from commit_production_bridge import CommitProductionBridge, classify_receipt
from transform_compiler import compile_plan


def plan():
    return compile_plan("demo", "(default)", "a" * 32)


def commit(plan_value, label="exact-500"):
    return next(
        operation
        for operation in plan_value["observation"]
        if operation["kind"] == "commit-transform"
        and operation["resources"][0].endswith("/" + label)
    )


def test_commit_bridge_sends_only_the_compiler_bound_commit():
    calls = []
    compiled = plan()
    bridge = CommitProductionBridge(
        compiled,
        transmit=lambda value: (
            calls.append(value)
            or {"complete": True, "failure": None, "status": 200, "body": {}}
        ),
    )

    result = bridge.send(commit(compiled))

    assert calls == [commit(compiled)]
    assert result["classification"] == "semantic"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda operation: {**operation, "method": "GET"},
        lambda operation: {**operation, "path": operation["path"] + "?x=1"},
        lambda operation: {
            **operation,
            "body": {**operation["body"], "writes": operation["body"]["writes"] + [{}]},
        },
        lambda operation: {
            **operation,
            "body": {
                **operation["body"],
                "writes": [
                    {
                        **operation["body"]["writes"][0],
                        "transform": {
                            **operation["body"]["writes"][0]["transform"],
                            "document": "projects/foreign/databases/(default)/documents/x/y",
                        },
                    },
                    operation["body"]["writes"][1],
                ],
            },
        },
    ],
)
def test_commit_binding_rejects_mutation_before_transport(mutation):
    calls = []
    compiled = plan()
    bridge = CommitProductionBridge(compiled, transmit=lambda value: calls.append(value))

    with pytest.raises(ValueError):
        bridge.send(mutation(copy.deepcopy(commit(compiled))))

    assert calls == []


def test_forged_plan_is_rejected_before_transport():
    calls = []
    forged = plan()
    forged["ownedResources"] = [
        resource.replace("projects/demo/", "projects/attacker/")
        for resource in forged["ownedResources"]
    ]
    commit_resources = iter(forged["ownedResources"])
    for operation in forged["observation"]:
        if operation["kind"] == "commit-transform":
            resource = next(commit_resources)
            for write in operation["body"]["writes"]:
                write["transform"]["document"] = resource
            operation["resources"] = [resource]

    with pytest.raises(ValueError):
        CommitProductionBridge(forged, transmit=lambda value: calls.append(value))

    assert calls == []


def test_complete_expected_four_x_is_retained_as_semantic_evidence():
    result = classify_receipt(
        {"complete": True, "status": 400, "body": {"error": {"status": "INVALID_ARGUMENT"}}}
    )

    assert result == {
        "classification": "semantic",
        "status": 400,
        "body": {"error": {"status": "INVALID_ARGUMENT"}},
        "failure": None,
    }


@pytest.mark.parametrize(
    "receipt",
    [
        {"complete": False, "failure": "timeout"},
        {"complete": True, "failure": "timeout", "status": 400, "body": {}},
        {"complete": True, "failure": None, "status": 0, "body": {}},
        {"complete": True, "status": 429, "body": {}},
        {"complete": True, "status": 503, "body": {}},
        {"complete": True, "status": 400, "body": "truncated"},
        {"complete": True, "failure": None, "status": 400, "body": {"value": float("nan")}},
    ],
)
def test_incomplete_or_infrastructure_receipts_are_indeterminate(receipt):
    result = classify_receipt(receipt)
    assert result["classification"] == "indeterminate"
    assert result["failure"]
