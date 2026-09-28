from __future__ import annotations

import copy

import pytest
from query_in_compiler import MAX_DISJUNCTIONS, compile_plan, validate_plan


def test_plan_is_deterministic_and_nonce_scoped() -> None:
    plan = compile_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert plan == compile_plan("fireemu-35fe6", "(default)", "a" * 32)
    other = compile_plan("fireemu-35fe6", "(default)", "b" * 32)
    assert plan["campaignId"] == "FS-DATA-QUERY-IN-BOUNDARY-04"
    assert plan["parent"] != other["parent"]
    assert plan["ownedResources"] == [plan["document"]]
    assert plan["ownedScope"] in plan["document"]


def test_owned_scope_has_root_document_before_relative_collection_document() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    assert plan["parent"].endswith("/o4-query-in-boundary/root")
    assert plan["document"] == plan["parent"] + "/cur/c"


def test_validator_rejects_a_parent_that_is_not_a_document_path() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    plan["parent"] = plan["parent"].removesuffix("/root")
    with pytest.raises(ValueError, match="document parent"):
        validate_plan(plan)


def test_plan_has_exact_six_observation_and_three_recovery_operations() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    assert len(plan["observation"]) == 6
    assert len(plan["recovery"]) == 3
    assert plan["budget"] == {
        "observationRequests": 6,
        "recoveryRequests": 3,
        "requestUpperBound": 9,
        "resourceUpperBound": 1,
        "concurrencyUpperBound": 1,
    }
    assert [row["kind"] for row in plan["observation"]] == [
        "preflight-typed-absence",
        "create-only-patch",
        "positive-query",
        "before-readback",
        "diagnostic-query",
        "after-readback",
    ]
    assert [row["kind"] for row in plan["recovery"]] == [
        "cleanup-ownership-read",
        "cleanup-conditional-delete",
        "cleanup-verify-absence",
    ]


def test_queries_are_parent_scoped_bounded_and_differ_only_by_operand_count() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    positive, diagnostic = plan["observation"][2], plan["observation"][4]
    assert (
        positive["path"] == diagnostic["path"] == "/v1/" + plan["parent"] + ":runQuery"
    )
    for operation, count in (
        (positive, MAX_DISJUNCTIONS),
        (diagnostic, MAX_DISJUNCTIONS + 1),
    ):
        query = operation["body"]["structuredQuery"]
        assert query["from"] == [{"collectionId": "cur"}]
        assert "allDescendants" not in query["from"][0]
        assert query["limit"] == 1
        assert set(query) == {"from", "where", "limit"}
        field_filter = query["where"]["fieldFilter"]
        assert field_filter["field"] == {"fieldPath": "n"}
        assert field_filter["op"] == "IN"
        assert len(field_filter["value"]["arrayValue"]["values"]) == count
        assert [
            value["integerValue"]
            for value in field_filter["value"]["arrayValue"]["values"]
        ] == [str(i) for i in range(count)]
    positive_query = copy.deepcopy(positive["body"])
    diagnostic_query = copy.deepcopy(diagnostic["body"])
    positive_query["structuredQuery"]["where"]["fieldFilter"]["value"]["arrayValue"][
        "values"
    ] = positive_query["structuredQuery"]["where"]["fieldFilter"]["value"][
        "arrayValue"
    ]["values"][:29]
    diagnostic_query["structuredQuery"]["where"]["fieldFilter"]["value"]["arrayValue"][
        "values"
    ] = diagnostic_query["structuredQuery"]["where"]["fieldFilter"]["value"][
        "arrayValue"
    ]["values"][:30]
    assert (
        positive_query["structuredQuery"].keys()
        == diagnostic_query["structuredQuery"].keys()
    )
    assert (
        positive_query["structuredQuery"]["from"]
        == diagnostic_query["structuredQuery"]["from"]
    )


def test_fixture_and_poststate_are_exactly_bound_to_the_owned_document() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    create = plan["observation"][1]
    assert create["body"]["name"] == plan["document"]
    assert create["body"]["fields"] == plan["fixtureFields"]
    assert plan["expectedPositiveDocument"] == {
        "name": plan["document"],
        "fields": plan["fixtureFields"],
    }
    for row in (
        plan["observation"][0],
        plan["observation"][1],
        plan["observation"][3],
        plan["observation"][5],
        *plan["recovery"],
    ):
        assert row["resource"] == plan["document"]
    for row in (plan["observation"][2], plan["observation"][4]):
        assert row["targetResources"] == [plan["document"]]
        assert row["parent"] == plan["parent"]


def test_cleanup_is_conditional_and_version_bound() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    read, delete, verify = plan["recovery"]
    assert read["expect"] == {"statuses": [200, 404], "owned": True}
    assert delete["versionFrom"] == 0
    assert delete["path"] == "/v1/" + plan["document"]
    assert "currentDocument.updateTime" not in delete["path"]
    assert verify["expect"] == {"status": 404, "typed": "NOT_FOUND"}


@pytest.mark.parametrize(
    "project,database,nonce",
    [
        ("", "(default)", "a" * 32),
        ("demo", "bad/name", "a" * 32),
        ("demo", "(default)", "A" * 32),
        ("demo", "(default)", "a" * 31),
    ],
)
def test_unsafe_target_is_rejected(project: str, database: str, nonce: str) -> None:
    with pytest.raises(ValueError):
        compile_plan(project, database, nonce)


def test_plan_rejects_mutation_of_compiled_query_inputs() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    original = copy.deepcopy(plan)
    plan["observation"][2]["body"]["structuredQuery"]["from"][0]["collectionId"] = (
        "other"
    )
    assert (
        original["observation"][2]["body"]["structuredQuery"]["from"][0]["collectionId"]
        == "cur"
    )
    assert (
        plan["observation"][2]["targetResources"]
        == original["observation"][2]["targetResources"]
    )


@pytest.mark.parametrize(
    "mutation",
    ["foreign-path", "foreign-collection", "all-descendants", "operand", "cleanup"],
)
def test_validator_rejects_query_scope_cardinality_and_cleanup_drift(
    mutation: str,
) -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    if mutation == "foreign-path":
        plan["observation"][2]["path"] = plan["observation"][2]["path"].replace(
            plan["parent"], "projects/foreign/databases/(default)/documents/other"
        )
    elif mutation == "foreign-collection":
        plan["observation"][2]["body"]["structuredQuery"]["from"][0]["collectionId"] = (
            "other"
        )
    elif mutation == "all-descendants":
        plan["observation"][2]["body"]["structuredQuery"]["from"][0][
            "allDescendants"
        ] = True
    elif mutation == "operand":
        plan["observation"][2]["body"]["structuredQuery"]["where"]["fieldFilter"][
            "value"
        ]["arrayValue"]["values"].append({"integerValue": "30"})
    else:
        plan["recovery"][1]["path"] = (
            "/v1/projects/foreign/databases/(default)/documents/x"
        )
    with pytest.raises(ValueError):
        validate_plan(plan)
