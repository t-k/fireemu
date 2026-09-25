"""Contract tests for the credential-free partition/cursor case compiler."""

from __future__ import annotations

import copy

import pytest
from partition_cursor_case import (
    CAMPAIGN,
    CURSOR_COLLECTION,
    CURSOR_DOCUMENTS,
    OBSERVATION_COUNT,
    PARTITION_DOCUMENTS,
    RECOVERY_COUNT,
    compile_plan,
    digest,
    group_collection,
    validate_plan,
)

NONCE = "0" * 32
OTHER = "f" * 32


def plan() -> dict:
    return compile_plan("demo-project", "(default)", NONCE)


def test_plan_is_deterministic_for_identical_inputs() -> None:
    assert plan() == plan()


def test_plan_changes_with_the_nonce() -> None:
    assert plan() != compile_plan("demo-project", "(default)", OTHER)


@pytest.mark.parametrize(
    ("project", "database", "nonce"),
    [
        ("", "(default)", NONCE),
        ("demo project", "(default)", NONCE),
        (None, "(default)", NONCE),
        ("demo-project", "bad/database", NONCE),
        ("demo-project", None, NONCE),
        ("demo-project", "(default)", "0" * 31),
        ("demo-project", "(default)", "0" * 33),
        ("demo-project", "(default)", "G" * 32),
        ("demo-project", "(default)", None),
    ],
)
def test_malformed_identity_is_rejected(project, database, nonce) -> None:
    with pytest.raises(ValueError):
        compile_plan(project, database, nonce)


def test_named_database_is_accepted() -> None:
    named = compile_plan("demo-project", "named-db", NONCE)
    assert named["database"] == "named-db"
    validate_plan(named)


def test_operation_counts_are_frozen() -> None:
    value = plan()
    assert len(value["observation"]) == OBSERVATION_COUNT == 31
    assert len(value["recovery"]) == RECOVERY_COUNT == 6
    assert value["budget"] == {
        "observationRequests": OBSERVATION_COUNT,
        "recoveryRequests": RECOVERY_COUNT,
        "requestUpperBound": OBSERVATION_COUNT + RECOVERY_COUNT,
        "resourceUpperBound": PARTITION_DOCUMENTS + CURSOR_DOCUMENTS + 1,
        "concurrencyUpperBound": 1,
        "reconstructionSlots": 2,
    }


def test_owned_document_budget_stays_far_below_two_hundred() -> None:
    value = plan()
    assert len(value["ownedResources"]) == 21
    assert len(value["ownedResources"]) < 200
    assert len(set(value["ownedResources"])) == len(value["ownedResources"])


def test_every_owned_resource_sits_below_the_nonce_scope() -> None:
    value = plan()
    assert value["ownedResources"][0] == value["ownedScope"]
    for resource in value["ownedResources"][1:]:
        assert resource.startswith(value["ownedScope"] + "/")
    assert value["ownedScope"].endswith(
        f"/oracle/{NONCE}/o4-query-partition-cursor/root"
    )


def test_seed_commit_writes_exactly_the_owned_fixture() -> None:
    value = plan()
    writes = value["observation"][2]["body"]["writes"]
    assert [write["update"]["name"] for write in writes] == value["ownedResources"][1:]
    assert value["observation"][2]["kind"] == "seed-commit"


def test_partition_operations_declare_a_collection_group_query() -> None:
    value = plan()
    accepted = [
        operation
        for operation in value["observation"]
        if operation["kind"].startswith("partition-")
        and operation["expect"].get("outcome") == "accepted"
    ]
    assert accepted
    for operation in accepted:
        query = operation["body"]["structuredQuery"]
        assert query["from"] == [
            {"collectionId": group_collection(NONCE), "allDescendants": True}
        ]
        assert query["orderBy"] == [
            {"field": {"fieldPath": "__name__"}, "direction": "ASCENDING"}
        ]
        assert "where" not in query and "limit" not in query and "offset" not in query


def test_negative_partition_cases_expect_typed_refusals() -> None:
    value = plan()
    kinds = {
        operation["kind"]
        for operation in value["observation"]
        if operation["expect"].get("outcome") == "refused"
    }
    assert {
        "partition-document-parent",
        "partition-not-collection-group",
        "partition-with-filter",
        "partition-count-zero",
        "partition-with-limit",
        "partition-with-offset",
        "partition-order-non-name",
        "cursor-too-many-values",
        "cursor-reference-type-mismatch",
        "cursor-foreign-reference",
        "cursor-negative-offset",
    } <= kinds
    for operation in value["observation"]:
        expect = operation["expect"]
        if expect.get("outcome") == "refused":
            assert expect["status"] == 400
            assert expect.get("typed") == "INVALID_ARGUMENT" or expect["typedOpen"]


def test_only_the_indexed_order_refusal_leaves_its_typed_code_open() -> None:
    open_typed = [
        operation["kind"]
        for operation in plan()["observation"]
        if operation["expect"].get("typedOpen")
    ]
    assert open_typed == ["partition-order-non-name"]


def test_partition_page_token_continuation_binds_an_earlier_observation() -> None:
    value = plan()
    continuation = value["observation"][8]
    assert continuation["kind"] == "partition-page-token-continuation"
    assert continuation["pageTokenFrom"] == 7
    assert value["observation"][7]["kind"] == "partition-count-4-page-size-2"
    assert "pageToken" not in continuation["body"]


def test_reconstruction_slots_bind_the_recorded_partition_cursors() -> None:
    value = plan()
    slots = [
        operation
        for operation in value["observation"]
        if operation.get("reconstructionSlot") is not None
    ]
    assert [operation["reconstructionSlot"] for operation in slots] == [0, 1]
    for operation in slots:
        assert operation["cursorFrom"] == 5
        assert value["observation"][5]["kind"] == "partition-count-1"
        assert operation["expect"]["outcome"] == "accepted"


def test_cursor_expectations_name_the_exact_expected_documents() -> None:
    value = plan()
    expected = {
        "cursor-start-at-value": ["c3", "c4", "c5", "c6", "c7"],
        "cursor-start-after-value": ["c4", "c5", "c6", "c7"],
        "cursor-end-at-value": ["c0", "c1", "c2", "c3"],
        "cursor-end-before-value": ["c0", "c1", "c2"],
        "cursor-document-reference-start-at": ["c3", "c4", "c5", "c6", "c7"],
        "cursor-offset-limit": ["c2", "c3", "c4"],
        "cursor-start-at-with-offset": ["c3", "c4"],
        "cursor-descending-limit": ["c7", "c6", "c5"],
    }
    by_kind = {operation["kind"]: operation for operation in value["observation"]}
    for kind, names in expected.items():
        documents = by_kind[kind]["expect"]["documents"]
        assert [document["name"].rsplit("/", 1)[1] for document in documents] == names
        for document in documents:
            assert document["name"].startswith(
                value["ownedScope"] + "/" + CURSOR_COLLECTION + "/"
            )


def test_offset_and_limit_are_carried_on_the_wire_as_declared() -> None:
    by_kind = {operation["kind"]: operation for operation in plan()["observation"]}
    combined = by_kind["cursor-start-at-with-offset"]["body"]["structuredQuery"]
    assert combined["offset"] == 1
    assert combined["limit"] == 2
    assert combined["startAt"]["before"] is True
    assert by_kind["cursor-negative-offset"]["body"]["structuredQuery"]["offset"] == -1


def test_descending_limit_documents_the_absent_rest_limit_to_last() -> None:
    by_kind = {operation["kind"]: operation for operation in plan()["observation"]}
    operation = by_kind["cursor-descending-limit"]
    assert operation["sdkEquivalent"] == "limitToLast(3) over an ascending order"
    assert (
        operation["body"]["structuredQuery"]["orderBy"][0]["direction"] == "DESCENDING"
    )


def test_every_accepted_partition_operation_uses_the_database_parent() -> None:
    value = plan()
    accepted = [
        operation
        for operation in value["observation"]
        if operation["kind"].startswith("partition-")
        and operation["expect"].get("outcome") == "accepted"
    ]
    for operation in accepted:
        assert operation["parent"] == value["databaseRoot"]
        assert operation["path"].startswith("/v1/" + value["databaseRoot"])


def test_the_collection_group_is_nonce_unique_so_a_database_query_stays_owned() -> None:
    value = plan()
    group = group_collection(NONCE)
    assert value["groupCollection"] == group
    assert NONCE in group
    assert group != group_collection(OTHER)
    for resource in value["ownedResources"][1:13]:
        assert f"/{group}/" in resource


def test_a_document_parent_partition_query_is_a_declared_refusal_control() -> None:
    by_kind = {operation["kind"]: operation for operation in plan()["observation"]}
    control = by_kind["partition-document-parent"]
    assert control["parent"] == plan()["ownedScope"]
    assert control["expect"]["outcome"] == "refused"


def test_recovery_deletes_are_bound_to_recorded_creation_versions() -> None:
    value = plan()
    kinds = [operation["kind"] for operation in value["recovery"]]
    assert kinds == [
        "cleanup-ownership-read",
        "cleanup-seed-delete",
        "cleanup-root-delete",
        "cleanup-verify-group-absence",
        "cleanup-verify-collection-absence",
        "cleanup-verify-root-absence",
    ]
    assert value["recovery"][1]["versionFrom"] == 2
    assert value["recovery"][2]["versionFrom"] == 1
    for write in value["recovery"][1]["body"]["writes"]:
        assert write["currentDocument"] == {"updateTime": None}
    assert value["recovery"][1]["expect"]["updateTimes"] is False


def test_plan_is_never_production_ready() -> None:
    value = plan()
    assert value["productionReady"] is False
    assert value["productionExecuted"] is False
    assert value["campaignId"] == CAMPAIGN


def test_validate_plan_accepts_the_compiled_plan() -> None:
    validate_plan(plan())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.__setitem__("planDigest", "0" * 64),
        lambda value: value.__setitem__("nonce", OTHER),
        lambda value: value["observation"].pop(),
        lambda value: value["recovery"].pop(),
        lambda value: value["observation"][3]["body"]["structuredQuery"].__setitem__(
            "limit", 1
        ),
        lambda value: value["budget"].__setitem__("requestUpperBound", 99),
        lambda value: value.__setitem__("productionReady", True),
        lambda value: value["ownedResources"].append("elsewhere"),
    ],
)
def test_validate_plan_rejects_drift(mutate) -> None:
    value = plan()
    mutate(value)
    with pytest.raises((TypeError, ValueError)):
        validate_plan(value)


@pytest.mark.parametrize(
    "escape",
    [
        "projects/other/databases/(default)/documents/oracle/x/y/z",
        "projects/demo-project/databases/(default)/documents/oracle",
        "not-a-path",
        42,
    ],
)
def test_validate_plan_rejects_foreign_or_malformed_scopes(escape) -> None:
    value = plan()
    value["ownedScope"] = escape
    with pytest.raises((TypeError, ValueError)):
        validate_plan(value)


def test_validate_plan_rejects_an_operation_outside_the_owned_scope() -> None:
    value = plan()
    value["observation"][3]["parent"] = (
        "projects/demo-project/databases/(default)/documents/elsewhere/doc"
    )
    with pytest.raises(ValueError):
        validate_plan(value)


def test_validate_plan_rejects_a_recovery_target_outside_the_owned_scope() -> None:
    value = plan()
    value["recovery"][1]["body"]["writes"][0]["delete"] = (
        "projects/demo-project/databases/(default)/documents/elsewhere/doc"
    )
    with pytest.raises(ValueError):
        validate_plan(value)


def test_validate_plan_rejects_a_non_object() -> None:
    with pytest.raises(TypeError):
        validate_plan(["not", "a", "plan"])


def test_digest_is_order_independent_and_rejects_non_finite_numbers() -> None:
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
    with pytest.raises(ValueError):
        digest({"a": float("nan")})


def test_compiled_plan_is_not_mutated_by_callers_of_a_copy() -> None:
    value = plan()
    snapshot = copy.deepcopy(value)
    value["observation"][0]["expect"]["status"] = 500
    assert snapshot != value
    validate_plan(snapshot)


def test_the_too_many_values_cursor_exceeds_the_normalized_order_length() -> None:
    """Firestore appends __name__, so only a third value exceeds one order clause."""
    by_kind = {operation["kind"]: operation for operation in plan()["observation"]}
    query = by_kind["cursor-too-many-values"]["body"]["structuredQuery"]
    values = query["startAt"]["values"]
    assert len(query["orderBy"]) == 1
    assert len(values) == 3
    assert values[0] == {"integerValue": "3"}
    assert "referenceValue" in values[1], "the __name__ position stays type correct"
    assert values[1]["referenceValue"].endswith("/cur/c3")
    assert values[2] == {"integerValue": "9"}


def test_the_value_type_case_stays_distinct_from_the_cardinality_case() -> None:
    by_kind = {operation["kind"]: operation for operation in plan()["observation"]}
    mismatch = by_kind["cursor-reference-type-mismatch"]["body"]["structuredQuery"]
    assert mismatch["orderBy"][0]["field"]["fieldPath"] == "__name__"
    assert len(mismatch["startAt"]["values"]) == 1
    assert mismatch["startAt"]["values"][0] == {"stringValue": "c3"}
