"""Index cleanup is confined to the newly reserved collection and exact definition."""

import pytest
from aggregation_corpus import index_definition
from aggregation_index import (
    cleanup_index,
    index_parent,
    owned_index,
    resolved_operation,
    select_indexes,
)
from probe import DATABASE


def test_broader_admin_listing_never_expands_cleanup_scope():
    collection = "compat_" + "a" * 32
    owned = {"name": index_parent(collection) + "/id", **index_definition()}
    foreign = {"name": index_parent("compat_" + "b" * 32) + "/id", **index_definition()}
    assert select_indexes([foreign, owned], collection) == [owned]
    assert select_indexes([foreign], collection) == []


def test_delayed_or_unknown_create_cannot_certify_absence():
    name = DATABASE + "/operations/owned-operation"
    for operation in [{}, {"name": name}, {"name": name, "done": False}]:
        assert not resolved_operation(operation, name)


def test_completed_create_requires_a_result_or_error():
    name = DATABASE + "/operations/owned-operation"
    assert resolved_operation({"name": name, "done": True, "response": {}}, name)
    assert resolved_operation({"name": name, "done": True, "error": {}}, name)
    for operation in [
        {"name": name + "other", "done": True, "response": {}},
        {"name": name, "done": True},
        {"name": name, "done": True, "response": {}, "error": {}},
    ]:
        assert not resolved_operation(operation, name)


def test_lost_create_response_stays_unresolved_without_listing_or_deleting():
    receipt = {"createAttempted": True, "baselineEmpty": True}
    cleanup_index("unused", "compat_" + "a" * 32, receipt)
    assert receipt["confirmedMissing"] is False
    assert receipt["cleanupError"] == "ValueError"
    assert "deletedNames" not in receipt


def test_index_cleanup_refuses_foreign_paths_or_definitions():
    collection = "compat_" + "a" * 32
    parent = index_parent(collection)
    value = {"name": parent + "/id", **index_definition(), "state": "READY"}
    assert owned_index(value, collection)
    for change in [
        {"name": parent.replace("a" * 32, "b" * 32) + "/id"},
        {"fields": []},
        {"queryScope": "COLLECTION_GROUP"},
        {"name": parent + "/../id"},
    ]:
        assert not owned_index({**value, **change}, collection)
    with pytest.raises(ValueError):
        index_parent("existing")
