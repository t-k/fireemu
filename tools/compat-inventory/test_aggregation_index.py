"""Index cleanup is confined to the newly reserved collection and exact definition."""

import pytest
from aggregation_corpus import index_definition
from aggregation_index import index_parent, owned_index, resolved_operation
from probe import DATABASE


def test_delayed_or_unknown_create_cannot_certify_absence():
    name = DATABASE + "/operations/owned-operation"
    for operation in [{}, {"name": name}, {"name": name, "done": False}]:
        assert not resolved_operation(operation, name)
    assert resolved_operation({"name": name, "done": True, "response": {}}, name)
    assert resolved_operation({"name": name, "done": True, "error": {}}, name)
    for operation in [
        {"name": name + "other", "done": True, "response": {}},
        {"name": name, "done": True},
        {"name": name, "done": True, "response": {}, "error": {}},
    ]:
        assert not resolved_operation(operation, name)


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
