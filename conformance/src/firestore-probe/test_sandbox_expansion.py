"""Exploration-informed inputs are recipes, never stored production expectations."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).with_name("sandbox_expansion.py")


def _module():
    spec = importlib.util.spec_from_file_location("sandbox_expansion", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_names_hit_exact_relative_boundaries_without_empty_segments() -> None:
    module = _module()
    for length in (2600, 2642, 2643, 4621, 4622, 5000, 6127, 6128):
        name = module.name_of_length(length, f"n{length}")
        segments = name.split("/")
        assert len(name.encode()) == length
        assert len(segments) % 2 == 0
        assert all(1 <= len(segment.encode()) <= 1500 for segment in segments)
        assert all(segment == "c" for segment in segments[::2])
        assert max(map(len, segments[1::2])) - min(map(len, segments[1::2])) <= 1


def test_index_sum_names_reproduce_the_exploration_layout() -> None:
    module = _module()
    for target, collection_bytes, document_bytes in (
        (500, 498, 1),
        (1000, 998, 1),
        (2000, 1400, 599),
    ):
        name = module.index_sum_name_of_length(target, "g2")
        collection, document = name.split("/")
        assert len(name.encode()) == target
        assert len(collection.encode()) == collection_bytes
        assert len(document.encode()) == document_bytes


def test_raw_request_boundary_is_exact_and_keeps_readback() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    for size in (11_534_336, 11_534_337):
        program = programs[f"writes/limits/raw-11mib/{size}"]
        assert len(program["steps"]) == 2
        assert len(program["steps"][0]["body"].encode()) == size
        assert len(json.loads(program["steps"][0]["body"])["writes"]) == 1
        assert program["steps"][1]["id"] == "readback"


def test_batchwrite_validation_variants_are_three_writes_plus_state_readback() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    for variant in (
        "no-operation",
        "collection-name",
        "empty-field-name",
        "reserved-field-name",
        "bad-mask-path",
        "bad-integer",
        "two-fields-bad-integer",
        "unknown-value-kind",
        "bad-timestamp",
        "exists-precondition-fails",
    ):
        program = programs[f"writes/batch-write-malformed/{variant}"]
        assert len(program["steps"][0]["body"]["writes"]) == 3
        assert len(program["steps"][1]["body"]["documents"]) == 3
        assert all("expected" not in step for step in program["steps"])


def test_index_and_decoded_request_boundaries_have_exact_input_shapes() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    for length in (2600, 2642, 2643):
        write = programs[f"writes/limits/index-entry-string-name/{length}"]["steps"][0][
            "body"
        ]["writes"][0]
        assert len(write["update"]["name"].split("/documents/")[1].encode()) == length
        assert len(write["update"]["fields"]["s"]["stringValue"].encode()) == 1500
    for length in (4621, 4622, 5000, 6127, 6128):
        write = programs[f"writes/limits/empty-document-name/{length}"]["steps"][0][
            "body"
        ]["writes"][0]
        assert write["update"]["fields"] == {}
    for length, count in (
        (500, 19999),
        (500, 20000),
        (2000, 9549),
        (2000, 9550),
        (1000, 19998),
        (1000, 19999),
    ):
        program = programs[f"writes/limits/index-entry-sum/{length}-{count}"]
        write = program["steps"][0]["body"]["writes"][0]
        assert len(write["update"]["name"].split("/documents/")[1].encode()) == length
        values = write["update"]["fields"]["a"]["arrayValue"]["values"]
        assert len(values) == count
        assert len({value["integerValue"] for value in values}) == count
    program = programs["writes/limits/decoded-11x1040000"]
    writes = program["steps"][0]["body"]["writes"]
    assert len(writes) == 11
    assert all(
        len(write["update"]["fields"]["s"]["stringValue"]) == 1_040_000
        for write in writes
    )
    assert len(program["steps"][1]["body"]["documents"]) == 11


def test_additional_field_path_boundaries_are_unbiased_and_have_readbacks() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    for length in (1499, 1500):
        mask = programs[f"writes/limits/field-path-mask/{length}"]
        assert len(mask["steps"]) == 2
        assert len(mask["steps"][0]["body"]["writes"]) == 1
        write = mask["steps"][0]["body"]["writes"][0]
        assert len(write["updateMask"]["fieldPaths"]) == 1
        field = write["updateMask"]["fieldPaths"][0]
        assert len(field.encode()) == length
        assert list(write["update"]["fields"]) == [field]
        assert mask["steps"][1]["id"] == "readback"
        assert mask["steps"][1]["body"]["documents"] == [write["update"]["name"]]
    for length in (1494, 1495):
        program = programs[f"writes/limits/implied-array-key/{length}"]
        assert len(program["steps"]) == 2
        assert len(program["steps"][0]["body"]["writes"]) == 1
        write = program["steps"][0]["body"]["writes"][0]
        fields = write["update"]["fields"]["a"]["arrayValue"]["values"][0]["mapValue"][
            "fields"
        ]
        assert [len(key.encode()) for key in fields] == [length]
        assert program["steps"][1]["id"] == "readback"
        assert program["steps"][1]["body"]["documents"] == [write["update"]["name"]]
    assert all(
        "expected" not in step
        for program in programs.values()
        for step in program["steps"]
    )


def test_nested_map_key_validation_covers_write_and_query_without_expected_outputs() -> (
    None
):
    programs = {program["id"]: program for program in _module().build_programs()}
    cases = {
        "reserved": "__bad__",
        "empty": "",
        "overlong": "k" * 1_501,
        "type-tag": "__type__",
    }
    for label, key in cases.items():
        query = programs[f"writes/map-key-validation/{label}/query"]
        assert len(query["steps"]) == 1
        step = query["steps"][0]
        assert step["method"] == "POST"
        assert step["path"] == f"/v1/{_module().DOCS}:runQuery"
        value = step["body"]["structuredQuery"]["where"]["fieldFilter"]["value"]
        assert list(value["mapValue"]["fields"]) == [key]
        assert "expected" not in step
        if label == "type-tag":
            continue
        write = programs[f"writes/map-key-validation/{label}/write"]
        assert [step["id"] for step in write["steps"]] == ["write", "readback"]
        fields = write["steps"][0]["body"]["writes"][0]["update"]["fields"]
        assert list(fields["m"]["mapValue"]["fields"]) == [key]
        assert write["steps"][1]["body"]["documents"] == [
            write["steps"][0]["body"]["writes"][0]["update"]["name"]
        ]
        assert all("expected" not in step for step in write["steps"])


def test_two_field_batch_decode_probe_distinguishes_source_order_from_sorted_order() -> (
    None
):
    programs = {program["id"]: program for program in _module().build_programs()}
    program = programs["writes/batch-write-malformed/two-fields-bad-integer"]
    assert [step["id"] for step in program["steps"]] == ["batch-write", "readback"]
    writes = program["steps"][0]["body"]["writes"]
    assert len(writes) == 3
    fields = writes[1]["update"]["fields"]
    assert list(fields) == ["z", "a"]
    assert fields["z"] == {"integerValue": "1"}
    assert fields["a"] == {"integerValue": "not-a-number"}
    assert program["steps"][1]["body"]["documents"] == [
        write["update"]["name"] for write in writes
    ]
    assert all("expected" not in step for step in program["steps"])
