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
    for length in (2642, 2643, 4621, 4622, 6127, 6128):
        name = module.name_of_length(length, f"n{length}")
        segments = name.split("/")
        assert len(name.encode()) == length
        assert len(segments) % 2 == 0
        assert all(1 <= len(segment.encode()) <= 1500 for segment in segments)
        assert all(segment == "c" for segment in segments[::2])
        assert max(map(len, segments[1::2])) - min(map(len, segments[1::2])) <= 1


def test_index_sum_names_reproduce_the_exploration_layout() -> None:
    module = _module()
    for target, collection_bytes, document_bytes in ((1000, 998, 1), (2000, 1400, 599)):
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
    for variant in ("no-operation", "collection-name", "empty-field-name", "reserved-field-name", "bad-mask-path", "bad-integer", "unknown-value-kind", "bad-timestamp", "exists-precondition-fails"):
        program = programs[f"writes/batch-write-malformed/{variant}"]
        assert len(program["steps"][0]["body"]["writes"]) == 3
        assert len(program["steps"][1]["body"]["documents"]) == 3
        assert all("expected" not in step for step in program["steps"])


def test_index_and_decoded_request_boundaries_have_exact_input_shapes() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    for length in (2642, 2643):
        write = programs[f"writes/limits/index-entry-string-name/{length}"]["steps"][0]["body"]["writes"][0]
        assert len(write["update"]["name"].split("/documents/")[1].encode()) == length
        assert len(write["update"]["fields"]["s"]["stringValue"].encode()) == 1500
    for length in (4621, 4622, 6127, 6128):
        write = programs[f"writes/limits/empty-document-name/{length}"]["steps"][0]["body"]["writes"][0]
        assert write["update"]["fields"] == {}
    for length, count in ((2000, 9549), (2000, 9550), (1000, 19998), (1000, 19999)):
        program = programs[f"writes/limits/index-entry-sum/{length}-{count}"]
        write = program["steps"][0]["body"]["writes"][0]
        assert len(write["update"]["name"].split("/documents/")[1].encode()) == length
        values = write["update"]["fields"]["a"]["arrayValue"]["values"]
        assert len(values) == count
        assert len({value["integerValue"] for value in values}) == count
    program = programs["writes/limits/decoded-11x1040000"]
    writes = program["steps"][0]["body"]["writes"]
    assert len(writes) == 11
    assert all(len(write["update"]["fields"]["s"]["stringValue"]) == 1_040_000 for write in writes)
    assert len(program["steps"][1]["body"]["documents"]) == 11
