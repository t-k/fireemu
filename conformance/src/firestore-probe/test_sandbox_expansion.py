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


def test_non_commit_batchwrite_request_boundary_is_exact_and_keeps_readback() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    for size in (10_485_760, 10_485_761):
        program = programs[
            f"writes/limits/non-commit-rest-request-bytes/batch-write/{size}"
        ]
        assert len(program["steps"]) == 2
        step = program["steps"][0]
        assert step["method"] == "POST"
        assert step["path"].endswith("/documents:batchWrite")
        assert len(step["body"].encode()) == size
        writes = json.loads(step["body"])["writes"]
        assert len(writes) == 1
        assert program["steps"][1]["id"] == "readback"
        assert program["steps"][1]["body"]["documents"] == [writes[0]["update"]["name"]]
        assert all("expected" not in item for item in program["steps"])


def test_non_commit_read_request_boundaries_seed_one_document() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    for family, suffix in (("batch-get", ":batchGet"), ("run-query", ":runQuery")):
        for size in (10_485_760, 10_485_761):
            program = programs[
                f"writes/limits/non-commit-rest-request-bytes/{family}/{size}"
            ]
            assert len(program["steps"]) == 2
            seed, probe = program["steps"]
            assert seed["id"] == "seed"
            assert seed["path"].endswith("/documents:commit")
            seeded_name = seed["body"]["writes"][0]["update"]["name"]
            assert probe["method"] == "POST"
            assert probe["path"].endswith(f"/documents{suffix}")
            assert len(probe["body"].encode()) == size
            body = json.loads(probe["body"])
            if family == "batch-get":
                assert body["documents"] == [seeded_name]
            else:
                assert body["structuredQuery"]["from"] == [
                    {"collectionId": seeded_name.split("/documents/")[1].split("/")[0]}
                ]
            assert all("expected" not in item for item in program["steps"])


def test_non_commit_document_write_boundaries_keep_state_readback() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    for family, method in (("create", "POST"), ("patch", "PATCH")):
        for size in (10_485_760, 10_485_761):
            program = programs[
                f"writes/limits/non-commit-rest-request-bytes/{family}/{size}"
            ]
            steps = program["steps"]
            assert len(steps) == (3 if family == "patch" else 2)
            probe = steps[-2]
            assert probe["method"] == method
            assert len(probe["body"].encode()) == size
            body = json.loads(probe["body"])
            assert body["fields"]["v"]["integerValue"] == "2"
            assert steps[-1]["id"] == "readback"
            if family == "patch":
                assert steps[0]["id"] == "seed"
                assert steps[0]["body"]["writes"][0]["update"]["name"] in probe["path"]
            else:
                assert "documentId=" in probe["path"]
            assert all("expected" not in item for item in steps)


def test_map_aggregate_probe_exceeds_strict_value_limit_but_fits_document() -> None:
    programs = {program["id"]: program for program in _module().build_programs()}
    program = programs["writes/limits/aggregate-map/strict-only"]
    write = program["steps"][0]["body"]["writes"][0]["update"]
    name = write["name"]
    assert name.endswith("/documents/m/x")
    value = write["fields"]["m"]["mapValue"]["fields"]["s"]["stringValue"]
    assert len(value.encode()) == 1_048_500
    map_size = len("s") + 1 + len(value.encode()) + 1
    document_size = (
        16 + (len("m") + 1) + (len("x") + 1) + 32 + (len("m") + 1) + map_size
    )
    assert 1_048_487 < map_size < document_size <= 1_048_576
    assert program["steps"][1]["body"]["documents"] == [name]
    assert all("expected" not in step for step in program["steps"])


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
    for length in (2641, 2642):
        write = programs[f"writes/limits/index-entry-string-name/{length}"]["steps"][0][
            "body"
        ]["writes"][0]
        assert len(write["update"]["name"].split("/documents/")[1].encode()) == length
        assert len(write["update"]["fields"]["s"]["stringValue"].encode()) == 1500
    for length in (4627, 4628, 6127, 6128):
        write = programs[f"writes/limits/empty-document-name/{length}"]["steps"][0][
            "body"
        ]["writes"][0]
        assert write["update"]["fields"] == {}
    boundary = programs["writes/limits/index-entry-sum/adjacent"]
    assert len(boundary["steps"]) == 12
    names = []
    for index, (length, count) in enumerate(
        (
            (500, 19999),
            (500, 20000),
            (2000, 7184),
            (2000, 7185),
            (1000, 12123),
            (1000, 12124),
        )
    ):
        write_step, readback_step = boundary["steps"][2 * index : 2 * index + 2]
        assert write_step["id"] == f"write-{length}-{count}"
        assert readback_step["id"] == f"readback-{length}-{count}"
        write = write_step["body"]["writes"][0]
        names.append(write["update"]["name"])
        assert readback_step["body"]["documents"] == [write["update"]["name"]]
        assert len(write["update"]["name"].split("/documents/")[1].encode()) == length
        values = write["update"]["fields"]["a"]["arrayValue"]["values"]
        assert len(values) == count
        assert len({value["integerValue"] for value in values}) == count
    assert len(set(names)) == 6
    assert len({name.split("/documents/")[1].split("/")[0] for name in names}) == 6
    program = programs["writes/limits/decoded-11x1040000"]
    writes = program["steps"][0]["body"]["writes"]
    assert len(writes) == 11
    assert all(
        len(write["update"]["fields"]["s"]["stringValue"]) == 1_040_000
        for write in writes
    )
    assert len(program["steps"][1]["body"]["documents"]) == 11


def test_next_recording_includes_observed_adjacent_default_name_pairs() -> None:
    programs = {program["id"] for program in _module().build_programs()}
    for length in (2641, 2642):
        assert f"writes/limits/index-entry-string-name/{length}" in programs
    for length in (4627, 4628):
        assert f"writes/limits/empty-document-name/{length}" in programs


def test_near_limit_delete_pairs_cover_each_rest_route_with_fresh_state_reads() -> None:
    programs = {
        program["id"]: program
        for program in _module().build_programs()
        if program["id"].startswith("writes/limits/near-limit-delete-refusal/")
    }
    assert set(programs) == {
        f"writes/limits/near-limit-delete-refusal/{route}/{count}"
        for route in ("rest", "commit", "batch-write")
        for count in (12_112, 12_113)
    }
    groups = set()
    for program_id, program in programs.items():
        route = program_id.split("/")[-2]
        count = int(program_id.split("/")[-1])
        seed, before, delete, after, group = program["steps"]
        assert seed["id"] == "seed"
        assert seed["method"] == "POST" and seed["path"].endswith(":commit")
        write = seed["body"]["writes"][0]["update"]
        name = write["name"]
        assert (
            len(
                name.replace("DELETE_RUN_ID", "a" * 32).split("/documents/")[1].encode()
            )
            == 1000
        )
        assert len(write["fields"]["a"]["arrayValue"]["values"]) == count
        assert "DELETE_RUN_ID" in name
        collection_id = name.split("/documents/")[1].split("/")[0]
        assert "explore" not in collection_id.lower()
        groups.add(collection_id)
        assert before == {"id": "before-delete", "method": "GET", "path": f"/v1/{name}"}
        assert after == {
            "id": "after-delete",
            "method": "POST",
            "path": "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:batchGet",
            "body": {"documents": [name]},
        }
        assert group["id"] == "group-after-delete"
        assert group["method"] == "POST" and group["path"].endswith("/documents:runQuery")
        if route == "rest":
            assert delete == {"id": "delete", "method": "DELETE", "path": f"/v1/{name}"}
        elif route == "commit":
            assert delete["id"] == "delete" and delete["path"].endswith(":commit")
            assert delete["body"] == {"writes": [{"delete": name}]}
        else:
            assert delete["id"] == "delete" and delete["path"].endswith(":batchWrite")
            assert delete["body"] == {"writes": [{"delete": name}]}
        assert group["id"] == "group-after-delete" and group["method"] == "POST"
        assert group["path"].endswith(":runQuery")
        assert group["body"]["structuredQuery"]["from"] == [
            {"collectionId": collection_id, "allDescendants": True}
        ]
    assert len(groups) == 6


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
