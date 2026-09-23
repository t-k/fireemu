"""The sandbox corpus reuses the existing exact-boundary request compiler."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).with_name("limits03_export.py")


def _build_programs() -> list[dict]:
    spec = importlib.util.spec_from_file_location("limits03_export", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_programs()


def test_all_compiled_limits03_cases_are_in_one_sandbox_corpus() -> None:
    programs = _build_programs()
    assert len(programs) == 16
    assert len({program["id"] for program in programs}) == 16
    assert sum(len(program["steps"]) for program in programs) == 60
    for program in programs:
        assert program["steps"]
        for step in program["steps"]:
            assert step["method"] in {"GET", "PATCH", "POST"}
            assert step["path"].startswith(
                "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents"
            )
    encoded = json.dumps(programs)
    assert "/nx/" not in encoded
    assert "/pk/" in encoded
    assert "FIREEMU_PRODUCTION_TOKEN" not in encoded


def test_exact_identifier_and_name_boundaries_are_retained() -> None:
    programs = _build_programs()
    by_id = {program["id"]: program for program in programs}
    collection = by_id["writes/limits/collection-id-boundary"]
    paths = [step["path"] for step in collection["steps"] if step["method"] == "PATCH"]
    assert [len(path.split("/")[-2].encode()) for path in paths] == [1500, 1501]
    names = by_id["writes/limits/document-name-bytes"]
    paths = [step["path"] for step in names["steps"] if step["method"] == "PATCH"]
    assert [
        len(path.removeprefix("/v1/").split("?", 1)[0].encode()) for path in paths
    ] == [6144, 6145]


def test_sandbox_limits_omit_legacy_shared_owner_reference() -> None:
    programs = _build_programs()
    assert all("_sharedOwner" not in json.dumps(program) for program in programs)
    affected = 0
    for program in programs:
        for step in program["steps"]:
            body = step.get("body")
            if not isinstance(body, dict) or not isinstance(body.get("fields"), dict):
                continue
            assert "_sharedOwner" not in body["fields"], program["id"]
            if step["method"] == "PATCH":
                assert body["fields"], program["id"]
                affected += 1
    assert affected >= 20


def test_index_entry_count_pair_rebalances_after_owner_removal() -> None:
    programs = {program["id"]: program for program in _build_programs()}
    steps = programs["writes/limits/index-entries-per-document"]["steps"]
    values = [step["body"]["fields"]["a"]["arrayValue"]["values"] for step in steps[:2]]
    assert [len(item) for item in values] == [19_999, 20_000]
    assert all(
        len({value["integerValue"] for value in item}) == len(item) for item in values
    )
    assert all("_sharedOwner" not in json.dumps(step) for step in steps)


def test_map_size_and_indexed_value_inputs_do_not_repeat_unbracketed_v2_shapes() -> (
    None
):
    programs = {program["id"]: program for program in _build_programs()}
    map_steps = programs["writes/limits/aggregate-map"]["steps"]
    map_lengths = [
        len(
            map_steps[index]["body"]["fields"]["m"]["mapValue"]["fields"]["s"][
                "stringValue"
            ].encode()
        )
        for index in (0, 2)
    ]
    assert map_lengths == [1_048_458, 1_048_459]

    indexed_steps = programs["writes/limits/indexed-field-value-bytes"]["steps"]
    for step in indexed_steps:
        assert (
            len(step["path"].split("/documents/", 1)[1].split("?", 1)[0].encode())
            < 2_600
        )
        if step["method"] == "PATCH":
            assert (
                step["body"]["name"]
                == step["path"].removeprefix("/v1/").split("?", 1)[0]
            )
    indexed_lengths = [
        len(
            next(iter(indexed_steps[index]["body"]["fields"].values()))[
                "stringValue"
            ].encode()
        )
        for index in (0, 1)
    ]
    assert indexed_lengths == [1_499, 2_999]
