"""Validate inputs independently; none of these tests runs the Rust backend."""
from __future__ import annotations

import base64
import copy
import itertools
import json
import re
import subprocess
import sys
from pathlib import Path

import boundaries
import pytest

NONCE = "a" * 32
FAMILIES = [
    "collection-id", "document-id", "subcollection-depth", "document-name",
    "field-name", "field-path", "field-string", "field-bytes", "field-map",
    "field-array", "indexed-value", "index-count", "index-entry", "index-sum",
]
POINTS = ["below", "exact", "over"]


def storage(value):
    """Independent evaluator for the five wire types in this finite corpus."""
    assert isinstance(value, dict) and len(value) == 1
    kind, content = next(iter(value.items()))
    if kind == "integerValue":
        assert isinstance(content, str) and str(int(content)) == content
        return 8
    if kind == "bytesValue":
        return len(base64.b64decode(content, validate=True))
    if kind == "stringValue":
        return len(content.encode("utf-8")) + 1
    if kind == "mapValue":
        return sum(len(k.encode()) + 1 + storage(v) for k, v in content["fields"].items())
    assert kind == "arrayValue"
    return sum(storage(v) for v in content["values"])


def paths(fields, prefix=()):
    for name, value in fields.items():
        full = (*prefix, name)
        yield full
        if "mapValue" in value:
            yield from paths(value["mapValue"]["fields"], full)


def composite_sizes(case):
    """Enumerate explicit entries; do not use the compiler's reported counters."""
    config = case["indexConfiguration"]
    parts = case["resource"].split("/", 5)[5].split("/")
    assert config["fieldOverrides"] == [
        {"collectionGroup": parts[-2], "fieldPath": "*", "indexes": []}
    ]
    name = 16 + sum(len(p.encode()) + 1 for p in parts)
    parent = 16 + sum(len(p.encode()) + 1 for p in parts[:-2]) if len(parts) > 2 else 0
    result = []
    for definition in config["indexes"]:
        assert definition["queryScope"] == "COLLECTION"
        assert definition["collectionGroup"] == parts[-2]
        columns = []
        for field in definition["fields"]:
            value = case["document"]["fields"][field["fieldPath"]]
            if field.get("arrayConfig") == "CONTAINS":
                values = value["arrayValue"]["values"]
                # Unique across integer/bytes types; no silent deduplication.
                keys = {json.dumps(v, sort_keys=True) for v in values}
                assert len(values) == len(keys)
                columns.append(values)
            else:
                assert field["order"] == "ASCENDING"
                columns.append([value])
        for values in itertools.product(*columns):
            result.append(name + parent + 32 + sum(min(1500, storage(v)) for v in values))
    return result


@pytest.mark.parametrize("family,position", list(itertools.product(FAMILIES, POINTS)))
def test_each_payload_hits_its_claimed_metric_and_declares_competing_limits(family, position):
    case = boundaries.compile_case(family, position, NONCE)
    maximum = boundaries.FAMILIES[family][1]
    point = maximum + {"below": -1, "exact": 0, "over": 1}[position]
    fields = case["document"]["fields"]
    parts = case["resource"].split("/", 5)[5].split("/")
    assert len(parts) % 2 == 0 and all(parts)
    assert NONCE in parts[-1]
    assert case["write"]["update"] == case["document"]
    assert case["write"]["currentDocument"] == {"exists": False}
    expected_acceptance = (
        (position != "over" and family != "document-name")
        or family == "indexed-value"
    )
    assert case["expect"]["accepted"] is expected_acceptance
    if family == "collection-id":
        measured = len(parts[-2].encode())
    elif family == "document-id":
        measured = len(parts[-1].encode())
    elif family == "subcollection-depth":
        measured = len(parts) // 2
    elif family == "document-name":
        measured = 16 + sum(len(p.encode()) + 1 for p in parts)
        assert max(len(p.encode()) for p in parts) <= 1500
        assert case["overlappingLimits"] == ["FS-LIMIT-INDEX-ENTRY-BYTES"]
    elif family == "field-name":
        measured = max(len(p[-1].encode()) for p in paths(fields))
        assert case["overlappingLimits"] == ["FS-LIMIT-FIELD-PATH-BYTES"]
    elif family == "field-path":
        measured = max(len(".".join(p).encode()) for p in paths(fields))
        assert max(len(p[-1].encode()) for p in paths(fields)) <= 500
    elif family == "field-string":
        measured = len(fields["v"]["stringValue"].encode())
    elif family.startswith("field-"):
        measured = storage(fields["v"])
    elif family == "indexed-value":
        measured = storage(fields["v"])
        assert case["metric"]["indexedValueBytes"] == min(measured, 1500)
        assert len(fields["v"]["stringValue"]) == point - 1
        assert composite_sizes(case) == [51 + 32 + 8 + min(point, 1500)]
    else:
        sizes = composite_sizes(case)
        measured = {"index-count": len(sizes), "index-entry": max(sizes), "index-sum": sum(sizes)}[family]
        assert case["metric"]["entries"] == len(sizes)
        assert case["metric"]["maximumEntryBytes"] == max(sizes)
        assert case["metric"]["indexBytes"] == sum(sizes)
        if family != "index-count":
            assert len(sizes) <= 40000
        if family != "index-entry":
            assert max(sizes) <= 7680
        if family != "index-sum":
            assert sum(sizes) <= 8388608
    assert measured == point == case["metric"]["target"]
    # Even the negative field-value point fits the separate document-byte limit.
    logical = 16 + sum(len(p.encode()) + 1 for p in parts) + 32
    logical += sum(len(k.encode()) + 1 + storage(v) for k, v in fields.items())
    assert logical <= 1048576
    request = {"writes": [case["write"]]}
    assert len(json.dumps(request).encode()) < 10485760


def test_full_inventory_keeps_existing_four_limits_separate_and_is_not_execution():
    value = boundaries.compile_suite(NONCE)
    assert len(value["cases"]) == 42
    assert len({c["id"] for c in value["cases"]}) == 42
    ids = {c["limitId"] for c in value["cases"]}
    existing = {c["limitId"] for c in value["separateExistingCoverage"]}
    assert len(ids) == 11 and len(existing) == 4 and not ids & existing
    for item in value["separateExistingCoverage"]:
        assert (boundaries.ROOT / item["source"]).is_file()
    assert value["productionExecuted"] is False
    assert value["authorizesProduction"] is False
    assert value["nativeExecuted"] is False
    assert value["compatibility"] == "not-observed"
    assert value["target"] == "isolated-local-backend-per-case"


@pytest.mark.parametrize("position", POINTS)
def test_document_name_fixture_exposes_the_competing_index_entry_limit(position):
    case = boundaries.compile_case("document-name", position, NONCE)
    assert case["expect"]["accepted"] is False
    assert case["overlappingLimits"] == ["FS-LIMIT-INDEX-ENTRY-BYTES"]


@pytest.mark.parametrize("value", [None, True, 42, [], {}, "", "A" * 32, "a" * 31, "a" * 33])
def test_invalid_nonce_never_compiles(value):
    with pytest.raises(ValueError):
        boundaries.compile_case("index-count", "exact", value)


@pytest.mark.parametrize("value", [True, 1, [], {}, "", "production", "../index-count"])
def test_unknown_selection_is_refused(value):
    with pytest.raises(ValueError):
        boundaries.compile_suite(NONCE, family=value)
    with pytest.raises(ValueError):
        boundaries.compile_suite(NONCE, position=value)


@pytest.mark.parametrize("mutation", ["maximum", "unsupported"])
def test_catalog_drift_cannot_silently_retarget_boundaries(tmp_path, monkeypatch, mutation):
    data = json.loads(boundaries.CATALOG.read_bytes())
    row = next(r for r in data["limits"] if r["id"] == "FS-LIMIT-INDEX-ENTRY-BYTES")
    row["maximum" if mutation == "maximum" else "implemented"] = 8000 if mutation == "maximum" else "unsupported"
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data))
    monkeypatch.setattr(boundaries, "CATALOG", path)
    with pytest.raises(ValueError, match="catalog drift"):
        boundaries.compile_suite(NONCE, family="indexed-value", position="over")


def test_case_instances_do_not_share_mutable_configuration():
    left = boundaries.compile_case("index-entry", "exact", NONCE)
    right = copy.deepcopy(left)
    left["indexConfiguration"]["fieldOverrides"].clear()
    assert boundaries.compile_case("index-entry", "exact", NONCE) == right


def test_real_cli_writes_new_local_input_without_overwriting(tmp_path):
    output = tmp_path / "input.json"
    args = [sys.executable, "-I", "-S", "-B", str(Path(boundaries.__file__)),
            "--nonce", NONCE, "--family", "indexed-value", "--position", "over", "--output", str(output)]
    first = subprocess.run(args, capture_output=True, timeout=20, check=False)
    assert first.returncode == 0, first.stderr
    raw = output.read_bytes()
    case = json.loads(raw)["cases"]
    assert len(case) == 1 and case[0]["id"] == "indexed-value/over"
    assert subprocess.run(args, capture_output=True, timeout=20, check=False).returncode != 0
    assert output.read_bytes() == raw
    link = tmp_path / "link.json"
    link.symlink_to(output)
    args[-1] = str(link)
    assert subprocess.run(args, capture_output=True, timeout=20, check=False).returncode != 0
    assert output.read_bytes() == raw


def test_native_source_declares_all_three_handlers_for_every_family():
    # This is source wiring, not a successful Rust compilation or test run.
    source = (boundaries.ROOT / "crates/fireemu-adapter-grpc/tests/write_boundary_corpus.rs").read_text()
    families = re.findall(r'boundaries!\([\s\w,]*"([\w-]+)"\s*\);', source)
    assert sorted(families) == sorted(FAMILIES)
    assert 'exercise($patch' not in source
    for route in ('exercise($family, "patch")', 'exercise($family, "commit")', 'exercise($family, "batchWrite")'):
        assert route in source
