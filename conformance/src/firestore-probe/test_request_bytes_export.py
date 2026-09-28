"""Request-byte sandbox recipes retain the compiler's exact wire-body sizes."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).with_name("request_bytes_export.py")
RECIPE_DIGESTS = MODULE.parents[2] / "fs-data-write-recipe-digests.json"


def _programs() -> list[dict]:
    spec = importlib.util.spec_from_file_location("request_bytes_export", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_programs()


def test_request_byte_corpus_has_three_decoded_boundary_cases_and_raw_sentinel() -> (
    None
):
    programs = _programs()
    assert [program["id"] for program in programs] == [
        "writes/limits/decoded-request-bytes/under",
        "writes/limits/decoded-request-bytes/exact",
        "writes/limits/decoded-request-bytes/over",
        "writes/limits/raw-request-bytes",
    ]
    sizes = [
        len(json.dumps(program["steps"][0]["body"], separators=(",", ":")).encode())
        for program in programs
    ]
    assert sizes == [10_485_759, 10_485_760, 10_485_761, 16_777_217]
    for program in programs:
        assert program["steps"][0]["method"] == "POST"
        assert program["steps"][0]["path"] == (
            "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:commit"
        )
        assert all(step["method"] == "GET" for step in program["steps"][1:])


def test_decoded_sample_ids_keep_the_saved_ten_mib_recipe_digests() -> None:
    programs = _programs()
    expected = json.loads(RECIPE_DIGESTS.read_text())["programs"]
    decoded = programs[:3]
    assert [program["id"] for program in decoded] == [
        "writes/limits/decoded-request-bytes/under",
        "writes/limits/decoded-request-bytes/exact",
        "writes/limits/decoded-request-bytes/over",
    ]
    for program in decoded:
        encoded = json.dumps(
            program, separators=(",", ":"), ensure_ascii=False
        ).encode()
        assert hashlib.sha256(encoded).hexdigest() == expected[program["id"]]


def test_exporter_uses_catalog_samples_separate_from_strict_targets() -> None:
    spec = importlib.util.spec_from_file_location("request_bytes_export", MODULE)
    assert spec is not None and spec.loader is not None
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    samples = exporter._catalog_samples_module()
    assert samples.CATALOG_SAMPLE_TARGETS == (10_485_759, 10_485_760, 10_485_761)
    assert exporter._compiler_module().REQUEST_TARGETS == (11_534_335, 11_534_336, 11_534_337)
    programs = exporter.build_programs()
    assert [
        len(json.dumps(program["steps"][0]["body"], separators=(",", ":")).encode())
        for program in programs[:3]
    ] == list(samples.CATALOG_SAMPLE_TARGETS)
