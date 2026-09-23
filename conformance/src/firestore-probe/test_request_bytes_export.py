"""Request-byte sandbox recipes retain the compiler's exact wire-body sizes."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).with_name("request_bytes_export.py")


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
