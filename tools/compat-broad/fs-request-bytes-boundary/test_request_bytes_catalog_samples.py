"""The 10 MiB catalog samples reuse the strict compiler without changing it."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import request_bytes_compiler as strict
from request_bytes_catalog_samples import (
    CATALOG_SAMPLE_TARGETS,
    compile_catalog_sample_plan,
)
from request_bytes_compiler import compact_utf8

HERE = Path(__file__).parent
NONCE = "a" * 32


def test_catalog_samples_are_the_adjacent_10_mib_triple():
    assert CATALOG_SAMPLE_TARGETS == (10_485_759, 10_485_760, 10_485_761)
    plan = compile_catalog_sample_plan("demo", "(default)", NONCE)
    sizes = [len(compact_utf8(probe["body"])) for probe in plan["probes"]]
    assert sizes == list(CATALOG_SAMPLE_TARGETS)
    assert [probe["bodyBytes"] for probe in plan["probes"]] == list(CATALOG_SAMPLE_TARGETS)
    assert plan["bounds"]["requestBytes"] == 10_485_761


def test_catalog_samples_leave_the_strict_compiler_unchanged():
    before = strict.REQUEST_TARGETS
    compile_catalog_sample_plan("demo", "(default)", NONCE)
    assert strict.REQUEST_TARGETS == before == (11_534_335, 11_534_336, 11_534_337)
    plan = strict.compile_request_bytes_plan("demo", "(default)", NONCE)
    assert [probe["bodyBytes"] for probe in plan["probes"]] == list(before)


def test_the_published_strict_shadow_still_matches_its_bound_sources():
    from request_bytes_shadow import OBSERVATION_MODULES, observation_source_digest

    assert "request_bytes_catalog_samples.py" not in OBSERVATION_MODULES
    record = json.loads(
        (
            HERE.parents[1].parent
            / "spec/compatibility/broad-runs/fs-request-bytes-local-shadow-11mib.json"
        ).read_text()
    )
    assert record["sourceDigestBefore"] == observation_source_digest()
