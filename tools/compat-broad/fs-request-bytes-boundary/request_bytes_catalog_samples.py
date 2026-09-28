"""Compile the saved 10 MiB catalog sample plan without changing the strict campaign.

The strict REST Commit campaign moved to an 11 MiB adjacent pair, and its compiler is
bound by the published 11 MiB local-shadow source digest, so it must stay unchanged.
The saved production samples (10 MiB - 1, 10 MiB and 10 MiB + 1 bytes) reuse its exact
body construction through a private module instance whose target triple is replaced.
The importable ``request_bytes_compiler`` module is never modified.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

COMPILER = Path(__file__).with_name("request_bytes_compiler.py")
CATALOG_MAXIMUM = 10_485_760
CATALOG_SAMPLE_TARGETS = (CATALOG_MAXIMUM - 1, CATALOG_MAXIMUM, CATALOG_MAXIMUM + 1)


def _private_compiler() -> Any:
    spec = importlib.util.spec_from_file_location(
        "request_bytes_catalog_sample_compiler", COMPILER
    )
    if spec is None or spec.loader is None:
        raise ValueError("request-byte compiler is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.CATALOG_MAXIMUM != CATALOG_MAXIMUM:
        raise ValueError("request-byte catalog maximum changed")
    module.REQUEST_TARGETS = CATALOG_SAMPLE_TARGETS
    return module


def compile_catalog_sample_plan(project: str, database: str, nonce: str) -> dict[str, Any]:
    """Compile and independently validate the three 10 MiB sample probes."""
    compiler = _private_compiler()
    plan = compiler.compile_request_bytes_plan(project, database, nonce)
    compiler.validate_request_bytes_plan(plan)
    sizes = [len(compiler.compact_utf8(probe["body"])) for probe in plan["probes"]]
    if sizes != list(CATALOG_SAMPLE_TARGETS):
        raise ValueError("request-byte compiler changed an exact catalog sample size")
    return plan
