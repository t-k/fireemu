"""Export exact-body REST Commit probes from the existing request-byte compiler.

The resulting programs have no expected status. Their production response and
every affected document readback are recorded before local comparison.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
COMPILER = (
    ROOT / "tools/compat-broad/fs-request-bytes-boundary/request_bytes_compiler.py"
)
CATALOG_SAMPLES = (
    ROOT / "tools/compat-broad/fs-request-bytes-boundary/request_bytes_catalog_samples.py"
)
PROJECT = "fireemu-oracle-sbx"
DATABASE = "(default)"
# Stable namespace component only; no admission nonce is used on the sandbox track.
PATH_COMPONENT = "a" * 32


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"{path.name} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _compiler_module() -> Any:
    return _load("request_bytes_sandbox_compiler", COMPILER)


def _catalog_samples_module() -> Any:
    return _load("request_bytes_sandbox_catalog_samples", CATALOG_SAMPLES)


def _program(recipe_id: str, probe: dict[str, Any]) -> dict[str, Any]:
    steps = [
        {
            "id": "commit",
            "method": "POST",
            "path": probe["path"],
            "body": probe["body"],
        },
        *[
            {
                "id": f"readback-{index}",
                "method": "GET",
                "path": f"/v1/{resource}",
            }
            for index, resource in enumerate(probe["resources"])
        ],
    ]
    if any(
        not step["path"].startswith(
            f"/v1/projects/{PROJECT}/databases/{DATABASE}/documents"
        )
        for step in steps
    ):
        raise ValueError("request-byte compiler escaped the sandbox project")
    return {"id": recipe_id, "area": "writes", "steps": steps}


def build_programs() -> list[dict[str, Any]]:
    compiler = _compiler_module()
    samples = _catalog_samples_module()
    # The saved production samples stay at 10 MiB; the strict campaign is 11 MiB.
    decoded = samples.compile_catalog_sample_plan(PROJECT, DATABASE, PATH_COMPONENT)
    sentinel = compiler.compile_request_bytes_sentinel_plan(
        PROJECT, DATABASE, PATH_COMPONENT
    )
    programs = [
        _program(f"writes/limits/decoded-request-bytes/{probe['label']}", probe)
        for probe in decoded["probes"]
    ]
    programs.extend(
        _program("writes/limits/raw-request-bytes", probe)
        for probe in sentinel["probes"]
    )
    if len(programs) != 4:
        raise ValueError("request-byte corpus has an unexpected probe count")
    for program in programs:
        body = program["steps"][0]["body"]
        size = len(json.dumps(body, separators=(",", ":")).encode())
        if size not in (*samples.CATALOG_SAMPLE_TARGETS, compiler.RAW_16MIB_OVER_BYTES):
            raise ValueError("request-byte compiler changed an exact wire size")
    return programs


if __name__ == "__main__":
    json.dump(build_programs(), sys.stdout, separators=(",", ":"))
