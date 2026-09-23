"""Export the existing Limits-03 boundary recipes for the disposable sandbox corpus.

This is an offline request transformation. It does not authorize or send requests.
The compiler supplies exact payloads and boundary math; the conformance runner
records production outcomes without using the compiler's guessed expectations.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
COMPILER = ROOT / "tools/compat-broad/fs-write-limits/compiler_03.py"
DESCRIPTOR = ROOT / "spec/compatibility/broad-runs/fs-write-limits-03.json"
PROJECT = "fireemu-oracle-sbx"
DATABASE = "(default)"
# This is a stable document-path component, not an admission nonce.
PATH_COMPONENT = "a" * 32

CASE_RECIPES = {
    "batch-malformed-middle": "writes/batch-write-malformed/missing-operation",
    "batch-undecodable-value": "writes/batch-write-malformed/undecodable-value",
    "batch-duplicate-document": "writes/batch-write-malformed/duplicate-document",
    "collection-id": "writes/limits/collection-id-boundary",
    "subcollection-depth": "writes/limits/subcollection-depth",
    "document-name": "writes/limits/document-name-bytes",
    "index-entry-bytes": "writes/limits/index-entry-bytes",
    "index-entries": "writes/limits/index-entries-per-document",
    "index-entry-sum": "writes/limits/index-entry-sum-per-document",
    "indexed-value": "writes/limits/indexed-field-value-bytes",
    "implied-map": "writes/limits/implied-map",
    "implied-array": "writes/limits/implied-array",
    "field-path": "writes/limits/field-path-direct-mask",
    "field-value": "writes/limits/field-value-scalar-refusal",
    "agg-string": "writes/limits/aggregate-string",
    "agg-map": "writes/limits/aggregate-map",
}


def _compiler_module() -> Any:
    sys.path.insert(0, str(ROOT / "tools/compat-broad"))
    spec = importlib.util.spec_from_file_location("limits03_sandbox_compiler", COMPILER)
    if spec is None or spec.loader is None:
        raise ValueError("Limits-03 compiler is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sandbox_index_exemption(value: Any) -> Any:
    """Use the deployed `pk` exemption; both group IDs are two bytes long."""
    if isinstance(value, str):
        return value.replace("/nx/", "/pk/")
    if isinstance(value, list):
        return [_sandbox_index_exemption(item) for item in value]
    if isinstance(value, dict):
        return {key: _sandbox_index_exemption(item) for key, item in value.items()}
    return value


def _remove_shared_owner(value: Any) -> None:
    if isinstance(value, dict):
        value.pop("_sharedOwner", None)
        for key, child in value.items():
            if key == "fieldPaths" and isinstance(child, list):
                child[:] = [path for path in child if path != "_sharedOwner"]
            else:
                _remove_shared_owner(child)
    elif isinstance(value, list):
        for child in value:
            _remove_shared_owner(child)


def _shorten_indexed_value_name(name: str) -> str:
    shortened, count = re.subn(r"/p/z+(?=/|\?|$)", "/p/z", name)
    if count != 3:
        raise ValueError("indexed-value recipe lost its long document-name segment")
    return shortened


def build_programs() -> list[dict[str, Any]]:
    descriptor = json.loads(DESCRIPTOR.read_text())
    compiled = _compiler_module().compile_limits_plan(
        PROJECT, DATABASE, PATH_COMPONENT, part="ALL"
    )
    declared = descriptor["cases"]
    cases = compiled["cases"]
    if [case["id"] for case in declared] != [case["id"] for case in cases]:
        raise ValueError("Limits-03 case order differs from the frozen descriptor")
    if len(cases) != len(CASE_RECIPES):
        raise ValueError("Limits-03 case count differs from sandbox recipe mapping")
    starts = []
    for case in declared:
        match = re.search(r"observation rows (\d+) to \d+", case["localBasis"])
        if match is None:
            raise ValueError(f"missing observation range for {case['id']}")
        starts.append(int(match.group(1)))
    requests = compiled["requests"]
    cleanup_start = next(
        index
        for index, request in enumerate(requests)
        if request["kind"] == "cleanup-ownership-read"
    )
    if starts[0] != 29 or cleanup_start != 89 or starts != sorted(set(starts)):
        raise ValueError("Limits-03 observation boundary drift")

    programs = []
    for case, start, end in zip(
        cases, starts, [*starts[1:], cleanup_start], strict=True
    ):
        label = case["id"].split("/")[-1]
        recipe_id = CASE_RECIPES.get(label)
        if recipe_id is None:
            raise ValueError(f"unmapped Limits-03 case {case['id']}")
        steps = []
        for index, request in enumerate(requests[start:end]):
            step = {
                "id": f"observation-{index}",
                "method": request["method"],
                "path": _sandbox_index_exemption(request["path"]),
            }
            if label == "indexed-value":
                step["path"] = _shorten_indexed_value_name(step["path"])
            if request.get("body") is not None:
                step["body"] = _sandbox_index_exemption(request["body"])
                _remove_shared_owner(step["body"])
                if label == "indexed-value" and "name" in step["body"]:
                    step["body"]["name"] = _shorten_indexed_value_name(
                        step["body"]["name"]
                    )
                if label == "agg-map" and index in (0, 2):
                    value = step["body"]["fields"]["m"]["mapValue"]["fields"]["s"]
                    value["stringValue"] = "x" * (1_048_458 + index // 2)
                if label == "index-entries" and index in (0, 1):
                    values = step["body"]["fields"]["a"]["arrayValue"]["values"]
                    values.append({"integerValue": str(len(values))})
            steps.append(step)
        programs.append({"id": recipe_id, "area": "writes", "steps": steps})
    return programs


if __name__ == "__main__":
    json.dump(build_programs(), sys.stdout, separators=(",", ":"))
