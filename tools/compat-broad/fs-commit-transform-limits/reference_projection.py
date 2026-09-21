"""Project one owned local run into the existing saved-reference shape.

This module deliberately does not compare with production data. It validates the
runner's complete plan/result using the existing comparator and writes the small
reference object consumed by ``commit_saved_recompare``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from transform_comparator import _validate_plan, compare_rows
from owned_transform_runner import compare_bound_rows, compiler_for_profile, validate_bound_plan

_ROW_KEYS = frozenset(
    {
        "index",
        "request",
        "complete",
        "failure",
        "status",
        "body",
        "skipped",
        "absent",
        "kind",
        "bodyBytes",
        "elapsedSeconds",
        "headers",
    }
)


def _load(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _validate_rows(rows: Any) -> None:
    if not isinstance(rows, list):
        raise ValueError("journal rows are not a list")
    for row in rows:
        if not isinstance(row, dict) or not set(row).issubset(_ROW_KEYS):
            raise ValueError("journal row keys are not bound")


def project_run(run: Path, historical_compiler: Path | None = None) -> dict[str, Any]:
    plan = _load(run / "plan.json")
    result = _load(run / "result.json")
    if not isinstance(plan, dict) or not isinstance(result, dict):
        raise ValueError("run records are not objects")
    if historical_compiler is None:
        _validate_plan(plan)
    else:
        inputs = _load(run / "run-inputs.json")
        profile = {"historicalCompilerSha256": inputs.get("historicalCompilerSha256")}
        historical_compiler = compiler_for_profile(historical_compiler, profile)
        validate_bound_plan(plan, historical_compiler)
    if result.get("recordingComplete") is not True or result.get("cleanupComplete") is not True:
        raise ValueError("run recording or cleanup is incomplete")
    rows = result.get("rows")
    cleanup = result.get("cleanup")
    _validate_rows(rows)
    _validate_rows(cleanup)
    absence = result.get("resourceAbsence")
    if not isinstance(absence, dict) or not absence or not all(value is True for value in absence.values()):
        raise ValueError("cleanup absence binding is incomplete")
    contract = (
        compare_bound_rows(historical_compiler, plan, rows, cleanup)
        if historical_compiler is not None
        else compare_rows(plan, rows, plan, rows, left_recovery=cleanup, right_recovery=cleanup)
    )
    if contract.get("classification") != "MATCH":
        raise ValueError("local comparator self-validation failed")
    return {"plan": plan, "rows": rows, "cleanup": cleanup}


def write_projection(run: Path, output: Path, historical_compiler: Path | None = None) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("projection output already exists")
    payload = project_run(run, historical_compiler)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--historical-compiler", type=Path)
    args = parser.parse_args()
    write_projection(args.run.resolve(), args.output.resolve(), args.historical_compiler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
