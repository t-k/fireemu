"""Project one owned local run into the existing saved-reference shape.

This module deliberately does not compare with production data. It validates the
runner's complete plan/result using the existing comparator and writes the small
reference object consumed by ``commit_saved_recompare``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from transform_comparator import _validate_plan, compare_rows
from broad_contract import digest
from owned_transform_runner import (
    CONFIGURATION,
    PROFILES,
    compare_bound_rows,
    compiler_for_profile,
    ROOT,
    validate_bound_plan,
    validate_copied_manifest,
)

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
_SEALED_BASE_FILES = frozenset(
    {
        "cases.json",
        "command.json",
        "config.json",
        "identity.json",
        "instance.json",
        "local-contract.json",
        "manifest.json",
        "owned-stderr.log",
        "plan.json",
        "result.json",
        "retained-manifest.json",
        "run-inputs.json",
        "supervisor-final.json",
    }
)
_SEALED_FILES = _SEALED_BASE_FILES | frozenset(
    f"wire/{index:03d}-{kind}.json"
    for index in range(17)
    for kind in ("request", "receipt")
)


def _load(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, ValueError) as error:
        raise ValueError("local run record is unreadable") from error


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("sealed run contains a non-regular file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _validate_source_map(inputs: dict[str, Any]) -> None:
    commit = inputs.get("collectorSourceCommit")
    source_inputs = inputs.get("sourceInputs")
    if not isinstance(commit, str) or not isinstance(source_inputs, dict) or not source_inputs:
        raise ValueError("collector source binding is incomplete")
    for relative, expected in source_inputs.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError("collector source binding is malformed")
        try:
            content = subprocess.check_output(["git", "show", f"{commit}:{relative}"], cwd=ROOT)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError("collector source binding differs") from error
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("collector source binding differs")


def _validate_seal(run: Path, profile: dict[str, Any]) -> dict[str, Any]:
    if (run / "evidence.json").is_symlink() or (run / "run-inputs.json").is_symlink():
        raise ValueError("local run seal contains a symlink")
    evidence = _load(run / "evidence.json")
    inputs = _load(run / "run-inputs.json")
    if not isinstance(evidence, dict) or not isinstance(inputs, dict):
        raise ValueError("local run seal is incomplete")
    if (
        evidence.get("status") != "completed"
        or evidence.get("sourceStable") is not True
        or evidence.get("recordingComplete") is not True
        or evidence.get("productionExecuted") is not False
        or evidence.get("promotionReady") is not False
        or evidence.get("ownedArtifactRemoved") is not True
    ):
        raise ValueError("local run seal is incomplete")
    owned_process = evidence.get("ownedProcess")
    if not isinstance(owned_process, dict) or owned_process.get("stopped") is not True or owned_process.get("listenersClosed") is not True:
        raise ValueError("owned process cleanup is incomplete")
    if evidence.get("binding") != digest(inputs):
        raise ValueError("local run binding differs")
    if inputs.get("artifactProfile") != profile["name"]:
        raise ValueError("registered artifact profile differs")
    if inputs.get("artifactSha256") != profile["artifactSha256"]:
        raise ValueError("registered artifact binding differs")
    artifact = inputs.get("ownedArtifact")
    if not isinstance(artifact, dict) or artifact.get("sha256") != profile["artifactSha256"]:
        raise ValueError("owned artifact binding differs")
    if inputs.get("historicalCompilerSha256") != profile.get("historicalCompilerSha256"):
        raise ValueError("historical compiler binding differs")
    if _sha(run / "config.json") != inputs.get("configurationDigest") or _load(run / "config.json") != CONFIGURATION:
        raise ValueError("configuration binding differs")
    validate_copied_manifest(run, inputs, profile)
    _validate_source_map(inputs)
    files = evidence.get("files")
    if not isinstance(files, dict) or set(files) != _SEALED_FILES:
        raise ValueError("sealed file digest map is incomplete")
    actual_files = {
        str(path.relative_to(run))
        for path in run.rglob("*")
        if path.is_file() and path.name != "evidence.json"
    }
    if actual_files != _SEALED_FILES or any(
        path.is_symlink() for path in run.rglob("*") if path.name != "evidence.json"
    ):
        raise ValueError("sealed run file set differs")
    for relative, expected in files.items():
        if not isinstance(relative, str) or not isinstance(expected, str) or _sha(run / relative) != expected:
            raise ValueError("sealed file digest differs")
    return inputs


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
    run_inputs = _load(run / "run-inputs.json")
    profile_name = run_inputs.get("artifactProfile") if isinstance(run_inputs, dict) else None
    if not isinstance(profile_name, str) or profile_name not in PROFILES:
        raise ValueError("unknown artifact profile")
    profile = PROFILES[profile_name]
    _validate_seal(run, profile)
    if historical_compiler is None:
        _validate_plan(plan)
    else:
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
