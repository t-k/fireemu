"""Credential-free current Explain replay against immutable production evidence."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_path = ROOT / "tools/compat-explain-reference-v3/evaluate.py"
_spec = importlib.util.spec_from_file_location("explain_v3", _path)
v3 = importlib.util.module_from_spec(_spec)
exec(compile(_path.read_bytes(), str(_path), "exec"), v3.__dict__)  # noqa: S102 -- verified source-only import; ignores stale bytecode.
sha, digest, require = v3.sha, v3.digest, v3.require
CURRENT_COMMIT = "cce4a4f9b7369938c89bd32a5106e8d3cab59f83"
INPUTS = "spec/compatibility/broad-runs/query-explain-reference-inputs-v5.json"
ANCHOR = "spec/compatibility/broad-runs/query-explain-reference-evaluator-v5.json"
SOURCE_FILES = (
    "tools/compat-explain-reference-v5/evaluate.py",
    "tools/compat-explain-reference-v5/test_evaluate_v5.py",
    INPUTS,
)


def contract():
    return {
        "kind": "query-explain-saved-reference-comparison-v5",
        "productionExecuted": False,
        "currentCollectorCommit": CURRENT_COMMIT,
        "historicalValidation": "Unchanged v3 historical worker and original v3 production/originalLocal anchors.",
        "currentValidation": "Exact current collector envelope validation and artifact/process companion equality, independently anchored.",
        "normalization": v3.contract()["normalization"],
        "comparison": "Unchanged v3 compare worker with frozen historical collector normalization.",
    }


def source_identity():
    historical = v3.source_identity()
    raw = (ROOT / ANCHOR).read_bytes()
    require(
        raw == v3.git("show", "HEAD:" + ANCHOR), "v5 anchor not committed unchanged"
    )
    anchor = json.loads(raw)
    files = {name: sha((ROOT / name).read_bytes()) for name in SOURCE_FILES}
    require(anchor["sourceFiles"] == files, "v5 source closure drift")
    commit = anchor["sourceCommit"]
    v3.git("merge-base", "--is-ancestor", commit, "HEAD")
    require(
        all(
            sha(v3.git("show", commit + ":" + name)) == value
            for name, value in files.items()
        ),
        "v5 source commit differs",
    )
    require(anchor["contractDigest"] == digest(contract()), "v5 contract differs")
    return {
        "sourceCommit": commit,
        "sourceDigest": digest(files),
        "anchorSha256": sha(raw),
        "historicalEvaluator": historical,
    }


def current_worker(root, directory):
    collector = v3.load_collector(root, CURRENT_COMMIT)
    local = json.loads((directory / "result.json").read_bytes())
    collector.validate_envelope(local, local=True, directory=directory)
    require(
        local["executionCommit"] == CURRENT_COMMIT
        and local["productionExecuted"] is False,
        "current execution identity differs",
    )
    require(
        json.loads((directory / "artifact.json").read_bytes())
        == local["runtime"]["build"],
        "artifact build file differs",
    )
    require(
        json.loads((directory / "process.json").read_bytes())
        == local["runtime"]["ownedProcess"],
        "process file differs",
    )
    return {
        "collectionComplete": True,
        "collector": v3.collector_identity(collector),
        "artifactSha256": local["runtime"]["artifactSha256"],
        "runtimeInputsDigest": digest(local["runtime"]["runtimeInputs"]),
        "sourceInputsDigest": digest(local["runtime"]["executionInputs"]),
        "runtimeConfigurationDigest": local["runtime"]["configurationDigest"],
        "indexSha256": local["instance"]["indexSha256"],
    }


def current_validation(root, directory):
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--current-worker",
            str(root),
            str(directory),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    require(
        process.returncode == 0, "current validator refused: " + process.stderr.strip()
    )
    return json.loads(process.stdout)


def evaluate(roots, old_root, current_root):
    result = {
        "kind": contract()["kind"],
        "productionExecuted": False,
        "collectionComplete": False,
        "cleanupComplete": False,
        "compatibility": "indeterminate",
        "rows": [],
    }
    try:
        identity = source_identity()
        inputs = json.loads((ROOT / INPUTS).read_bytes())
        original = json.loads((ROOT / v3.INPUTS).read_bytes())
        require(
            set(roots) == {"production", "originalLocal", "currentLocal"},
            "input directory set differs",
        )
        for name in ("production", "originalLocal"):
            require(
                inputs["directories"][name] == original["directories"][name],
                "historical directory anchor differs",
            )
        v3.validate_hashes(roots, inputs["directories"])
        historical = v3.run_validator("historical", old_root, roots)
        require(
            historical["collector"] == original["historicalCollector"],
            "historical collector anchor differs",
        )
        current = current_validation(current_root, roots["currentLocal"])
        require(
            current == inputs["currentValidation"],
            "current collector/artifact anchor differs",
        )
        comparison_roots = {**roots, "repairedLocal": roots["currentLocal"]}
        rows = v3.run_validator("compare", old_root, comparison_roots)["rows"]
        require(len(rows) == 12, "expected twelve observation rows")
        v3.validate_hashes(roots, inputs["directories"])
        require(source_identity() == identity, "evaluator changed during evaluation")
        result.update(
            evaluator=identity,
            comparisonContract=contract(),
            frozenInputDirectories=inputs["directories"],
            historical=historical,
            current=current,
            collectionComplete=True,
            cleanupComplete=True,
            stateVerified=True,
            rows=rows,
            compatibility="match"
            if all(row["compatibility"] == "match" for row in rows)
            else "mismatch",
        )
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        result["reason"] = str(error)
    return result


def write_private_result(output, result):
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--current-worker":
        print(
            json.dumps(
                current_worker(Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve())
            )
        )
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "production-dir",
        "original-local-dir",
        "current-local-dir",
        "collector-root",
        "current-collector-root",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    roots = {
        "production": args.production_dir.resolve(),
        "originalLocal": args.original_local_dir.resolve(),
        "currentLocal": args.current_local_dir.resolve(),
    }
    output = args.output.resolve()
    require(
        not any(
            output.is_relative_to(path) or path.is_relative_to(output)
            for path in roots.values()
        ),
        "output overlaps frozen inputs",
    )
    result = evaluate(
        roots, args.collector_root.resolve(), args.current_collector_root.resolve()
    )
    write_private_result(output, result)
    print(
        json.dumps(
            {
                key: result[key]
                for key in ("compatibility", "collectionComplete", "productionExecuted")
            }
        )
    )
    return 0 if result["compatibility"] in ("match", "mismatch") else 2


if __name__ == "__main__":
    raise SystemExit(main())
