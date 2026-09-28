"""Versioned, offline reevaluation of the frozen Query Explain campaign receipt."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR_COMMIT = "109a9b459b94d59eec541be579e305437cdfaa30"
INPUTS = "spec/compatibility/broad-runs/query-explain-reference-inputs-v2.json"
ANCHOR = "spec/compatibility/broad-runs/query-explain-reference-evaluator-v2.json"
SOURCE_FILES = (
    str(Path(__file__).relative_to(ROOT)),
    "tools/compat-explain-reference/test_evaluate.py",
    "docs/compatibility/query-explain-saved-reference-v2.md",
    INPUTS,
)
OLD_REASON = "campaign envelope: typed Explain response incomplete"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def git(*arguments, root=ROOT):
    return subprocess.check_output(
        ["git", *arguments], cwd=root, stderr=subprocess.PIPE
    )


def canonical_body(operation, status, value):
    """Only two absent defaults in a runQuery empty-analyze result are equivalent."""
    result = copy.deepcopy(value)
    body = operation.get("body") if isinstance(operation, dict) else None
    query = body.get("structuredQuery") if isinstance(body, dict) else None
    if (
        type(status) is not int
        or status != 200
        or operation.get("method") != "POST"
        or not operation.get("path", "").endswith(":runQuery")
        or not isinstance(query, dict)
        or type(query.get("limit")) is not int
        or query["limit"] != 0
        or body.get("explainOptions") != {"analyze": True}
        or not isinstance(result, list)
        or len(result) != 1
        or not isinstance(result[0], dict)
        or set(result[0]) != {"readTime", "explainMetrics"}
    ):
        return result, []
    metrics = result[0]["explainMetrics"]
    if (
        not isinstance(metrics, dict)
        or not isinstance(metrics.get("planSummary"), dict)
        or not isinstance(metrics.get("executionStats"), dict)
    ):
        return result, []
    paths = []
    for container, key, default in (
        (metrics["planSummary"], "indexesUsed", []),
        (metrics["executionStats"], "resultsReturned", "0"),
    ):
        if key not in container:
            container[key] = default
            paths.append(
                "/0/explainMetrics/"
                + ("planSummary/" if key == "indexesUsed" else "executionStats/")
                + key
            )
    return result, paths


def contract():
    return {
        "kind": "query-explain-saved-reference-comparison-v2",
        "collectorCommit": COLLECTOR_COMMIT,
        "normalization": "empty-runQuery-analyze-protojson-defaults-v1",
        "defaults": {
            "/0/explainMetrics/planSummary/indexesUsed": [],
            "/0/explainMetrics/executionStats/resultsReturned": "0",
        },
        "scope": "HTTP 200 POST runQuery; structuredQuery.limit is integer zero; analyze is true; one readTime/explainMetrics row; both parent objects remain required",
        "completionBridge": "The pinned old execute result overwrote completed with the original indeterminate comparison verdict. Derive collectionComplete from independently verified lifecycle; never rewrite the original result.",
        "validatorExtensions": [
            "explain_response_valid: canonicalize only the two absent scoped defaults, then call the frozen predicate",
            "_require: bridge only envelope completed incomplete after the pinned original diagnostic and every other lifecycle flag are checked",
        ],
        "preserve": [
            "old source, observer, manifest, permission and comparison",
            "raw request, response and dispatch digests",
            "all other metrics, status, body and state differences",
        ],
    }


def source_identity():
    anchor_raw = (ROOT / ANCHOR).read_bytes()
    require(
        anchor_raw == git("show", "HEAD:" + ANCHOR),
        "evaluator anchor is not committed unchanged",
    )
    anchor = json.loads(anchor_raw)
    source_commit = anchor["evaluatorSourceCommit"]
    require(
        len(source_commit) == 40
        and all(c in "0123456789abcdef" for c in source_commit),
        "invalid evaluator source commit",
    )
    git("merge-base", "--is-ancestor", source_commit, "HEAD")
    files = {name: sha((ROOT / name).read_bytes()) for name in SOURCE_FILES}
    require(anchor["sourceFiles"] == files, "evaluator source closure drift")
    require(
        all(
            sha(git("show", source_commit + ":" + name)) == expected
            for name, expected in files.items()
        ),
        "evaluator source commit differs",
    )
    require(
        anchor["contractDigest"] == digest(contract()),
        "evaluator comparison contract differs",
    )
    return {
        "executionCommit": git("rev-parse", "HEAD").decode().strip(),
        "sourceCommit": source_commit,
        "sourceDigest": digest(files),
        "anchorFileSha256": sha(anchor_raw),
        "contractDigest": digest(contract()),
    }


def load_collector(root):
    root = root.resolve()
    require(
        git("rev-parse", "HEAD", root=root).decode().strip() == COLLECTOR_COMMIT,
        "wrong collector checkout",
    )
    require(
        not git("status", "--porcelain", root=root).strip(),
        "collector checkout is not frozen",
    )
    require(
        not git("diff", COLLECTOR_COMMIT, "--", root=root).strip(),
        "collector source differs",
    )
    existing = sys.modules.get("campaign_explain")
    require(
        existing is None
        or Path(existing.__file__).resolve()
        == root / "tools/compat-broad/campaign_explain.py",
        "use an isolated process for historical collector imports",
    )
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "tools/compat-broad"))
    old = importlib.import_module("campaign_explain")
    require(old.ROOT == root, "historical validator root differs")
    return old


def read_inputs(production_dir, local_path):
    pinned = json.loads((ROOT / INPUTS).read_bytes())
    paths = {
        "production": production_dir / "result.json",
        "originalComparison": production_dir / "comparison.json",
        "executionInputs": production_dir / "execution-inputs.json",
        "local": local_path,
    }
    records = {}
    for key, path in paths.items():
        raw = path.read_bytes()
        require(sha(raw) == pinned["files"][key], "frozen " + key + " bytes differ")
        records[key] = json.loads(raw)
    return records, pinned, paths


def completion_bridge(production, comparison):
    require(
        comparison
        == {
            "compatibility": "indeterminate",
            "rows": [],
            "cleanupComplete": False,
            "reason": OLD_REASON,
        },
        "original indeterminate diagnostic differs",
    )
    require(
        production.get("completed") is False
        and production.get("compatibility") == "indeterminate",
        "original completed/comparison state differs",
    )
    require(
        all(
            production.get(key) is True
            for key in (
                "recordingComplete",
                "stateVerified",
                "cleanupComplete",
                "configurationUnchanged",
            )
        ),
        "production collection lifecycle incomplete",
    )
    require(
        "failure" in production and production["failure"] is None,
        "production failure present or missing",
    )


def validate_records(records, pinned, old, local_directory):
    production, local = records["production"], records["local"]
    completion_bridge(production, records["originalComparison"])
    require(
        sha(Path(old.__file__).read_bytes()) == pinned["collectorSourceSha256"],
        "old collector source hash differs",
    )
    require(
        old.campaign_observer_digest() == pinned["observerSha256"]
        and old.manifest_digest() == pinned["manifestDigest"]
        and old.digest(old.binding()) == pinned["comparisonContractDigest"],
        "old source contract binding differs",
    )
    execution = records["executionInputs"]
    require(
        execution
        == {
            "permission": production["permission"],
            "localRecordSha256": production["localRecordSha256"],
            "manifest": old.manifest(),
        },
        "frozen execution inputs differ",
    )
    require(
        production["localRecordSha256"] == digest(local),
        "permission local receipt binding differs",
    )
    require(
        production.get("jobs") == {"query-explain": production["receipt"]},
        "production receipt aliases differ",
    )
    before = digest(records)
    old.validate_envelope(local, local=True, directory=local_directory)

    def shape(operation, status, body):
        normalized, _ = canonical_body(operation, status, body)
        return old.explain_response_valid(operation, status, normalized)

    def lifecycle_require(condition, reason):
        if reason == "envelope completed incomplete":
            # This sole exception was established from the frozen diagnostic above.
            require(condition is False, "unexpected original completion flag")
            return
        old._require(condition, reason)

    # Reuse the exact frozen validator instructions. The two explicit evaluator
    # dependencies are versioned by this file's independent source/contract anchor.
    namespace = {
        **old.__dict__,
        "explain_response_valid": shape,
        "_require": lifecycle_require,
    }
    validate = types.FunctionType(old._validate_envelope.__code__, namespace)
    validate(production, local=False, directory=None)
    require(before == digest(records), "evaluation mutated source records")
    return True


def compare_rows(production, local, old):
    rows = []
    for left, right in zip(
        production["receipt"]["rows"], local["receipt"]["rows"], strict=True
    ):
        normalized_left, left_defaults = canonical_body(
            left["request"], left["status"], left["body"]
        )
        normalized_right, right_defaults = canonical_body(
            right["request"], right["status"], right["body"]
        )
        observed_left = old.normalize_response(normalized_left, production["nonce"])
        observed_right = old.normalize_response(normalized_right, local["nonce"])
        rows.append(
            {
                "id": left["id"],
                "compatibility": "match"
                if digest([left["status"], observed_left])
                == digest([right["status"], observed_right])
                else "mismatch",
                "production": {"status": left["status"], "body": observed_left},
                "local": {"status": right["status"], "body": observed_right},
                "rawProductionBodyDigest": digest(left["body"]),
                "rawLocalBodyDigest": digest(right["body"]),
                "defaultEquivalencesApplied": {
                    "production": left_defaults,
                    "local": right_defaults,
                },
            }
        )
    return rows


def evaluate(production_dir, local_path, collector_root):
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
        records, pinned, paths = read_inputs(production_dir, local_path)
        old = load_collector(collector_root)
        validate_records(records, pinned, old, local_path.parent)
        rows = compare_rows(records["production"], records["local"], old)
        require(
            all(
                sha(path.read_bytes()) == pinned["files"][key]
                for key, path in paths.items()
            ),
            "frozen inputs changed during evaluation",
        )
        result.update(
            evaluator=identity,
            comparisonContract=contract(),
            sourceFiles=pinned["files"],
            historicalCollector={
                key: pinned[key]
                for key in (
                    "collectorCommit",
                    "collectorSourceSha256",
                    "observerSha256",
                    "manifestDigest",
                    "comparisonContractDigest",
                )
            },
            originalComparison=records["originalComparison"],
            originalProductionCompleted=records["production"]["completed"],
            collectionComplete=True,
            cleanupComplete=True,
            stateVerified=True,
            compatibility="match"
            if all(row["compatibility"] == "match" for row in rows)
            else "mismatch",
            rows=rows,
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-dir", required=True, type=Path)
    parser.add_argument("--local", required=True, type=Path)
    parser.add_argument("--collector-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    protected = (
        args.production_dir.resolve(),
        args.local.resolve().parent,
        args.collector_root.resolve(),
    )
    require(
        not any(output.is_relative_to(directory) for directory in protected),
        "output may not overwrite or extend a frozen input directory",
    )
    require(not output.exists(), "evaluation output already exists")
    result = evaluate(
        args.production_dir.resolve(),
        args.local.resolve(),
        args.collector_root.resolve(),
    )
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(
        json.dumps(
            {
                "compatibility": result["compatibility"],
                "collectionComplete": result["collectionComplete"],
                "reason": result.get("reason"),
            }
        )
    )
    return 0 if result["compatibility"] in {"match", "mismatch"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
