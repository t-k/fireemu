"""Offline, fail-closed comparison of frozen production with repaired Explain."""

from __future__ import annotations

import argparse
import copy
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
OLD_COMMIT = "109a9b459b94d59eec541be579e305437cdfaa30"
REPAIRED_COMMIT = "aad1a41de926fae244b42ac1bd2baa57bf2bcdde"
INPUTS = "spec/compatibility/broad-runs/query-explain-reference-inputs-v3.json"
ANCHOR = "spec/compatibility/broad-runs/query-explain-reference-evaluator-v3.json"
V2_SUMMARY = "spec/compatibility/broad-runs/query-explain-reference-summary-v2.json"
SOURCE_FILES = (
    "tools/compat-explain-reference-v3/evaluate.py",
    "tools/compat-explain-reference-v3/test_evaluate_v3.py",
    "docs/compatibility/query-explain-saved-reference-v3.md",
    INPUTS,
    "tools/compat-explain-reference/evaluate.py",
    "tools/compat-explain-reference/test_evaluate.py",
    "docs/compatibility/query-explain-saved-reference-v2.md",
    "spec/compatibility/broad-runs/query-explain-reference-inputs-v2.json",
    "spec/compatibility/broad-runs/query-explain-reference-evaluator-v2.json",
    V2_SUMMARY,
    "tools/compat-inventory/pyproject.toml",
    "tools/compat-inventory/uv.lock",
)


class SourceOnlyLoader(importlib.machinery.SourceFileLoader):
    """Compile source bytes directly; never consult or generate a bytecode cache."""

    def get_code(self, fullname):
        return compile(self.get_data(self.path), self.path, "exec", dont_inherit=True)


class RepositorySourceFinder(importlib.abc.MetaPathFinder):
    """Apply source-only loading to all imports located inside a verified checkout."""

    def __init__(self):
        self.roots = {ROOT}

    def find_spec(self, fullname, path=None, target=None):
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None or spec.origin is None:
            return None
        origin = Path(spec.origin).absolute()
        if not any(origin.is_relative_to(root) for root in self.roots):
            return None
        if origin.suffix != ".py":
            raise ImportError(
                "repository import requires Python source: " + str(origin)
            )
        spec.loader = SourceOnlyLoader(fullname, str(origin))
        return spec


_source_finder = RepositorySourceFinder()
sys.meta_path.insert(0, _source_finder)
_v2_path = ROOT / "tools/compat-explain-reference/evaluate.py"
_spec = importlib.util.spec_from_file_location(
    "saved_reference_v2",
    _v2_path,
    loader=SourceOnlyLoader("saved_reference_v2", str(_v2_path)),
)
assert _spec is not None and _spec.loader is not None
v2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v2)
sha, digest, require, git = v2.sha, v2.digest, v2.require, v2.git


def contract():
    return {
        "kind": "query-explain-saved-reference-comparison-v3",
        "historicalCollectorCommit": OLD_COMMIT,
        "repairedCollectorCommit": REPAIRED_COMMIT,
        "repositoryImports": "Compile source bytes directly for v2 and every repository-local collector dependency; ignore bytecode caches and refuse sourceless repository imports.",
        "historicalValidation": "Unchanged v2 frozen-input verification, default projection and exact completion bridge; exact historical collector validates original production and original local.",
        "repairedValidation": "Unmodified exact repaired collector validates its own local envelope, source/runtime/build/artifact/configuration/observer/manifest/principal/operation/state/cleanup bindings and saved files.",
        "normalization": [
            "Frozen collector absolute-time, nonce and existing error-prose normalization; raw body digests retain prose",
            "Unchanged v2 scoped absent ProtoJSON defaults",
            "Successful analyze response executionDuration must exist and parse as nonnegative protobuf Duration; replace only that field with a typed nondeterminism marker",
        ],
        "durationMarker": {
            "type": "google.protobuf.Duration",
            "nondeterministic": True,
        },
        "exact": [
            "operation and row identity",
            "administrator and quota project",
            "status",
            "all other body fields, index plans, stats, debug and read counts",
            "post-state and cleanup responses",
        ],
        "provenance": "The original production permission authorizes the original collection only. The repaired local is independently validated and never substituted into that permission or receipt.",
    }


def source_identity():
    raw = (ROOT / ANCHOR).read_bytes()
    require(
        raw == git("show", "HEAD:" + ANCHOR),
        "evaluator anchor is not committed unchanged",
    )
    anchor = json.loads(raw)
    commit = anchor["evaluatorSourceCommit"]
    require(
        re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
        "invalid evaluator source commit",
    )
    git("merge-base", "--is-ancestor", commit, "HEAD")
    files = {name: sha((ROOT / name).read_bytes()) for name in SOURCE_FILES}
    require(anchor["sourceFiles"] == files, "evaluator source closure drift")
    require(
        all(
            sha(git("show", commit + ":" + name)) == expected
            for name, expected in files.items()
        ),
        "evaluator source commit differs",
    )
    require(
        anchor["contractDigest"] == digest(contract()), "evaluator contract differs"
    )
    return {
        "executionCommit": git("rev-parse", "HEAD").decode().strip(),
        "sourceCommit": commit,
        "sourceDigest": digest(files),
        "anchorFileSha256": sha(raw),
        "contractDigest": digest(contract()),
    }


def tree_hashes(root):
    result = {}
    require(root.is_dir() and not root.is_symlink(), "frozen input directory required")
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "frozen input symlink refused")
        if path.is_file():
            result[str(path.relative_to(root))] = sha(path.read_bytes())
        else:
            require(path.is_dir(), "frozen special file refused")
    return result


def validate_hashes(roots, pinned):
    require(set(roots) == set(pinned), "frozen directory set differs")
    for key, root in roots.items():
        require(
            tree_hashes(root) == pinned[key],
            "frozen " + key + " bytes or file set differ",
        )


def canonical_body(operation, status, body):
    # Protobuf installs generated message classes into the module namespace.
    Duration = vars(importlib.import_module("google.protobuf.duration_pb2"))["Duration"]

    result, defaults = v2.canonical_body(operation, status, body)
    applied = {"defaults": defaults, "duration": []}
    request = operation.get("body", {})
    if (
        type(status) is not int
        or status != 200
        or operation.get("method") != "POST"
        or not operation.get("path", "").endswith((":runQuery", ":runAggregationQuery"))
        or request.get("explainOptions") != {"analyze": True}
    ):
        return result, applied
    require(isinstance(result, list), "duration response rows missing")
    metrics_rows = [
        (i, row["explainMetrics"])
        for i, row in enumerate(result)
        if isinstance(row, dict) and "explainMetrics" in row
    ]
    require(len(metrics_rows) == 1, "duration metrics row missing or repeated")
    index, metrics = metrics_rows[0]
    require(
        isinstance(metrics, dict) and isinstance(metrics.get("executionStats"), dict),
        "duration executionStats missing",
    )
    stats = metrics["executionStats"]
    value = stats.get("executionDuration")
    require(
        isinstance(value, str)
        and re.fullmatch(r"[0-9]+(?:\.[0-9]{1,9})?s", value) is not None,
        "duration missing or invalid",
    )
    duration = Duration()
    try:
        duration.FromJsonString(value)
        require(duration.seconds >= 0 and duration.nanos >= 0, "duration negative")
    except (ValueError, OverflowError) as error:
        raise ValueError("duration invalid: " + str(error)) from error
    stats["executionDuration"] = copy.deepcopy(contract()["durationMarker"])
    applied["duration"].append(
        f"/{index}/explainMetrics/executionStats/executionDuration"
    )
    return result, applied


def namespace(value, nonce):
    if isinstance(value, str):
        return value.replace(nonce, "<campaign-nonce>")
    if isinstance(value, list):
        return [namespace(v, nonce) for v in value]
    if isinstance(value, dict):
        return {k: namespace(v, nonce) for k, v in value.items()}
    return value


def comparable_request(row, nonce, phase, normalize):
    request = namespace(row["request"], nonce)
    if phase == "cleanup" and request["method"] == "DELETE":
        path, separator, version = request["path"].partition(
            "?currentDocument.updateTime="
        )
        require(
            separator and version and "&" not in version,
            "cleanup version precondition missing",
        )
        normalized = normalize({"updateTime": unquote(version)}, nonce)["updateTime"]
        require(
            isinstance(normalized, dict) and normalized.get("$absoluteTime") is True,
            "cleanup version time invalid",
        )
        request = {**request, "path": path, "currentDocument.updateTime": normalized}
    return request


def compare_records(production, local, normalize):
    for key in ("principal", "quotaProject"):
        require(
            production["receipt"]["principalEvidence"][key]
            == local["receipt"]["principalEvidence"][key],
            "principal comparison differs",
        )
    rows = []
    for phase in ("rows", "cleanup"):
        left_rows, right_rows = production["receipt"][phase], local["receipt"][phase]
        require(len(left_rows) == len(right_rows), phase + " operation count differs")
        for left, right in zip(left_rows, right_rows, strict=True):
            require(
                left["id" if phase == "rows" else "index"]
                == right["id" if phase == "rows" else "index"],
                "operation row identity differs",
            )
            require(
                digest(comparable_request(left, production["nonce"], phase, normalize))
                == digest(comparable_request(right, local["nonce"], phase, normalize)),
                "operation comparison differs",
            )
            lbody, lapplied = canonical_body(
                left["request"], left["status"], left["body"]
            )
            rbody, rapplied = canonical_body(
                right["request"], right["status"], right["body"]
            )
            lbody, rbody = (
                normalize(lbody, production["nonce"]),
                normalize(rbody, local["nonce"]),
            )
            verdict = (
                "match"
                if digest([left["status"], lbody]) == digest([right["status"], rbody])
                else "mismatch"
            )
            if phase == "cleanup":
                require(verdict == "match", "cleanup response comparison differs")
                continue
            rows.append(
                {
                    "id": left["id"],
                    "compatibility": verdict,
                    "production": {"status": left["status"], "body": lbody},
                    "local": {"status": right["status"], "body": rbody},
                    "rawProductionBodyDigest": digest(left["body"]),
                    "rawLocalBodyDigest": digest(right["body"]),
                    "equivalencesApplied": {"production": lapplied, "local": rapplied},
                }
            )
    return rows


def load_collector(root, commit):
    require(
        git("rev-parse", "HEAD", root=root).decode().strip() == commit,
        "wrong collector checkout",
    )
    require(
        not git("status", "--porcelain", root=root).strip(),
        "collector checkout is not frozen",
    )
    require(
        not git("diff", commit, "--", root=root).strip(), "collector source differs"
    )
    _source_finder.roots.add(root)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "tools/compat-broad"))
    collector = importlib.import_module("campaign_explain")

    require(collector.ROOT == root, "collector import root differs")
    return collector


def collector_identity(collector):
    return {
        "collectorCommit": git("rev-parse", "HEAD", root=collector.ROOT)
        .decode()
        .strip(),
        "collectorSourceSha256": sha(Path(collector.__file__).read_bytes()),
        "observerSha256": collector.campaign_observer_digest(),
        "manifestDigest": collector.manifest_digest(),
        "comparisonContractDigest": digest(collector.binding()),
        "configurationDigest": digest(collector.configuration()),
    }


def worker(mode, root, roots):
    collector = load_collector(
        root, REPAIRED_COMMIT if mode == "repaired" else OLD_COMMIT
    )
    if mode == "repaired":
        directory = roots["repairedLocal"]
        local = json.loads((directory / "result.json").read_bytes())
        collector.validate_envelope(local, local=True, directory=directory)
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
            "collector": collector_identity(collector),
            "artifactSha256": local["runtime"]["artifactSha256"],
            "runtimeInputsDigest": digest(local["runtime"]["runtimeInputs"]),
            "sourceInputsDigest": digest(local["runtime"]["executionInputs"]),
            "runtimeConfigurationDigest": local["runtime"]["configurationDigest"],
            "indexSha256": local["instance"]["indexSha256"],
        }
    if mode == "compare":
        production = json.loads((roots["production"] / "result.json").read_bytes())
        repaired = json.loads((roots["repairedLocal"] / "result.json").read_bytes())
        return {
            "rows": compare_records(production, repaired, collector.normalize_response)
        }
    records, pinned, _ = v2.read_inputs(
        roots["production"], roots["originalLocal"] / "result.json"
    )
    v2.source_identity()
    v2.validate_records(records, pinned, collector, roots["originalLocal"])
    rows = v2.compare_rows(records["production"], records["local"], collector)
    summary = json.loads((ROOT / V2_SUMMARY).read_bytes())
    require(
        [
            {key: row[key] for key in saved}
            for row, saved in zip(rows, summary["rows"], strict=True)
        ]
        == summary["rows"],
        "original v2 rows differ",
    )
    verdict = (
        "match" if all(r["compatibility"] == "match" for r in rows) else "mismatch"
    )
    require(
        verdict == summary["compatibility"] == "mismatch",
        "original v2 mismatch differs",
    )
    return {
        "collectionComplete": True,
        "collector": collector_identity(collector),
        "originalComparison": records["originalComparison"],
        "originalProductionCompleted": records["production"]["completed"],
        "originalV2Compatibility": verdict,
        "originalV2Rows": summary["rows"],
        "originalV2SummarySha256": sha((ROOT / V2_SUMMARY).read_bytes()),
    }


def run_validator(mode, root, roots):
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--worker",
            mode,
            str(root),
            json.dumps({k: str(v) for k, v in roots.items()}),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    require(
        process.returncode == 0, mode + " validator refused: " + process.stderr.strip()
    )
    return json.loads(process.stdout)


def evaluate(roots, old_root, repaired_root):
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
        validate_hashes(roots, inputs["directories"])
        historical = run_validator("historical", old_root, roots)
        repaired = run_validator("repaired", repaired_root, roots)
        require(
            historical["collector"] == inputs["historicalCollector"],
            "historical collector anchor differs",
        )
        require(
            repaired == inputs["repairedValidation"],
            "repaired collector/artifact anchor differs",
        )
        rows = run_validator("compare", old_root, roots)["rows"]
        require(len(rows) == 12, "expected twelve observation rows")
        validate_hashes(roots, inputs["directories"])
        require(source_identity() == identity, "evaluator changed during evaluation")
        result.update(
            evaluator=identity,
            comparisonContract=contract(),
            frozenInputDirectories=inputs["directories"],
            historical=historical,
            repaired=repaired,
            collectionComplete=True,
            cleanupComplete=True,
            stateVerified=True,
            compatibility="match"
            if all(r["compatibility"] == "match" for r in rows)
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


def summary_bytes(comparison_raw):
    """Reproduce the public projection while binding the complete private artifact."""
    result = json.loads(comparison_raw)
    require(
        result["kind"] == "query-explain-saved-reference-comparison-v3",
        "summary input kind differs",
    )
    require(
        result["compatibility"] in {"match", "mismatch"} and len(result["rows"]) == 12,
        "summary requires a determinate twelve-row comparison",
    )
    summary = {
        key: result[key]
        for key in (
            "productionExecuted",
            "evaluator",
            "comparisonContract",
            "frozenInputDirectories",
            "historical",
            "repaired",
            "collectionComplete",
            "cleanupComplete",
            "stateVerified",
            "compatibility",
        )
    }
    summary["kind"] = "query-explain-saved-reference-summary-v3"
    summary["comparisonArtifactSha256"] = sha(comparison_raw)
    summary["rows"] = [
        {
            **{
                key: row[key]
                for key in (
                    "id",
                    "compatibility",
                    "rawProductionBodyDigest",
                    "rawLocalBodyDigest",
                    "equivalencesApplied",
                )
            },
            "productionStatus": row["production"]["status"],
            "localStatus": row["local"]["status"],
            "normalizedProductionBodyDigest": digest(row["production"]["body"]),
            "normalizedLocalBodyDigest": digest(row["local"]["body"]),
        }
        for row in result["rows"]
    ]
    summary["scope"] = [
        "Offline reuse of immutable production collection; no new Cloud execution.",
        "Six Explain cases, four setup observations, two post-state readbacks; independently validated six-operation cleanup.",
        "Original indeterminate and v2 mismatch retained; repaired match uses validated duration nondeterminism and established v2 projections.",
        "Recorded build artifact digest is bound; owned temporary executable was removed during collection cleanup.",
        "No claim for other query/index shapes, IAM users or subsequent production changes.",
    ]
    return (json.dumps(summary, indent=2, allow_nan=False) + "\n").encode()


def check_summary(comparison, summary):
    require(
        summary_bytes(comparison.read_bytes()) == summary.read_bytes(),
        "published summary differs from comparison projection",
    )


def summary_command():
    mode = sys.argv[1]
    parser = argparse.ArgumentParser(
        description="Generate or check a deterministic public comparison projection."
    )
    parser.add_argument(mode, required=True, type=Path)
    parser.add_argument(
        "--summary" if mode == "--check-summary" else "--output",
        required=True,
        type=Path,
    )
    args = parser.parse_args()
    source_identity()
    comparison = getattr(args, mode[2:].replace("-", "_"))
    if mode == "--check-summary":
        check_summary(comparison, args.summary)
        print(
            json.dumps(
                {
                    "summaryValid": True,
                    "comparisonArtifactSha256": sha(comparison.read_bytes()),
                }
            )
        )
    else:
        projected = summary_bytes(comparison.read_bytes())
        # Exclusive creation also prevents replacing either comparison or an earlier summary.
        with args.output.open("xb") as stream:
            stream.write(projected)
        print(json.dumps({"summarySha256": sha(projected)}))
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] in {"--project-summary", "--check-summary"}:
        return summary_command()
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        try:
            print(
                json.dumps(
                    worker(
                        sys.argv[2],
                        Path(sys.argv[3]).resolve(),
                        {
                            k: Path(v).resolve()
                            for k, v in json.loads(sys.argv[4]).items()
                        },
                    ),
                    allow_nan=False,
                )
            )
            return 0
        except (
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            IndexError,
            OSError,
            subprocess.SubprocessError,
        ) as error:
            print(str(error), file=sys.stderr)
            return 2
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "production-dir",
        "original-local",
        "local",
        "collector-root",
        "repaired-collector-root",
        "output",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    roots = {
        "production": args.production_dir.resolve(),
        "originalLocal": args.original_local.resolve().parent,
        "repairedLocal": args.local.resolve().parent,
    }
    require(
        args.original_local.name == args.local.name == "result.json",
        "local file must be result.json",
    )
    output = args.output.resolve()
    require(
        not any(
            output.is_relative_to(p)
            for p in [
                *roots.values(),
                args.collector_root.resolve(),
                args.repaired_collector_root.resolve(),
            ]
        ),
        "output overlaps frozen inputs",
    )
    require(not output.exists(), "output already exists")
    result = evaluate(
        roots, args.collector_root.resolve(), args.repaired_collector_root.resolve()
    )
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with os.fdopen(
        os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w"
    ) as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(
        json.dumps(
            {
                key: result.get(key)
                for key in ("compatibility", "collectionComplete", "reason")
            }
        )
    )
    return 0 if result["compatibility"] in {"match", "mismatch"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
