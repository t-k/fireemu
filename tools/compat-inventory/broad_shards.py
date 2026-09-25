"""Plan compat-broad CI shards by measured duration.

Every `tools/compat-broad/**/test_*.py` (or `*_test.py`) file is one unit. Files under a
retired suite (the `RETIRED_SUITES` list in the compatibility-inventory workflow, a
directory or a single file) are left out of the required shards; the workflow runs them
only on demand. The rest are assigned longest first to the least-loaded shard, using the
per-file seconds in `broad-test-durations.json` (files without a measurement count as
`--default` seconds). A file longer than `SPLIT_SHARE` of the budget is collected and
run as contiguous chunks of whole tests of about `CHUNK_SHARE` of the budget each, so one
slow file can still fit the job limit and its chunks pack evenly.
A plan in which any shard exceeds `--budget` is refused.
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BROAD = "tools/compat-broad"
DURATIONS = Path(__file__).with_name("broad-test-durations.json")
SPLIT_SHARE = 0.8
CHUNK_SHARE = 0.25
sys.path.insert(0, str(Path(__file__).parent))

from closure_records import retired_suites  # noqa: E402


def _is_test(path: Path) -> bool:
    return path.suffix == ".py" and (
        path.name.startswith("test_") or path.name.endswith("_test.py")
    )


def discover(root: Path, include_retired: bool = False) -> list[str]:
    retired = retired_suites(root)
    files = []
    for path in sorted((root / BROAD).rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        if not _is_test(path) or "__pycache__" in relative:
            continue
        is_retired = any(
            relative == suite or relative.startswith(f"{suite}/") for suite in retired
        )
        if is_retired == include_retired:
            files.append(relative)
    return files


def assign(
    files: list[str], durations: dict[str, float], shards: int, default: float
) -> list[list[str]]:
    weights = {path: float(durations.get(path, default)) for path in files}
    order = sorted(files, key=lambda path: (-weights[path], path))
    buckets: list[list[str]] = [[] for _ in range(shards)]
    totals = [0.0] * shards
    for path in order:
        index = min(range(shards), key=lambda i: (totals[i], i))
        buckets[index].append(path)
        totals[index] += weights[path]
    return buckets


def node_ids(path: str, listing: str) -> list[str]:
    """Rebase `pytest --collect-only -q` IDs, which are relative to pytest's rootdir, on `path`."""
    return [
        f"{path}::{line.strip().split('::', 1)[1]}"
        for line in listing.splitlines()
        if "::" in line
    ]


def collect_tests(root: Path, path: str) -> list[str]:
    """The pytest node IDs in one file, in run order."""
    listing = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", path],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    tests = node_ids(path, listing)
    if not tests:
        raise ValueError(f"{path} collected no tests")
    return tests


def _chunks(tests: list[str], count: int) -> list[list[str]]:
    size, extra = divmod(len(tests), count)
    chunks, start = [], 0
    for index in range(count):
        end = start + size + (1 if index < extra else 0)
        chunks.append(tests[start:end])
        start = end
    return [chunk for chunk in chunks if chunk]


def plan(
    root: Path,
    durations: dict[str, float],
    shards: int,
    budget: float,
    default: float,
    collect=collect_tests,
) -> dict:
    files = discover(root)
    limit = budget * SPLIT_SHARE
    units: dict[str, list[str]] = {}
    weights: dict[str, float] = {}
    for path in files:
        seconds = float(durations.get(path, default))
        if seconds <= limit:
            units[path] = [path]
            weights[path] = seconds
            continue
        tests = collect(root, path)
        chunks = _chunks(tests, math.ceil(seconds / (budget * CHUNK_SHARE)))
        for number, chunk in enumerate(chunks):
            key = f"{path}#chunk{number}"
            units[key] = chunk
            weights[key] = seconds * len(chunk) / len(tests)
    buckets = assign(list(units), weights, shards, default)
    result = []
    for index, bucket in enumerate(buckets):
        seconds = sum(weights[key] for key in bucket)
        if seconds > budget:
            raise ValueError(
                f"shard {index} needs {seconds:.0f} s, over the {budget:.0f} s budget; "
                "add shards to the workflow matrix"
            )
        arguments = [argument for key in bucket for argument in units[key]]
        result.append({"index": index, "seconds": round(seconds, 1), "arguments": arguments})
    return {"files": len(files), "shards": result}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--shard", type=int)
    parser.add_argument("--budget", type=float, default=35 * 60)
    parser.add_argument("--default", type=float, default=60.0)
    parser.add_argument("--retired", action="store_true", help="print the retired test files")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if args.retired:
        print("\n".join(discover(args.root, include_retired=True)))
        return 0
    durations = json.loads(DURATIONS.read_text())["seconds"]
    result = plan(args.root, durations, args.shards, args.budget, args.default)
    if args.shard is None:
        print(json.dumps({"files": result["files"], "shardSeconds": [s["seconds"] for s in result["shards"]]}))
    else:
        print("\n".join(result["shards"][args.shard]["arguments"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
