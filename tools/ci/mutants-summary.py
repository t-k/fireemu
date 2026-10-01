#!/usr/bin/env python3
"""Merges the outcomes of the shards of one cargo-mutants run into one summary.

Usage: mutants-summary.py [--expected-shards N] <shards-dir> <out-dir>

<shards-dir> holds one directory per shard (`mutants-shard-K`, the downloaded artifact), each with
the shard's `outcomes.json`. The summary counts the mutants by outcome (caught, missed, unviable,
timeout) and names every missed and every timed-out mutant. It writes `summary.json` and
`summary.md` to <out-dir>, and exits 1 when the run cannot be trusted: an expected shard is
missing, a shard has no readable outcomes, or a baseline did not succeed (a baseline that fails
makes every mutant look caught, so no result of that run is a result).
"""

import argparse
import json
import re
import sys
from pathlib import Path

CAUGHT, MISSED, UNVIABLE, TIMEOUT = "CaughtMutant", "MissedMutant", "Unviable", "Timeout"
SHARD_DIRECTORY = re.compile(r"^mutants-shard-(\d+)$")


def read_shard(directory: Path):
    """The outcomes of one shard, or the reason they cannot be read."""
    path = directory / "outcomes.json"
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        return None, f"{path.name} is unreadable: {error}"
    outcomes = document.get("outcomes") if isinstance(document, dict) else None
    if not isinstance(outcomes, list):
        return None, f"{path.name} has no outcomes list"
    return outcomes, None


def merge(shards_dir: Path, expected):
    found = {}
    for entry in sorted(shards_dir.iterdir()) if shards_dir.is_dir() else []:
        match = SHARD_DIRECTORY.match(entry.name)
        if match and entry.is_dir():
            found[int(match.group(1))] = entry
    problems = []
    missing = [] if expected is None else [k for k in range(expected) if k not in found]
    for shard in missing:
        problems.append(f"shard {shard} left no artifact")
    counts = {CAUGHT: 0, MISSED: 0, UNVIABLE: 0, TIMEOUT: 0}
    other = {}
    missed, timed_out = [], []
    for shard, directory in sorted(found.items()):
        outcomes, reason = read_shard(directory)
        if outcomes is None:
            problems.append(f"shard {shard}: {reason}")
            continue
        for outcome in outcomes:
            summary = outcome.get("summary")
            scenario = outcome.get("scenario")
            if scenario == "Baseline":
                if summary != "Success":
                    problems.append(f"shard {shard}: the baseline did not succeed ({summary})")
                continue
            name = scenario["Mutant"]["name"] if isinstance(scenario, dict) else str(scenario)
            if summary in counts:
                counts[summary] += 1
            else:
                other[summary] = other.get(summary, 0) + 1
            if summary == MISSED:
                missed.append(name)
            elif summary == TIMEOUT:
                timed_out.append(name)
    total = sum(counts.values()) + sum(other.values())
    return {
        "shards_expected": expected,
        "shards_found": sorted(found),
        "total": total,
        "caught": counts[CAUGHT],
        "missed": counts[MISSED],
        "unviable": counts[UNVIABLE],
        "timeout": counts[TIMEOUT],
        "other": other,
        "missed_mutants": sorted(missed),
        "timeout_mutants": sorted(timed_out),
        "problems": problems,
    }


def markdown(summary):
    lines = [
        "## Mutation testing",
        "",
        "| total | caught | missed | unviable | timeout |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {summary['total']} | {summary['caught']} | {summary['missed']} | "
        f"{summary['unviable']} | {summary['timeout']} |",
        "",
        f"Shards found: {len(summary['shards_found'])}"
        + ("" if summary["shards_expected"] is None else f" of {summary['shards_expected']}"),
    ]
    if summary["other"]:
        lines += ["", f"Other outcomes: {json.dumps(summary['other'], sort_keys=True)}"]
    for title, key in (("Missed mutants", "missed_mutants"), ("Timed-out mutants", "timeout_mutants")):
        if summary[key]:
            lines += ["", f"### {title}", ""] + [f"- `{name}`" for name in summary[key]]
    if summary["problems"]:
        lines += ["", "### The run cannot be trusted", ""] + [f"- {p}" for p in summary["problems"]]
    return "\n".join(lines) + "\n"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("shards_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--expected-shards", type=int, default=None)
    args = parser.parse_args(argv)
    summary = merge(args.shards_dir, args.expected_shards)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (args.out_dir / "summary.md").write_text(markdown(summary))
    return 1 if summary["problems"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
