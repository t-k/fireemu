#!/usr/bin/env python3
"""Merges the outcomes of the shards of one cargo-mutants run into one summary.

Usage: mutants-summary.py [--expected-shards N] <shards-dir> <out-dir>

<shards-dir> holds one directory per shard (`mutants-shard-K`, the downloaded artifact), each with
the shard's `outcomes.json`. The summary counts the mutants by outcome (caught, missed, unviable,
timeout) and names every missed and every timed-out mutant. It writes `summary.json` and
`summary.md` to <out-dir>, and exits 1 when the run cannot be trusted: an expected shard is
missing, a shard has no readable outcomes, or a baseline did not succeed (a baseline that fails
makes every mutant look caught, so no result of that run is a result). Every reason is also printed
on stderr, naming the shard.

A shard that held no mutant (more shards than mutants) is not a failure: cargo-mutants then writes
no `outcomes.json` at all, only an empty `mutants.json` list, and the shard counts as zero mutants.
A shard with no `outcomes.json` and anything else (nothing written, an unreadable list, a list that
names mutants) did not finish and fails.
"""

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

CAUGHT, MISSED, UNVIABLE, TIMEOUT = "CaughtMutant", "MissedMutant", "Unviable", "Timeout"
SHARD_DIRECTORY = re.compile(r"^mutants-shard-(\d+)$")


MAX_NAME = 300


def clean(value, limit=MAX_NAME):
    """A string taken from a shard, made safe to print and to put in Markdown.

    The shard's code can write anything into its outcomes: control characters, newlines (which would
    forge headings), bidirectional overrides, backticks. Each such character becomes a visible
    `\\uXXXX` escape, backticks become apostrophes, and the text is cut at `limit` characters.
    """
    text = value if isinstance(value, str) else repr(value)
    out = []
    for char in text:
        category = unicodedata.category(char)
        if char == "`":
            out.append("'")
        elif category in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp") or (category == "Zs" and char != " "):
            out.append(f"\\u{ord(char):04x}" if ord(char) <= 0xFFFF else f"\\U{ord(char):08x}")
        else:
            out.append(char)
    cleaned = "".join(out)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def read_shard(directory: Path):
    """The outcomes of one shard, or the reason they cannot be read.

    Returns `(outcomes, reason, empty)`: `empty` is true for a shard that held no mutant.
    """
    path = directory / "outcomes.json"
    if not path.exists():
        return read_missing_outcomes(directory)
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        return None, f"{path.name} is unreadable: {clean(str(error), 120)}", False
    outcomes = document.get("outcomes") if isinstance(document, dict) else None
    if not isinstance(outcomes, list):
        return None, f"{path.name} has no outcomes list", False
    return outcomes, None, False


def read_missing_outcomes(directory: Path):
    """A shard without `outcomes.json`: zero mutants if its list of mutants is empty, else a failure."""
    path = directory / "mutants.json"
    if not path.exists():
        return None, "outcomes.json and mutants.json are missing: the shard wrote nothing", False
    try:
        listed = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        return None, f"outcomes.json is missing and {path.name} is unreadable: {clean(str(error), 120)}", False
    if not isinstance(listed, list):
        return None, f"outcomes.json is missing and {path.name} is not a list", False
    if listed:
        return None, f"outcomes.json is missing but {path.name} lists {len(listed)} mutants: the shard did not finish", False
    return [], None, True


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
    empty_shards = []
    for shard, directory in sorted(found.items()):
        outcomes, reason, empty = read_shard(directory)
        if outcomes is None:
            problems.append(f"shard {shard}: {reason}")
            continue
        if empty:
            empty_shards.append(shard)
        for outcome in outcomes:
            if not isinstance(outcome, dict):
                problems.append(f"shard {shard}: an outcome is not an object")
                continue
            summary = outcome.get("summary")
            scenario = outcome.get("scenario")
            if scenario == "Baseline":
                if summary != "Success":
                    problems.append(f"shard {shard}: the baseline did not succeed ({clean(summary, 40)})")
                continue
            mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
            if not isinstance(mutant, dict) or not isinstance(mutant.get("name"), str):
                problems.append(f"shard {shard}: an outcome has no mutant name")
                continue
            name = clean(mutant["name"])
            if not isinstance(summary, str):
                problems.append(f"shard {shard}: the outcome of {name} has no summary")
                continue
            if summary in counts:
                counts[summary] += 1
            else:
                key = clean(summary, 40)
                other[key] = other.get(key, 0) + 1
            if summary == MISSED:
                missed.append(name)
            elif summary == TIMEOUT:
                timed_out.append(name)
    total = sum(counts.values()) + sum(other.values())
    return {
        "shards_expected": expected,
        "shards_found": sorted(found),
        "shards_empty": empty_shards,
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
    if summary["shards_empty"]:
        lines += ["", "Empty shards (no mutants): " + ", ".join(str(k) for k in summary["shards_empty"])]
    if summary["total"] == 0 and not summary["problems"]:
        lines += ["", "No mutant was generated for this diff."]
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
    for problem in summary["problems"]:
        print(f"mutants-summary: {problem}", file=sys.stderr)
    if summary["problems"]:
        print(
            f"mutants-summary: the run cannot be trusted ({len(summary['problems'])} problems)",
            file=sys.stderr,
        )
    return 1 if summary["problems"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
