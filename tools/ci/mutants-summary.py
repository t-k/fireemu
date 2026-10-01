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
That is only believed when the shards agree with the sharding: the run is checked against
cargo-mutants 27.1.0's default `Slice` sharding (shard k of n holds chunk = ceil(M / n) consecutive
mutants of the M listed in all), so a shard that is empty while an earlier one is not, or a run in
which every shard is empty, is a problem (with `--in-diff` an empty run writes no output at all).
The workflow must therefore not pass `--sharding`. A shard whose `outcomes.json` covers fewer mutants
than its `mutants.json` lists, or has no `end_time`, was stopped and fails; so does any other shard
without `outcomes.json` (nothing written, an unreadable list, a list that names mutants). A shard
number beyond --expected-shards is reported and not counted. `--mutants-result` passes the result of
the shard job: anything but success is a problem.
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


def slice_size(total: int, shards: int, k: int) -> int:
    """How many of `total` mutants shard `k` of `shards` holds under cargo-mutants' default `Slice` sharding
    (27.1.0, `shard.rs`): chunks of ceil(total / shards), shard k taking [k * chunk, (k + 1) * chunk)."""
    chunk = -(-total // shards)
    start = k * chunk
    return 0 if start >= total else min((k + 1) * chunk, total) - start


def read_listed(directory: Path):
    """The mutants a shard was given (`mutants.json`, written before anything runs): `(list, None)` or
    `(None, reason)`."""
    path = directory / "mutants.json"
    if not path.exists():
        return None, f"{path.name} is missing"
    try:
        listed = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        return None, f"{path.name} is unreadable: {clean(str(error), 120)}"
    if not isinstance(listed, list):
        return None, f"{path.name} is not a list"
    return listed, None


def read_shard(directory: Path):
    """What one shard left: `(outcomes, listed, reason)`.

    `outcomes` is the shard's outcomes (empty for a shard that held no mutant), `listed` the number of
    mutants it was given, `reason` why the shard cannot be trusted (then `outcomes` is None).

    cargo-mutants writes `mutants.json` first and rewrites `outcomes.json` after every mutant, and
    sets `end_time` only when it finishes. A shard that was stopped (the job timed out, the tool
    failed) therefore leaves a partial `outcomes.json` without `end_time`, which must not be read as
    a result. A shard that held no mutant writes no `outcomes.json` at all.
    """
    listed, listed_reason = read_listed(directory)
    path = directory / "outcomes.json"
    if not path.exists():
        if listed is None:
            if listed_reason.endswith("is missing"):
                return None, None, "outcomes.json and mutants.json are missing: the shard wrote nothing"
            return None, None, f"outcomes.json is missing and {listed_reason}"
        if listed:
            return None, len(listed), (
                f"outcomes.json is missing but mutants.json lists {len(listed)} mutants: the shard did not finish"
            )
        return [], 0, None
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        return None, None, f"{path.name} is unreadable: {clean(str(error), 120)}"
    outcomes = document.get("outcomes") if isinstance(document, dict) else None
    if not isinstance(outcomes, list):
        return None, None, f"{path.name} has no outcomes list"
    if listed is None:
        return None, None, f"{path.name} exists but {listed_reason}"
    if document.get("end_time") in (None, ""):
        return None, len(listed), f"{path.name} has no end_time: the shard did not finish"
    return outcomes, len(listed), None


def merge(shards_dir: Path, expected, mutants_result=None):
    found = {}
    for entry in sorted(shards_dir.iterdir()) if shards_dir.is_dir() else []:
        match = SHARD_DIRECTORY.match(entry.name)
        if match and entry.is_dir():
            found[int(match.group(1))] = entry
    problems = []
    if mutants_result is not None and mutants_result != "success":
        problems.append(f"the mutants job ended {clean(mutants_result, 40)}, not success")
    unexpected = [] if expected is None else sorted(k for k in found if k >= expected)
    for shard in unexpected:
        problems.append(f"shard {shard} is beyond the {expected} expected shards and is not counted")
        del found[shard]
    missing = [] if expected is None else [k for k in range(expected) if k not in found]
    for shard in missing:
        problems.append(f"shard {shard} left no artifact")
    counts = {CAUGHT: 0, MISSED: 0, UNVIABLE: 0, TIMEOUT: 0}
    other = {}
    missed, timed_out = [], []
    empty_shards = []
    listed_sizes = {}
    for shard, directory in sorted(found.items()):
        outcomes, listed, reason = read_shard(directory)
        if listed is not None:
            listed_sizes[shard] = listed
        if outcomes is None:
            problems.append(f"shard {shard}: {reason}")
            continue
        if listed == 0:
            empty_shards.append(shard)
        baseline_failed = False
        covered = 0
        for outcome in outcomes:
            if not isinstance(outcome, dict):
                problems.append(f"shard {shard}: an outcome is not an object")
                continue
            summary = outcome.get("summary")
            scenario = outcome.get("scenario")
            if scenario == "Baseline":
                if summary != "Success":
                    baseline_failed = True
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
            covered += 1
            if summary in counts:
                counts[summary] += 1
            else:
                key = clean(summary, 40)
                other[key] = other.get(key, 0) + 1
            if summary == MISSED:
                missed.append(name)
            elif summary == TIMEOUT:
                timed_out.append(name)
        if not baseline_failed and covered != listed:
            problems.append(
                f"shard {shard}: outcomes.json covers {covered} of {listed} listed mutants: the shard did not finish"
            )
    mutants_listed = sum(listed_sizes.values())
    complete = bool(found) and all(k in listed_sizes for k in found) and not missing
    if complete and mutants_listed == 0:
        problems.append(
            "every shard is empty: cargo-mutants 27.1.0 never writes an empty run for --in-diff, "
            "so nothing here is a result"
        )
    elif complete and expected is not None:
        for shard in range(expected):
            wanted = slice_size(mutants_listed, expected, shard)
            if listed_sizes[shard] != wanted:
                problems.append(
                    f"shard {shard} holds {listed_sizes[shard]} mutants but the default slice sharding of "
                    f"{mutants_listed} mutants over {expected} shards gives {wanted}"
                )
    total = sum(counts.values()) + sum(other.values())
    return {
        "shards_expected": expected,
        "shards_found": sorted(found),
        "shards_empty": empty_shards,
        "shards_unexpected": unexpected,
        "mutants_listed": mutants_listed,
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
    parser.add_argument(
        "--mutants-result",
        default=None,
        help="the result of the job that ran the shards (needs.mutants.result); anything but success is a problem",
    )
    args = parser.parse_args(argv)
    summary = merge(args.shards_dir, args.expected_shards, args.mutants_result)
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
