#!/usr/bin/env python3
"""Merges the outcomes of the shards of one cargo-mutants run into one summary.

Usage: mutants-summary.py [--expected-shards N] [--mutants-result R] [--fail-on-missed] [--survivors PATH] [--critical PATH] [--fail-on-new-critical] <shards-dir> <out-dir>

<shards-dir> holds one directory per shard (`mutants-shard-K`, the downloaded artifact), each with
the shard's `outcomes.json`. The summary counts the mutants by outcome (caught, missed, unviable,
timeout) and names every missed and every timed-out mutant. It writes `summary.json` and
`summary.md` to <out-dir>, and exits 1 when the run cannot be trusted: an expected shard is
missing, a shard has no readable outcomes, or a baseline did not succeed (a baseline that fails
makes every mutant look caught, so no result of that run is a result). Every reason is also printed
on stderr, naming the shard.

Survivor keys remove line and column numbers from raw mutant names and include a fingerprint of
the removed source lines from the mutant diff. A missing or ambiguous diff produces `fp:none`,
which is never accepted. Accepted keys and critical file patterns can be supplied with --survivors
and --critical. With --fail-on-new-critical, new
critical survivors exit 2; --fail-on-missed also exits 2 for any missed mutant. Untrusted runs and
unreadable lists exit 1.

A shard that held no mutant (more shards than mutants) is not a failure: cargo-mutants then writes
no `outcomes.json` at all, only an empty `mutants.json` list, and the shard counts as zero mutants.
That is only believed when the shards agree with the sharding: the run is checked against
cargo-mutants 27.1.0's default `Slice` sharding (shard k of n holds chunk = ceil(M / n) consecutive
mutants of the M listed in all), so a shard that is empty while an earlier one is not, or a run in
which every shard is empty, is a problem (with `--in-diff` an empty run writes no output at all).
The workflow pins it with `--sharding slice` (the command line wins over the `sharding` of a ref's
`.cargo/mutants.toml`). A shard whose `outcomes.json` has no `end_time`, covers fewer mutants than its
`mutants.json` lists, or names other mutants than it lists (compared as multisets of names) was stopped or
is inconsistent and fails, and a shard with any problem adds nothing to the totals; so does any other shard
without `outcomes.json` (nothing written, an unreadable list, a list that names mutants). A shard
number beyond --expected-shards is reported and not counted. `--mutants-result` passes the result of
the shard job: anything but success is a problem.
"""

import argparse
import fnmatch
import hashlib
import json
import re
import sys
from typing import Optional
import unicodedata
from collections import Counter
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


def survivor_key(raw_name: str) -> str:
    """Remove the first line and column location from a raw mutant name."""
    return re.sub(r"^(.*?):[0-9]+:[0-9]+: ", r"\1: ", raw_name, count=1, flags=re.DOTALL)


def mutant_fingerprint(shard_dir: Path, raw_name: str) -> Optional[str]:
    """Hash removed source lines from the matching cargo-mutants diff, without location metadata."""
    match = re.match(r"^(.*?):([0-9]+):([0-9]+): (.*)$", raw_name, flags=re.DOTALL)
    if match is None:
        return None
    file, line, column, description = match.groups()
    filename = re.compile(rf"^{re.escape(file.replace('/', '__'))}_line_{line}_col_{column}(?:_[0-9]+)?\.diff$")
    removed = []
    try:
        for path in sorted((shard_dir / "diff").iterdir()):
            if not filename.fullmatch(path.name):
                continue
            lines = path.read_text().split("\n")
            if len(lines) < 2 or lines[1] != f"+++ {description}":
                continue
            removed.append([line[1:] for line in lines if line.startswith("-") and not line.startswith("--- ")])
    except (OSError, UnicodeError):
        return None
    if not removed or any(lines != removed[0] for lines in removed[1:]):
        return None
    return hashlib.sha256("\n".join(removed[0]).encode("utf-8")).hexdigest()[:16]


def fingerprinted_key(raw_name: str, shard_dir: Path) -> str:
    """Return a location-independent survivor key with its source fingerprint."""
    fingerprint = mutant_fingerprint(shard_dir, raw_name)
    return f"{survivor_key(raw_name)} [fp:{fingerprint or 'none'}]"


def critical_pattern(line: str) -> str:
    """The file pattern of a critical-list line: the path before any comment or ` @` function list."""
    return line.split("#", 1)[0].split(" @", 1)[0].strip()


def scoped_critical_regex(path: Path):
    """A regex over mutant names for the scoped lines (`<path> @ <function> ...`) of the critical list,
    in the form tools/ci/critical-selection.py prints; None when the list has no scoped line."""
    alternatives = []
    for raw in read_entries(path):
        body = raw.split("#", 1)[0].strip()
        if " @" not in body:
            continue
        file_part, _, names = body.partition(" @")
        alt = "|".join(re.escape(name) for name in names.split())
        head = re.escape(file_part.strip())
        alternatives.append(f"^{head}:[0-9]+:[0-9]+:\\s.*(in|replace)\\s({alt})(\\s|$)")
    return "(" + "|".join(alternatives) + ")" if alternatives else None


def read_entries(path: Path):
    """Read keys or patterns while preserving leading spaces."""
    return [line for raw in path.read_text().splitlines()
            if (line := raw.rstrip()) and not line.startswith("#")]


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

    `outcomes` is the shard's outcomes (empty for a shard that held no mutant), `listed` the list of
    mutants it was given (`mutants.json`), `reason` why the shard cannot be trusted (then `outcomes`
    is None).

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
            return None, listed, (
                f"outcomes.json is missing but mutants.json lists {len(listed)} mutants: the shard did not finish"
            )
        return [], listed, None
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
        return None, listed, f"{path.name} has no end_time: the shard did not finish"
    return outcomes, listed, None


def reconcile(shard: int, listed, outcome_names: Counter):
    """The problems of one shard's outcomes against the mutants it was given: the number of outcomes
    must equal the number of listed mutants, and the names must be the same multiset."""
    problems = []
    listed_names = Counter()
    unnamed = 0
    for entry in listed:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            listed_names[entry["name"]] += 1
        else:
            unnamed += 1
    if unnamed:
        problems.append(f"shard {shard}: mutants.json has {unnamed} entries without a name")
        return problems
    covered = sum(outcome_names.values())
    if covered != len(listed):
        problems.append(
            f"shard {shard}: outcomes.json covers {covered} of {len(listed)} listed mutants: the shard did not finish"
        )
    elif outcome_names != listed_names:
        absent = sorted((listed_names - outcome_names).elements())
        extra = sorted((outcome_names - listed_names).elements())
        problems.append(
            f"shard {shard}: the outcomes and mutants.json do not match: "
            f"listed but without an outcome: {names_text(absent)}; outcome of a mutant that was not listed: {names_text(extra)}"
        )
    return problems


def names_text(names, shown=5):
    text = ", ".join(clean(name, 80) for name in names[:shown])
    return text + (f", … ({len(names)} in all)" if len(names) > shown else "") if names else "none"


def merge(shards_dir: Path, expected, mutants_result=None, raw_missed=None, missed_shards=None):
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
            listed_sizes[shard] = len(listed)
        if outcomes is None:
            problems.append(f"shard {shard}: {reason}")
            continue
        if not listed:
            empty_shards.append(shard)
        # What this shard adds is kept apart: a shard with any problem adds nothing to the totals.
        shard_problems = []
        shard_counts = {CAUGHT: 0, MISSED: 0, UNVIABLE: 0, TIMEOUT: 0}
        shard_other = {}
        shard_missed, shard_timed_out, shard_raw_missed = [], [], []
        outcome_names = Counter()
        baseline_failed = False
        for outcome in outcomes:
            if not isinstance(outcome, dict):
                shard_problems.append(f"shard {shard}: an outcome is not an object")
                continue
            summary = outcome.get("summary")
            scenario = outcome.get("scenario")
            if scenario == "Baseline":
                if summary != "Success":
                    baseline_failed = True
                    shard_problems.append(f"shard {shard}: the baseline did not succeed ({clean(summary, 40)})")
                continue
            mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
            if not isinstance(mutant, dict) or not isinstance(mutant.get("name"), str):
                shard_problems.append(f"shard {shard}: an outcome has no mutant name")
                continue
            name = clean(mutant["name"])
            if not isinstance(summary, str):
                shard_problems.append(f"shard {shard}: the outcome of {name} has no summary")
                continue
            outcome_names[mutant["name"]] += 1
            if summary in shard_counts:
                shard_counts[summary] += 1
            else:
                key = clean(summary, 40)
                shard_other[key] = shard_other.get(key, 0) + 1
            if summary == MISSED:
                shard_missed.append(name)
                shard_raw_missed.append(mutant["name"])
            elif summary == TIMEOUT:
                shard_timed_out.append(name)
        if not baseline_failed:
            shard_problems.extend(reconcile(shard, listed, outcome_names))
        problems.extend(shard_problems)
        if shard_problems:
            continue
        for key, value in shard_counts.items():
            counts[key] += value
        for key, value in shard_other.items():
            other[key] = other.get(key, 0) + value
        missed.extend(shard_missed)
        if raw_missed is not None:
            raw_missed.extend(shard_raw_missed)
        if missed_shards is not None:
            missed_shards.extend((name, directory) for name in shard_raw_missed)
        timed_out.extend(shard_timed_out)
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
            lines += ["", f"### {title}", ""] + [f"- `{clean(name)}`" for name in summary[key]]
    if "new_survivors" in summary:
        critical = set(summary["new_critical_survivors"])
        lines += ["", "### New survivors", "", f"{summary['accepted_survivors']} accepted survivors."]
        lines += [f"- `{clean(name)}`" + (" (critical)" if name in critical else "")
                  for name in summary["new_survivors"]]
    if summary["problems"]:
        lines += ["", "### The run cannot be trusted", ""] + [f"- {p}" for p in summary["problems"]]
    return "\n".join(lines) + "\n"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("shards_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--expected-shards", type=int, default=None)
    parser.add_argument(
        "--fail-on-missed",
        action="store_true",
        help="exit 2 when the run can be trusted and a mutant was missed (a run that cannot be trusted exits 1)",
    )
    parser.add_argument(
        "--mutants-result",
        default=None,
        help="the result of the job that ran the shards (needs.mutants.result); anything but success is a problem",
    )
    parser.add_argument("--survivors", type=Path, help="file containing accepted survivor keys")
    parser.add_argument("--critical", type=Path, help="file containing critical path patterns")
    parser.add_argument("--fail-on-new-critical", action="store_true", help="exit 2 for new critical survivors")
    args = parser.parse_args(argv)
    try:
        accepted = set(read_entries(args.survivors)) if args.survivors is not None else set()
        lines = read_entries(args.critical) if args.critical is not None else []
        critical = [critical_pattern(line) for line in lines if " @" not in line.split("#", 1)[0]]
    except (OSError, UnicodeError) as error:
        print(f"mutants-summary: cannot read survivor or critical list: {clean(str(error))}", file=sys.stderr)
        return 1
    missed_shards = []
    summary = merge(args.shards_dir, args.expected_shards, args.mutants_result, missed_shards=missed_shards)
    if args.survivors is not None or args.critical is not None or args.fail_on_new_critical:
        keys = [fingerprinted_key(name, directory) for name, directory in missed_shards]
        is_accepted = [not key.endswith(" [fp:none]") and key in accepted for key in keys]
        summary["accepted_survivors"] = sum(is_accepted)
        summary["new_survivors"] = sorted(key for key, accepted_key in zip(keys, is_accepted) if not accepted_key)
        scoped = scoped_critical_regex(args.critical) if args.critical is not None else None
        new_critical = set()
        for key, (raw, _), accepted_key in zip(keys, missed_shards, is_accepted):
            if accepted_key:
                continue
            file_part = key.split(": ", 1)[0]
            whole_file = any(fnmatch.fnmatchcase(file_part, pattern) for pattern in critical)
            if whole_file or (scoped is not None and re.search(scoped, raw)):
                new_critical.add(key)
        summary["new_critical_survivors"] = sorted(new_critical)
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
    if summary["problems"]:
        return 1
    if args.fail_on_new_critical and summary["new_critical_survivors"]:
        names = summary["new_critical_survivors"]
        print(f"mutants-summary: {len(names)} new critical survivors: " + ", ".join(clean(name) for name in names),
              file=sys.stderr)
        return 2
    if args.fail_on_missed and summary["missed"]:
        print(f"mutants-summary: {summary['missed']} mutants were missed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
