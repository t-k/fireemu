#!/usr/bin/env python3
"""Turns the critical-path list into a cargo-mutants selection for the critical run.

Usage:
  critical-selection.py --regex LIST       one regex for `cargo mutants --re`, on one line
  critical-selection.py --paths LIST       the distinct file paths of the list, one per line
  critical-selection.py --packages LIST    the distinct packages of the list (crates/<package>/...),
                                           one line, space-separated, for `cargo mutants -p`
  critical-selection.py --check LIST ROOT  every path is a file under ROOT and every scoped
                                           function name occurs in that file

Each line of LIST is `<path>` (every mutant of the file) or `<path> @ <name> [<name> ...]` (only the
mutants whose text names one of the functions, as `in <name>` or `replace <name> `). Text from the first
`#` is a comment, and blank lines are ignored. A path must be a Rust file under crates/ with no `..` and
no `//`; a name is a Rust path such as `build_request` or `FirestoreState::transaction_conflicted`.
Any other token is an error, reported with its line number (exit 1), so a bad list fails closed.
The file-level selection is needed because `cargo mutants --list --file <glob>` did not filter in a
measurement, while `--re` did: the regex is matched against names such as
`crates/x/src/f.rs:42:9: replace f -> bool with true` (body mutants end with `in <function>`).
cargo-mutants filters struct-literal field deletions (`delete field ... in <function>`) by no regex, so
a critical run also mutates those in the packages of the list; the summary counts them as critical only
when their name matches the scoped selection. The regex contains no literal space, because the wrapper that runs cargo in a measurement split arguments on spaces; it uses \s instead.
Exit 2 is a usage error.
"""

import re
import sys
from pathlib import Path

PATH = re.compile(r"^crates/[A-Za-z0-9_./-]+\.rs$")
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$")


class ListError(Exception):
    pass


def parse(text: str):
    """The entries of a list as (path, names) pairs; names is empty for a whole file."""
    entries = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        path, _, rest = line.partition(" @ ")
        if rest == "" and " @" in line:
            raise ListError(f"line {number}: the function list must follow ' @ '")
        path = path.strip()
        if not PATH.match(path) or ".." in path or "//" in path:
            raise ListError(f"line {number}: a bad path: {path!r}")
        names = rest.split() if rest else []
        for name in names:
            if not NAME.match(name):
                raise ListError(f"line {number}: a bad function name: {name!r}")
        entries.append((path, names))
    if not entries:
        raise ListError("the list has no entries")
    return entries


def regex_of(entries) -> str:
    alternatives = []
    for path, names in entries:
        head = path.replace(".", r"\.") + r":[0-9]+:[0-9]+:\s"
        if not names:
            alternatives.append("^" + head)
        else:
            alt = "|".join(names)
            alternatives.append(f"^{head}.*(in|replace)\\s({alt})(\\s|$)")
    return "(" + "|".join(alternatives) + ")"


def check(entries, root: Path):
    problems = []
    for path, names in entries:
        target = root / path
        if not target.is_file():
            problems.append(f"{path}: no such file under {root}")
            continue
        text = target.read_text(encoding="utf-8", errors="replace")
        for name in names:
            last = name.split("::")[-1]
            if not re.search(rf"\bfn\s+{re.escape(last)}\b", text):
                problems.append(f"{path}: no function {name}")
    return problems


def main(argv) -> int:
    if len(argv) < 2 or argv[0] not in ("--regex", "--paths", "--packages", "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    mode = argv[0]
    if mode == "--check" and len(argv) != 3:
        return 2
    if mode != "--check" and len(argv) != 2:
        return 2
    try:
        entries = parse(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        print(f"critical-selection: cannot read the list: {error}", file=sys.stderr)
        return 1
    except ListError as error:
        print(f"critical-selection: {error}", file=sys.stderr)
        return 1
    if mode == "--regex":
        print(regex_of(entries))
        return 0
    if mode == "--packages":
        packages = []
        for path, _ in entries:
            package = path.split("/")[1]
            if package not in packages:
                packages.append(package)
        print(" ".join(packages))
        return 0
    if mode == "--paths":
        seen = []
        for path, _ in entries:
            if path not in seen:
                seen.append(path)
        print("\n".join(seen))
        return 0
    problems = check(entries, Path(argv[2]))
    for problem in problems:
        print(f"critical-selection: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
