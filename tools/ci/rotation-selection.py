#!/usr/bin/env python3
"""Turns one line of the weekly rotation into a cargo-mutants `--re` selection for its package.

Usage: rotation-selection.py <package> [<token> ...] < files.txt

files.txt holds the repository paths of the package's Rust files (one per line; the workflow takes them
from the commit under test). The tokens are the rest of the rotation line: a path or a glob (fnmatch on
the repository path) names files to include, and `!<path or glob>` names files to exclude. With no
include token every file of the package is included. The output is one line: a regex for `re.search`
against cargo-mutants `--list` names, matching only mutants of the selected files.

Why a regex rather than `--file`: a measurement showed `cargo mutants --list --file <glob>` listing the
whole package, while `--re` filters the names within `-p <package>`. The regex has no literal space
(the wrapper that runs cargo in a measurement split arguments on spaces) and no lookaround (the regex
engine of cargo-mutants has none), so an exclusion is applied here, to the file list, instead.
Exit 1 on a bad token or an empty selection; exit 2 on a usage error.
"""

import fnmatch
import re
import sys

PACKAGE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
TOKEN = re.compile(r"^!?[A-Za-z0-9_./*-]{1,200}$")


def fail(message: str) -> int:
    print(f"rotation-selection: {message}", file=sys.stderr)
    return 1


def select(package: str, tokens, files):
    if not PACKAGE.match(package):
        raise ValueError(f"a bad package name: {package!r}")
    prefix = f"crates/{package}/"
    own = sorted({f.strip() for f in files if f.strip().startswith(prefix) and f.strip().endswith(".rs")})
    includes, excludes = [], []
    for token in tokens:
        if not TOKEN.match(token) or ".." in token or "//" in token:
            raise ValueError(f"a bad token: {token!r}")
        if token.startswith("!"):
            excludes.append(token[1:])
        else:
            includes.append(token)
    chosen = own if not includes else [f for f in own if any(fnmatch.fnmatchcase(f, g) for g in includes)]
    chosen = [f for f in chosen if not any(fnmatch.fnmatchcase(f, g) for g in excludes)]
    if not chosen:
        raise ValueError("the rotation line selects no file of the package")
    for path in chosen:
        if not re.match(r"^[A-Za-z0-9_./-]+$", path):
            raise ValueError(f"a file name with an unsupported character: {path!r}")
    alternatives = [path.replace(".", r"\.") + r":[0-9]+:[0-9]+:\s" for path in chosen]
    return "(^" + "|^".join(alternatives) + ")"


def main(argv) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        print(select(argv[0], argv[1:], sys.stdin.read().splitlines()))
    except ValueError as error:
        return fail(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
