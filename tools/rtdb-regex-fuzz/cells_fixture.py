"""Builds the per-cell fixture from recorded runs.

python3 cells_fixture.py <out.json> <run dir or interesting-*.json>...

Each run dir holds jar-<name>.json and emu-<name>.json from run_corpus.sh (probe.mjs rows); an
interesting-*.json file (from compare.py) adds only the rows that differ.
The fixture has one row per line: the expression, the official emulator's load answer and
refusal text per context (R, W, V) and its status per cell (ra ru qa qu wa wu va vu, null
when the context's rules were refused), and, where fireemu differs, fireemu's statuses and
load answers with the reason the difference is listed. A difference is listed only when it
is fail-closed in every cell; a fail-open row stops the build.
"""
import json
import re
import sys
from pathlib import Path

CELLS = ["ra", "ru", "qa", "qu", "wa", "wu", "va", "vu"]
CONTEXT = {"ra": "R", "ru": "R", "qa": "R", "qu": "R", "wa": "W", "wu": "W", "va": "V", "vu": "V"}


def compact(row):
    loads = [row.get(f"load{c}") for c in "RWV"]
    errors = [row.get(f"err{c}") for c in "RWV"]
    cells = [row.get(cell) if row.get(f"load{CONTEXT[cell]}") == 200 else None for cell in CELLS]
    return loads, errors, cells


def outcome(loads, cells, i):
    load = loads["RWV".index(CONTEXT[CELLS[i]])]
    return f"load{load}" if load != 200 else cells[i]


def reason(expr, jar_errors, jar_cells, emu_cells):
    if any("could not determinize efficiently" in str(x) for x in jar_errors):
        return "the official emulator cannot determinize the pattern, its own resource limit (M14)"
    if 500 in jar_cells:
        return "the official emulator answers 500 (an internal error); fireemu denies (ruling 15)"
    if re.search(r"\.(contains|beginsWith|endsWith|replace|toLowerCase|toUpperCase|matches)\s*[!=]", expr):
        return "a string method read without a call is an error here, a function there"
    if re.search(r"\bauth\s*[!=]==?\s*auth\b", expr) or (
        "?" in expr and any(op in expr for op in ("==", "!=")) and "matches(" not in expr
    ):
        return "an equality of two snapshots, auth or query is a rule error (review r9 M25 (b))"
    if "\\u" in expr and "matches(" not in expr:
        return "a \\u escape in a name or a lone escaped surrogate is refused at load (review r5 S13)"
    if "matches(" in expr:
        return "a regular-expression construct fireemu does not reproduce is a rule error (ruling 11)"
    return "fail-closed difference"


def pairs(source):
    source = Path(source)
    if source.is_file():
        for pair in json.load(open(source, encoding="utf-8")):
            yield pair["jar"], pair["fireemu"]
        return
    for jar_file in sorted(source.glob("jar-*.json")):
        name = jar_file.name[len("jar-"):]
        # run_corpus.sh also leaves each chunk (jar-<name>.<part>.json): only the whole.
        if re.fullmatch(r".+\.\d+\.json", name):
            continue
        emu_file = source / f"emu-{name}"
        if not emu_file.exists():
            continue
        jar = json.load(open(jar_file, encoding="utf-8"))
        emu = json.load(open(emu_file, encoding="utf-8"))
        yield from zip(jar, emu)


out = sys.argv[1]
rows, seen = [], set()
for source in sys.argv[2:]:
    for j, e in pairs(source):
        if j["expr"] in seen:
            continue
        seen.add(j["expr"])
        jl, jx, jc = compact(j)
        el, ex, ec = compact(e)
        row = {"expr": j["expr"], "load": jl, "error": jx, "cells": jc}
        outcomes = [(outcome(jl, jc, i), outcome(el, ec, i)) for i in range(len(CELLS))]
        if any(a != b for a, b in outcomes) or jx != ex:
            determinize = any("could not determinize efficiently" in str(x) for x in jx)
            if not determinize and any(b == 200 and a != 200 for a, b in outcomes):
                raise SystemExit(f"fail-open row: {j['expr']!r}")
            row["fireemu"] = {"load": el, "error": ex, "cells": ec,
                              "why": reason(j["expr"], jx, jc, ec)}
        rows.append(row)
with open(out, "w", encoding="utf-8") as f:
    f.write("[\n")
    f.write(",\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows))
    f.write("\n]\n")
print(len(rows), "rows,", sum("fireemu" in r for r in rows), "listed")
