"""Builds the per-cell fixture from recorded runs.

python3 cells_fixture.py [--base <fixture.json>] <out.json> <run dir or interesting-*.json>...

Each run dir holds jar-<name>.json and emu-<name>.json from run_corpus.sh (probe.mjs rows); an
interesting-*.json file (from compare.py) adds only the rows that differ.
The fixture has one row per line: the expression, the official emulator's load answer and
refusal text per context (R, W, V) and its status per cell (ra ru qa qu sa su xa xu la lu wa wu va
vu, null when the context's rules were refused or the cell was not recorded), and, where fireemu differs, fireemu's statuses and
load answers with the reason the difference is listed. A difference is listed only when it
is fail-closed in every cell; a fail-open row stops the build.

--base keeps the rows of an earlier fixture that the recorded runs do not hold again; a row
recorded before the xa and xu cells existed has them null (not recorded).
"""
import json
import re
import sys
from pathlib import Path

CELLS = ["ra", "ru", "qa", "qu", "sa", "su", "xa", "xu", "la", "lu", "wa", "wu", "va", "vu"]
CONTEXT = {"ra": "R", "ru": "R", "qa": "R", "qu": "R", "sa": "R", "su": "R", "xa": "R", "xu": "R",
           "la": "R", "lu": "R", "wa": "W", "wu": "W", "va": "V", "vu": "V"}
# The cells of a fixture recorded before xa and xu, in order.
OLD_CELLS = ["ra", "ru", "qa", "qu", "sa", "su", "la", "lu", "wa", "wu", "va", "vu"]


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
    if 500 in jar_cells or 503 in jar_cells or "gone" in jar_cells:
        return "the official emulator answers 500 (an internal error); fireemu denies (ruling 15)"
    beyond = "[\U00010D50-\U00010D65\U00010D70-\U00010D85\U00016EA0-\U00016EB8\U00016EBB-\U00016ED3]"
    escaped = r"\\u[dD]803\\u[dD][dD][5-8]|\\u[dD]81[bB]\\u[dD][eE][a-dA-D]"
    if re.search(r"to(Lower|Upper)Case", expr) and (re.search(beyond, expr) or re.search(escaped, expr)):
        return "a case map Java 21 and fireemu's newer Unicode tables give differently is a rule error (review r11 M41)"
    if "toLowerCase" in expr and ("\u03a3" in expr or re.search(r"\\u03[aA]3", expr)):
        return "a lowercase of capital sigma beside other than an edge, a space or a cased Latin, Greek or Cyrillic letter is a rule error (review r11 M41)"
    if ".replace(''" in expr:
        return "replace('', ...) of text beyond the Basic Multilingual Plane is an error here; Java splits its surrogate pairs"
    if re.search(r"\b(OrderByKey|OrderByValue|OrderByPriority|http)\b|query\.(orderBy|endBefore|isOrderByChild)\b", expr):
        return "a query or ordering name the official emulator loads is refused here (listed)"
    if "getPriority" in expr and re.search(r"x{700}", expr):
        return "getPriority() near the path length limit is an error here a few bytes before it is one there (fail closed)"
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


args = sys.argv[1:]
base = []
if args[0] == "--base":
    base, args = json.load(open(args[1], encoding="utf-8")), args[2:]
out = args[0]
rows, seen = [], set()
for source in args[1:]:
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


def widen(cells):
    if len(cells) == len(CELLS):
        return cells
    old = dict(zip(OLD_CELLS, cells))
    return [old.get(cell) for cell in CELLS]


for row in base:
    if row["expr"] in seen:
        continue
    seen.add(row["expr"])
    row["cells"] = widen(row["cells"])
    if "fireemu" in row:
        row["fireemu"]["cells"] = widen(row["fireemu"]["cells"])
    rows.append(row)
with open(out, "w", encoding="utf-8") as f:
    f.write("[\n")
    f.write(",\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows))
    f.write("\n]\n")
print(len(rows), "rows,", sum("fireemu" in r for r in rows), "listed")
