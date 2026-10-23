"""Compares the official emulator's and fireemu's answers for the same expressions, per cell.

python3 compare.py <jar.json> <fireemu.json> <report.txt> [<interesting.json>]

Each row holds the answers of fourteen cells (see probe.mjs): ra, ru, qa, qu (reads without and
with a query), sa, su (event streams), xa, xu (event streams with the query), la, lu (realtime listens), wa, wu (`.write`) and va, vu (`.validate`), signed in (a) and anonymous (u). A
cell's outcome is its status, or "load<status>" when the rules of its context were refused.
A cell is fail-open, and the row BLOCKING, when fireemu answers 200 where the official
emulator does not, including a determinization resource refusal. Any other difference is
fail-closed and listed. A fireemu transport failure remains BLOCKING even when both
products stop answering. The report
counts both per cell.
"""
import json
import sys

CELLS = {"ra": "R", "ru": "R", "qa": "R", "qu": "R", "sa": "R", "su": "R", "xa": "R", "xu": "R",
         "la": "R", "lu": "R",
         "wa": "W", "wu": "W", "va": "V", "vu": "V"}

jar = json.load(open(sys.argv[1], encoding="utf-8"))
emu = json.load(open(sys.argv[2], encoding="utf-8"))
assert len(jar) == len(emu) and all(a["expr"] == b["expr"] for a, b in zip(jar, emu))


def outcome(row, cell):
    context = CELLS[cell]
    load = row.get(f"load{context}")
    if load != 200:
        return f"load{load}"
    return str(row.get(cell))


blocking, closed, same = [], [], 0
per_cell = {cell: {"open": 0, "closed": 0} for cell in CELLS}
interesting = []
for j, e in zip(jar, emu):
    opened, differed = [], []
    for cell in CELLS:
        a, b = outcome(j, cell), outcome(e, cell)
        if a == b and b not in ("503", "gone"):
            continue
        # fireemu never stops answering; if it did, the cell is not known to be safe.
        if b == "200" or b in ("503", "gone"):
            opened.append(f"{cell} jar {a} fireemu {b}")
            per_cell[cell]["open"] += 1
        else:
            differed.append(f"{cell} jar {a} fireemu {b}")
            per_cell[cell]["closed"] += 1
    if not opened and not differed:
        same += 1
        continue
    line = f"{j['expr']!r}: " + "; ".join(opened + differed)
    (blocking if opened else closed).append(line)
    interesting.append({"jar": j, "fireemu": e})
summary = (f"rows {len(jar)}, same {same}, fail-closed {len(closed)}, "
           f"BLOCKING {len(blocking)}")
with open(sys.argv[3], "w", encoding="utf-8") as f:
    f.write(summary + "\n")
    f.write("per cell: " + ", ".join(f"{c} open {v['open']} closed {v['closed']}" for c, v in per_cell.items()) + "\n")
    for line in blocking:
        f.write(f"BLOCKING {line}\n")
    for line in closed:
        f.write(f"closed {line}\n")
if len(sys.argv) > 4:
    with open(sys.argv[4], "w", encoding="utf-8") as f:
        json.dump(interesting, f, ensure_ascii=False, indent=1)
print(summary)
