"""Compares write_probe.mjs runs (the r11 review wrote it).
python3 -I write_compare.py <jar.json> <emu.json> <report.txt> <interesting.json>
Per cell (operation x signed in / anonymous): FAIL-OPEN when fireemu allows (200 / "ok") and the
jar does not, or when both allow but fireemu stored what the jar did not (state differs after a
jar denial is covered by the first case). FAIL-CLOSED when the jar allows and fireemu does not.
STATE when the answers agree and the stored trees differ. OTHER for other answer differences
(e.g. 400 against 401). LOADDIFF when one side refuses the rules at load."""
import json
import sys
from collections import Counter, defaultdict

jar = json.load(open(sys.argv[1]))
emu = json.load(open(sys.argv[2]))
assert len(jar) == len(emu)
per_cell = defaultdict(Counter)
interesting = []
rows = Counter()
for a, b in zip(jar, emu):
    if a is None or b is None:
        rows["missing"] += 1
        continue
    assert a["expr"] == b["expr"]
    if a["load"] != b["load"]:
        rows["loaddiff"] += 1
        interesting.append({"kind": "LOADDIFF", "expr": a["expr"], "place": a["place"], "jar": a.get("err"), "emu": b.get("err")})
        continue
    if a["load"] != 200:
        rows["both refuse"] += 1
        continue
    rows["loaded"] += 1
    row_kinds = set()
    for cell, v in a.items():
        if not isinstance(v, list):
            continue
        ja, js = v
        ea, es = b[cell]
        jal, eal = ja == 200, ea == 200
        if eal and not jal:
            kind = "FAIL-OPEN"
        elif jal and not eal:
            kind = "FAIL-CLOSED"
        elif ja != ea:
            kind = "OTHER"
        elif js != es:
            kind = "STATE"
        else:
            kind = "same"
        per_cell[cell][kind] += 1
        if kind != "same":
            row_kinds.add(kind)
            interesting.append({"kind": kind, "cell": cell, "expr": a["expr"], "place": a["place"], "jar": [ja, js], "emu": [ea, es]})
    rows["rows with " + ("FAIL-OPEN" if "FAIL-OPEN" in row_kinds else "difference" if row_kinds else "no difference")] += 1
with open(sys.argv[3], "w") as f:
    total = Counter()
    for c in per_cell.values():
        total.update(c)
    print("rows:", dict(rows), file=f)
    print("cells:", dict(total), file=f)
    if total["FAIL-OPEN"]:
        print("BLOCKING: fail-open cells", total["FAIL-OPEN"], file=f)
    for cell in sorted(per_cell):
        print(f"{cell:16s}", dict(per_cell[cell]), file=f)
json.dump(interesting, open(sys.argv[4], "w"), ensure_ascii=False, indent=0)
print(open(sys.argv[3]).read())
