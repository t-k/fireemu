"""Compares the official emulator's and fireemu's answers for the same expressions.

python3 compare.py <jar.json> <fireemu.json> <report.txt> [<interesting.json>]
A row blocks when fireemu allows (read 200) where the official emulator denies (401) or
refuses the rules (400). Other differences are fail-closed and are listed.
"""
import json
import sys

jar = json.load(open(sys.argv[1], encoding="utf-8"))
emu = json.load(open(sys.argv[2], encoding="utf-8"))
assert all(a["expr"] == b["expr"] for a, b in zip(jar, emu))


def outcome(row):
    return "load400" if row["load"] != 200 else str(row["read"])


blocking, closed, same = [], [], 0
interesting = []
for j, e in zip(jar, emu):
    a, b = outcome(j), outcome(e)
    if a == b:
        same += 1
        continue
    line = f"{j['expr']!r}: jar {a}, fireemu {b}"
    if b == "200":
        blocking.append(line)
    else:
        closed.append(line)
    interesting.append({**j, "fireemu": b})
with open(sys.argv[3], "w", encoding="utf-8") as f:
    f.write(f"rows {len(jar)}, same {same}, fail-closed {len(closed)}, BLOCKING {len(blocking)}\n")
    for line in blocking:
        f.write(f"BLOCKING {line}\n")
    for line in closed:
        f.write(f"closed {line}\n")
if len(sys.argv) > 4:
    with open(sys.argv[4], "w", encoding="utf-8") as f:
        json.dump(interesting, f, ensure_ascii=False, indent=1)
print(f"rows {len(jar)}, same {same}, fail-closed {len(closed)}, BLOCKING {len(blocking)}")
