"""Builds the committed corpus from the fuzz rounds: every hand-written row, the generated rows
whose pattern has a grammar edge (class backslash, comment, leading operator, empty
alternative), and seeded samples of the fail-closed and agreeing rows. Pairs stay together.

python3 select.py <out.json> <named,...> <seed,...>
Reads <name>-jar.json/<name>-emu.json and jar-<seed>.json/emu-<seed>.json from the current directory.
"""
import json
import random
import re
import sys

rng = random.Random(6)
named = sys.argv[2].split(",") if len(sys.argv) > 2 else []
seeds = [int(n) for n in sys.argv[3].split(",")] if len(sys.argv) > 3 else []


def load(jar, emu):
    j = json.load(open(jar, encoding="utf-8"))
    e = json.load(open(emu, encoding="utf-8"))
    return list(zip(j, e))


def outcome(r):
    return "load" if r["load"] != 200 else r["read"]


def row(j, e):
    out = {"expr": j["expr"], "query": "", "load": j["load"], "error": j["error"], "read": j["read"]}
    if outcome(j) != outcome(e):
        assert e["load"] == 200 and e["read"] == 401 and j["read"] == 200, j["expr"]
        out["fireemu"] = "denies"
    return out


chosen, seen = [], set()


def take(pairs):
    for j, e in pairs:
        if j["expr"] not in seen:
            seen.add(j["expr"])
            chosen.append(row(j, e))


for n in named:
    take(load(f"{n}-jar.json", f"{n}-emu.json"))
EDGE = re.compile(r"\[[^\]]*\\\\|matches\(//|matches\(/[{+?*]|\(\||\|\||\|\)|/\^?\||\(\.\*|\{\d")
edge, closed, same = [], [], []
for n in seeds:
    pairs = load(f"jar-{n}.json", f"emu-{n}.json")
    for k in range(0, len(pairs), 2):
        pair = pairs[k:k + 2]
        if EDGE.search(pair[0][0]["expr"]):
            edge.append(pair)
        elif any(outcome(j) != outcome(e) for j, e in pair):
            closed.append(pair)
        else:
            same.append(pair)
for group, size in [(edge, 120), (closed, 80), (same, 150)]:
    for pair in rng.sample(group, min(size, len(group))):
        take(pair)
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write(json.dumps(chosen, ensure_ascii=False, indent=1) + "\n")
print(len(chosen), "rows,", sum("fireemu" in r for r in chosen), "denied here")
