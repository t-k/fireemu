"""Adds each expression's negation after it: python3 pair.py <in.json> <out.json>."""
import json
import sys

rows = []
for expr in json.load(open(sys.argv[1], encoding="utf-8")):
    rows += [expr, f"!({expr})"]
json.dump(list(dict.fromkeys(rows)), open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=0)
print(len(rows))
