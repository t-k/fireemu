"""Fails when a round generated some grammar production fewer than `minimum` times.

python3 check_coverage.py <corpus.coverage.json> [minimum] [edges]
The productions are those fireemu's rules and regular-expression readers accept: every escape
and class form, plain, lazy-looking and chained quantifiers, top-level alternatives with and
without anchors, white space and comments between tokens, both flags and the empty subject.
"""
import json
import sys

import gen_productions

counts = json.load(open(sys.argv[1], encoding="utf-8"))
minimum = int(sys.argv[2]) if len(sys.argv) > 2 else 5
required = gen_productions.required(edges=len(sys.argv) > 3 and sys.argv[3] == "edges")
short = {name: counts.get(name, 0) for name in required if counts.get(name, 0) < minimum}
if short:
    print(f"coverage below {minimum}: {short}")
    sys.exit(1)
print(f"coverage ok: {len(required)} productions, each at least {minimum} times")
