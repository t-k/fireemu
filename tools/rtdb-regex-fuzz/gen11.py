"""The fifth independent generator (the r11 review wrote it): write-side rules (.write,
.validate, child .validate, child .write, parent .write) judged over every write kind. gen.py,
gen2.py, gen9, gen9t and gen10 judge expressions through one PUT only.

python3 -I gen11.py <seed> <count> <out.json> <coverage.json>

Each entry is {"expr", "place"}, and a control also has "bodies", the body each named
operation sends. The runner (write_probe.mjs) judges each entry as E and !(E) in its
placement over every write operation, signed in and anonymous. The corpus starts with
CONTROLS, rows that failed open before review r11's fixes, with bodies fixed so that each
shows its class whatever the seed. Productions are counted so that each is shown used
(coverage)."""
import json
import random
import sys
from collections import Counter

seed, count, out, cov_out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
rng = random.Random(seed)
cov = Counter()

PATHS = ["'a'", "'b'", "'x'", "'s'", "'q/r'", "'.priority'", "'a/.priority'", "''", "'zz'", "'o/a'", "'p/m'", "$k", "'a/b'"]
SNAP_BASE = ["newData", "data", "root.child('t/o')", "root.child('t')", "newData.parent()", "data.parent()", "root",
             "newData.parent().parent()", "newData.child($k)", "newData.parent().child($k)"]
LIT = ["1", "2", "5", "7", "9", "0", "-1", "1.5", "'Hello'", "'w'", "'Hi'", "''", "null", "true", "false", "now", "$k", "auth.uid", "auth.token.n", "'o'", "'p'"]
PLACES = ["W", "V", "VC", "WC", "WT", "VA", "VO"]


def pick(name, options):
    cov[name] += 1
    return rng.choice(options)


def snap(d):
    r = rng.random()
    if d <= 0 or r < 0.4:
        return pick("snap.base", SNAP_BASE)
    if r < 0.85:
        return f"{snap(d - 1)}.child({pick('snap.path', PATHS)})"
    return f"{snap(d - 1)}.parent()"


def value(d):
    r = rng.random()
    if d <= 0 or r < 0.3:
        return pick("value.lit", LIT)
    if r < 0.6:
        cov["value.val"] += 1
        return f"{snap(d - 1)}.val()"
    if r < 0.7:
        cov["value.prio"] += 1
        return f"{snap(d - 1)}.getPriority()"
    if r < 0.8:
        op = pick("value.arith", ["+", "-", "*"])
        return f"({value(d - 1)} {op} {value(d - 1)})"
    if r < 0.88:
        cov["value.ternary"] += 1
        return f"({boolean(d - 1)} ? {value(d - 1)} : {value(d - 1)})"
    if r < 0.94:
        m = pick("value.strmethod", ["length", "toLowerCase()", "toUpperCase()", "replace('l', 'L')"])
        return f"({snap(d - 1)}.val() + '').{m}"
    cov["value.numkey"] += 1
    return f"{snap(d - 1)}.child('a').val()"


def boolean(d):
    r = rng.random()
    if d <= 0 or r < 0.3:
        m = pick("bool.snapmethod", ["exists()", "hasChildren()", "isNumber()", "isString()", "isBoolean()", "hasChild('a')",
                                      "hasChild('x')", "hasChild('.priority')", "hasChildren(['a'])", "hasChildren(['a', 'b'])",
                                      "hasChildren(['x'])", "hasChildren([])", "hasChildren(['a', 'zz'])", "hasChild('')"])
        return f"{snap(max(d - 1, 0))}.{m}"
    if r < 0.6:
        op = pick("bool.cmp", ["==", "!=", "<", ">", "<=", ">=", "===", "!=="])
        return f"{value(d - 1)} {op} {value(d - 1)}"
    if r < 0.75:
        op = pick("bool.logic", ["&&", "||"])
        return f"({boolean(d - 1)} {op} {boolean(d - 1)})"
    if r < 0.82:
        cov["bool.not"] += 1
        return f"!{boolean(d - 1)}"
    if r < 0.88:
        cov["bool.ternary"] += 1
        return f"({boolean(d - 1)} ? {boolean(d - 1)} : {boolean(d - 1)})"
    if r < 0.94:
        m = pick("bool.strmethod", ["contains('l')", "beginsWith('H')", "endsWith('o')", "matches(/^H/)", "matches(/^[0-9]+$/)"])
        return f"({snap(d - 1)}.val() + '').{m}"
    cov["bool.auth"] += 1
    return pick("bool.authform", ["auth != null", "auth == null", "auth.uid == $k", "auth.uid == 'u1'", "$k == 'o'", "$k.length == 20", "$k.beginsWith('-')"])


# Each control failed open on fireemu before review r11's fixes, in the operation its bodies
# name: an onDisconnect merge judged as one update (M39), and a priority written through its
# path compared as a number (M40). The last is a row both servers allow everywhere.
CONTROLS = [
    {"expr": "newData.child('a').val() == newData.child('b').val()", "place": "V",
     "bodies": {"od_merge": {"a": 5, "b": 5}, "ws_merge": {"a": 5, "b": 5}, "patch_o": {"a": 5, "b": 5}}},
    {"expr": "newData.parent().child('o/a').val() == newData.parent().child('p/m').val()", "place": "V",
     "bodies": {"od_merge_t": {"o/a": 5, "p/m": 5}, "ws_merge_t": {"o/a": 5, "p/m": 5}, "patch_t": {"o/a": 5, "p/m": 5}}},
    {"expr": "newData.getPriority() < 6", "place": "V", "bodies": {"prio": 5}},
    {"expr": "true", "place": "W", "bodies": {}},
]
rows = list(CONTROLS)
for _ in range(count):
    place = pick("place", PLACES)
    rows.append({"expr": boolean(rng.choice([1, 2, 2, 3])), "place": place})
json.dump(rows, open(out, "w"), ensure_ascii=False, indent=0)
json.dump(dict(sorted(cov.items())), open(cov_out, "w"), indent=1)
print(len(rows), "entries;", len(cov), "productions; min use", min(cov.values()))
