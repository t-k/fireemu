"""Random matches() rows for the differential fuzz against the official emulator.

python3 gen.py <seed> <count> <out.json> [edges]
Each generated (subject, pattern, flags) gives two expressions: the match and its negation.
`edges` adds grammar edges (operators that start an alternative, empty groups, stray braces).
"""
import json
import random
import sys

seed, count, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
EDGES = len(sys.argv) > 4 and sys.argv[4] == "edges"
rng = random.Random(seed)

ASCII_LETTERS = list("abkisyzABKISYZ")
DIGITS = list("019")
PUNCT = list("!-@_`{~ .")
NON_ASCII = ["é", "É", "ä", "Ä", "K", "ſ", "ı", "İ",
             "ß", "ẞ", "ω", "Ω", "Ω", "å", "Å", "ǅ",
             "ǆ", "Ǆ", "ａ", "Ａ", "ｚ", "Ｚ", "＄", "\U0001f600"]
ESCAPES = ["\\w", "\\d", "\\s", "\\S", "\\W", "\\D", "\\.", "\\-", "\\]", "\\\\", "\\[", "\\^", "\\$", "\\*"]
SUBJECT_POOL = ASCII_LETTERS + DIGITS + PUNCT + NON_ASCII + ["[", "]", "^", "$", "\\", "'"]


def char(non_ascii_weight):
    roll = rng.random()
    if roll < non_ascii_weight:
        return rng.choice(NON_ASCII)
    if roll < non_ascii_weight + 0.6:
        return rng.choice(ASCII_LETTERS)
    if roll < non_ascii_weight + 0.75:
        return rng.choice(DIGITS)
    return rng.choice(["!", "-", "@", "_", "`", "~", " "])


def class_item(fold, non_ascii_weight):
    roll = rng.random()
    if roll < 0.15:
        return rng.choice(["\\w", "\\d", "\\W", "\\D", "\\-", "\\]", "\\\\", "\\\\a", "\\\\]"])
    if roll < 0.55:
        lo, hi = char(non_ascii_weight), char(non_ascii_weight)
        # The official emulator stalls on wide ranges under i beyond ASCII (review S14).
        if fold and (ord(lo) > 127 or ord(hi) > 127) and abs(ord(hi) - ord(lo)) > 200:
            return lo
        if lo in "-]\\[":
            lo = "\\" + lo
        if hi in "-]\\[":
            hi = "\\" + hi
        return f"{lo}-{hi}"
    c = char(non_ascii_weight)
    return "\\" + c if c in "-]\\[" else c


def atom(fold, depth, non_ascii_weight):
    roll = rng.random()
    if roll < 0.45:
        c = char(non_ascii_weight)
        return "\\" + c if c in ".-" and rng.random() < 0.5 else c
    if roll < 0.6:
        return rng.choice(ESCAPES)
    if roll < 0.85:
        neg = "^" if rng.random() < 0.3 else ""
        items = "".join(class_item(fold, non_ascii_weight) for _ in range(rng.randint(1, 3)))
        return f"[{neg}{items}]"
    if roll < 0.92:
        return "."
    if depth < 2:
        inner = "|".join(seq(fold, depth + 1, non_ascii_weight) for _ in range(rng.randint(1, 2)))
        return f"({inner})"
    return char(non_ascii_weight)


GRAMMAR_EDGES = ["|", ")", "*", "+", "?", "{", "{2}", "}", "()", "**", "\\\\", "{1,", "{,2}"]


def seq(fold, depth, non_ascii_weight):
    parts = []
    if EDGES and rng.random() < 0.25:
        parts.append(rng.choice(GRAMMAR_EDGES))
    for _ in range(rng.randint(0 if EDGES else 1, 3)):
        a = atom(fold, depth, non_ascii_weight)
        if rng.random() < 0.2:
            a += rng.choice(["+", "*", "?", "{2}", "{1,2}"])
        parts.append(a)
    return "".join(parts)


def pattern(fold):
    non_ascii_weight = rng.choice([0.0, 0.1, 0.3])
    body = seq(fold, 0, non_ascii_weight)
    if rng.random() < 0.6:
        body = "^" + body
    if rng.random() < 0.6:
        body = body + "$"
    return body


def subject():
    return "".join(rng.choice(SUBJECT_POOL) for _ in range(rng.randint(0, 3)))


def js_string(text):
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


rows = []
seen = set()
while len(rows) < 2 * count:
    flags = "i" if rng.random() < 0.5 else ""
    pat = pattern(flags == "i")
    if "/" in pat or "\n" in pat:
        continue
    expr = f"{js_string(subject())}.matches(/{pat}/{flags})"
    if expr in seen:
        continue
    seen.add(expr)
    rows.append(expr)
    rows.append(f"!({expr})")
with open(out, "w", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False, indent=0)
print(len(rows))
