"""Random matches() rows for the differential fuzz against the official emulator.

python3 gen.py <seed> <count> <out.json> [edges]
Each generated (subject, pattern, flags) gives two expressions: the match and its negation.
`edges` adds grammar edges (operators that start an alternative, empty groups, stray braces).
Next to <out.json>, <out>.coverage.json counts how often each grammar production was
generated; check_coverage.py fails a round where one falls below its minimum.
"""
import json
import random
import sys
from collections import Counter

seed, count, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
EDGES = len(sys.argv) > 4 and sys.argv[4] == "edges"
rng = random.Random(seed)
used = Counter()

ASCII_LETTERS = list("abkisyzABKISYZ")
DIGITS = list("019")
NON_ASCII = ["é", "É", "ä", "Ä", "K", "ſ", "ı", "İ",
             "ß", "ẞ", "ω", "Ω", "Ω", "å", "Å", "ǅ",
             "ǆ", "Ǆ", "ａ", "Ａ", "ｚ", "Ｚ", "＄", "\U0001f600"]
ESCAPES = ["\\w", "\\d", "\\s", "\\S", "\\W", "\\D", "\\.", "\\-", "\\]", "\\\\", "\\[", "\\^",
           "\\$", "\\*", "\\+", "\\?", "\\(", "\\)", "\\|", "\\{"]
CLASS_ESCAPES = ["\\w", "\\d", "\\s", "\\W", "\\D", "\\-", "\\]", "\\\\", "\\\\a", "\\\\]", "\\^"]
SUBJECT_POOL = ASCII_LETTERS + DIGITS + list("!-@_`{~ .|*+?") + NON_ASCII + ["[", "]", "^", "$", "\\", "'"]
# Characters between tokens of the expression: ASCII and Unicode white space, format
# characters, U+0085 (a name character there), line terminators.
SPACES = [" ", "\t", "\u000b", "\u000c", " ", " ", " ", " ", "　",
          "﻿", "᠎", "​", "­", "⁠", "\u0085", "\n", "\r", " "]
QUANTIFIERS = {
    "q_star": "*", "q_plus": "+", "q_opt": "?", "q_count": "{2}", "q_count_range": "{1,2}",
    "q_count_open": "{1,}",
}
LAZY_LOOKING = {"q_plus_opt": "+?", "q_star_opt": "*?", "q_opt_opt": "??", "q_count_opt": "{2}?",
                "q_range_opt": "{0,2}?"}
CHAINS = {"q_star_star": "**", "q_plus_star": "+*", "q_count_count": "{2}{2}", "q_opt_plus": "?+",
          "q_count_plus": "{1,2}+"}


def char(non_ascii_weight):
    roll = rng.random()
    if roll < non_ascii_weight:
        used["literal_non_ascii"] += 1
        return rng.choice(NON_ASCII)
    if roll < non_ascii_weight + 0.6:
        used["literal_letter"] += 1
        return rng.choice(ASCII_LETTERS)
    if roll < non_ascii_weight + 0.75:
        used["literal_digit"] += 1
        return rng.choice(DIGITS)
    used["literal_punctuation"] += 1
    return rng.choice(["!", "-", "@", "_", "`", "~", " "])


def class_item(fold, non_ascii_weight):
    roll = rng.random()
    if roll < 0.2:
        item = rng.choice(CLASS_ESCAPES)
        used["class_escape " + item] += 1
        return item
    if roll < 0.6:
        lo, hi = char(non_ascii_weight), char(non_ascii_weight)
        # The official emulator stalls on wide ranges under i beyond ASCII (review S14).
        if fold and (ord(lo) > 127 or ord(hi) > 127) and abs(ord(hi) - ord(lo)) > 200:
            return lo
        used["class_range"] += 1
        if lo in "-]\\[":
            lo = "\\" + lo
        if hi in "-]\\[":
            hi = "\\" + hi
        return f"{lo}-{hi}"
    c = char(non_ascii_weight)
    return "\\" + c if c in "-]\\[" else c


def atom(fold, depth, non_ascii_weight):
    roll = rng.random()
    if roll < 0.4:
        c = char(non_ascii_weight)
        return "\\" + c if c in ".-" and rng.random() < 0.5 else c
    if roll < 0.55:
        item = rng.choice(ESCAPES)
        used["escape " + item] += 1
        return item
    if roll < 0.78:
        neg = "^" if rng.random() < 0.3 else ""
        used["class_negated" if neg else "class"] += 1
        if rng.random() < 0.05:
            used["class_first_bracket"] += 1
            return f"[{neg}]a]"
        items = "".join(class_item(fold, non_ascii_weight) for _ in range(rng.randint(1, 3)))
        return f"[{neg}{items}]"
    if roll < 0.86:
        used["dot"] += 1
        return "."
    if roll < 0.9:
        used["empty_group"] += 1
        return "()"
    if depth < 2:
        used["group"] += 1
        inner = "|".join(seq(fold, depth + 1, non_ascii_weight) for _ in range(rng.randint(1, 3)))
        if "|" in inner:
            used["group_alternation"] += 1
        return f"({inner})"
    return char(non_ascii_weight)


def quantifier():
    roll = rng.random()
    table = QUANTIFIERS if roll < 0.6 else LAZY_LOOKING if roll < 0.85 else CHAINS
    name = rng.choice(list(table))
    used[name] += 1
    return table[name]


GRAMMAR_EDGES = ["|", ")", "*", "+", "?", "{", "{2}", "}", "()", "**", "\\\\", "{1,", "{,2}"]


def seq(fold, depth, non_ascii_weight):
    parts = []
    if EDGES and rng.random() < 0.25:
        edge = rng.choice(GRAMMAR_EDGES)
        used["edge " + edge] += 1
        parts.append(edge)
    for _ in range(rng.randint(0 if EDGES else 1, 3)):
        a = atom(fold, depth, non_ascii_weight)
        if rng.random() < 0.3:
            a += quantifier()
        parts.append(a)
    return "".join(parts)


def pattern(fold):
    non_ascii_weight = rng.choice([0.0, 0.1, 0.3])
    # Top-level alternatives: the official emulator writes its `.*` around them as text.
    alternatives = [seq(fold, 0, non_ascii_weight) for _ in range(rng.choice([1, 1, 2, 3]))]
    body = "|".join(alternatives)
    start, end = rng.random() < 0.5, rng.random() < 0.5
    if len(alternatives) > 1:
        used["top_alternation " + {(False, False): "unanchored", (True, False): "start_anchored",
                                   (False, True): "end_anchored", (True, True): "anchored"}[(start, end)]] += 1
    if start:
        body = "^" + body
    if end:
        body = body + "$"
    return body


def subject():
    if rng.random() < 0.1:
        used["subject_empty"] += 1
        return ""
    return "".join(rng.choice(SUBJECT_POOL) for _ in range(rng.randint(1, 3)))


def js_string(text):
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def spaced(expr):
    """The expression with a white-space character or a comment between some of its tokens."""
    roll = rng.random()
    if roll < 0.35:
        space = rng.choice(SPACES)
        used["space U+%04X" % ord(space)] += 1
        return expr.replace(".matches(", space + ".matches(" if rng.random() < 0.5 else ".matches(" + space, 1)
    if roll < 0.45:
        comment = rng.choice(["/* c */", "/**/", "// c\n", "// c ", "/* a\nb */"])
        used["comment " + comment.split()[0]] += 1
        return expr.replace(".matches(", ".matches(" + comment, 1)
    return expr


rows = []
seen = set()
while len(rows) < 2 * count:
    flags = "i" if rng.random() < 0.5 else ""
    pat = pattern(flags == "i")
    if "/" in pat or "\n" in pat:
        continue
    used["flag_i" if flags else "flag_none"] += 1
    expr = spaced(f"{js_string(subject())}.matches(/{pat}/{flags})")
    if expr in seen:
        continue
    seen.add(expr)
    rows.append(expr)
    rows.append(f"!({expr})")
with open(out, "w", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False, indent=0)
with open(out.removesuffix(".json") + ".coverage.json", "w", encoding="utf-8") as f:
    json.dump(dict(sorted(used.items())), f, ensure_ascii=False, indent=1)
print(len(rows))
