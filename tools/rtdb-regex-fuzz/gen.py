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


# The rest of the lexer: string literals, numbers, operators, and format characters in
# every place a character is read (review r7 S20).
FORMATS = ["\u200b", "\u00ad", "\u180e", "\u2060", "\u206f", "\ufeff"]
TERMINATORS = {"LF": "\n", "CR": "\r", "CRLF": "\r\n", "LS": "\u2028", "PS": "\u2029"}
STRING_ESCAPES = {
    "esc_n": "\\n", "esc_t": "\\t", "esc_r": "\\r", "esc_b": "\\b", "esc_f": "\\f",
    "esc_v": "\\v", "esc_0": "\\0", "esc_octal": "\\101", "esc_octal_long": "\\3777",
    "esc_x": "\\x41", "esc_x_short": "\\x4", "esc_u": "\\u0041", "esc_u_short": "\\u004",
    "esc_identity": "\\q", "esc_quote": "\\'", "esc_dquote": '\\"', "esc_backslash": "\\\\",
}
NUMBERS = {"num_int": "10", "num_decimal": "1.5", "num_leading_dot": ".5", "num_exp": "1e3",
           "num_exp_signed": "1E-2", "num_hex": "0x1F", "num_octal": "017", "num_08": "08",
           "num_zero": "0"}
OPERATORS = ["==", "!=", "===", "!==", "<=", ">=", "<", ">", "&&", "||"]


def fmt():
    return rng.choice(FORMATS)


def string_piece():
    roll = rng.random()
    if roll < 0.4:
        name = rng.choice(list(STRING_ESCAPES))
        used["string " + name] += 1
        piece = STRING_ESCAPES[name]
        if rng.random() < 0.2:
            # A format character after the backslash or inside the digits.
            at = rng.randint(1, len(piece) - 1) if len(piece) > 1 else 1
            used["format after_backslash" if at == 1 else "format in_escape"] += 1
            piece = piece[:at] + fmt() + piece[at:]
        return piece
    if roll < 0.6:
        name = rng.choice(list(TERMINATORS))
        if rng.random() < 0.5:
            used["string continuation " + name] += 1
            return "\\" + TERMINATORS[name]
        used["string raw_terminator " + name] += 1
        return TERMINATORS[name]
    if roll < 0.7:
        used["format in_string_body"] += 1
        return fmt()
    return rng.choice(["a", "b", "A", " ", "\u00e9", "\u0085"])


def string_literal():
    quote = rng.choice(["'", '"'])
    used["string quote " + ("single" if quote == "'" else "double")] += 1
    body = "".join(string_piece() for _ in range(rng.randint(0, 3)))
    return f"{quote}{body}{quote}"


def number():
    name = rng.choice(list(NUMBERS))
    used[name] += 1
    text = NUMBERS[name]
    if len(text) > 1 and rng.random() < 0.2:
        at = rng.randint(1, len(text) - 1)
        used["format in_number"] += 1
        text = text[:at] + fmt() + text[at:]
    return text


def operator():
    op = rng.choice(OPERATORS)
    used["operator " + op] += 1
    if len(op) > 1 and rng.random() < 0.2:
        at = rng.randint(1, len(op) - 1)
        used["format in_operator"] += 1
        op = op[:at] + fmt() + op[at:]
    return op


# Name characters by Java class (review r8 S22): starts, parts, and characters that are
# neither there although Unicode calls some of them letters or digits.
NAME_CHARS = {
    "start Lu": "\u00c9", "start Ll": "\u00e9", "start Lt": "\u01c5", "start Lm": "\u02b0",
    "start Lo": "\u05d0", "start Nl": "\u2160", "start Sc": "\u20ac", "start Pc": "_",
    "part Mn": "\u0300", "part Mc": "\u0903", "part Nd": "\u0663", "part Pc": "\u203f",
    "part ignorable": "\u0001", "part ignorable_c1": "\u009f",
    "neither No": "\u00b2", "neither No_fraction": "\u00bd", "neither Other_Alphabetic": "\u0345",
    "neither So_letter": "\u24d0", "neither astral_letter": "\U0001d41a",
    "neither newer_than_java": "\u1c89",
}
VALUES = ["null", "data.child('x').val()", "true", "5", "-0", "'a'", "''",
          "data.child('o').val()", "data", "auth", "auth.uid", "(0 / 0)"]


def name_expression():
    name = rng.choice(list(NAME_CHARS))
    used["name " + name] += 1
    c = NAME_CHARS[name]
    where = rng.choice(["member", "variable", "inside"])
    used["name_place " + where] += 1
    return {
        "member": f"auth.token.{c}x == null",
        "variable": f"$x{c} == 'k'" if not name.startswith("start") else f"{c}x == null",
        "inside": f"auth.u{c}id == 'u1'",
    }[where]


def keyword_member():
    member = rng.choice(["length", "val", "child", "exists", "contains", "matches", "parent",
                         "true", "null", "if", "return", "typeof", "auth", "now"])
    receiver = rng.choice(["auth.token", "data.val()", "'Hello'", "data", "root.child('t')"])
    used["keyword_member " + member] += 1
    return f"{receiver}.{member} == null"


def update_operator():
    shape = rng.choice(["--5 == 5", "5--1 == 6", "5 -- 1 == 6", "5 - -1 == 6", "- -5 == 5",
                        "5 -F-1 == 6", "++5 == 5", "auth.uid-- == 1", "data.val()--1 == 6"])
    used["update " + shape.split()[0]] += 1
    return shape.replace("F", fmt())


def split_comment():
    shape = rng.choice(["/* a *F/ false && */ true", "true /F/ && false", "1 /F* 2 */ == 1",
                        "'x'.matches(/F/) || true", "/*F*/ true", "true /* x *F/ && false */"])
    used["comment_split " + shape[:6]] += 1
    return shape.replace("F", fmt())


def regex_terminator():
    name = rng.choice(list(TERMINATORS))
    t = TERMINATORS[name]
    where = rng.choice([f"/a{t}b/", f"/[{t}]/", f"/ab{t}/", f"/a\\{t}b/"])
    used["regex_terminator " + name] += 1
    return f"'ab'.matches({where})"


def relation():
    op = rng.choice(["<", "<=", ">", ">="])
    left, right = rng.choice(VALUES), rng.choice(VALUES)
    used["relation " + op] += 1
    return f"{left} {op} {right}"


def lexer_expression():
    roll = rng.random()
    if roll < 0.6:
        return rng.choices([name_expression, keyword_member, update_operator, split_comment,
                            regex_terminator, relation], weights=[4, 2, 2, 1, 1, 1])[0]()
    roll = rng.random()
    if roll < 0.35:
        return f"{string_literal()} {operator()} {string_literal()}"
    if roll < 0.55:
        used["string length"] += 1
        return f"{string_literal()}.length {operator()} {rng.randint(0, 4)}"
    if roll < 0.8:
        return f"{number()} {operator()} {number()}"
    # A format character in a name, a regex body, after a regex backslash and in flags.
    place = rng.choice(["in_name", "in_regex", "after_regex_backslash", "in_flags"])
    used["format " + place] += 1
    f = fmt()
    return {
        "in_name": f"tr{f}ue {operator()} true",
        "in_regex": f"'ab'.matches(/a{f}b/)",
        "after_regex_backslash": f"'a.'.matches(/^a\\{f}.$/)",
        "in_flags": f"'A'.matches(/^a$/{f}i)",
    }[place]


rows = []
seen = set()
while len(rows) < 2 * count:
    if rng.random() < 0.5:
        expr = lexer_expression()
        if expr in seen:
            continue
        seen.add(expr)
        rows.append(expr)
        rows.append(f"!({expr})")
        continue
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
