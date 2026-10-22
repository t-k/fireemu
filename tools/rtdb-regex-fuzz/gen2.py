"""A second, independent generator: the one the r8 review wrote without reference to gen.py.

python3 gen2.py <seed> <count> <out.json> [family]
Families: num, str, ident, member, comment, nest, mix (default: all). Each template marks
token gaps, which become nothing, a space, a comment or a character from FMT/ODD; characters
may also be inserted anywhere (inside tokens, string bodies and regex literals) with a small
probability. round.sh runs it on every round next to gen.py.
"""
import json
import random
import sys

seed, count, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
FAMILY = sys.argv[4] if len(sys.argv) > 4 else "all"
R = random.Random(seed)
GAP = ""
# Java Cf in the BMP (a selection), BOM, controls, other separators, astral Cf.
FMT = ["­", "؀", "؜", "۝", "܏", "࢐", "࣢", "᠎", "​",
       "‌", "‍", "‎", "‏", "‪", "‮", "⁠", "⁤", "⁦",
       "⁯", "￹", "￻"]
ODD = ["﻿", "\u0001", "\u001f", "\u007f", "\u0085", "\u009f", " ", " ", "　",
       "\u000b", "\u000c", " ", "\U000e0001", "\U0001bca0", "\U0001d173", " ", "\n",
       "\r", "\t"]
COMMENTS = ["/**/", "/* c */", "/*'*/", "/*/*/", "/***/", "//c\n", "//\n", "/*\n*/", "//c ",
            "//c\r", "/* a // b */", "/*\"*/"]


def gap_fill():
    r = R.random()
    if r < 0.45:
        return ""
    if r < 0.6:
        return " "
    if r < 0.75:
        return R.choice(COMMENTS)
    if r < 0.93:
        return R.choice(FMT)
    return R.choice(ODD)


def finish(t, p_inside=0.04):
    out = []
    for ch in t:
        if ch == GAP:
            out.append(gap_fill())
            continue
        out.append(ch)
        if R.random() < p_inside:
            out.append(R.choice(FMT) if R.random() < 0.8 else R.choice(ODD + COMMENTS))
    return "".join(out)


G = GAP
# ---- numbers
NUMS = ["0", "5", "-0", "0.0", "5.", ".5", "5.0", "05", "005", "0x5", "0X5", "0xF", "0xf", "0x",
        "0xg", "0x1e3", "1e3", "1E3", "1e+3", "1e-3", "1e", "1e+", "1.e3", ".5e1", "50e-1", "1e400",
        "-1e400", "1e-400", "1e308", "017", "018", "019", "08", "09", "08.5", "017.5", "00", "00.5",
        "0.5", "1_0", "0b1", "0o7", "1n", "9007199254740993", "0xFFFFFFFFFFFFFFFFFF",
        "077777777777777777777777", "1.5e3.5", "1..5", "5..", "0x1.5", ".e3", "Infinity", "NaN",
        "1.7976931348623157e308", "4.9e-324", "0e0", "0.", "5e0", "1/0", "-1/0", "0/0", "08e1",
        "09.5", "0.08", "1e08", "0x00", "000", "007", "0777", "0400", "1 .5", "- 5", "--5", "+5",
        "- -5", "5 .toString", "0xA - 0xa", "1e1e1"]
OPS = ["==", "===", "!=", "!==", "<", "<=", ">", ">="]


def gen_num():
    a, b = R.choice(NUMS), R.choice(NUMS)
    shape = R.random()
    if shape < 0.5:
        return f"{a}{G}{R.choice(OPS)}{G}{b}"
    if shape < 0.7:
        return f"data.child('n').val(){G}{R.choice(OPS)}{G}{a}"
    if shape < 0.85:
        return f"{a}{G}{R.choice(['+', '-', '*', '/', '%'])}{G}{b}{G}{R.choice(OPS)}{G}{R.choice(NUMS)}"
    return f"({a}){G}{R.choice(OPS)}{G}({b})"


# ---- strings
STRS = ["'a'", '"a"', "''", '""', "'\\''", '"\\""', "'\"'", '"\'"', "'\\\"'", '"\\\'"', "'a\"",
        '"a\'', "'\\\\'", '"\\\\"', "'\\\\\\''", "'//'", "'/*'", "'*/'", "'/**/'", "\"//x\"",
        "'Hello'", '"Hello"', "'Hel' + \"lo\"", "'\\x48ello'", "'\\u0048ello'", "'\\110ello'",
        "'H\\ello'", "'\\'Hello'", "'a\\\\'+'b'", "'\\0'", "'\\8'", "'\\9'", "'\\08'", "'\\400'",
        "'\\u{48}'", "'\\x4'", "'\\u004'", "'abc", '"abc', "'it''s'", "'a' 'b'"]
SMETH = [".length", ".toLowerCase()", ".toUpperCase()", ".contains('a')", ".beginsWith('H')",
         ".endsWith('o')", ".replace('l', 'L')", ".matches(/^H/)", ".matches(/'/)",
         ".matches(/\"/)", ".matches(/\\//)", ".matches(/\\/\\*/)", ".matches(/a\\/\\/b/)"]


def gen_str():
    a, b = R.choice(STRS), R.choice(STRS)
    shape = R.random()
    if shape < 0.35:
        return f"{a}{G}{R.choice(['==', '!=', '===', '<', '>'])}{G}{b}"
    if shape < 0.6:
        return f"{a}{G}{R.choice(SMETH)}{G}{R.choice(['==', '!='])}{G}{R.choice(STRS + ['true', '5', '1', '0', '2', '3', '4'])}"
    if shape < 0.8:
        return f"data.child({a}).val(){G}=={G}{b}"
    return f"data.child('s').val(){G}{R.choice(['==', '!='])}{G}{a}"


# ---- identifiers in member positions and names
IDCH = ["e", "é", "ñ", "中", "ǅ", "ʰ", "²", "½", "Ⅻ", "ⅰ", "ⓐ", "Ⓐ", "̃", "ְ",
        "ः", "€", "¢", "‿", "\u0001", "٣", "１", "ａ", "\U0001d41a", "\U0001d7ce", "ª", "º",
        "µ", "ß", "ﬁ", "İ", "ı", "ͅ", "ᢅ", "℘", "℮", "゛", "々",
        "〇", "٠", "_", "$", "‌", "‍", "·", "·", "፩", "᧚"]


def ident():
    n = R.randint(1, 3)
    s = "".join(R.choice(IDCH + ["x"] * 4) for _ in range(n))
    return s


def gen_ident():
    shape = R.random()
    x = ident()
    if shape < 0.35:
        return f"auth.token.{x}{G}{R.choice(['==', '!='])}{G}null"
    if shape < 0.5:
        rhs = R.choice(["null", "'z'"])
        return f"auth.token.a{x}{G}{R.choice(['==', '!='])}{G}{rhs}"
    if shape < 0.6:
        return f"auth.token[{G}'{x}'{G}]{G}=={G}null"
    if shape < 0.7:
        return f"{x}{G}=={G}null"
    if shape < 0.8:
        return f"data.child('{x}').exists(){G}||{G}true"
    if shape < 0.9:
        return f"auth.u{x}id == 'u1'"
    return f"$ui{x}d == 'u1'"


# ---- keywords and members
MEMB = ["true", "false", "null", "if", "in", "new", "this", "typeof", "var", "function", "class",
        "let", "yield", "undefined", "NaN", "Infinity", "length", "val", "exists", "child",
        "uid", "provider", "token", "sub", "aud", "email", "firebase", "auth", "data", "root",
        "now", "newData", "instanceof", "delete", "void", "do", "for", "while", "return", "else",
        "case", "default", "with", "try", "catch", "throw", "const", "enum", "export", "import",
        "super", "debugger", "switch", "break", "continue", "finally", "package", "static",
        "abstract", "int", "goto", "native", "matches", "contains", "hasChild", "getPriority",
        "isString", "constructor", "__proto__", "prototype", "toString", "valueOf", "hasOwnProperty"]
OBJS = ["auth", "auth.token", "auth.token.firebase", "data", "data.child('s')", "data.child('s').val()",
        "data.val()", "root", "root.child('t')", "now", "newData", "auth.uid", "'Hello'", "5"]


def gen_member():
    o, m = R.choice(OBJS), R.choice(MEMB)
    shape = R.random()
    if shape < 0.4:
        return f"{o}{G}.{G}{m}{G}{R.choice(['==', '!='])}{G}null"
    if shape < 0.55:
        return f"{o}{G}.{G}{m}{G}({G}){G}{R.choice(['==', '!='])}{G}null"
    if shape < 0.7:
        return f"{o}{G}[{G}'{m}'{G}]{G}{R.choice(['==', '!='])}{G}null"
    if shape < 0.8:
        return f"{m}{G}{R.choice(['==', '!='])}{G}null"
    if shape < 0.9:
        return f"{o}.{m}.{R.choice(MEMB)}{G}=={G}null"
    return f"{o}{G}.{G}{m}{G}"


# ---- comments in every position (comments placed by GAP and by explicit edits)
BASE = ["auth.uid == 'u1'", "data.child('s').val() == 'Hello'", "data.child('n').val() > 4",
        "'a/*b*/c'.length == 7", "'a//b'.length == 4", "'Hello'.matches(/l\\/*l/)",
        "'l/*l'.matches(/^l\\/\\*l$/)", "auth != null && auth.uid.length == 2",
        "root.child('t').child('s').val().beginsWith('He')", "now > 0", "1 / 2 == 0.5",
        "!(auth == null)", "(auth.uid == 'u1') == true", "auth.token.sub == auth.uid"]


def gen_comment():
    b = R.choice(BASE)
    # put a GAP between every pair of characters with some probability, outside quotes too
    out = []
    for ch in b:
        out.append(ch)
        if R.random() < 0.25:
            out.append(GAP)
    s = "".join(out)
    r = R.random()
    if r < 0.15:
        s = s + R.choice(["//", "// x", "/*", "/* x", "/", "*/", "/**/", "//\n"])
    elif r < 0.3:
        s = R.choice(["/**/", "//\n", "/*\n*/", "/*"]) + s
    return s


# ---- nesting of () and []
def gen_nest():
    b = R.choice(BASE + ["auth['uid'] == 'u1'", "data['val']() == null", "data.child(('s')).val() == 'Hello'"])
    d = R.randint(1, 6)
    opens = "".join(R.choice(["(", "(", G + "("]) for _ in range(d))
    closes = "".join(R.choice([")", ")", G + ")"]) for _ in range(d))
    r = R.random()
    if r < 0.1:
        closes = closes[:-1]
    elif r < 0.2:
        closes = closes + ")"
    elif r < 0.27:
        closes = closes.replace(")", "]", 1)
    elif r < 0.33:
        opens = opens.replace("(", "[", 1)
    s = f"{opens}{b}{closes}"
    if R.random() < 0.3:
        s = s.replace("auth.uid", f"auth{G}[{G}({G}'uid'{G}){G}]", 1)
    if R.random() < 0.2:
        s = s.replace("'s'", f"[{G}'s'{G}][0]", 1)
    return s


FAMS = {"num": gen_num, "str": gen_str, "ident": gen_ident, "member": gen_member,
        "comment": gen_comment, "nest": gen_nest}
seen = set()
rows = []
tries = 0
while len(rows) < count and tries < count * 20:
    tries += 1
    fam = R.choice(list(FAMS)) if FAMILY == "all" else FAMILY
    e = finish(FAMS[fam](), p_inside=0.03 if fam != "ident" else 0.06)
    if e in seen:
        continue
    seen.add(e)
    rows.append(e)
json.dump(rows, open(out, "w"), ensure_ascii=False, indent=0)
print(len(rows))
