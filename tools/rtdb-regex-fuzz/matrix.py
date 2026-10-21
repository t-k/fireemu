"""Exhaustive operator x operand and method x receiver matrices for rules expressions.

python3 matrix.py operators <out.json>
python3 matrix.py methods <out.json>
python3 matrix.py fold <out.json>

Every row is an expression for `.read` of `/t` (see probe.mjs for the data and the token);
each comes with its negation, so a difference shows in the polarity that lets a read
through. The operands cover every kind of value the language has: null and a missing
child, booleans, numbers (integer, fraction, zero, -0, a NaN and an infinity), strings
(empty, numeric), objects and arrays from the data, snapshots, `auth` and its members,
`now` and `query` members.
"""
import json
import sys

OPERANDS = [
    "null", "true", "false", "0", "5", "2.5", "-0", "'a'", "''", "'5'",
    "data.child('x').val()", "data.child('n').val()", "data.child('d').val()",
    "data.child('z').val()", "data.child('s').val()", "data.child('b').val()",
    "data.child('o').val()", "data.child('arr').val()", "data.val()", "data", "root",
    "auth", "auth.uid", "auth.token.n", "auth.token.roles", "auth.token.missing",
    "now", "query.orderByKey", "(0 / 0)", "(1 / 0)",
]
COMPARISONS = ["<", "<=", ">", ">=", "==", "!=", "===", "!=="]
ARITHMETIC = ["+", "-", "*", "/", "%"]
LOGICAL = ["&&", "||"]


def pair(expr):
    return [expr, f"!({expr})"]


def operators():
    rows = []
    for left in OPERANDS:
        for right in OPERANDS:
            for op in COMPARISONS + LOGICAL:
                rows += pair(f"{left} {op} {right}")
            for op in ARITHMETIC:
                value = f"({left} {op} {right})"
                rows += pair(f"{value} == null")
                rows += pair(f"{value} === {value}")
                rows += pair(f"({value} + '').length > 3")
    for operand in OPERANDS:
        rows += pair(f"!{operand}")
        rows += pair(f"(-{operand}) == null")
        rows += pair(f"(-{operand}) === (-{operand})")
        rows += pair(f"{operand} ? true : false")
        rows += pair(f"(true ? {operand} : null) == null")
    return rows


RECEIVERS = OPERANDS + ["data.child('s')", "data.child('o')", "data.child('x')",
                        "root.child('t')", "newData"]
CALLS = [
    "length", "contains('e')", "contains(5)", "contains(null)", "contains()",
    "contains('e', 'f')", "contains(data.child('s'))", "beginsWith('H')", "beginsWith(5)",
    "endsWith('o')", "endsWith()", "replace('l', 'L')", "replace('l', 5)", "replace(5, 'x')",
    "replace('l')", "toLowerCase()", "toUpperCase()", "toLowerCase('x')", "matches(/l/)",
    "matches('l')", "matches()", "child('s')", "child(5)", "child()", "child('a', 'b')",
    "child('o/k')", "parent()", "parent(1)", "val()", "val(1)", "exists()", "exists(1)",
    "hasChild('s')", "hasChild(5)", "hasChild()", "hasChildren()", "hasChildren(['s', 'n'])",
    "hasChildren('s')", "hasChildren([5])", "hasChildren([])", "isNumber()", "isString()",
    "isBoolean()", "getPriority()", "k", "x",
]
INDEXES = ["['s']", "[0]", "['length']", "[data.child('s').val()]", "[null]", "['k']"]


def methods():
    rows = []
    for receiver in RECEIVERS:
        target = f"({receiver})" if not receiver.replace(".", "").replace("_", "").isalnum() else receiver
        for call in CALLS:
            expr = f"{target}.{call}"
            rows += pair(expr)
            rows += pair(f"({expr}) == null")
        for index in INDEXES:
            expr = f"{target}{index}"
            rows += pair(expr)
            rows += pair(f"({expr}) == null")
    return rows


# Range endpoints at every boundary of the ASCII letter classes, for the `i` fold.
FOLD_ENDPOINTS = [" ", "!", "0", "9", "@", "A", "B", "Y", "Z", "[", "_", "`", "a", "b", "y", "z",
                  "{", "~"]
SUBJECTS = [chr(c) for c in range(0x20, 0x7F)]


def literal(c):
    return "\\" + c if c in "\\]-^[/" else c


def subject(c):
    return "\\" + c if c in "\\'" else c


def fold():
    rows = []
    for lo in FOLD_ENDPOINTS:
        for hi in FOLD_ENDPOINTS:
            if lo > hi:
                continue
            for c in SUBJECTS:
                rows += pair(f"'{subject(c)}'.matches(/^[{literal(lo)}-{literal(hi)}]$/i)")
    return rows


kind, out = sys.argv[1], sys.argv[2]
rows = {"operators": operators, "methods": methods, "fold": fold}[kind]()
seen, unique = set(), []
for row in rows:
    if row not in seen:
        seen.add(row)
        unique.append(row)
with open(out, "w", encoding="utf-8") as f:
    json.dump(unique, f, ensure_ascii=False, indent=0)
print(len(unique))
