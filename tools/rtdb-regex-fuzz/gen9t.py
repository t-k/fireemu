"""The r9 review's type matrices (the fourth generator): ternaries and query members.
python3 -I gen9t.py ternary <out.json>: (c ? A : B) in every operand position, for A, B over the
  value types (string, number, boolean, null, snapshot, auth, auth member, val(), $k, query member).
python3 -I gen9t.py query <out.json>: every query member against every operand kind, with every
  comparison, both sides."""
import json, sys
ATOMS = ["'a'", "1", "true", "null", "root", "auth", "auth.uid", "data.val()", "$k",
         "query.orderByChild", "query.startAt", "query.limitToFirst", "data.child('k').val()"]
COND = "auth != null"
CTX = ["{x}.length == 1", "{x}.length == null", "{x}.contains('a')", "root.child({x}).exists()",
       "'a'.replace('a', {x}) == 'a'", "{x} == 1", "{x} == 'a'", "{x} == null", "{x} < 1", "{x} > 'a'",
       "({x} + 1) == 2", "({x} - 1) == 0", "!{x}", "{x} && true", "{x} ? true : false",
       "{x}.val() == 'v'", "{x}.matches(/a/)", "'a'.contains({x})", "{x}.uid == 'u1'",
       "{x}['uid'] == 'u1'", "{x}.exists()", "{x} === {x}", "{x} == auth", "{x}.toLowerCase() == 'a'"]
def ternary():
    rows = []
    for a in ATOMS:
        for b in ATOMS:
            x = f"({COND} ? {a} : {b})"
            for c in CTX:
                rows.append(c.replace("{x}", x))
    return rows
QM = ["orderByKey", "orderByValue", "orderByPriority", "orderByChild", "startAt", "endAt", "equalTo",
      "limitToFirst", "limitToLast"]
OPS = ["==", "!=", "===", "!==", "<", ">="]
OPERANDS = ["'a'", "'k'", "1", "true", "null", "$k", "auth.uid", "data.val()", "data.child('k').val()",
            "('a' + 'b')", "(auth != null ? 'a' : 'b')", "query.orderByChild", "query.startAt", "now"]
def query():
    rows = []
    for m in QM:
        for op in OPS:
            for o in OPERANDS:
                rows.append(f"query.{m} {op} {o}")
                rows.append(f"{o} {op} query.{m}")
        rows += [f"query.{m}", f"query.{m}.length == 1", f"query.{m}.contains('a')", f"query.{m} + 1 == 2"]
    return rows
kind, out = sys.argv[1], sys.argv[2]
rows = list(dict.fromkeys({"ternary": ternary, "query": query}[kind]()))
json.dump(rows, open(out, "w"), ensure_ascii=False, indent=0)
print(len(rows))
