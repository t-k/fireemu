"""The r9 review's generator (the third generator; written for that review independently of gen.py and gen2.py).

python3 -I gen9.py <seed> <count> <out.json>

A typed recursive grammar for rules expressions. Each production has a name, and the generator
counts how often each one is used; the counts go to <out>.coverage.json. The expressions are
judged by probe.mjs in every cell (.read with and without a query, .write and .validate, signed
in and anonymous), on a node /t/$k = /t/o, so every operand kind (auth, now, data, newData, root, $k,
query) is in play. Type mismatches are generated on purpose (one operand in four is drawn from
another type), as are separators between tokens (spaces, comments, format characters, line
terminators).
"""
import collections
import json
import random
import sys

seed, count, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
R = random.Random(seed)
USED = collections.Counter()
MAX_DEPTH = 4


def use(name):
    USED[name] += 1


SEPS = [" ", " ", " ", "", "  ", "\t", "\n", "/**/", "/* c */", "​", "­", " ",
        " ", "﻿", "　", "\u000b", "\u000c", "⁠"]


def sep():
    if R.random() < 0.85:
        return " " if R.random() < 0.8 else ""
    use("sep:odd")
    return R.choice(SEPS)


NUM_LITS = ["0", "1", "5", "3", "-1", "2.5", "1e3", "1E-2", "0.5", ".5", "5.", "0x1F", "0X0",
            "1e400", "-0", "9007199254740993", "017", "1.0", "100000000000000000000"]
STR_LITS = ["'Hello'", "'v'", "'u1'", "''", "'5'", "\"o\"", "'a\\'b'", "\"q\\\"\"", "'\\u0076'",
            "'\\x76'", "'line\\nx'", "'tab\\t'", "'H'", "'o'", "'k'", "'w'", "'Hi'", "'é'",
            "'é'", "'A@b.co'", "'s'", "'m'"]


def num(d):
    k = R.randrange(10) if d < MAX_DEPTH else R.randrange(4)
    if k == 0:
        use("num:lit")
        return R.choice(NUM_LITS)
    if k == 1:
        use("num:now")
        return "now"
    if k == 2:
        use("num:val")
        return f"{snap(d + 1)}.val()"
    if k == 3:
        use("num:auth")
        return R.choice(["auth.token.n", "auth.token['n']", "auth.token.iat", "auth.token.exp"])
    if k == 4:
        use("num:length")
        return f"{strx(d + 1)}.length"
    if k == 5:
        op = R.choice(["+", "-", "*", "/", "%"])
        use(f"num:bin{op}")
        return f"({operand('num', d + 1)}{sep()}{op}{sep()}{operand('num', d + 1)})"
    if k == 6:
        use("num:neg")
        return f"-{sep()}{operand('num', d + 1)}"
    if k == 7:
        use("num:ternary")
        return f"({boolx(d + 1)} ? {operand('num', d + 1)} : {operand('num', d + 1)})"
    if k == 8:
        use("num:query")
        return R.choice(["query.limitToFirst", "query.limitToLast", "query.startAt", "query.endAt",
                         "query.equalTo"])
    use("num:paren")
    return f"({num(d + 1)})"


def strx(d):
    k = R.randrange(11) if d < MAX_DEPTH else R.randrange(4)
    if k == 0:
        use("str:lit")
        return R.choice(STR_LITS)
    if k == 1:
        use("str:wild")
        return "$k"
    if k == 2:
        use("str:auth")
        return R.choice(["auth.uid", "auth.provider", "auth.token.email", "auth.token.sub",
                         "auth['uid']", "auth.token.firebase.sign_in_provider"])
    if k == 3:
        use("str:val")
        return f"{snap(d + 1)}.val()"
    if k == 4:
        m = R.choice(["toLowerCase()", "toUpperCase()", "replace('l', 'L')", "replace(/l/, 'L')",
                      f"replace({strx(d + 1)}, {strx(d + 1)})"])
        use("str:method:" + m.split("(")[0])
        return f"{strx(d + 1)}.{m}"
    if k == 5:
        use("str:concat")
        return f"({operand('str', d + 1)}{sep()}+{sep()}{operand(R.choice(['str', 'num', 'any']), d + 1)})"
    if k == 6:
        use("str:ternary")
        return f"({boolx(d + 1)} ? {operand('str', d + 1)} : {operand('str', d + 1)})"
    if k == 7:
        use("str:index")
        return R.choice([f"{snap(d + 1)}.val()['k']", "auth.token['email']", "auth['uid']",
                         f"data.val()[{strx(d + 1)}]", "auth.token[$k]"])
    if k == 8:
        use("str:priority")
        return f"{snap(d + 1)}.getPriority()"
    if k == 9:
        use("str:paren")
        return f"({strx(d + 1)})"
    use("str:querykey")
    return R.choice(["query.orderByChild", "query.startAt", "query.endAt", "query.equalTo"])


def regex():
    parts = []
    for _ in range(R.randrange(1, 5)):
        k = R.randrange(9)
        if k == 0:
            parts.append(R.choice(["a", "l", "H", "o", "v", "e", "1", "u"]))
        elif k == 1:
            parts.append(R.choice(["[a-z]", "[A-Z]", "[0-9]", "[^a]", "[aeiou]", "[A-z]", "[lo]"]))
        elif k == 2:
            parts.append(R.choice(["\\d", "\\w", "\\s", "\\.", "\\/", "\\b"]))
        elif k == 3:
            parts.append(".")
        elif k == 4 and parts:
            parts[-1] += R.choice(["*", "+", "?", "{2}", "{1,3}", "{0,}"])
        elif k == 5:
            parts.append(R.choice(["(l)", "(a|e)", "(lo)+"]))
        elif k == 6:
            parts.append(R.choice(["^", "$"]))
        else:
            parts.append(R.choice(["l", "lo", "He"]))
    flags = R.choice(["", "", "", "i"])
    body = "".join(parts)
    use("regex:" + ("i" if flags else "plain"))
    return f"/{body}/{flags}"


KEYS = ['k', 's', 'n', 'm', 'b', 'o', 'arr', 'x', 'e', 'num', 'd', 'z']


def snap(d):
    k = R.randrange(7) if d < MAX_DEPTH else R.randrange(3)
    base = R.choice(["data", "newData", "root", "data.parent()", "root.child('t')"])
    use("snap:" + base.split(".")[0])
    if k <= 2:
        return base
    if k == 3:
        use("snap:child")
        return f"{base}.child({R.choice(KEYS)!r})"
    if k == 4:
        use("snap:child-expr")
        return f"{base}.child({strx(d + 1)})"
    if k == 5:
        use("snap:child-path")
        return f"{base}.child('o/k')"
    use("snap:parent")
    return f"{snap(d + 1)}.parent()"


def boolx(d):
    k = R.randrange(13) if d < MAX_DEPTH else R.randrange(3)
    if k == 0:
        use("bool:lit")
        return R.choice(["true", "false"])
    if k == 1:
        use("bool:auth-null")
        return R.choice(["auth != null", "auth == null", "auth === null", "auth !== null"])
    if k == 2:
        m = R.choice(["exists()", "hasChild('k')", "hasChild('s')", "hasChildren()",
                      "hasChildren(['k', 'm'])", "hasChildren(['s'])", "isNumber()", "isString()",
                      "isBoolean()", "hasChildren([])"])
        use("bool:snap:" + m.split("(")[0])
        return f"{snap(d + 1)}.{m}"
    if k in (3, 4):
        op = R.choice(["==", "!=", "===", "!==", "<", "<=", ">", ">="])
        t = R.choice(["num", "str", "any", "bool", "num", "str"])
        use(f"bool:cmp{op}:{t}")
        return f"{operand(t, d + 1)}{sep()}{op}{sep()}{operand(t, d + 1)}"
    if k == 5:
        op = R.choice(["&&", "||"])
        use(f"bool:{op}")
        return f"({operand('bool', d + 1)}{sep()}{op}{sep()}{operand('bool', d + 1)})"
    if k == 6:
        use("bool:not")
        return f"!{sep()}{operand('bool', d + 1)}"
    if k == 7:
        m = R.choice(["contains", "beginsWith", "endsWith"])
        use("bool:str:" + m)
        return f"{strx(d + 1)}.{m}({operand('str', d + 1)})"
    if k == 8:
        use("bool:matches")
        return f"{strx(d + 1)}.matches({regex()})"
    if k == 9:
        use("bool:ternary")
        return f"({boolx(d + 1)} ? {operand('bool', d + 1)} : {operand('bool', d + 1)})"
    if k == 10:
        use("bool:val")
        return f"{snap(d + 1)}.child('b').val()"
    if k == 11:
        use("bool:query")
        return R.choice(["query.orderByKey", "query.orderByValue", "query.orderByPriority"])
    use("bool:paren")
    return f"({boolx(d + 1)})"


def anyx(d):
    k = R.randrange(7)
    if k == 0:
        use("any:null")
        return "null"
    if k == 1:
        use("any:val-obj")
        return R.choice(["data.val()", "newData.val()", "root.val()", "auth", "auth.token",
                         "auth.token.roles", "auth.token.missing", "auth.token.missing.deep"])
    if k == 2:
        use("any:length-obj")
        return R.choice(["data.val().length", "auth.token.length", "auth.token.roles.length",
                         "auth.length", "newData.val().length"])
    if k == 3:
        use("any:snapshot")
        return R.choice(["data", "root", "newData"])
    if k == 4:
        use("any:index")
        return R.choice(["auth.token.roles[0]", "auth.token.roles['0']", "data.val()['m']",
                         "auth.token[0]", "auth[1]"])
    if k == 5:
        use("any:missing")
        return f"{snap(d + 1)}.child('x').val()"
    use("any:bool")
    return boolx(min(d + 1, MAX_DEPTH))


def operand(t, d):
    # One operand in four is drawn from another type.
    if R.random() < 0.25:
        use("operand:mismatch")
        t = R.choice(["num", "str", "bool", "any"])
    return {"num": num, "str": strx, "bool": boolx, "any": anyx}[t](d)


rows, seen = [], set()
while len(rows) < count:
    e = boolx(0) if R.random() < 0.85 else operand("any", 0)
    if R.random() < 0.05:
        use("top:leading-sep")
        e = R.choice(SEPS) + e
    if e not in seen and len(e) < 1500:
        seen.add(e)
        rows.append(e)
json.dump(rows, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=0)
json.dump(dict(sorted(USED.items())), open(out.replace(".json", ".coverage.json"), "w"), indent=0)
print(len(rows), "expressions,", len(USED), "productions, min", min(USED.values()))
