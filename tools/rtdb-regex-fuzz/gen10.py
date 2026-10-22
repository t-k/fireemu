"""The r10 review's generator (the fifth; written independently of gen.py, gen2.py, gen9 and gen9t).
python3 -I gen10.py <seed> <count> <out.json>

A type-set stress grammar. Every operand is drawn from a pool of value kinds whose static type
sets differ (exact string, exact number, exact boolean, null, snapshot, auth and its members,
val()/getPriority() unions, query members of every type, orderings, $k, uncalled methods,
unknown names), and then composed by productions chosen to make union types reach every
check: mixed ternaries (with conditions that differ per cell: signed in or not, with or
without a query, read or write), member and method chains on those ternaries, equality and
!= against orderings, arithmetic and + on unions, query members in every position (operand,
argument, condition, receiver, index), and $k in every position. Ill-typed rules are wanted
too: they test load acceptance. Production counts go to <out>.coverage.json."""
import collections, json, random, sys

seed, count, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
R = random.Random(seed)
cov = collections.Counter()

STR = ["'a'", "'m'", "'k'", "''", "'Hello'", "'u1'", "'o'", "'a/b'", "'m/.priority'", "'.priority'",
       "'v'", "'5'", "'x.y'", "'$k'", "'.info/x'", "'//m//'"]
NUM = ["0", "1", "2", "5", "2.5", "-1", "1e3", "now", "7", "3"]
BOOL = ["true", "false"]
SNAP = ["root", "data", "data.parent()", "root.child('t')", "data.child('a')", "root.child($k)",
        "data.child(auth.uid)", "root.child('t').child($k)", "data.child('missing')", "newData",
        "newData.child('k')", "root.child('t/o')", "data.child('a').parent()"]
AUTH = ["auth", "auth.uid", "auth.token", "auth.n", "auth.z", "auth.roles", "auth.roles[0]",
        "auth.roles[1.0]", "auth.missing", "auth.nested", "auth.nested.a.b", "auth['uid']",
        "auth[$k]", "auth.missing.deeper", "auth.email", "auth.firebase.sign_in_provider",
        "auth.length", "auth.uid.length"]
VALS = ["data.val()", "data.child('m').val()", "data.child('a').val()", "data.child('missing').val()",
        "root.child('u').val()", "data.child('s').val()", "data.child('b').val()",
        "data.getPriority()", "data.child('c').getPriority()", "data.child('a').getPriority()",
        "newData.child('n').val()", "newData.val()", "data.child('num').val()"]
QRY = ["query", "query.orderByChild", "query.orderByKey", "query.orderByValue", "query.orderByPriority",
       "query.startAt", "query.endAt", "query.equalTo", "query.limitToFirst", "query.limitToLast"]
WILD = ["$k"]
ODD = ["OrderByKey", "http", "$j", "query.orderBy", "query.endBefore", "data.child", "'a'.contains",
       "root.exists", "query.isOrderByChild('m')"]
POOLS = {"str": STR, "num": NUM, "bool": BOOL, "null": ["null"], "snap": SNAP, "auth": AUTH,
         "val": VALS, "query": QRY, "wild": WILD, "odd": ODD}
WEIGHT = {"str": 10, "num": 8, "bool": 4, "null": 4, "snap": 10, "auth": 12, "val": 10,
          "query": 16, "wild": 8, "odd": 2}
CONDS = ["auth != null", "query.orderByKey", "query.limitToFirst == 2", "$k == 'o'",
         "data.child('m').val() == 1", "root.child('u').val() == auth.uid", "now > 0",
         "query.orderByChild == 'm'", "query.startAt == 1", "auth.n == 3", "data.exists()",
         "query.orderByChild != null", "auth.missing == null"]


def atom(kind=None):
    kind = kind or R.choices(list(WEIGHT), weights=list(WEIGHT.values()))[0]
    cov["atom:" + kind] += 1
    return R.choice(POOLS[kind])


def cond(d):
    if d > 0 and R.random() < 0.25:
        cov["cond:any"] += 1
        return gen(d - 1)
    cov["cond:pool"] += 1
    c = R.choice(CONDS)
    return f"!({c})" if R.random() < 0.2 else c


def ternary(d):
    cov["ternary"] += 1
    return f"({cond(d)} ? {gen(d - 1)} : {gen(d - 1)})"


METHODS0 = ["val", "exists", "parent", "getPriority", "isString", "isNumber", "isBoolean",
            "toLowerCase", "toUpperCase", "hasChildren"]
METHODS1 = ["child", "hasChild", "contains", "beginsWith", "endsWith"]
MEMBERS = ["length", "uid", "orderByChild", "startAt", "limitToFirst", "orderByKey", "k", "token",
           "equalTo", "endAt"]


def chain(d):
    t = gen(d - 1) if R.random() < 0.6 else ternary(d)
    r = R.random()
    if r < 0.3:
        m = R.choice(METHODS0); cov["chain:m0:" + m] += 1
        return f"{t}.{m}()"
    if r < 0.6:
        m = R.choice(METHODS1); cov["chain:m1:" + m] += 1
        return f"{t}.{m}({arg(d)})"
    if r < 0.7:
        cov["chain:replace"] += 1
        return f"{t}.replace({arg(d)}, {arg(d)})"
    if r < 0.75:
        cov["chain:matches"] += 1
        return f"{t}.matches(/{R.choice(['a', '^H', 'o$', '.*', '[a-z]+', 'u1'])}/)"
    if r < 0.8:
        cov["chain:hasChildren"] += 1
        return f"{t}.hasChildren([{arg(d)}, {arg(d)}])"
    if r < 0.9:
        m = R.choice(MEMBERS); cov["chain:member:" + m] += 1
        return f"{t}.{m}"
    cov["chain:index"] += 1
    return f"{t}[{arg(d)}]"


def arg(d):
    if d > 0 and R.random() < 0.35:
        cov["arg:gen"] += 1
        return gen(d - 1)
    cov["arg:atom"] += 1
    return atom(R.choice(["str", "str", "wild", "query", "auth", "val", "num", "null"]))


EQ = ["==", "===", "!=", "!=="]
REL = ["<", "<=", ">", ">="]
ARITH = ["+", "-", "*", "/", "%"]


def binary(d):
    r = R.random()
    if r < 0.5:
        op = R.choice(EQ)
    elif r < 0.7:
        op = R.choice(REL)
    elif r < 0.9:
        op = R.choice(ARITH)
    else:
        op = R.choice(["&&", "||"])
    cov["binary:" + op] += 1
    a, b = gen(d - 1), gen(d - 1)
    if R.random() < 0.5:
        a, b = b, a
    return f"({a} {op} {b})"


def ordering(d):
    # Equality against orderings: literals, paths, unions, ternaries of orderings.
    cov["ordering"] += 1
    o = R.choice(["query.orderByChild", f"({cond(0)} ? query.orderByChild : query.orderByChild)",
                  f"({cond(0)} ? query.orderByChild : {atom('str')})", "(query.orderByChild)"])
    other = R.choice(STR + ["null", "(null)", "$k", "auth.uid", "query.orderByChild", "query.startAt",
                            f"({cond(0)} ? 'm' : 'm')", f"('m')", "data.child('k').val()", "1", "true"])
    op = R.choice(EQ)
    return f"{o} {op} {other}" if R.random() < 0.5 else f"{other} {op} {o}"


def gen(d):
    if d <= 0:
        return atom()
    r = R.random()
    if r < 0.25:
        return atom()
    if r < 0.45:
        return ternary(d)
    if r < 0.7:
        return chain(d)
    if r < 0.9:
        return binary(d)
    if r < 0.95:
        cov["unary:!"] += 1
        return f"!{gen(d - 1)}"
    cov["unary:-"] += 1
    return f"-{gen(d - 1)}"


def top():
    r = R.random()
    d = R.choice([1, 2, 2, 3, 3, 4])
    if r < 0.4:
        cov["top:compare"] += 1
        return f"{gen(d)} {R.choice(EQ)} {R.choice([atom(), gen(d - 1)])}"
    if r < 0.5:
        cov["top:ordering"] += 1
        return ordering(d)
    if r < 0.6:
        cov["top:rel"] += 1
        return f"{gen(d)} {R.choice(REL)} {atom(R.choice(['num', 'str', 'query', 'val']))}"
    if r < 0.75:
        cov["top:boolean-chain"] += 1
        return f"{chain(d)} {R.choice(['==', '!='])} {R.choice(['true', 'false', 'null', atom()])}"
    if r < 0.85:
        cov["top:logic"] += 1
        return f"{top_simple(d)} {R.choice(['&&', '||'])} {top_simple(d)}"
    cov["top:any"] += 1
    return gen(d)


def top_simple(d):
    return f"({gen(d - 1)} {R.choice(EQ)} {atom()})"


rows = []
seen = set()
while len(rows) < count:
    e = top()
    if e not in seen and len(e) < 400:
        seen.add(e)
        rows.append(e)
json.dump(rows, open(out, "w"), ensure_ascii=False, indent=0)
json.dump(dict(sorted(cov.items())), open(out.replace(".json", ".coverage.json"), "w"), indent=0)
print(len(rows), "expressions;", len(cov), "productions; least used",
      sorted(cov.items(), key=lambda kv: kv[1])[:3])
