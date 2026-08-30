// The generated half of the language matrix: bounded Rules expressions from a seeded PRNG.
//
// Generation is over a tiny AST rather than over strings, because a mismatch has to shrink:
// `shrink()` enumerates structurally smaller programs (a node replaced by one of its
// children, an operand replaced by a literal) and the caller keeps the smallest one that
// still disagrees. Rendering inserts the spaces the official lexer needs around `/`.

/** Deterministic PRNG (mulberry32). */
export function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const LITERALS = [
  "0",
  "1",
  "-1",
  "2",
  "3",
  "9223372036854775807",
  "0.0",
  "1.5",
  "-2.5",
  "''",
  "'a'",
  "'abc'",
  "'A b'",
  "true",
  "false",
  "null",
  "[]",
  "[1, 2]",
  "['a', 'b']",
  "[1, 'a']",
  "{}",
  "{'a': 1}",
  "{'a': 'b', 'c': 2}",
  "request.time",
  "request.path",
  "request.auth",
  "resource",
];

const ARITH = ["+", "-", "*", "/", "%"];
const CMP = ["==", "!=", "<", "<=", ">", ">="];
const TYPES = [
  "int",
  "float",
  "number",
  "string",
  "bool",
  "list",
  "map",
  "set",
  "path",
  "timestamp",
  "duration",
  "latlng",
  "bytes",
];
const NILADIC = [
  "size",
  "lower",
  "upper",
  "trim",
  "keys",
  "values",
  "toSet",
  "toUtf8",
  "toBase64",
  "toHexString",
  "toMillis",
  "seconds",
  "nanos",
  "year",
  "day",
  "date",
  "time",
  "latitude",
];
const MONADIC = [
  "hasAll",
  "hasAny",
  "hasOnly",
  "concat",
  "join",
  "removeAll",
  "split",
  "matches",
  "union",
  "intersection",
  "difference",
  "diff",
  "distance",
];
const CONVERT = ["int", "float", "string", "bool", "path", "bytes"];

const pick = (r, xs) => xs[Math.floor(r() * xs.length) % xs.length];

/** Builds one bounded expression node. */
function expr(r, depth) {
  if (depth <= 0) return { k: "lit", v: pick(r, LITERALS) };
  switch (Math.floor(r() * 8)) {
    case 0:
      return { k: "bin", op: pick(r, ARITH), l: expr(r, depth - 1), rr: expr(r, depth - 1) };
    case 1:
      return { k: "bin", op: pick(r, CMP), l: expr(r, depth - 1), rr: expr(r, depth - 1) };
    case 2:
      return { k: "bin", op: pick(r, ["&&", "||"]), l: expr(r, depth - 1), rr: expr(r, depth - 1) };
    case 3:
      return { k: "is", e: expr(r, depth - 1), t: pick(r, TYPES) };
    case 4:
      return { k: "m0", e: expr(r, depth - 1), name: pick(r, NILADIC) };
    case 5:
      return { k: "m1", e: expr(r, depth - 1), name: pick(r, MONADIC), a: expr(r, depth - 1) };
    case 6:
      return { k: "conv", name: pick(r, CONVERT), e: expr(r, depth - 1) };
    default:
      return r() < 0.5
        ? { k: "index", e: expr(r, depth - 1), i: expr(r, depth - 1) }
        : { k: "bin", op: "in", l: expr(r, depth - 1), rr: expr(r, depth - 1) };
  }
}

/** Renders a node as Rules source. Binary operators are always parenthesised. */
export function render(n) {
  switch (n.k) {
    case "lit":
      return n.v;
    case "bin":
      return `(${render(n.l)} ${n.op} ${render(n.rr)})`;
    case "is":
      return `(${render(n.e)} is ${n.t})`;
    case "m0":
      return `${render(n.e)}.${n.name}()`;
    case "m1":
      return `${render(n.e)}.${n.name}(${render(n.a)})`;
    case "conv":
      return `${n.name}(${render(n.e)})`;
    case "index":
      return `${render(n.e)}[${render(n.i)}]`;
    default:
      throw new Error(`unknown node ${n.k}`);
  }
}

/** Children of a node, in render order. */
function children(n) {
  switch (n.k) {
    case "bin":
      return [n.l, n.rr];
    case "is":
    case "conv":
      return [n.e];
    case "m0":
      return [n.e];
    case "m1":
      return [n.e, n.a];
    case "index":
      return [n.e, n.i];
    default:
      return [];
  }
}

/** Rebuilds `n` with its children replaced. */
function withChildren(n, kids) {
  switch (n.k) {
    case "bin":
      return { ...n, l: kids[0], rr: kids[1] };
    case "is":
    case "conv":
    case "m0":
      return { ...n, e: kids[0] };
    case "m1":
      return { ...n, e: kids[0], a: kids[1] };
    case "index":
      return { ...n, e: kids[0], i: kids[1] };
    default:
      return n;
  }
}

const size = (n) => 1 + children(n).reduce((acc, c) => acc + size(c), 0);

/**
 * Structurally smaller variants of `n`: the node replaced by each child, each child
 * replaced by a literal, and each child shrunk in place. Smallest first.
 */
export function shrink(n) {
  const out = [];
  const kids = children(n);
  for (const c of kids) out.push(c);
  for (let i = 0; i < kids.length; i++) {
    for (const lit of ["1", "'a'", "null", "[1, 2]", "{'a': 1}"]) {
      if (kids[i].k === "lit") continue;
      const next = kids.slice();
      next[i] = { k: "lit", v: lit };
      out.push(withChildren(n, next));
    }
  }
  for (let i = 0; i < kids.length; i++) {
    for (const s of shrink(kids[i])) {
      const next = kids.slice();
      next[i] = s;
      out.push(withChildren(n, next));
    }
  }
  return out.toSorted((a, b) => size(a) - size(b));
}

/**
 * `count` generated claims. Each is a boolean expression: the raw node when it is already
 * a comparison, otherwise the node compared with a literal or tested with `is`.
 *
 * @returns {{ id: string, area: string, claim: string, node: object }[]}
 */
export function generated(seed, count, maxDepth = 3) {
  const r = rng(seed);
  const out = [];
  const seen = new Set();
  let i = 0;
  let guard = 0;
  while (out.length < count && guard++ < count * 40) {
    const depth = 1 + Math.floor(r() * maxDepth);
    let node = expr(r, depth);
    if (
      !(node.k === "bin" && CMP.concat(["in", "&&", "||"]).includes(node.op)) &&
      node.k !== "is"
    ) {
      node =
        r() < 0.5
          ? { k: "is", e: node, t: pick(r, TYPES) }
          : { k: "bin", op: pick(r, CMP), l: node, rr: { k: "lit", v: pick(r, LITERALS) } };
    }
    const claim = render(node);
    if (seen.has(claim) || claim.length > 220) continue;
    seen.add(claim);
    i += 1;
    out.push({ id: `gen-${String(i).padStart(4, "0")}`, area: "generated", claim, node });
  }
  return out;
}
