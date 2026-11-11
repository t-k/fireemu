// The corpus normalizer erases a value only where a scenario declared the field generated.
// A user-supplied string that looks like a generated one must stay comparable. No property
// library is a dependency, so the generated cases come from a small deterministic PRNG; every
// failure names its seed and case.
import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext } from "./corpus/context.mjs";
import { GENERATED_KINDS, compileGenerated, normalize, normalizeError } from "./normalize.mjs";

const CASES = 300;
const SEED = 0x26_26_2026;

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const int = (random, max) => Math.floor(random() * max);
const chars = (random, alphabet, length) =>
  Array.from({ length }, () => alphabet[int(random, alphabet.length)]).join("");
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const URLSAFE = `${ALNUM}-_`;
const HEX = "0123456789abcdef";
const DIGITS = "0123456789";
const pad = (random, length) => chars(random, DIGITS, length);

// One generator per kind: a string of exactly the shape the generated-value rule accepts.
const SHAPES = {
  timestamp: (random) =>
    `20${pad(random, 2)}-${pad(random, 2)}-${pad(random, 2)}T${pad(random, 2)}:${pad(random, 2)}:${pad(random, 2)}${
      random() < 0.5 ? `.${pad(random, 1 + int(random, 9))}` : ""
    }${random() < 0.5 ? "Z" : `+${pad(random, 2)}:${pad(random, 2)}`}`,
  "auto-id": (random) => chars(random, ALNUM, 20),
  jwt: (random) =>
    `ey${chars(random, URLSAFE, 1 + int(random, 20))}.${chars(random, URLSAFE, 1 + int(random, 20))}.${chars(random, URLSAFE, int(random, 20))}`,
  uuid: (random) =>
    `${chars(random, HEX, 8)}-${chars(random, HEX, 4)}-${chars(random, HEX, 4)}-${chars(random, HEX, 4)}-${chars(random, HEX, 12)}`,
  generation: (random) => `1${pad(random, 15 + int(random, 4))}`,
};

const PLACEHOLDER = (kind) => `<${kind}>`;

test("every declarable kind has a shape generator and a placeholder", () => {
  assert.deepEqual(Object.keys(SHAPES).toSorted(), [...GENERATED_KINDS].toSorted());
});

test("a value at a declared path is replaced by its kind's placeholder", () => {
  for (const kind of GENERATED_KINDS) {
    const random = mulberry32(SEED ^ kind.length);
    for (let i = 0; i < CASES; i += 1) {
      const shape = SHAPES[kind](random);
      const out = normalize({ data: { v: shape } }, { generated: { "data.v": kind } });
      assert.deepEqual(out, { data: { v: PLACEHOLDER(kind) } }, `${kind} case ${i}: ${shape}`);
    }
  }
});

test("a user string of a generated shape at an undeclared path is compared exactly", () => {
  for (const kind of GENERATED_KINDS) {
    const random = mulberry32(SEED ^ (kind.length * 7));
    for (let i = 0; i < CASES; i += 1) {
      const shape = SHAPES[kind](random);
      // Nothing declared: the shape alone never erases a value.
      assert.deepEqual(normalize({ v: shape }), { v: shape }, `${kind} case ${i}: ${shape}`);
      // Declared elsewhere: a neighbouring declaration does not cover this path.
      assert.deepEqual(
        normalize({ v: shape, generated: shape }, { generated: { generated: kind } }),
        { v: shape, generated: PLACEHOLDER(kind) },
        `${kind} case ${i}: ${shape}`,
      );
    }
  }
});

test("two different user strings of a generated shape stay different", () => {
  for (const kind of GENERATED_KINDS) {
    const random = mulberry32(SEED ^ (kind.length * 13));
    let compared = 0;
    for (let i = 0; i < CASES; i += 1) {
      const a = SHAPES[kind](random);
      const b = SHAPES[kind](random);
      if (a === b) continue;
      compared += 1;
      assert.notDeepEqual(normalize({ v: a }), normalize({ v: b }), `${kind} case ${i}`);
      // Arrays and keys of user data are no different.
      assert.notDeepEqual(normalize([a]), normalize([b]), `${kind} case ${i}`);
      assert.notDeepEqual(normalize({ list: { x: [a] } }), normalize({ list: { x: [b] } }));
    }
    assert.ok(compared > CASES / 2, `${kind}: too few distinct pairs`);
  }
});

test("a generated value at a declared path hides the difference between two runs", () => {
  for (const kind of GENERATED_KINDS) {
    const random = mulberry32(SEED ^ (kind.length * 17));
    for (let i = 0; i < CASES; i += 1) {
      const generated = { "doc.v": kind };
      const a = normalize({ doc: { v: SHAPES[kind](random), keep: "k" } }, { generated });
      const b = normalize({ doc: { v: SHAPES[kind](random), keep: "k" } }, { generated });
      assert.deepEqual(a, b, `${kind} case ${i}`);
    }
  }
});

test("a declared path still checks the shape: a changed type or length is not hidden", () => {
  const cases = [
    ["timestamp", 1700000000],
    ["timestamp", "2026-11-11"],
    ["timestamp", "2026-11-11T01:02:03"],
    ["timestamp", ""],
    ["auto-id", "a".repeat(19)],
    ["auto-id", "a".repeat(21)],
    ["auto-id", `${"a".repeat(19)}-`],
    ["jwt", "not-a-jwt"],
    ["uuid", "0123456789abcdef"],
    ["generation", "1234"],
    ["generation", 1700000000000000],
    ["generation", "1".padEnd(15, "0")],
    ["generation", "1".padEnd(20, "0")],
    ["generation", "2".padEnd(17, "0")],
    ["uuid", "01234567-89ab-cdef-0123-456789abcde"],
    ["uuid", "01234567-89ab-cdef-0123-456789abcdef0"],
    ["uuid", "01234567-89AB-CDEF-0123-456789ABCDEF"],
    ["jwt", "ey.a.b"],
    ["jwt", "eyJhbGciOi.payload"],
    ["jwt", "xyJhbGciOi.payload.sig"],
    ["auto-id", `${"a".repeat(19)}_`],
  ];
  for (const [kind, value] of cases) {
    assert.deepEqual(
      normalize({ v: value }, { generated: { v: kind } }),
      { v: value },
      `${kind}: ${String(value)}`,
    );
  }
});

test("an instant is replaced only where declared; otherwise it is exact to the nanosecond", () => {
  class Timestamp {
    constructor(seconds, nanoseconds) {
      this.seconds = seconds;
      this.nanoseconds = nanoseconds;
    }
  }
  const at = new Timestamp(1583298367, 8_000_000);
  assert.deepEqual(normalize({ at }, { generated: { at: "timestamp" } }), { at: "<timestamp>" });
  assert.deepEqual(normalize({ at }), {
    at: { timestamp: { seconds: 1583298367, nanoseconds: 8_000_000 } },
  });
  assert.notDeepEqual(normalize({ at }), normalize({ at: new Timestamp(1583298367, 8_000_001) }));
  const date = new Date("2020-03-04T05:06:07.008Z");
  assert.deepEqual(normalize({ date }, { generated: { date: "timestamp" } }), {
    date: "<timestamp>",
  });
  assert.deepEqual(normalize({ date }), { date: { date: "2020-03-04T05:06:07.008Z" } });
  assert.deepEqual(normalize({ date: new Date(Number.NaN) }), { date: { date: "Invalid Date" } });
  // A Timestamp is not a string-shaped id.
  assert.deepEqual(normalize({ at }, { generated: { at: "auto-id" } }), normalize({ at }));
});

test("paths reach through arrays, wildcards and the root", () => {
  const value = {
    body: [
      {
        document: { createTime: "2026-01-01T00:00:00Z", name: "n" },
        readTime: "2026-01-01T00:00:01Z",
      },
      {
        document: { createTime: "2026-01-02T00:00:00Z", name: "n" },
        readTime: "2026-01-02T00:00:01Z",
      },
    ],
    status: 200,
  };
  const out = normalize(value, {
    generated: {
      "body[].document.createTime": "timestamp",
      "body[].readTime": "timestamp",
    },
  });
  assert.deepEqual(out.body, [
    { document: { createTime: "<timestamp>", name: "n" }, readTime: "<timestamp>" },
    { document: { createTime: "<timestamp>", name: "n" }, readTime: "<timestamp>" },
  ]);
  assert.equal(out.status, 200);

  assert.deepEqual(
    normalize(["a".repeat(20), "b".repeat(20)], { generated: { "[]": "auto-id" } }),
    ["<auto-id>", "<auto-id>"],
  );
  assert.equal(normalize("a".repeat(20), { generated: { "": "auto-id" } }), "<auto-id>");
  assert.deepEqual(
    normalize(
      { x: { id: "a".repeat(20) }, y: { id: "b".repeat(20) }, z: "c".repeat(20) },
      {
        generated: { "*.id": "auto-id" },
      },
    ),
    { x: { id: "<auto-id>" }, y: { id: "<auto-id>" }, z: "c".repeat(20) },
  );
  // A wildcard names a key, never an array element.
  assert.deepEqual(normalize([{ id: "a".repeat(20) }], { generated: { "*.id": "auto-id" } }), [
    { id: "a".repeat(20) },
  ]);
  assert.deepEqual(normalize([[{ id: "a".repeat(20) }]], { generated: { "[][].id": "auto-id" } }), [
    [{ id: "<auto-id>" }],
  ]);
  assert.deepEqual(normalize([["a".repeat(20)]], { generated: { "[]": "auto-id" } }), [
    ["a".repeat(20)],
  ]);
  // A path names a depth: `id` does not reach `a.id`, and `a` does not reach `a[]`.
  assert.deepEqual(normalize({ a: { id: "a".repeat(20) } }, { generated: { id: "auto-id" } }), {
    a: { id: "a".repeat(20) },
  });
  assert.deepEqual(normalize({ a: ["a".repeat(20)] }, { generated: { a: "auto-id" } }), {
    a: ["a".repeat(20)],
  });
  assert.deepEqual(normalize({ a: "a".repeat(20) }, { generated: { "a[]": "auto-id" } }), {
    a: "a".repeat(20),
  });
});

test("a key name is never a value: a 20-letter key stays what it is", () => {
  const keys = ["email", "mfaPendingCredential", "kind"];
  assert.deepEqual(normalize({ keys }), { keys });
  assert.equal("mfaPendingCredential".length, 20);
});

test("declarations are validated eagerly", () => {
  assert.throws(() => compileGenerated({ a: "date" }), /unknown kind/);
  assert.throws(() => compileGenerated({ "a..b": "uuid" }), /bad segment/);
  assert.throws(() => compileGenerated({ "a.[]": "uuid" }), /bad segment/);
  assert.throws(() => compileGenerated({ ".a": "uuid" }), /bad segment/);
  assert.throws(() => compileGenerated({ ".": "uuid" }), /bad segment/);
  assert.throws(() => compileGenerated({ "a[": "uuid" }), /bad segment/);
  assert.throws(() => normalize({}, { generated: { "a.": "jwt" } }), /bad segment/);
  assert.doesNotThrow(() =>
    compileGenerated({ "": "jwt", "[].a[][]": "uuid", "*.b": "generation" }),
  );
});

test("host:port text is still normalized everywhere, and keys are still sorted", () => {
  assert.deepEqual(normalize({ b: "http://127.0.0.1:9199/x", a: [1] }), {
    a: [1],
    b: "http://<host>/x",
  });
  assert.deepEqual(Object.keys(normalize({ z: 1, a: 2 })), ["a", "z"]);
  assert.equal(normalizeError({ code: 1, message: "at localhost:8080" }).message, "at <host>");
});

test("a corpus step records generated fields only where it declares them", async () => {
  const { ctx, steps } = createContext({
    side: "testd",
    variant: "baseline",
    hosts: {},
    shared: {},
  });
  const same = "A".repeat(20);
  const other = "B".repeat(20);
  await ctx.step("declared", async () => ({ id: other, mine: same }), {
    generated: { id: "auto-id" },
  });
  await ctx.step("undeclared", async () => ({ id: other, mine: same }));
  await ctx.step("thrown", async () => {
    throw Object.assign(new Error(`unreachable ${same} at 127.0.0.1:1234`), { code: "x" });
  });
  assert.deepEqual(steps[0].value, { id: "<auto-id>", mine: same });
  assert.deepEqual(steps[1].value, { id: other, mine: same });
  assert.equal(steps[2].value.message, `unreachable ${same} at <host>`);
});
