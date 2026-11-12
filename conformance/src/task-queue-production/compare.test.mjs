import "./record/isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";

import {
  LAYOUT_RULES,
  TOLERANCE,
  allDifferences,
  compareProjections,
  compareProperties,
  compareTiming,
  firstDifference,
  maxOverlap,
} from "./compare.mjs";
import { KNOWN_DIFFERENCES, NO_TIMING_CLAIM } from "./known-differences.mjs";

const prng = (seed) => () => {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed / 2 ** 32;
};

const delivery = (over = {}) => ({
  retryCount: 0,
  request: {
    method: "POST",
    path: "/",
    headers: {
      names: ["content-type", "x-cloudtasks-taskname"],
      fixed: { "content-type": "application/json" },
      queueName: "tqdef",
      taskName: "ID(19)",
      eta: "UNIX(f6)",
      contentLength: "present",
    },
    body: { length: 3, text: "{}" },
  },
  context: {
    retryCount: 0,
    executionCount: 0,
    previousResponse: null,
    retryReason: null,
    hasAuth: true,
  },
  step: null,
  ...over,
});
const timing = (firstMs = 100, gapsMs = []) => ({
  firstMs,
  gapsMs,
  startsAtMs: [0],
  endsAtMs: [10],
  holdMs: [10],
});
const record = (over = {}) => ({
  kind: "create",
  sent: true,
  admission: { status: 200, body: { name: "projects/p/tasks/ID(19)" }, shape: { name: "string" } },
  deliveries: [delivery()],
  timing: timing(),
  ...over,
});
const projection = (cases, alias = "x") => ({ alias, corpusSha256: "c", cases });
const verdictOf = (left, right, options) =>
  compareProjections(projection(left), projection(right), options).rows[0];

test("equal projections match, in structure and in timing", () => {
  const row = verdictOf({ a: record() }, { a: record() });
  assert.equal(row.structure, "MATCH");
  assert.equal(row.timing.verdict, "WITHIN");
});

test("a difference with no known difference is a mismatch and is named by path", () => {
  const changed = record({
    admission: { status: 400, error: { code: 400, status: "INVALID_ARGUMENT", message: "m" } },
  });
  const row = verdictOf({ a: record() }, { a: changed });
  assert.equal(row.structure, "MISMATCH");
  assert.equal(row.parts.admission.verdict, "MISMATCH");
  assert.ok(row.parts.admission.uncovered.length > 0);
});

test("a known difference covers exactly its case, part and path", () => {
  const kd = {
    id: "KD",
    part: "admission",
    cases: ["a"],
    paths: [/^\/body\/name$/],
    ruling: 3,
    what: "w",
  };
  const other = record({
    admission: { status: 200, body: { name: "projects/p/tasks/OTHER" }, shape: { name: "string" } },
  });
  assert.equal(
    verdictOf({ a: record() }, { a: other }, { knownDifferences: [kd] }).structure,
    "KNOWN_DIFFERENCE",
  );
  assert.equal(
    verdictOf({ a: record() }, { a: other }, { knownDifferences: [{ ...kd, cases: ["b"] }] })
      .structure,
    "MISMATCH",
  );
  assert.equal(
    verdictOf({ a: record() }, { a: other }, { knownDifferences: [{ ...kd, part: "deliveries" }] })
      .structure,
    "MISMATCH",
  );
  assert.equal(
    verdictOf(
      { a: record() },
      { a: other },
      { knownDifferences: [{ ...kd, paths: [/^\/body\/other$/] }] },
    ).structure,
    "MISMATCH",
  );
});

test("a known difference without a ruling, a text or a path is refused", () => {
  const base = { id: "KD", part: "admission", cases: "*", paths: [/x/], ruling: 3, what: "w" };
  for (const bad of [
    { ruling: undefined },
    { what: "" },
    { paths: [] },
    { id: "" },
    { paths: undefined },
  ])
    assert.throws(
      () =>
        compareProjections(projection({ a: record() }), projection({ a: record() }), {
          knownDifferences: [{ ...base, ...bad }],
        }),
      /a known difference needs/,
    );
});

test("a hide hook removes a part of a delivery on both sides before the comparison", () => {
  const kd = {
    id: "KD-H",
    part: "deliveries",
    cases: "*",
    paths: [],
    ruling: 3,
    what: "w",
    hide(d) {
      const had = d.request.headers.names.includes("x-cloudtasks-taskname");
      d.request.headers.names = d.request.headers.names.filter(
        (n) => n !== "x-cloudtasks-taskname",
      );
      return had;
    },
  };
  const left = record();
  const right = record({
    deliveries: [
      delivery({
        request: {
          ...delivery().request,
          headers: { ...delivery().request.headers, names: ["content-type"] },
        },
      }),
    ],
  });
  assert.equal(verdictOf({ a: left }, { a: right }).structure, "MISMATCH");
  assert.equal(
    verdictOf({ a: left }, { a: right }, { knownDifferences: [kd] }).structure,
    "KNOWN_DIFFERENCE",
  );
});

test("a layout rule makes the volatile edge header, the ETA digits and the id length equal, and is counted", () => {
  const withEdge = (eta, id, names) =>
    record({
      deliveries: [
        delivery({
          request: {
            ...delivery().request,
            headers: { ...delivery().request.headers, names, eta, taskName: id },
          },
        }),
      ],
    });
  const left = withEdge("UNIX(f6)", "ID(19)", ["content-type", "x-client-data"]);
  const right = withEdge("UNIX(f5)", "ID(20)", ["content-type"]);
  const result = compareProjections(projection({ a: left }), projection({ a: right }));
  assert.equal(result.rows[0].structure, "MATCH_LAYOUT");
  for (const rule of ["volatile-edge-header", "eta-digits", "numeric-id-length"])
    assert.equal(result.layoutRules.find((r) => r.id === rule).rows, 1, rule);
  assert.deepEqual(
    LAYOUT_RULES.map((r) => r.id),
    ["volatile-edge-header", "eta-digits", "numeric-id-length"],
  );
  // An ETA with 2 digits is a difference of format, not a layout.
  assert.equal(
    verdictOf(
      { a: withEdge("UNIX(f6)", "ID(19)", ["content-type"]) },
      { a: withEdge("UNIX(f2)", "ID(19)", ["content-type"]) },
    ).structure,
    "MISMATCH",
  );
  assert.equal(
    verdictOf(
      { a: withEdge("UNIX(f6)", "ID(19)", ["content-type"]) },
      { a: withEdge("UNIX(f6)", "ID(18)", ["content-type"]) },
    ).structure,
    "MISMATCH",
  );
});

test("timing is within the tolerance and outside beyond it, for the first delivery and every gap", () => {
  const t = (first, gaps) => timing(first, gaps);
  assert.equal(
    compareTiming(t(100, [1000, 2000]), t(100 + TOLERANCE.firstMs, [1000 + TOLERANCE.gapMs, 2000]))
      .verdict,
    "WITHIN",
  );
  assert.deepEqual(compareTiming(t(100, []), t(101 + TOLERANCE.firstMs, [])), {
    verdict: "OUTSIDE",
    why: "first",
    a: 100,
    b: 101 + TOLERANCE.firstMs,
  });
  const gap = compareTiming(t(100, [1000, 2000]), t(100, [1000, 2001 + TOLERANCE.gapMs]));
  assert.equal(gap.verdict, "OUTSIDE");
  assert.equal(gap.why, "gap 2");
  assert.equal(compareTiming(t(100, [1000]), t(100, [1000, 5])).why, "attempts");
  assert.equal(compareTiming(t(100, []), t(99999, []), { claim: false }).verdict, "NOT_COMPARED");
  assert.equal(compareTiming(t(null, [null]), t(5, [5])).verdict, "WITHIN");
});

test("a case on only one side is refused or unknown", () => {
  assert.throws(
    () => compareProjections(projection({ a: record() }), projection({ a: record(), b: record() })),
    /only on the right/,
  );
  assert.equal(
    compareProjections(projection({ a: record(), b: record() }), projection({ a: record() }))
      .rows[1].structure,
    "UNKNOWN",
  );
});

test("firstDifference and allDifferences agree on where two values differ", () => {
  const next = prng(3);
  const make = (depth) => {
    if (depth === 0 || next() < 0.3) return [1, 2, 3, "x", null, true][Math.floor(next() * 6)];
    if (next() < 0.5) return Array.from({ length: Math.floor(next() * 3) }, () => make(depth - 1));
    return Object.fromEntries(
      ["a", "b", "c"].filter(() => next() < 0.7).map((k) => [k, make(depth - 1)]),
    );
  };
  for (let i = 0; i < 500; i++) {
    const a = make(3);
    const b = next() < 0.4 ? JSON.parse(JSON.stringify(a)) : make(3);
    const first = firstDifference(a, b);
    const all = allDifferences(a, b);
    assert.equal(first === null, all.length === 0, JSON.stringify([a, b]));
    assert.equal(JSON.stringify(a) === JSON.stringify(b) && first !== null, false);
    if (first)
      assert.ok(
        all.some((d) => d.path === first.path),
        `${JSON.stringify(first)} in ${JSON.stringify(all)}`,
      );
    assert.equal(firstDifference(a, a), null);
  }
});

test("the overlap of deliveries counts the most running at once and frees a slot at the instant of the next start", () => {
  const run = (...spans) => ({
    cases: Object.fromEntries(
      spans.map((s, i) => ["k" + i, { timing: { startsAtMs: [s[0]], endsAtMs: [s[1]] } }]),
    ),
  });
  const keys = (n) => Array.from({ length: n }, (_, i) => "k" + i);
  assert.equal(maxOverlap(run([0, 10], [10, 20], [20, 30]), keys(3)), 1);
  assert.equal(maxOverlap(run([0, 10], [5, 20], [6, 7]), keys(3)), 3);
  assert.equal(maxOverlap(run([0, 10]), ["absent"]), 0);
  assert.equal(
    maxOverlap({ cases: { k0: { timing: { startsAtMs: [null], endsAtMs: [5] } } } }, ["k0"]),
    0,
  );
});

test("the overlap is the maximum clique of intervals for any set of spans", () => {
  const next = prng(5);
  for (let i = 0; i < 300; i++) {
    const spans = Array.from({ length: 1 + Math.floor(next() * 6) }, () => {
      const s = Math.floor(next() * 50);
      return [s, s + 1 + Math.floor(next() * 20)];
    });
    const projectionOf = {
      cases: Object.fromEntries(
        spans.map((s, k) => ["k" + k, { timing: { startsAtMs: [s[0]], endsAtMs: [s[1]] } }]),
      ),
    };
    // Brute force: the most spans containing one start instant.
    const brute = Math.max(...spans.map(([s]) => spans.filter(([a, b]) => a <= s && s < b).length));
    assert.equal(
      maxOverlap(
        projectionOf,
        spans.map((_, k) => "k" + k),
      ),
      brute,
      JSON.stringify(spans),
    );
  }
});

test("a property compares the overlap of both sides as numbers", () => {
  const side = (n) => ({
    cases: Object.fromEntries(
      ["a", "b", "c", "d"].map((k, i) => [
        "conc1-" + k,
        { timing: { startsAtMs: [i < n ? 0 : 100 * i], endsAtMs: [i < n ? 50 : 100 * i + 5] } },
      ]),
    ),
  });
  const [one] = compareProperties(side(1), side(1));
  assert.equal(one.verdict, "MATCH");
  const [two] = compareProperties(side(1), side(2));
  assert.deepEqual([two.left, two.right, two.verdict], [1, 2, "MISMATCH"]);
});

test("every known difference cites a ruling and a text, and the no-claim set holds only queue cases of the program", () => {
  const ids = new Set();
  for (const kd of KNOWN_DIFFERENCES) {
    assert.ok([3, 6, 16].includes(kd.ruling), kd.id);
    assert.ok(kd.what.length > 40, kd.id);
    assert.ok(!ids.has(kd.id), kd.id);
    ids.add(kd.id);
    assert.ok(kd.paths.length > 0 || kd.hide || kd.window, kd.id);
    // A timing difference is a bound, never a blanket.
    if (kd.part === "timing") assert.equal(typeof kd.allowance, "function", kd.id);
  }
  for (const key of NO_TIMING_CLAIM) assert.match(key, /^(conc1-[a-d]|conc2-[a-e]|rate-[a-h])$/);
});

test("a hide hook of other cases does not cover a case it does not name", () => {
  const kd = {
    id: "KD-H",
    part: "deliveries",
    cases: ["b"],
    paths: [],
    ruling: 3,
    what: "w",
    hide(d) {
      d.request.headers.names = [];
      return true;
    },
  };
  const right = record({
    deliveries: [
      delivery({
        request: {
          ...delivery().request,
          headers: { ...delivery().request.headers, names: ["x"] },
        },
      }),
    ],
  });
  assert.equal(
    verdictOf({ a: record() }, { a: right }, { knownDifferences: [kd] }).structure,
    "MISMATCH",
  );
  assert.equal(
    verdictOf({ b: record() }, { b: right }, { knownDifferences: [kd] }).structure,
    "KNOWN_DIFFERENCE",
  );
});

test("the layout rules take exactly the recorded forms: ETA digits 3 to 7 and ids of 19 or 20 digits", () => {
  const withForms = (eta, id, bodyName) =>
    record({
      admission: { status: 200, body: { name: bodyName }, shape: { name: "string" } },
      deliveries: [
        delivery({
          request: {
            ...delivery().request,
            headers: { ...delivery().request.headers, eta, taskName: id },
          },
        }),
      ],
    });
  const base = (eta, id, name) => withForms(eta, id, name);
  const one = "projects/p/tasks/ID(19)";
  for (const eta of ["UNIX(f3)", "UNIX(f7)"])
    assert.equal(
      verdictOf({ a: base("UNIX(f5)", "ID(19)", one) }, { a: base(eta, "ID(19)", one) }).structure,
      "MATCH_LAYOUT",
      eta,
    );
  for (const eta of ["UNIX(f2)", "UNIX(f8)"])
    assert.equal(
      verdictOf({ a: base("UNIX(f5)", "ID(19)", one) }, { a: base(eta, "ID(19)", one) }).structure,
      "MISMATCH",
      eta,
    );
  assert.equal(
    verdictOf(
      { a: base("UNIX(f5)", "ID(19)", one) },
      { a: base("UNIX(f5)", "ID(20)", "projects/p/tasks/ID(20)") },
    ).structure,
    "MATCH_LAYOUT",
  );
  assert.equal(
    verdictOf({ a: base("UNIX(f5)", "ID(19)", one) }, { a: base("UNIX(f5)", "ID(21)", one) })
      .structure,
    "MISMATCH",
  );
  assert.equal(
    verdictOf(
      { a: base("UNIX(f5)", "ID(19)", one) },
      { a: base("UNIX(f5)", "ID(19)", "projects/p/tasks/ID(21)") },
    ).structure,
    "MISMATCH",
  );
});

// ---- observation window, timing allowance and the lateness of the first delivery (review of 2026-11-12) ---------------------------

const windowKd = {
  id: "KD-W",
  part: "deliveries",
  cases: ["w"],
  paths: [],
  window: { minAttempts: 5 },
  ruling: 16,
  what: "w",
};
const attempts = (n, gap = 1000) =>
  record({
    deliveries: Array.from({ length: n }, () => delivery()),
    timing: timing(100, Array(n - 1).fill(gap)),
  });
const windowRow = (left, right, kd = windowKd) =>
  compareProjections(projection({ w: left }), projection({ w: right }), { knownDifferences: [kd] })
    .rows[0];

test("an observation window compares the shorter side only when it holds the minimum of attempts, and says so", () => {
  const covered = windowRow(attempts(8), attempts(5));
  assert.equal(covered.structure, "KNOWN_DIFFERENCE");
  assert.deepEqual(covered.parts.deliveries, {
    verdict: "KNOWN_DIFFERENCE",
    knownDifferences: ["KD-W"],
  });
  assert.deepEqual(covered.observationWindow, { attempts: { left: 8, right: 5 }, compared: 5 });
  assert.equal(covered.timing.verdict, "WITHIN");
  assert.equal(windowRow(attempts(8), attempts(4)).structure, "MISMATCH", "below the minimum");
  assert.equal(
    windowRow(attempts(5), attempts(5)).structure,
    "MATCH",
    "equal counts need no window",
  );
  assert.equal(windowRow(attempts(5), attempts(5)).observationWindow, undefined);
  const other = compareProjections(projection({ x: attempts(8) }), projection({ x: attempts(5) }), {
    knownDifferences: [windowKd],
  }).rows[0];
  assert.equal(other.structure, "MISMATCH", "another case has no window");
});

test("inside the window a difference of content or of a gap is still a difference", () => {
  const changed = attempts(8);
  changed.deliveries[2] = delivery({ context: { ...delivery().context, retryReason: "x" } });
  assert.equal(windowRow(attempts(5), changed).structure, "MISMATCH");
  assert.equal(
    windowRow(attempts(8), attempts(6, 5000)).timing.verdict,
    "OUTSIDE",
    "gaps are claimed",
  );
  assert.equal(windowRow(attempts(8, 4000), attempts(6, 4000)).timing.verdict, "WITHIN");
  // Attempts after the shorter side's last are not looked at, in structure or in timing.
  const longer = attempts(9);
  longer.timing.gapsMs[6] = 99999;
  assert.equal(windowRow(longer, attempts(6)).timing.verdict, "WITHIN");
});

test("a window needs a minimum of at least two attempts, and a timing known difference needs a bound", () => {
  for (const bad of [{ minAttempts: 1 }, { minAttempts: 2.5 }, {}, { minAttempts: "5" }])
    assert.throws(
      () => windowRow(attempts(8), attempts(5), { ...windowKd, window: bad }),
      /minimum of attempts/,
    );
  const timingKd = { id: "KD-T", part: "timing", cases: "*", paths: [/x/], ruling: 6, what: "w" };
  assert.throws(
    () =>
      compareProjections(projection({ a: record() }), projection({ a: record() }), {
        knownDifferences: [timingKd],
      }),
    /needs an allowance bound/,
  );
  assert.doesNotThrow(() =>
    compareProjections(projection({ a: record() }), projection({ a: record() }), {
      knownDifferences: [{ ...timingKd, allowance: () => null }],
    }),
  );
});

test("a timing allowance covers a timing only inside its own bound, and the row records the bound", () => {
  const kd = {
    id: "KD-T",
    part: "timing",
    cases: ["a"],
    paths: [/x/],
    ruling: 6,
    what: "w",
    allowance: ({ timing, tolerance }) =>
      timing.why === "first late" && Math.abs(timing.a - timing.b) - tolerance.firstMs <= 400
        ? { excessMs: Math.abs(timing.a - timing.b) - tolerance.firstMs }
        : null,
  };
  const late = (ms) => record({ timing: { ...timing(100), lateMs: [ms] } });
  const row = (ms) =>
    compareProjections(projection({ a: late(0) }), projection({ a: late(ms) }), {
      knownDifferences: [kd],
    }).rows[0];
  assert.equal(row(1000).timing.verdict, "WITHIN");
  const covered = row(1900);
  assert.equal(covered.timing.verdict, "KNOWN_DIFFERENCE");
  assert.deepEqual(covered.timing.allowance, { excessMs: 400 });
  assert.equal(covered.timingKnownDifference, "KD-T");
  assert.equal(row(1901).timing.verdict, "OUTSIDE");
  const result = compareProjections(projection({ a: late(0) }), projection({ a: late(1900) }), {
    knownDifferences: [kd],
  });
  assert.equal(result.knownDifferences[0].rows, 1);
  assert.equal(result.knownDifferences[0].bounded, true);
  const quiet = compareProjections(projection({ a: late(0) }), projection({ a: late(10) }), {
    knownDifferences: [kd],
  });
  assert.equal(quiet.knownDifferences[0].rows, 0);
  assert.equal(
    compareProjections(projection({ b: late(0) }), projection({ b: late(1900) }), {
      knownDifferences: [kd],
    }).rows[0].timing.verdict,
    "OUTSIDE",
    "another case",
  );
});

test("the first delivery is compared by its lateness after the ETA when both sides have it", () => {
  const t = (first, late) => ({ ...timing(first), lateMs: [late] });
  assert.equal(
    compareTiming(t(5000, 40), t(2000, 80)).verdict,
    "WITHIN",
    "the delay from the create time is not looked at",
  );
  assert.deepEqual(compareTiming(t(100, 40), t(100, 40 + TOLERANCE.firstMs + 1)), {
    verdict: "OUTSIDE",
    why: "first late",
    a: 40,
    b: 40 + TOLERANCE.firstMs + 1,
  });
  assert.equal(
    compareTiming(t(100, 40), t(100, 40 + TOLERANCE.firstMs)).verdict,
    "WITHIN",
    "inclusive",
  );
  // One side without an ETA falls back to the delay from the create time.
  const without = { ...timing(100), lateMs: [null] };
  assert.deepEqual(
    compareTiming(t(100, 40), { ...without, firstMs: 100 + TOLERANCE.firstMs + 1 }),
    { verdict: "OUTSIDE", why: "first", a: 100, b: 100 + TOLERANCE.firstMs + 1 },
  );
  assert.equal(compareTiming(timing(100), timing(100)).verdict, "WITHIN", "no lateMs at all");
});

test("a layout rule that changed something is counted although the part ends as a known difference", () => {
  const withIds = (id, name) =>
    record({
      deliveries: [
        delivery({
          request: {
            ...delivery().request,
            headers: { ...delivery().request.headers, taskName: id },
            path: name,
          },
        }),
      ],
    });
  const kd = {
    id: "KD-P",
    part: "deliveries",
    cases: "*",
    paths: [/^\[\]\/request\/path$/],
    ruling: 3,
    what: "w",
  };
  const result = compareProjections(
    projection({ a: withIds("ID(19)", "/x") }),
    projection({ a: withIds("ID(20)", "/y") }),
    { knownDifferences: [kd] },
  );
  assert.equal(result.rows[0].structure, "KNOWN_DIFFERENCE");
  assert.equal(result.layoutRules.find((rule) => rule.id === "numeric-id-length").rows, 1);
});
