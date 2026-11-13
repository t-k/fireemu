import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { classify, latencyClass } from "./answer.mjs";
import { CELLS_V5 } from "./program-v5.mjs";

import {
  combineRuns as combineRunsFull,
  EXPECT,
  inWindow,
  judgeRun,
  judgeRunV5,
  prerequisite,
  readOutcome,
  WINDOW_EDGE_MS,
  window,
} from "./judge.mjs";
import { CELLS } from "./program.mjs";
import { prng, record } from "./support.mjs";

// The combined answers; `combineRunsFull` also says whether any rule may be written (S3).
const combineRuns = (a, b) => combineRunsFull(a, b).answers;

const judged = async (params) => {
  const { run } = record({ params });
  const out = await run();
  return { ...judgeRun(out.records), records: out.records };
};
const base = await judged({});
const A = base.answers;

const step = (
  status,
  latency,
  kind = status >= 200 && status < 300 ? "ok" : "error",
  extra = {},
) => ({ i: 0, op: "getSub", status, latency, kind, ageMs: 1000, ...extra });

test("read outcomes", () => {
  assert.equal(readOutcome(step(404, "fast")), "hit");
  assert.equal(readOutcome(step(404, "slow")), "miss");
  assert.equal(readOutcome(step(404, "ambiguous")), "ambiguous");
  assert.equal(readOutcome(step(200, "slow")), "ok");
  assert.equal(readOutcome(step(200, "fast")), "ok");
  assert.equal(readOutcome(step(409, "slow")), "other");
  assert.equal(readOutcome(step(null, "unknown", "unknown")), "other");
  assert.equal(readOutcome(undefined), "other");
});

test("a window is read from the hit and miss pattern in age order", () => {
  const record = {
    arm: 0,
    steps: [0, 1, 2, 3, 4].map((i) => ({
      i,
      op: "getSub",
      ageMs: i === 0 ? 0 : i * 3000,
      ...(i < 3 ? step(404, "fast") : step(200, "slow")),
    })),
  };
  record.steps.forEach((s, i) => ((s.i = i), (s.ageMs = i * 3000)));
  const w = window(record, 1);
  assert.equal(w.lastHit, 6000);
  assert.equal(w.firstMiss, 9000);
  assert.ok(w.consistent);
  record.steps[4] = { ...step(404, "fast"), i: 4, ageMs: 12000 };
  assert.ok(!window(record, 1).consistent, "a hit after a miss is inconsistent");
  record.steps[4] = { ...step(404, "ambiguous"), i: 4, ageMs: 12000 };
  assert.ok(!window(record, 1).consistent, "an ambiguous latency is inconsistent");
});

test("a prerequisite that fails voids the cell", () => {
  const rec = base.records.find((r) => r.id === "N2a");
  assert.ok(prerequisite(rec).ok);
  const broken = structuredClone(rec);
  broken.steps[0].status = 200;
  assert.ok(!prerequisite(broken).ok);
  assert.match(prerequisite(broken).reason, /step 0 answered 200, expected 404/);
  const cut = { id: "N2a", aborted: "request cap", steps: [rec.steps[0]] };
  assert.ok(!prerequisite(cut).ok);
  assert.ok(!prerequisite({ id: "nope", steps: [] }).ok);
  assert.equal(Object.keys(EXPECT).length, CELLS.length);
});

test("the baseline world reads as the provisional rule", () => {
  assert.deepEqual(base.invalid, {});
  assert.equal(base.valid.length, 33);
  assert.equal(A.ttl.verdict, "window");
  assert.ok(A.ttl.lastHitMs < 9600 && A.ttl.firstMissMs >= 9600, JSON.stringify(A.ttl));
  assert.deepEqual([A.arm.A1, A.arm.A7, A.arm.A9], ["arms", "arms", "arms"]);
  assert.deepEqual(
    [A.arm.A2, A.arm.A3, A.arm.A4, A.arm.A5, A.arm.A8],
    Array(5).fill("does-not-arm"),
  );
  assert.deepEqual(A.arm.seek, { arms: 0, of: 3, other: 0 });
  assert.equal(A.absent.pureNegative, "served");
  assert.equal(A.absent.existingServed, "served");
  assert.deepEqual(A.body, { urlName: "does-not-clear", otherName: "clears" });
  assert.deepEqual(
    [A.serve.V1, A.serve.V2, A.serve.V3, A.serve.V4],
    Array(4).fill("reaches-backend"),
  );
  assert.equal(A.serve.V3applied, "yes");
  assert.equal(A.serve.V4present, "no");
  assert.equal(A.rearm.deleteHit, "not-applicable", "the DELETE reached the backend");
  assert.equal(A.rearm.getHitExtends, "no");
  assert.deepEqual(A.exempt, { "4000ms": "exempt", "7000ms": "exempt", "13000ms": "armed" });
  assert.deepEqual(A.key, {
    queryAltJson: "shared",
    queryFields: "shared",
    snapshotSameId: "separate",
    grpc: "separate",
    topic: "separate",
  });
  assert.deepEqual(A.conn, { grid_a_existing: "same", grid_b_existing: "same", base: "same" });
});

// Every alternative of the open questions reads differently from the baseline in the intended answer.
const flips = [
  ["window 8.5 s", { ttl: 8500 }, (a) => a.ttl.lastHitMs < 8500 && a.ttl.verdict === "window"],
  [
    "window 10.5 s",
    { ttl: 10500 },
    (a) => a.ttl.lastHitMs >= 10200 || a.ttl.firstMissMs === null || a.ttl.firstMissMs > 10200,
  ],
  [
    "absent names not served",
    { absentServed: false },
    (a) => a.absent.pureNegative === "not-served" && a.absent.existingServed === "served",
  ],
  [
    "a body name clears nothing",
    { bodyClear: "none" },
    (a) => a.body.otherName === "does-not-clear",
  ],
  ["a body name clears its own URL too", { bodyClear: "all" }, (a) => a.body.urlName === "clears"],
  [
    "DELETE 404 arms",
    { armers: ["getSub", "getSnap", "putSub", "putSnap", "deleteSub"] },
    (a) => a.arm.A2 === "arms" && a.arm.A3 === "does-not-arm",
  ],
  [
    "PATCH 404 arms",
    { armers: ["getSub", "getSnap", "putSub", "putSnap", "patchSub"] },
    (a) => a.arm.A3 === "arms",
  ],
  [
    "pull 404 arms",
    { armers: ["getSub", "getSnap", "putSub", "putSnap", "pullSub"] },
    (a) => a.arm.A4 === "arms",
  ],
  [
    "getIamPolicy 404 arms",
    { armers: ["getSub", "getSnap", "putSub", "putSnap", "getIamSub"] },
    (a) => a.arm.A5 === "arms",
  ],
  [
    "seek 404 arms",
    { armers: ["getSub", "getSnap", "putSub", "putSnap", "seekSub"] },
    (a) => a.arm.seek.arms === 3,
  ],
  [
    "snapshot DELETE 404 arms",
    { armers: ["getSub", "getSnap", "putSub", "putSnap", "deleteSnap"] },
    (a) => a.arm.A8 === "arms",
  ],
  [
    "a failed create does not arm",
    { armers: ["getSub", "getSnap"] },
    (a) => a.arm.A1 === "does-not-arm" && a.arm.A9 === "does-not-arm",
  ],
  [
    "DELETE is answered from the entry",
    { served: ["getSub", "getSnap", "deleteSub"] },
    (a) => a.serve.V4 === "answered-from-entry" && a.serve.V4present === "yes",
  ],
  [
    "getIamPolicy is answered from the entry",
    { served: ["getSub", "getSnap", "getIamSub"] },
    (a) => a.serve.V1 === "answered-from-entry",
  ],
  [
    "pull is answered from the entry",
    { served: ["getSub", "getSnap", "pullSub"] },
    (a) => a.serve.V2 === "answered-from-entry",
  ],
  [
    "PATCH is answered from the entry",
    { served: ["getSub", "getSnap", "patchSub"] },
    (a) => a.serve.V3 === "answered-from-entry" && a.serve.V3applied === "no",
  ],
  [
    "a DELETE hit re-arms the entry",
    { served: ["getSub", "getSnap", "deleteSub"], deleteHitRearms: true },
    (a) => a.rearm.deleteHit === "re-armed",
  ],
  [
    "a GET hit extends the entry",
    { getHitRearms: true },
    (a) => a.rearm.getHitExtends === "yes-or-window-over-10.5s" && a.ttl.verdict === "open",
  ],
  ["no positive exemption", { positiveExempt: false }, (a) => a.exempt["4000ms"] === "armed"],
  [
    "a short exemption",
    { exemptTtl: 5000 },
    (a) => a.exempt["4000ms"] === "exempt" && a.exempt["7000ms"] === "armed",
  ],
  [
    "the query string is part of the key",
    { keyIncludesQuery: true },
    (a) => a.key.queryAltJson === "separate" && a.key.queryFields === "separate",
  ],
  ["kinds share the key", { kindsShared: true }, (a) => a.key.snapshotSameId === "shared"],
  ["gRPC shares the entry", { grpcShared: true }, (a) => a.key.grpc === "shared"],
  [
    "entries are per connection",
    { connAffinity: true },
    (a) => a.conn.base === "differs" && a.conn.grid_a_existing === "differs",
  ],
];
for (const [name, params, check] of flips)
  test(`flip: ${name}`, async () => {
    const { answers } = await judged(params);
    assert.ok(check(answers), JSON.stringify(answers));
    assert.notDeepEqual(answers, A);
  });

test("a failed create of an existing name that answers 409 voids the E cells and the rest still read", async () => {
  const { answers, invalid } = await judged({ existingMissingTopic: 409 });
  assert.deepEqual(
    Object.keys(invalid).toSorted(),
    ["A6.1", "A6.2", "A6.3", "D1", "D2", "E1", "E2", "E3", "E4", "N5"]
      .toSorted()
      .filter((id) => id in invalid),
  );
  for (const id of ["E1", "E2", "E3", "E4", "N5"]) assert.ok(id in invalid, id);
  assert.equal(answers.ttl.verdict, "window");
  assert.equal(answers.absent.existingServed, "no-data");
});

test("two recordings answer a question only where they agree", async () => {
  const second = await judged({ ttl: 8500 });
  const combined = combineRuns(base, second);
  assert.deepEqual(combined.arm.A1, "arms");
  // Windows that do not overlap are inconsistent, whatever each run said alone.
  assert.equal(combined.ttl.verdict, "inconsistent");
  assert.deepEqual(combineRuns(base, base), {
    ...A,
    calibration: { runs: [A.calibration, A.calibration] },
  });
  const flipped = await judged({ bodyClear: "none" });
  assert.deepEqual(combineRuns(base, flipped).body.otherName.mixed, ["clears", "does-not-clear"]);
});

test("window bounds of two runs are combined as intervals: ages 30 ms apart give max(last hit) and min(first miss)", () => {
  const run = (lastHitMs, firstMissMs, verdict = "window") => ({
    answers: {
      ttl: { cells: ["E1"], lastHitMs, firstMissMs, verdict },
      rearm: { afterSeek: [null, null] },
    },
  });
  assert.deepEqual(combineRuns(run(9400, 9900), run(9430, 9880)).ttl, {
    cells: ["E1"],
    excludedCells: [],
    lastHitMs: 9430,
    firstMissMs: 9880,
    verdict: "window",
  });
  assert.equal(combineRuns(run(9400, 9900), run(9950, 10300)).ttl.verdict, "inconsistent");
  assert.deepEqual(combineRuns(run(9400, 9900), run(9400, 9900, "open")).ttl.verdict, {
    mixed: ["window", "open"],
  });
  assert.equal(combineRuns(run(null, 9900), run(9400, null)).ttl.lastHitMs, 9400);
  const seek = (a) => ({
    answers: {
      ttl: { cells: [], lastHitMs: null, firstMissMs: null, verdict: "no-data" },
      rearm: { afterSeek: a },
    },
  });
  assert.deepEqual(combineRuns(seek([3000, null]), seek([3010, null])).rearm.afterSeek, [
    3010,
    null,
  ]);
  assert.ok(combineRuns(seek([3000, null]), seek([null, null])).rearm.afterSeek.mixed);
});

test("a read of a forwarded answer after the window is inconclusive, not 'never armed'", async () => {
  // Slow creates push the first read of the snapshot cells past the window.
  const { answers } = await judged({ ttl: 9600, positiveExempt: true });
  const rec = structuredClone(base.records.find((r) => r.id === "A8"));
  rec.steps[2] = { ...rec.steps[2], status: 200, kind: "ok", latency: "slow", ageMs: 9800 };
  const out = judgeRun([...base.records.filter((r) => r.id !== "A8"), rec]);
  assert.equal(out.answers.arm.A8, "inconclusive");
  assert.ok(answers);
});

const recordOf = (id) => structuredClone(base.records.find((r) => r.id === id));
const withRecords = (...replacements) => {
  const ids = new Set(replacements.map((r) => r.id));
  return judgeRun([...base.records.filter((r) => !ids.has(r.id)), ...replacements]);
};
const setStep = (rec, i, patch) => {
  Object.assign(
    rec.steps.find((s) => s.i === i),
    patch,
  );
  return rec;
};
const HIT = { status: 404, kind: "error", latency: "fast" };
const OK = { status: 200, kind: "ok", latency: "slow" };
const MISS = { status: 404, kind: "error", latency: "slow" };

test("the window edge is 9400 ms and a step without an age is not inside it", () => {
  assert.equal(WINDOW_EDGE_MS, 9400);
  assert.ok(inWindow({ ageMs: 9399 }));
  assert.ok(!inWindow({ ageMs: 9400 }));
  assert.ok(!inWindow({ ageMs: null }));
  assert.ok(!inWindow(undefined));
});

test("a cell with exactly the expected leading steps passes; a step without an age is not read", () => {
  assert.ok(prerequisite({ id: "N1", aborted: null, steps: [{ status: 404 }] }).ok);
  const rec = { arm: 0, steps: [{ i: 1, op: "getSub", ageMs: null, ...HIT }] };
  assert.deepEqual(window(rec, 1).items, []);
  assert.equal(window(rec, 1).lastHit, null);
  assert.equal(window(rec, 1).firstMiss, null);
});

test("with no hit at all the window reports null and an open window reports a null first miss", async () => {
  const { answers } = await judged({ armers: [] });
  assert.equal(answers.ttl.lastHitMs, null);
  const open = await judged({ getHitRearms: true });
  assert.equal(open.answers.ttl.firstMissMs, null);
  assert.equal(open.answers.ttl.verdict, "open");
});

test("an ambiguous latency makes the window inconsistent even when hits precede misses", () => {
  const e1 = setStep(recordOf("E1"), 5, { latency: "ambiguous" });
  assert.equal(withRecords(e1).answers.ttl.verdict, "inconsistent");
});

test("a hit and a miss at the same age are inconsistent", () => {
  const e1 = recordOf("E1");
  const e2 = recordOf("E3");
  const a = e1.steps.find((s) => s.i === 5);
  const b = e2.steps.find((s) => s.i === 5);
  Object.assign(a, HIT, { ageMs: 9300 });
  Object.assign(b, OK, { ageMs: 9300 });
  for (const rec of [e1, e2])
    rec.steps.filter((s) => s.i > 5).forEach((s) => Object.assign(s, { ...OK, ageMs: s.ageMs }));
  for (const id of ["E3", "E4", "N2a", "N2b"]) {
    const rec = recordOf(id);
    rec.steps
      .filter((s) => s.i > rec.arm)
      .forEach((s) => Object.assign(s, OK, { ageMs: 12000 + s.i }));
    Object.assign(e1, e1);
    if (id === "E3") e1.id = "E1";
  }
  const out = judgeRun([e1, e2]);
  assert.equal(out.answers.ttl.verdict, "inconsistent");
});

test("N1 reads: two slow answers or an in-window 200 mean not served; mixed answers stay mixed", () => {
  const n1 = recordOf("N1");
  setStep(n1, 1, MISS);
  setStep(n1, 2, OK);
  assert.equal(withRecords(n1).answers.absent.pureNegative, "not-served");
  setStep(n1, 2, { status: 500, kind: "error", latency: "slow" });
  assert.equal(withRecords(n1).answers.absent.pureNegative, "no-data");
  assert.match(withRecords(n1).invalid.N1, /unknown/);
});

test("a forwarded 200 outside the window does not show that the probe reached the backend", () => {
  const v1 = setStep(recordOf("V1"), 2, { ...OK, ageMs: 9800 });
  assert.equal(withRecords(v1).answers.serve.V1, "mixed");
  const v1b = setStep(recordOf("V1"), 2, { ...OK, ageMs: 5000 });
  assert.equal(withRecords(v1b).answers.serve.V1, "reaches-backend");
  const v1c = setStep(recordOf("V1"), 2, { ...HIT, ageMs: 5000 });
  assert.equal(withRecords(v1c).answers.serve.V1, "answered-from-entry");
});

test("a LIST that was not read, or has no subscriptions, is reported as such", () => {
  const v4 = setStep(recordOf("V4"), 3, { body: null });
  assert.equal(withRecords(v4).answers.serve.V4present, "unread");
  const v4a = setStep(recordOf("V4"), 3, {
    ...MISS,
    body: { subscriptions: [{ name: "x-nc-v4-x" }] },
  });
  assert.equal(withRecords(v4a).answers.serve.V4present, "unread");
  const v4b = setStep(recordOf("V4"), 3, { body: { complete: true } });
  assert.equal(withRecords(v4b).answers.serve.V4present, "no");
  const v4c = setStep(recordOf("V4"), 3, {
    body: { complete: true, subscriptions: [{ name: "x-nc-v4-x" }] },
  });
  const v4d = setStep(recordOf("V4"), 3, {
    body: { complete: false, subscriptions: [{ name: "x-nc-v4-x" }] },
  });
  assert.equal(
    withRecords(v4d).answers.serve.V4present,
    "unread",
    "a first page of several shows nothing absent",
  );
  assert.equal(withRecords(v4c).answers.serve.V4present, "yes");
});

test("exemption reads: inconclusive late reads, mixed errors", () => {
  const p1 = setStep(recordOf("P1"), 5, { ...OK, ageMs: 9800 });
  assert.equal(withRecords(p1).answers.exempt["4000ms"], "inconclusive");
  const p1b = setStep(recordOf("P1"), 5, { status: 409, kind: "error", latency: "slow" });
  assert.equal(withRecords(p1b).answers.exempt["4000ms"], "mixed");
  const p1c = setStep(recordOf("P1"), 5, { ...HIT });
  assert.equal(withRecords(p1c).answers.exempt["4000ms"], "armed");
});

test("the connection comparison needs both cells", () => {
  const e2 = recordOf("E2");
  e2.steps[1].status = 200;
  assert.equal(withRecords(e2).answers.conn.grid_a_existing, "no-data");
  const e1 = recordOf("E1");
  e1.steps[1].status = 200;
  assert.equal(withRecords(e1).answers.conn.grid_a_existing, "no-data");
});

test("combining runs keeps nulls and objects apart and agrees on equal values", () => {
  const a = { answers: { k: null, o: { z: 1 }, same: [1, 2] } };
  const b = { answers: { k: { z: 1 }, o: null, same: [1, 2] } };
  const merged = combineRuns(a, b);
  assert.deepEqual(merged.k, { mixed: [null, { z: 1 }] });
  assert.deepEqual(merged.o, { mixed: [{ z: 1 }, null] });
  assert.deepEqual(merged.same, [1, 2]);
  assert.deepEqual(combineRuns({ answers: { k: null } }, { answers: { k: null } }), { k: null });
});

test("a hit on the first read after a seek is the window after the seek", () => {
  const d1 = setStep(recordOf("D1"), 2, { ...HIT, ageMs: 3000 });
  assert.deepEqual(withRecords(d1).answers.rearm.afterSeek[0], 3000);
});

test("conn: an ambiguous or unexpected read in either cell says no-data, not differs", () => {
  const e2 = setStep(recordOf("E2"), 3, { latency: "ambiguous" });
  assert.equal(withRecords(e2).answers.conn.grid_a_existing, "no-data");
  const e2b = setStep(recordOf("E2"), 3, { status: 500, kind: "error", latency: "slow" });
  assert.equal(withRecords(e2b).answers.conn.grid_a_existing, "no-data");
  const e2c = setStep(recordOf("E2"), 3, { ...MISS });
  assert.equal(
    withRecords(e2c).answers.conn.grid_a_existing,
    "differs",
    "clear outcomes that differ are a difference",
  );
});

test("calibration answers: forwarded GETs, handshake, the empty pull, and the failed create of an existing name", () => {
  const c = base.answers.calibration;
  assert.equal(c.latencyClassesHold, true);
  assert.ok(c.forwardedGetMs.dedicated >= 120 && c.forwardedGetMs.fresh >= 120);
  assert.deepEqual(c.emptyPull.status, 200);
  assert.equal(c.failedCreateOnExisting, 404);
  assert.equal(c.failedCreateArms, true, "the fake production arms a failed create");
  const c0 = recordOf("C0f");
  c0.steps.forEach((s) => (s.headersMs = 40));
  assert.equal(
    withRecords(c0).answers.calibration.latencyClassesHold,
    false,
    "forwarded GETs that look cached break the classes",
  );
});

test("a skipped cell is reported with its reason and contributes nothing", async () => {
  const { invalid, valid } = await judged({ existingMissingTopic: 409 });
  for (const id of ["E1", "E2", "E3", "E4", "N5"])
    assert.match(invalid[id], /^skipped: calibration failedCreateExisting answered 409/);
  assert.ok(!valid.includes("E1"));
});

test("calibration: nothing recorded reads as null, the classes hold only when both medians reach 120 ms, the pull is the pull", () => {
  const without = judgeRun(base.records.filter((r) => !["C0d", "C0f"].includes(r.id)));
  assert.deepEqual(without.answers.calibration.forwardedGetMs, { dedicated: null, fresh: null });
  assert.equal(without.answers.calibration.latencyClassesHold, "no-data");
  assert.equal(without.answers.calibration.emptyPull, "no-data");
  const set = (d, f) => {
    const cd = recordOf("C0d");
    cd.steps.filter((s) => s.op === "getTopic").forEach((s) => (s.headersMs = d));
    const cf = recordOf("C0f");
    cf.steps.forEach((s) => (s.headersMs = f));
    return withRecords(cd, cf).answers.calibration;
  };
  assert.equal(set(120, 120).latencyClassesHold, true);
  assert.equal(set(119, 500).latencyClassesHold, false);
  assert.equal(set(500, 119).latencyClassesHold, false);
  const cd = recordOf("C0d");
  cd.steps.find((s) => s.op === "pullSub").headersMs = 777;
  assert.equal(withRecords(cd).answers.calibration.emptyPull.headersMs, 777);
  assert.equal(withRecords(cd).answers.calibration.freshConnectMs, 0);
  // A C2 whose prerequisite failed still reports what its failed create answered.
  const c2 = recordOf("C2");
  c2.steps[0].status = 500;
  c2.steps[1].status = 409;
  assert.equal(withRecords(c2).answers.calibration.failedCreateOnExisting, 409);
  assert.equal(
    judgeRun(base.records.filter((r) => r.id !== "C2")).answers.calibration.failedCreateOnExisting,
    "no-data",
  );
});

test("combine: a side without ttl, rearm or calibration does not crash, equal bounds are inconsistent, a missing bound is not zero", () => {
  const ttl = (a, b, verdict = "window") => ({
    ttl: { cells: ["E1"], lastHitMs: a, firstMissMs: b, verdict },
  });
  const run = (extra) => ({ answers: extra });
  assert.ok(combineRuns(run({ ...ttl(1, 2) }), run({})).ttl.mixed);
  assert.ok(combineRuns(run({ rearm: { afterSeek: [null] } }), run({})).rearm.mixed);
  assert.ok(combineRuns(run({ calibration: { a: 1 } }), run({})).calibration.mixed);
  assert.equal(combineRuns(run(ttl(9400, 9400)), run(ttl(9400, 9400))).ttl.verdict, "inconsistent");
  const open = combineRuns(run(ttl(9400, null, "open")), run(ttl(9400, null, "open"))).ttl;
  assert.equal(open.verdict, "open");
  assert.equal(open.firstMissMs, null);
  const mixedBounds = combineRuns(run(ttl(null, 9900)), run(ttl(9400, null))).ttl;
  assert.deepEqual([mixedBounds.lastHitMs, mixedBounds.firstMissMs], [9400, 9900]);
  assert.equal(mixedBounds.verdict, "window");
});

test("calibration: one missing side of the forwarded-GET comparison is no-data, and an empty window keeps strict nulls", () => {
  const onlyFresh = judgeRun(base.records.filter((r) => r.id !== "C0d")).answers.calibration;
  assert.equal(onlyFresh.latencyClassesHold, "no-data");
  assert.equal(onlyFresh.forwardedGetMs.dedicated, null);
  const onlyDedicated = judgeRun(base.records.filter((r) => r.id !== "C0f")).answers.calibration;
  assert.equal(onlyDedicated.latencyClassesHold, "no-data");
  assert.equal(onlyDedicated.forwardedGetMs.fresh, null);
  const none = {
    answers: { ttl: { cells: [], lastHitMs: null, firstMissMs: null, verdict: "no-data" } },
  };
  const merged = combineRuns(none, none).ttl;
  assert.ok(merged.lastHitMs === null && merged.firstMissMs === null);
});

test("S3: no rule is written unless forwarded GETs classified as slow in both runs", async () => {
  const slowCalib = (v) => ({ answers: { calibration: { latencyClassesHold: v } } });
  const ok = combineRunsFull(slowCalib(true), slowCalib(true));
  assert.equal(ok.rulesAllowed, true);
  assert.equal(ok.withheld, undefined);
  for (const [a, b] of [
    [true, false],
    [false, true],
    [false, false],
    [true, "no-data"],
    ["no-data", true],
    [true, undefined],
  ]) {
    const out = combineRunsFull(slowCalib(a), slowCalib(b));
    assert.equal(out.rulesAllowed, false, `${a} ${b}`);
    assert.match(
      out.withheld,
      /latencyClassesHold is .* not true in both runs: no rule is written/,
    );
  }
  assert.equal(combineRunsFull({ answers: {} }, { answers: {} }).rulesAllowed, false);
  // A real pair of runs on the fake production passes the gate.
  assert.equal(combineRunsFull(base, base).rulesAllowed, true);
  const slowFresh = recordOf("C0f");
  slowFresh.steps.forEach((s) => (s.headersMs = 40));
  assert.equal(combineRunsFull(base, withRecords(slowFresh)).rulesAllowed, false);
});

// The published recordings contain status and timing only; replay them without inventing bodies.
const recordings = [1, 2].map((n) =>
  JSON.parse(
    readFileSync(
      new URL(`../../pubsub-negcache/recordings/run-${n}.json`, import.meta.url),
      "utf8",
    ),
  ),
);
const recordedCells = recordings.map(({ requests }) =>
  CELLS.flatMap((cell) => {
    const rows = requests.filter((r) => r.cell === cell.id);
    if (!rows.length) return [];
    const arm = rows.find((r) => r.step === cell.arm);
    return [
      {
        id: cell.id,
        conn: rows[0].conn,
        arm: cell.arm,
        aborted: null,
        steps: rows.map((r) => ({
          i: r.step,
          op: cell.steps[r.step].op,
          status: r.status,
          kind: r.status === 200 ? "ok" : "error",
          headersMs: r.headersMs,
          latency: latencyClass(r.headersMs),
          startedMs: r.startedAtMs - rows[0].startedAtMs,
          ageMs: r.step < cell.arm ? null : r.startedAtMs - arm.startedAtMs,
        })),
      },
    ];
  }),
);

test("recorded v4 runs reproduce the pooled inconsistency and combine only dedicated TTL evidence", () => {
  const old = JSON.parse(
    readFileSync(
      new URL("../../pubsub-negcache/recordings/combined-runs.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(old.answers.ttl.verdict, "inconsistent");
  const pooled = recordedCells.map((records) =>
    judgeRun(records.map((r) => ({ ...r, conn: "dedicated" }))),
  );
  assert.equal(combineRuns(...pooled).ttl.verdict, "inconsistent");
  const runs = recordedCells.map((records) => ({ ...judgeRun(records), records }));
  const fixed = combineRuns(...runs).ttl;
  assert.notEqual(fixed.verdict, "inconsistent");
  assert.equal(fixed.verdict, "open");
  assert.deepEqual(fixed.cells, ["N2a"]);
  assert.ok(fixed.excludedCells.includes("N2b"));
  assert.ok(fixed.lastHitMs >= 10200);
  assert.equal(fixed.firstMissMs, null);
  // Stale summaries are rejudged from their records, not their old pooled bounds.
  assert.deepEqual(combineRuns(...runs.map((r) => ({ ...r, answers: old.answers }))).ttl, fixed);
});

test("a fresh-connection hit after a dedicated miss cannot make the combined TTL inconsistent", () => {
  const dedicated = recordOf("N2a");
  const fresh = recordOf("N2b");
  for (const r of [dedicated, fresh])
    for (const s of r.steps.filter((s) => s.i >= 2))
      Object.assign(s, r === dedicated ? OK : HIT, { ageMs: r === dedicated ? 10000 : 11000 });
  const judged = judgeRun([dedicated, fresh]);
  const ttl = combineRuns(judged, judged).ttl;
  assert.equal(ttl.verdict, "window");
  assert.equal(ttl.lastHitMs, null);
  assert.equal(ttl.firstMissMs, 10000);
  assert.deepEqual(ttl.cells, ["N2a"]);
  assert.deepEqual(ttl.excludedCells, ["N2b"]);
});

const v5Base = (await record({ cells: CELLS_V5 }).run()).records;
const probeOf = (r) => r.steps.find((s) => s.i > r.arm && s.op === "getSub");

test("v5 uses the existing fake world and reports all four questions", () => {
  const result = judgeRunV5(v5Base);
  assert.deepEqual(result.invalid, {});
  assert.equal(result.valid.length, 44);
  assert.equal(result.answers.calibration.latencyClassesHold, true);
  assert.equal(result.answers.deleteArms, "no");
  assert.equal(result.answers.neverCreatedActivationMs, "mixed", "all hits give no lower bound");
  assert.deepEqual(result.answers.recent200Exempts, {
    4000: "exempt",
    7000: "exempt",
    13000: "not-exempt",
  });
  for (const rows of Object.values(result.answers.recent200Readings))
    for (const row of rows) assert.equal(row.since200Ms, row.requestedMs);
  assert.equal(result.answers.windowEdge.verdict, "window");
  assert.deepEqual(
    result.answers.windowEdge.cells,
    CELLS_V5.filter((c) => c.id.startsWith("W")).map((c) => c.id),
  );
});

test("v5 replays every recorded 404 and 200 GET with the original latency classes and measured ages", () => {
  for (const records of recordedCells) {
    const calibration = records.filter((r) => ["C0d", "C0f"].includes(r.id));
    assert.equal(judgeRunV5(calibration).answers.calibration.latencyClassesHold, true);
    for (const record of records)
      for (const answer of record.steps) {
        if (answer.op !== "getSub" || ![200, 404].includes(answer.status) || answer.ageMs === null)
          continue;
        const cell = structuredClone(v5Base.find((r) => r.id === "W25a"));
        cell.conn = record.conn;
        const probe = probeOf(cell);
        Object.assign(probe, answer, { i: probe.i, op: probe.op });
        const result = judgeRunV5([...calibration, cell]);
        const row = result.answers.windowEdge.buckets[10250][0];
        const outcome = readOutcome(answer);
        assert.equal(row.outcome, outcome === "ok" ? "miss" : outcome);
        assert.equal(row.ageMs, answer.ageMs);
        assert.equal(row.conn, record.conn);
        assert.equal(row.status, answer.status);
        assert.equal(result.answers.ttl.cells.includes(cell.id), record.conn === "dedicated");
        assert.equal(
          result.answers.ttl.excludedCells.includes(cell.id),
          record.conn !== "dedicated",
        );
      }
  }
});

test("v5 DELETE verdict uses measured ages, includes 10200 ms, and cannot prove yes with no in-window reads", () => {
  const records = structuredClone(v5Base);
  const deletes = records.filter((r) => r.id.startsWith("DA"));
  for (const [i, r] of deletes.entries())
    Object.assign(probeOf(r), HIT, { headersMs: 20, ageMs: i < 6 ? 10200 : 10500 });
  for (const r of deletes.slice(6)) Object.assign(probeOf(r), OK, { headersMs: 300 });
  let out = judgeRunV5(records).answers;
  assert.equal(out.deleteArms, "yes");
  assert.deepEqual(Object.keys(out.deleteArming), ["6000", "7500", "9000", "10500"]);
  assert.ok(Object.values(out.deleteArming).every((rows) => rows.length === 2));
  Object.assign(probeOf(deletes[0]), OK, { headersMs: 300 });
  assert.equal(judgeRunV5(records).answers.deleteArms, "mixed");
  for (const r of deletes) Object.assign(probeOf(r), HIT, { headersMs: 20, ageMs: 10201 });
  assert.equal(judgeRunV5(records).answers.deleteArms, "mixed");
  for (const r of deletes) Object.assign(probeOf(r), OK, { headersMs: 300 });
  assert.equal(judgeRunV5(records).answers.deleteArms, "no");
});

test("v5 never-created activation is a measured interval only when every miss precedes every hit", () => {
  const records = structuredClone(v5Base);
  const never = records.filter((r) => r.id.startsWith("N1"));
  for (const [i, r] of never.entries())
    Object.assign(probeOf(r), i < 8 ? MISS : HIT, {
      headersMs: i < 8 ? 300 : 20,
      ageMs: 3201 + i * 151,
    });
  const expected = [probeOf(never[7]).ageMs, probeOf(never[8]).ageMs];
  assert.deepEqual(judgeRunV5(records).answers.neverCreatedActivationMs, expected);
  for (const badAge of [expected[1], expected[1] + 1]) {
    probeOf(never[7]).ageMs = badAge;
    assert.equal(judgeRunV5(records).answers.neverCreatedActivationMs, "mixed");
  }
  probeOf(never[7]).ageMs = expected[0];
  probeOf(never[8]).headersMs = 90;
  assert.equal(judgeRunV5(records).answers.neverCreatedActivationMs, "mixed");
  for (const r of never) Object.assign(probeOf(r), MISS, { headersMs: 300 });
  assert.equal(
    judgeRunV5(records).answers.neverCreatedActivationMs,
    "mixed",
    "all misses give no upper bound",
  );
});

test("v5 subscription exemption needs both repeats and a 404 arm, and uses the final 200 even after a late create", () => {
  for (const seconds of [4, 7, 13]) {
    const records = structuredClone(v5Base);
    const pair = records.filter((r) => r.id.startsWith(`E200-${seconds}`));
    for (const r of pair) Object.assign(probeOf(r), OK, { headersMs: 300, ageMs: 15000 });
    assert.equal(judgeRunV5(records).answers.recent200Exempts[seconds * 1000], "exempt");
    Object.assign(probeOf(pair[0]), HIT, { headersMs: 20 });
    assert.equal(judgeRunV5(records).answers.recent200Exempts[seconds * 1000], "mixed");
    Object.assign(probeOf(pair[1]), HIT, { headersMs: 20 });
    assert.equal(judgeRunV5(records).answers.recent200Exempts[seconds * 1000], "not-exempt");
    pair[0].steps[pair[0].arm].status = 200;
    const result = judgeRunV5(records);
    assert.match(result.invalid[pair[0].id], /expected 404/);
    assert.equal(result.answers.recent200Exempts[seconds * 1000], "mixed");
    assert.equal(result.answers.recent200Readings[seconds * 1000].length, 1);
  }
});

test("v5 window bounds use late measured ages and exclude fresh hits in single and combined runs", () => {
  const first = structuredClone(v5Base);
  const second = structuredClone(v5Base);
  for (const records of [first, second]) {
    for (const r of records.filter((r) => r.id.startsWith("W"))) {
      const hit = r.id.startsWith("W25");
      Object.assign(probeOf(r), hit ? HIT : OK, {
        headersMs: hit ? 20 : 300,
        ageMs: hit ? 10360 : 10410,
      });
    }
    const fresh = records.find((r) => r.id === "W50b");
    fresh.conn = "fresh";
    Object.assign(probeOf(fresh), HIT, { headersMs: 20, ageMs: 15000 });
  }
  probeOf(second.find((r) => r.id === "W25a")).ageMs = 10370;
  probeOf(second.find((r) => r.id === "W30a")).ageMs = 10400;
  const combined = combineRunsFull(judgeRunV5(first), judgeRunV5(second));
  assert.equal(combined.rulesAllowed, true);
  for (const answer of [combined.answers.ttl, combined.answers.windowEdge]) {
    assert.equal(answer.verdict, "window");
    assert.equal(answer.lastHitMs, 10370);
    assert.equal(answer.firstMissMs, 10400);
    assert.deepEqual(answer.excludedCells, ["W50b"]);
    assert.ok(!answer.cells.includes("W50b"));
  }
  probeOf(second.find((r) => r.id === "W25a")).ageMs = 10400;
  assert.equal(
    combineRunsFull(judgeRunV5(first), judgeRunV5(second)).answers.windowEdge.verdict,
    "inconsistent",
  );
});

test("v5 combines activation intervals by measured ages and requires the calibration in both runs", () => {
  const records = structuredClone(v5Base);
  for (const [i, r] of records.filter((r) => r.id.startsWith("N1")).entries())
    Object.assign(probeOf(r), i < 8 ? MISS : HIT, {
      headersMs: i < 8 ? 300 : 20,
      ageMs: i < 8 ? 4000 : 4400,
    });
  const other = structuredClone(records);
  probeOf(other.find((r) => r.id === "N1a")).ageMs = 4100;
  probeOf(other.find((r) => r.id === "N1p")).ageMs = 4300;
  let combined = combineRunsFull(judgeRunV5(records), judgeRunV5(other));
  assert.deepEqual(combined.answers.neverCreatedActivationMs, [4100, 4300]);
  probeOf(other.find((r) => r.id === "N1p")).ageMs = 4000;
  combined = combineRunsFull(judgeRunV5(records), judgeRunV5(other));
  assert.equal(combined.answers.neverCreatedActivationMs, "mixed");
  other
    .find((r) => r.id === "C0f")
    .steps.forEach((s) => {
      s.headersMs = 20;
    });
  combined = combineRunsFull(judgeRunV5(records), judgeRunV5(other));
  assert.equal(combined.rulesAllowed, false);
});

test("every unknown answer in every v5 step invalidates the entire cell, including its final delete", () => {
  const unknowns = [
    { status: 199, bodyText: "{}" },
    { status: 302, bodyText: "{}" },
    { status: 500, bodyText: "{}" },
    { failure: "timeout" },
    { status: 200, bodyText: "<html>" },
    { status: 404, bodyText: "<html>" },
  ].map((raw) => classify({ ...raw, headersMs: 20 }));
  for (const cell of v5Base)
    for (const s of cell.steps)
      for (const unknown of unknowns) {
        const broken = structuredClone(cell);
        Object.assign(broken.steps[s.i], unknown);
        const result = judgeRunV5(v5Base.map((r) => (r.id === broken.id ? broken : r)));
        assert.match(result.invalid[broken.id], /unknown/, `${broken.id}/${s.i}`);
        assert.ok(!result.valid.includes(broken.id));
        for (const buckets of [
          result.answers.deleteArming,
          result.answers.neverCreated,
          result.answers.recent200Readings,
          result.answers.windowEdge.buckets,
        ])
          assert.ok(
            Object.values(buckets)
              .flat()
              .every((row) => row.id !== broken.id),
          );
      }
});

test("v5 rejects truncated cells and missing measured ages, while ambiguous reads never become hits or misses", () => {
  for (const cell of v5Base.filter((r) => !r.id.startsWith("C0"))) {
    const broken = structuredClone(cell);
    broken.steps.pop();
    assert.ok(judgeRunV5([broken]).invalid[cell.id]);
    const untimed = structuredClone(cell);
    probeOf(untimed).ageMs = null;
    assert.match(judgeRunV5([untimed]).invalid[cell.id], /measured age/);
    const ambiguous = structuredClone(cell);
    Object.assign(probeOf(ambiguous), HIT, { headersMs: 90 });
    const result = judgeRunV5([ambiguous]);
    const rows = [
      result.answers.deleteArming,
      result.answers.neverCreated,
      result.answers.recent200Readings,
      result.answers.windowEdge.buckets,
    ].flatMap((b) => Object.values(b).flat());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].outcome, "ambiguous");
  }
});

test("property: v5 edge bounds depend only on measured dedicated ages, regardless of record order or fresh outcomes", () => {
  const random = prng(51);
  for (let round = 0; round < 100; round++) {
    const records = structuredClone(v5Base);
    const edge = 10200 + random() * 600;
    const hits = [],
      misses = [];
    for (const r of records.filter((r) => r.id.startsWith("W"))) {
      const ageMs = 10200 + random() * 600;
      const dedicated = random() > 0.3;
      const hit = dedicated ? ageMs < edge : random() > 0.5;
      r.conn = dedicated ? "dedicated" : "fresh";
      Object.assign(probeOf(r), hit ? HIT : OK, { headersMs: hit ? 20 : 300, ageMs });
      if (dedicated) (hit ? hits : misses).push(ageMs);
    }
    const expectedHit = hits.length ? Math.max(...hits) : null;
    const expectedMiss = misses.length ? Math.min(...misses) : null;
    for (const rows of [records, [...records].reverse()]) {
      const result = judgeRunV5(rows).answers;
      for (const answer of [result.ttl, result.windowEdge]) {
        assert.equal(answer.lastHitMs, expectedHit);
        assert.equal(answer.firstMissMs, expectedMiss);
        assert.notEqual(answer.verdict, "inconsistent");
      }
    }
  }
});

test("v5 combining cannot promote missing repeats or an inconclusive run to an affirmative answer", () => {
  const complete = judgeRunV5(v5Base);
  const partial = judgeRunV5(v5Base.filter((r) => !["DA1", "E200-4a"].includes(r.id)));
  const combined = combineRunsFull(complete, partial);
  assert.equal(combined.answers.deleteArms, "mixed");
  assert.equal(combined.answers.recent200Exempts[4000], "mixed");
  const empty = combineRunsFull(complete, judgeRunV5([]));
  assert.equal(empty.rulesAllowed, false);
  assert.equal(empty.answers.deleteArms, "mixed");
  assert.deepEqual(empty.answers.windowEdge.verdict, { mixed: ["window", "no-data"] });
});

test("unknown answer boundaries are rejected independently in both judges", () => {
  const cases = [
    [199, true],
    [200, false],
    [299, false],
    [300, true],
    [399, true],
    [400, false],
    [499, false],
    [500, true],
    [501, true],
    [undefined, true],
  ];
  for (const [status, unknown] of cases) {
    const legacy = {
      id: "N1",
      steps: [
        { i: 0, status: 404 },
        { i: 1, status, kind: "error" },
      ],
    };
    const cell = structuredClone(v5Base.find((r) => r.id === "W25a"));
    Object.assign(probeOf(cell), { status, kind: "error", failure: null });
    assert.equal(prerequisite(legacy).ok, !unknown, `prerequisite status ${status}`);
    assert.equal(Boolean(judgeRunV5([cell]).invalid[cell.id]), unknown, `v5 status ${status}`);
  }
  for (const patch of [{ kind: "unknown" }, { failure: "timeout" }]) {
    const legacy = {
      id: "N1",
      steps: [
        { i: 0, status: 404 },
        { i: 1, status: 200, ...patch },
      ],
    };
    const cell = structuredClone(v5Base.find((r) => r.id === "W25a"));
    Object.assign(probeOf(cell), { status: 200, kind: "ok", failure: null }, patch);
    assert.match(prerequisite(legacy).reason, /unknown answer/);
    assert.match(judgeRunV5([cell]).invalid[cell.id], /unknown answer/);
  }
});

test("v5 rejects skipped or aborted cells and independently checks step index and operation", () => {
  for (const field of ["skipped", "aborted"]) {
    const cell = structuredClone(v5Base.find((r) => r.id === "W25a"));
    cell[field] = "interrupted";
    assert.equal(judgeRunV5([cell]).invalid[cell.id], "interrupted");
  }
  for (const patch of [{ i: 99 }, { op: "unexpected" }]) {
    const cell = structuredClone(v5Base.find((r) => r.id === "W25a"));
    Object.assign(cell.steps[0], patch);
    assert.equal(judgeRunV5([cell]).invalid[cell.id], "unexpected step 0");
  }
});

test("v5 never-created interval requires 404 misses as well as 404 hits", () => {
  const records = structuredClone(v5Base);
  const never = records.filter((r) => r.id.startsWith("N1"));
  for (const [i, r] of never.entries())
    Object.assign(probeOf(r), i < 8 ? MISS : HIT, {
      headersMs: i < 8 ? 300 : 20,
      ageMs: i < 8 ? 4000 : 4400,
    });
  assert.deepEqual(judgeRunV5(records).answers.neverCreatedActivationMs, [4000, 4400]);
  Object.assign(probeOf(never[0]), OK, { headersMs: 300 });
  assert.equal(judgeRunV5(records).answers.neverCreatedActivationMs, "mixed");
});

test("v5 merging preserves agreement, disagreement, and incomplete individual runs", () => {
  const complete = structuredClone(v5Base);
  const activation = complete.filter((r) => r.id.startsWith("N1"));
  for (const [i, r] of activation.entries())
    Object.assign(probeOf(r), i < 8 ? MISS : HIT, {
      headersMs: i < 8 ? 300 : 20,
      ageMs: i < 8 ? 4000 : 4400,
    });
  const run = (records) => judgeRunV5(records);
  const agreement = combineRuns(run(complete), run(complete));
  assert.equal(agreement.deleteArms, "no");
  assert.deepEqual(agreement.neverCreatedActivationMs, [4000, 4400]);
  for (const age of [4000, 7000, 13000])
    assert.equal(agreement.recent200Exempts[age], run(complete).answers.recent200Exempts[age]);
  for (const key of ["ttl", "windowEdge"]) assert.equal(agreement[key].verdict, "window");

  const opposite = structuredClone(complete);
  for (const r of opposite.filter((r) => r.id.startsWith("DA")))
    Object.assign(probeOf(r), HIT, { headersMs: 20, ageMs: 6000 });
  for (const r of opposite.filter((r) => r.id.startsWith("E200"))) {
    const isHit = probeOf(r).status === 404;
    Object.assign(probeOf(r), isHit ? OK : HIT, { headersMs: isHit ? 300 : 20 });
  }
  for (const r of opposite.filter((r) => r.id.startsWith("W")))
    Object.assign(probeOf(r), HIT, { headersMs: 20, ageMs: 1000 });
  const disagreement = combineRuns(run(complete), run(opposite));
  assert.equal(disagreement.deleteArms, "mixed");
  for (const age of [4000, 7000, 13000]) assert.equal(disagreement.recent200Exempts[age], "mixed");
  for (const key of ["ttl", "windowEdge"])
    assert.deepEqual(disagreement[key].verdict, { mixed: ["window", "open"] });

  for (const id of ["DA1", "N1a", "E200-4a", "E200-7a", "E200-13a"]) {
    const missing = complete.filter((r) => r.id !== id);
    const extra = [...complete, structuredClone(complete.find((r) => r.id === id))];
    for (const [first, second] of [
      [missing, extra],
      [extra, missing],
    ]) {
      const merged = combineRuns(run(first), run(second));
      if (id.startsWith("DA")) assert.equal(merged.deleteArms, "mixed");
      else if (id.startsWith("N1")) assert.equal(merged.neverCreatedActivationMs, "mixed");
      else assert.equal(merged.recent200Exempts[Number(id.match(/E200-(\d+)/)[1]) * 1000], "mixed");
    }
  }
});

test("v5 pooling requires records and v5 answers from both runs", () => {
  const v5 = judgeRunV5(v5Base);
  const summary = { answers: v5.answers };
  assert.doesNotThrow(() => combineRunsFull(v5, summary));
  assert.doesNotThrow(() => combineRunsFull(summary, v5));
  assert.doesNotThrow(() => combineRunsFull(v5, base));
  assert.doesNotThrow(() => combineRunsFull(base, v5));
});
