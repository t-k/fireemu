import assert from "node:assert/strict";
import test from "node:test";

import {
  combineRuns,
  EXPECT,
  inWindow,
  judgeRun,
  prerequisite,
  readOutcome,
  WINDOW_EDGE_MS,
  window,
} from "./judge.mjs";
import { CELLS } from "./program.mjs";
import { record } from "./support.mjs";

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
  assert.equal(base.valid.length, 30);
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
  assert.equal(A.rearm.deleteHit, "not-re-armed");
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
  assert.ok(combined.ttl.lastHitMs.mixed);
  assert.ok(combined.ttl.verdict === "window");
  assert.deepEqual(combineRuns(base, base), A);
  const flipped = await judged({ bodyClear: "none" });
  assert.deepEqual(combineRuns(base, flipped).body.otherName.mixed, ["clears", "does-not-clear"]);
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
  const e2 = recordOf("E2");
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
  assert.equal(withRecords(n1).answers.absent.pureNegative, "mixed");
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
  const v4b = setStep(recordOf("V4"), 3, { body: {} });
  assert.equal(withRecords(v4b).answers.serve.V4present, "no");
  const v4c = setStep(recordOf("V4"), 3, { body: { subscriptions: [{ name: "x-nc-v4-x" }] } });
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
