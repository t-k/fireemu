import assert from "node:assert/strict";
import test from "node:test";

import { combineRuns, EXPECT, judgeRun, prerequisite, readOutcome, window } from "./judge.mjs";
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
