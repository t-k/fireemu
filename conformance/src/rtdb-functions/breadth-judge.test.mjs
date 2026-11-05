import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { judgeRun } from "./breadth-judge.mjs";
import { observe as cvObserve, buildSteps } from "./sequence.mjs";
import { observe } from "./breadth-sequence.mjs";
test("replays all CV14 frames without rejecting the observations", () => {
  const recording = JSON.parse(
    readFileSync(new URL("./recorded/production-rtdb-triggers.json", import.meta.url), "utf8"),
  );
  const frames = recording.frames.map(({ n: _n, step: _step, ...frame }) => frame);
  const writes = Object.fromEntries(
    recording.steps.map((s) => [s.id, { outcome: s.outcome, status: s.status }]),
  );
  const report = cvObserve({ writes, frames, steps: buildSteps(recording.recording.nonce) });
  assert.equal(frames.length, 28);
  assert.equal(report.totals.attributed, 28);
  const reasons = judgeRun({ report, frames, writes, ignored: {} });
  assert.ok(reasons.some((reason) => reason.includes("unnamed members")));
});
test("judge reports strangers and missing observations without rejecting", () => {
  const writes = { w1: { outcome: "ok" } };
  const frames = [
    { handler: "g9WrittenV1Retry", generation: 1, event: { context: { auth: { uid: "other" } } } },
  ];
  const reasons = judgeRun({
    report: observe({ writes, frames }),
    frames,
    writes,
    ignored: { unparsed: 1 },
    userUid: "owner",
  });
  assert.ok(reasons.some((x) => x.includes("stranger")));
  assert.ok(reasons.some((x) => x.includes("missing")));
  assert.ok(reasons.some((x) => x.includes("unparsed")));
});
test("ancestor counts and retry-off redelivery remain observations", () => {
  const steps = [
    { id: "a", path: "g9-rtdb/gr", method: "PUT", body: { items: { x: { failForMs: 45000 } } } },
  ];
  const frames = [
    {
      handler: "g9WrittenV2",
      generation: 2,
      event: {
        id: "same",
        params: { group: "gr", id: "x" },
        data: {
          before: { exists: false, value: null },
          after: { exists: true, value: { failForMs: 45000 } },
        },
      },
    },
  ];
  const writes = { a: { outcome: "ok" } };
  const report = observe({ steps, writes, frames: [...frames, ...frames] });
  assert.deepEqual(judgeRun({ report, frames: [...frames, ...frames], writes, ignored: {} }), []);
});

test("leaf deliveries distinguish retry duplicates and multiple event IDs", () => {
  const reasonsFor = (group, value, seen) =>
    judgeRun({
      report: {
        steps: [
          {
            id: "w",
            path: `g9-rtdb/${group}/items/a`,
            write: { outcome: "ok" },
            leaves: [{ group, id: "a", after: value, handlers: { handler: seen } }],
          },
        ],
        totals: { unattributed: 0 },
      },
      frames: [{}],
      writes: {},
      ignored: {},
    });
  const seen = { frames: 2, distinctEventIds: 1, duplicateFrames: 1 };
  assert.ok(reasonsFor("ga", { value: 1 }, seen).some((x) => x.includes("repeated delivery")));
  assert.ok(
    !reasonsFor("gr", { failForMs: 1000 }, seen).some((x) => x.includes("repeated delivery")),
  );
  assert.ok(
    reasonsFor("ga", { value: 1 }, { ...seen, distinctEventIds: 2 }).some((x) =>
      x.includes("multiple event ids"),
    ),
  );
});
