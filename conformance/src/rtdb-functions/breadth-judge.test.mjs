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
  const written = frames.filter((frame) => frame.handler.startsWith("rtdbWritten"));
  for (const handler of ["g9WrittenV2Retry", "g9WrittenV1Retry", "g9WrittenV2"]) {
    const generation = handler.includes("V1") ? 1 : 2;
    const mapped = written
      .filter((frame) => frame.generation === generation)
      .map((frame) => ({ ...frame, handler }));
    assert.ok(mapped.length > 0);
    assert.deepEqual(
      judgeRun({ report: { steps: [], totals: {} }, frames: mapped, writes: {}, ignored: {} }),
      [],
    );
    const holder = generation === 1 ? mapped[0].event.context : mapped[0].event;
    holder.extras = { ...holder.extras, neverRecorded: true };
    assert.ok(
      judgeRun({ report: { steps: [], totals: {} }, frames: mapped, writes: {} }).some((reason) =>
        reason.includes("neverRecorded"),
      ),
    );
    delete holder.extras.neverRecorded;
  }
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

test("recorded members require the handler generation and exact recorded shape", async () => {
  const { isRecordedMember } = await import("./breadth-frames.mjs");
  assert.equal(isRecordedMember("g9WrittenV1Retry", 1, "domain", "firebaseio.com"), true);
  assert.equal(isRecordedMember("g9WrittenV1Retry", 1, "domain", "other"), false);
  assert.equal(isRecordedMember("g9WrittenV2Retry", 1, "domain", "firebaseio.com"), false);
  assert.equal(isRecordedMember("foreign", 1, "domain", "firebaseio.com"), false);
  assert.equal(
    isRecordedMember("g9WrittenV2", 2, "change", { type: "object", keys: ["after", "before"] }),
    true,
  );
  for (const value of [
    null,
    {},
    { type: "object", keys: ["after"] },
    { type: "object", keys: ["before", "after"] },
  ])
    assert.equal(isRecordedMember("g9WrittenV2", 2, "change", value), false);
});

test("judge ignores refused optional handlers and reports second generation strangers", () => {
  const report = {
    steps: [
      {
        id: "w10",
        path: "g9-rtdb/gu/items/a",
        write: { outcome: "ok" },
        leaves: [
          {
            group: "gu",
            id: "a",
            handlers: { g9WrittenV2: { frames: 0 }, g9WrittenV1Retry: { frames: 1 } },
          },
        ],
      },
    ],
    totals: {},
  };
  const frames = [{ handler: "g9WrittenV2Retry", generation: 2, event: { authId: "stranger" } }];
  const reasons = judgeRun({
    report,
    frames,
    writes: {},
    userUid: "owner",
    deployed: ["g9WrittenV1Retry"],
  });
  assert.ok(!reasons.some((reason) => reason.includes("missing delivery")));
  assert.ok(reasons.some((reason) => reason.includes("stranger auth")));
  for (const authId of [null, undefined, "owner"])
    assert.deepEqual(
      judgeRun({
        report: { steps: [], totals: {} },
        frames: [{ generation: 2, event: { authId } }],
        writes: {},
        userUid: "owner",
      }),
      [],
    );
});
