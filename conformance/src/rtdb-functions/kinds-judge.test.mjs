import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FIXTURE_HANDLERS, NAMED_CONTEXT_MEMBERS, NAMED_EVENT_MEMBERS } from "./kinds-frames.mjs";
import { judgeRun } from "./kinds-judge.mjs";
import { buildSteps, observe, transitions } from "./kinds-sequence.mjs";

const steps = buildSteps("N");
const all = FIXTURE_HANDLERS.map((h) => h.name);
const okWrites = Object.fromEntries(steps.map((s) => [s.id, { outcome: "ok", status: 200 }]));

const snap = (v) =>
  v === null
    ? { exists: false, key: "k", value: null, priority: null }
    : { exists: true, key: "k", value: v, priority: null };
function perfectFrames(only = all) {
  const frames = [];
  let n = 0;
  for (const t of transitions(steps)) {
    for (const leaf of t.leaves)
      for (const handler of FIXTURE_HANDLERS.filter((h) => h.level === "item")) {
        if (!only.includes(handler.name)) continue;
        if (handler.event !== "write" && handler.event !== leaf.kind) continue;
        const data =
          handler.event === "create"
            ? snap(leaf.after)
            : handler.event === "delete"
              ? snap(leaf.before)
              : { before: snap(leaf.before), after: snap(leaf.after) };
        const params = { group: leaf.group, id: leaf.id };
        frames.push({
          handler: handler.name,
          generation: handler.generation,
          seq: ++n,
          event:
            handler.generation === 1
              ? { context: { params, eventId: `e${n}`, contextKeys: [] }, data }
              : { params, id: `e${n}`, data, eventKeys: [] },
        });
      }
    for (const g of t.groups) {
      const handler = FIXTURE_HANDLERS.find((h) => h.level === "group");
      if (!only.includes(handler.name)) continue;
      frames.push({
        handler: handler.name,
        generation: 2,
        seq: ++n,
        event: {
          params: { group: g.group },
          id: `e${n}`,
          data: { before: snap(g.before), after: snap(g.after) },
          eventKeys: [],
        },
      });
    }
  }
  return frames;
}
const judge = (frames, extra = {}) =>
  judgeRun({
    report: observe({ writes: okWrites, frames, steps }),
    frames,
    writes: okWrites,
    ignored: {},
    deployed: all,
    ...extra,
  });

test("a complete and exact delivery set raises no reason", () => {
  assert.deepEqual(judge(perfectFrames()), []);
});

test("a missing delivery is a reason, except on observation-only steps", () => {
  const frames = perfectFrames();
  const withoutCreate = frames.filter(
    (f) => !(f.handler === "k9CreatedV2" && f.event.params.id === "a1"),
  );
  assert.deepEqual(judge(withoutCreate), ["missing delivery: k1 k9CreatedV2 ga/a1"]);
  const large = frames.filter((f) => !(f.handler === "k9CreatedV2" && f.event.params.id === "l2"));
  assert.deepEqual(judge(large), []);
});

test("a delivery of another kind fits no transition of its handler", () => {
  const frames = perfectFrames();
  const wrong = structuredClone(frames.find((f) => f.handler === "k9CreatedV2"));
  // the created transition's data, sent to the deleted handler
  wrong.handler = "k9DeletedV2";
  assert.deepEqual(judge([...frames, wrong]), ["1 frame(s) could not be attributed"]);
});

test("a handler counted for a transition of another kind is unexpected", () => {
  const report = {
    steps: [
      {
        id: "k1",
        write: { outcome: "ok" },
        leaves: [
          {
            group: "ga",
            id: "a1",
            handlers: {
              k9DeletedV2: { expected: 0, frames: 1, distinctEventIds: 1, duplicateFrames: 0 },
              k9CreatedV2: { expected: 1, frames: 1, distinctEventIds: 1, duplicateFrames: 0 },
            },
          },
        ],
        groups: [],
      },
    ],
    totals: { unattributed: 0 },
  };
  assert.deepEqual(
    judgeRun({ report, frames: [{}], writes: { k1: { outcome: "ok" } }, ignored: {} }),
    ["unexpected delivery: k1 k9DeletedV2 ga/a1"],
  );
});

test("repeated and multiple-id deliveries are reasons", () => {
  const frames = perfectFrames();
  const target = frames.find((f) => f.handler === "k9UpdatedV2");
  const same = structuredClone(target);
  assert.deepEqual(judge([...frames, same]), [
    `repeated delivery: ${label(target, "k2")}`,
  ]);
  const other = structuredClone(target);
  other.event.id = "different";
  assert.deepEqual(judge([...frames, other]), [`multiple event ids: ${label(target, "k2")}`]);
});
const label = (frame, step) =>
  `${step} ${frame.handler} ${frame.event.params.group}/${frame.event.params.id}`;

test("group handler deliveries are judged per changed group", () => {
  const frames = perfectFrames();
  const without = frames.filter(
    (f) => !(f.handler === "k9GroupWrittenV2" && f.event.params.group === "gb"),
  );
  assert.deepEqual(judge(without), ["missing delivery: k5 k9GroupWrittenV2 gb"]);
});

test("an undeployed optional handler is not expected", () => {
  const without = perfectFrames().filter((f) => f.handler !== "k9GroupWrittenV2");
  assert.ok(judge(without).length > 0);
  assert.deepEqual(
    judge(without, { deployed: all.filter((n) => n !== "k9GroupWrittenV2") }),
    [],
  );
});

test("a write that was refused yet delivered is unexpected", () => {
  const writes = { ...okWrites, k1: { outcome: "refused", status: 400 } };
  const frames = perfectFrames();
  const reasons = judgeRun({
    report: observe({ writes, frames, steps }),
    frames,
    writes,
    ignored: {},
    deployed: all,
  });
  assert.ok(reasons.includes("write k1 was not answered ok"));
  assert.ok(reasons.some((r) => r.startsWith("unexpected delivery: k1 ")));
});

test("no frames at all after an acknowledged write is a reason", () => {
  assert.ok(judge([]).includes("no frames read"));
});

test("dropped log entries and unattributed frames are reasons", () => {
  const frames = perfectFrames();
  const stray = structuredClone(frames[0]);
  stray.event.params.id = "nobody";
  assert.ok(judge([...frames, stray]).includes("1 frame(s) could not be attributed"));
  assert.ok(judge(frames, { ignored: { unparsed: 2 } }).includes("log entries dropped: unparsed"));
  assert.ok(judge(frames, { ignored: { foreignOrigin: 1 } }).includes("log entries dropped: foreignOrigin"));
  assert.ok(judge(frames, { ignored: { unknownHandler: 1 } }).includes("log entries dropped: unknownHandler"));
});

test("an auth uid other than the run's user is a stranger", () => {
  const frames = perfectFrames();
  const v1 = frames.find((f) => f.handler === "k9CreatedV1");
  v1.event.context.auth = { uid: "other" };
  const v2 = frames.find((f) => f.handler === "k9CreatedV2");
  v2.event.authId = "other";
  const reasons = judge(frames, { userUid: "owner" });
  assert.deepEqual(
    reasons.filter((r) => r.startsWith("stranger")).toSorted(),
    ["stranger auth: k9CreatedV1", "stranger auth: k9CreatedV2"],
  );
  assert.deepEqual(judge(frames, { userUid: undefined }), []);
});

test("members beyond the recorded shapes make the run need review", () => {
  const frames = perfectFrames();
  const v2 = frames.find((f) => f.handler === "k9UpdatedV2");
  v2.event.extras = { surprise: 1 };
  v2.event.eventKeys = ["surprise"];
  assert.deepEqual(judge(frames), ["frames carry unnamed members: surprise"]);
  v2.event.extras = {};
  v2.event.eventKeys = [...NAMED_EVENT_MEMBERS];
  assert.deepEqual(judge(frames), []);
  const v1 = frames.find((f) => f.handler === "k9UpdatedV1");
  v1.event.context.contextKeys = [...NAMED_CONTEXT_MEMBERS, "domain"];
  v1.event.context.extras = { domain: "firebaseio.com" };
  assert.deepEqual(judge(frames), []);
  v1.event.context.extras = { domain: "example.com" };
  assert.deepEqual(judge(frames), ["frames carry unnamed members: domain"]);
});

test("replays the CV14 production frames: every member is a recorded shape for its kind", () => {
  const recording = JSON.parse(
    readFileSync(new URL("./recorded/production-rtdb-triggers.json", import.meta.url), "utf8"),
  );
  const rename = (name) => name.replace(/^rtdb(Created|Updated|Deleted|Written)V(\d)$/u, "k9$1V$2");
  const frames = recording.frames
    .filter((f) => !f.handler.startsWith("rtdbWritten"))
    .map(({ n: _n, step: _step, ...f }) => ({ ...f, handler: rename(f.handler) }));
  assert.ok(frames.length >= 14);
  const reasons = judgeRun({
    report: { steps: [], totals: {} },
    frames,
    writes: {},
    ignored: {},
  });
  assert.deepEqual(reasons, []);
  // the same frames on the wrong event type are not recorded shapes
  const wrong = frames.map((f) => ({ ...f, handler: f.handler.replace("Created", "Updated") }));
  const created = wrong.find((f) => f.handler === "k9UpdatedV2");
  assert.ok(created);
  assert.ok(
    judgeRun({ report: { steps: [], totals: {} }, frames: wrong, writes: {}, ignored: {} }).length > 0,
  );
});
