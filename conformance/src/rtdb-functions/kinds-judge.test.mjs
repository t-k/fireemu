import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FIXTURE_HANDLERS, NAMED_CONTEXT_MEMBERS, NAMED_EVENT_MEMBERS } from "./kinds-frames.mjs";
import { judgeRun } from "./kinds-judge.mjs";
import { buildSteps, matchFrame, observe } from "./kinds-sequence.mjs";
import { perfectFrames } from "./kinds-world.fake.mjs";

const steps = buildSteps("N");
const all = FIXTURE_HANDLERS.map((h) => h.name);
const okWrites = Object.fromEntries(steps.map((s) => [s.id, { outcome: "ok", status: 200 }]));

const frameSet = (only = all) => perfectFrames(steps, only);
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
  assert.deepEqual(judge(frameSet()), []);
});

test("a missing delivery is a reason, except on observation-only steps", () => {
  const frames = frameSet();
  const withoutCreate = frames.filter(
    (f) => !(f.handler === "k9CreatedV2" && f.event.params.id === "a1"),
  );
  assert.deepEqual(judge(withoutCreate), ["missing delivery: k1 k9CreatedV2 ga/a1"]);
  const large = frames.filter((f) => !(f.handler === "k9CreatedV2" && f.event.params.id === "l2"));
  assert.deepEqual(judge(large), []);
});

test("a delivery of another kind fits no transition of its handler", () => {
  const frames = frameSet();
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
  const frames = frameSet();
  const target = frames.find((f) => f.handler === "k9UpdatedV2");
  const same = structuredClone(target);
  assert.deepEqual(judge([...frames, same]), [`repeated delivery: ${label(target, "k2")}`]);
  const other = structuredClone(target);
  other.event.id = "different";
  assert.deepEqual(judge([...frames, other]), [`multiple event ids: ${label(target, "k2")}`]);
});
const label = (frame, step) =>
  `${step} ${frame.handler} ${frame.event.params.group}/${frame.event.params.id}`;

test("group handler deliveries are judged per changed group", () => {
  const frames = frameSet();
  const without = frames.filter(
    (f) => !(f.handler === "k9GroupWrittenV2" && f.event.params.group === "gb"),
  );
  assert.deepEqual(judge(without), ["missing delivery: k5 k9GroupWrittenV2 gb"]);
});

test("an undeployed optional handler is not expected", () => {
  const without = frameSet().filter((f) => f.handler !== "k9GroupWrittenV2");
  assert.ok(judge(without).length > 0);
  assert.deepEqual(judge(without, { deployed: all.filter((n) => n !== "k9GroupWrittenV2") }), []);
});

test("a write that was refused yet delivered is unexpected", () => {
  const writes = { ...okWrites, k1: { outcome: "refused", status: 400 } };
  const frames = frameSet();
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
  const frames = frameSet();
  const stray = structuredClone(frames[0]);
  stray.event.params.id = "nobody";
  assert.ok(judge([...frames, stray]).includes("1 frame(s) could not be attributed"));
  assert.ok(judge(frames, { ignored: { unparsed: 2 } }).includes("log entries dropped: unparsed"));
  assert.ok(
    judge(frames, { ignored: { foreignOrigin: 1 } }).includes("log entries dropped: foreignOrigin"),
  );
  assert.ok(
    judge(frames, { ignored: { unknownHandler: 1 } }).includes(
      "log entries dropped: unknownHandler",
    ),
  );
});

test("an auth uid other than the run's user is a stranger", () => {
  const frames = frameSet();
  const v1 = frames.find((f) => f.handler === "k9CreatedV1");
  v1.event.context.auth = { uid: "other" };
  const v2 = frames.find((f) => f.handler === "k9CreatedV2");
  v2.event.authId = "other";
  const reasons = judge(frames, { userUid: "owner" });
  assert.deepEqual(reasons.filter((r) => r.startsWith("stranger")).toSorted(), [
    "stranger auth: k9CreatedV1",
    "stranger auth: k9CreatedV2",
  ]);
  assert.deepEqual(judge(frames, { userUid: undefined }), []);
});

test("members beyond the recorded shapes make the run need review", () => {
  const frames = frameSet();
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

test("the user-write context of the SDK is accepted on 2nd gen handlers in exactly the recorded key set", () => {
  const keys = ["auth", "authType", "eventId", "eventType", "params", "resource", "timestamp"];
  const frames = frameSet();
  const v2 = frames.find((f) => f.handler === "k9CreatedV2");
  v2.event.eventKeys = [...NAMED_EVENT_MEMBERS, "context"];
  v2.event.extras = { context: { type: "object", keys } };
  assert.deepEqual(judge(frames), []);
  // one key more, one key less, another order and the wrong type are not the recorded shape
  for (const shape of [
    { type: "object", keys: [...keys, "extra"] },
    { type: "object", keys: keys.slice(1) },
    { type: "object", keys: [...keys].reverse() },
    { type: "array", keys },
  ]) {
    v2.event.extras = { context: shape };
    assert.deepEqual(judge(frames), ["frames carry unnamed members: context"]);
  }
  // a 1st gen handler has no such member
  const v1 = frames.find((f) => f.handler === "k9CreatedV1");
  v2.event.extras = {};
  v2.event.eventKeys = [...NAMED_EVENT_MEMBERS];
  v1.event.context.contextKeys = [...NAMED_CONTEXT_MEMBERS, "context"];
  v1.event.context.extras = { context: { type: "object", keys } };
  assert.deepEqual(judge(frames), ["frames carry unnamed members: context"]);
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
    judgeRun({ report: { steps: [], totals: {} }, frames: wrong, writes: {}, ignored: {} }).length >
      0,
  );
});

test("steps never reached have no write and raise nothing", () => {
  // the run stopped after k2: the later steps have no answer and no frames
  const early = new Set(["k1", "k2"]);
  const writes = Object.fromEntries([...early].map((id) => [id, { outcome: "ok", status: 200 }]));
  const frames = frameSet().filter((f) => early.has(matchFrame(f, steps).step));
  assert.ok(frames.length > 0 && frames.length < 20);
  assert.deepEqual(
    judgeRun({
      report: observe({ writes, frames, steps }),
      frames,
      writes,
      ignored: {},
      deployed: all,
    }),
    [],
  );
});

test("an unknown write answer is not a refusal and expects nothing", () => {
  const writes = { ...okWrites, k1: { outcome: "unknown" } };
  const frames = frameSet().filter(
    (f) =>
      !(
        f.event.params?.id === "a1" &&
        f.event.params?.group === "ga" &&
        ["k9CreatedV1", "k9CreatedV2", "k9AnyWrittenV2"].includes(f.handler)
      ),
  );
  const reasons = judgeRun({
    report: observe({ writes, frames, steps }),
    frames,
    writes,
    ignored: {},
    deployed: all,
  });
  assert.ok(
    reasons.every((r) => !r.startsWith("write k1")),
    reasons.join(),
  );
  assert.ok(!reasons.some((r) => r.startsWith("missing delivery: k1 ")), reasons.join());
});

test("an undeployed optional item handler is not expected", () => {
  const without = frameSet().filter((f) => f.handler !== "k9AnyWrittenV2");
  assert.ok(judge(without).length > 0);
  assert.deepEqual(judge(without, { deployed: all.filter((n) => n !== "k9AnyWrittenV2") }), []);
});

test("members are read from the key lists and from the extras, each on its own generation", () => {
  const onlyKeys = frameSet();
  const v1 = onlyKeys.find((f) => f.handler === "k9CreatedV1");
  v1.event.context.contextKeys = ["mystery"];
  assert.deepEqual(judge(onlyKeys), ["frames carry unnamed members: mystery"]);
  v1.event.context.contextKeys = [];
  // a member of the 2nd gen list is not looked up in the 1st gen context
  v1.event.context.eventKeys = ["mystery"];
  assert.deepEqual(judge(onlyKeys), []);
  const v2 = onlyKeys.find((f) => f.handler === "k9CreatedV2");
  v2.event.eventKeys = ["mystery-event"];
  assert.deepEqual(judge(onlyKeys), ["frames carry unnamed members: mystery-event"]);
  v2.event.eventKeys = [];
  v2.event.extras = { "only-extra": 1 };
  assert.deepEqual(judge(onlyKeys), ["frames carry unnamed members: only-extra"]);
  // a 2nd gen key list on a 1st gen frame is not read
  v2.event.extras = {};
  v1.event.eventKeys = ["mystery"];
  assert.deepEqual(judge(onlyKeys), []);
});

test("several unnamed members are listed once each, sorted", () => {
  const frames = frameSet();
  frames.find((f) => f.handler === "k9CreatedV2").event.extras = { zeta: 1, alpha: 1 };
  frames.find((f) => f.handler === "k9UpdatedV2").event.extras = { alpha: 1, beta: 1 };
  assert.deepEqual(judge(frames), ["frames carry unnamed members: alpha, beta, zeta"]);
});

test("a frame's auth is read from the generation's own holder", () => {
  const frames = frameSet();
  const v2 = frames.find((f) => f.handler === "k9CreatedV2");
  v2.event.context = { auth: { uid: "other" } };
  assert.deepEqual(judge(frames, { userUid: "owner" }), []);
  const v1 = frames.find((f) => f.handler === "k9CreatedV1");
  v1.event.authId = "other";
  assert.deepEqual(judge(frames, { userUid: "owner" }), []);
  // a v2 authId that is null (admin writes) is nobody
  v2.event.authId = null;
  assert.deepEqual(judge(frames, { userUid: "owner" }), []);
});
