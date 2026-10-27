// The judge of a whole run. No RTDB trigger event has ever been recorded, so the run is `recorded` only
// when everything the log held was read, every frame belongs to one write, every documented delivery
// came, and no frame carries a member nobody named. Anything else is kept in full and adds a reason, so
// the coordinator reads the observation before it is called recorded.

import assert from "node:assert/strict";
import { test } from "node:test";

import { FIXTURE_HANDLERS } from "./frames.mjs";
import { judgeRun } from "./judge.mjs";
import { STEPS, documentedFires, itemTransitions, observe } from "./sequence.mjs";
import { frameForTransition } from "./world.fake.mjs";

const T = Object.fromEntries(itemTransitions(STEPS).map((t) => [t.step, t]));
const ok = { outcome: "ok", status: 200, answeredAtMs: 0 };
const allOk = Object.fromEntries(STEPS.map((s) => [s.id, ok]));

/** Every documented frame of the given steps, once. */
function frames(stepIds = STEPS.map((s) => s.id), tweak = (frame) => frame) {
  const out = [];
  for (const id of stepIds) {
    const { id: item, before, after } = T[id];
    for (const h of FIXTURE_HANDLERS) {
      if (item !== null && documentedFires(h.event, before, after)) {
        out.push(tweak(frameForTransition(h.name, item, before, after, { seq: out.length + 1 })));
      }
    }
  }
  return out;
}
const run = (overrides = {}) => {
  const list = overrides.frames ?? frames();
  const writes = overrides.writes ?? allOk;
  return judgeRun({
    report: observe({ writes, frames: list }),
    frames: list,
    writes,
    ignored: overrides.ignored ?? {},
  });
};

test("a complete, readable, fully named observation has nothing to report", () => {
  assert.deepEqual(run(), []);
});

test("frames that cannot be attributed to a write are a reason, with how many and why", () => {
  const stranger = frameForTransition("rtdbWrittenV2", "a", { n: 9 }, { n: 10 }, { seq: 99 });
  const unreadable = frameForTransition("rtdbWrittenV2", "a", null, { n: 1 }, { seq: 98 });
  unreadable.event.data = null;
  const reasons = run({ frames: [...frames(), stranger, unreadable] });
  assert.equal(reasons.length, 1);
  assert.match(reasons[0], /2 frame\(s\) could not be attributed/);
  assert.match(reasons[0], /no-match: 1/);
  assert.match(reasons[0], /shape: 1/);
});

test("log entries the parser dropped are a reason, per class", () => {
  const reasons = run({
    ignored: { unparsed: 1, unknownHandler: 2, foreignOrigin: 3, notFrame: 4, notTyped: 5 },
  });
  assert.equal(reasons.length, 1);
  assert.match(reasons[0], /unparsed 1/);
  assert.match(reasons[0], /unknownHandler 2/);
  assert.match(reasons[0], /foreignOrigin 3/);
  assert.doesNotMatch(reasons[0], /notFrame|notTyped/);
  for (const klass of ["unparsed", "unknownHandler", "foreignOrigin"]) {
    assert.equal(run({ ignored: { [klass]: 1 } }).length, 1, klass);
  }
  assert.deepEqual(run({ ignored: { notFrame: 9, notTyped: 9, unparsed: 0 } }), []);
});

test("a run with answered writes and no frame at all is a reason of its own", () => {
  const reasons = run({ frames: [] });
  assert.ok(
    reasons.some((r) => /no frame was read/.test(r)),
    reasons.join("|"),
  );
  // nothing was written: nothing to judge
  assert.deepEqual(run({ frames: [], writes: {} }), []);
  assert.deepEqual(
    run({ frames: [], writes: { s1: { outcome: "unknown", status: 0, answeredAtMs: null } } }),
    [],
  );
});

test("a documented delivery that received no frame is a reason that names the write and the handler", () => {
  const without = frames().filter(
    (f) => !(f.handler === "rtdbCreatedV2" && f.event.params.id === "a"),
  );
  const reasons = run({ frames: without });
  assert.equal(reasons.length, 1);
  assert.match(reasons[0], /documented delivery received no frame/);
  assert.match(reasons[0], /s1 rtdbCreatedV2/);
  // a write that was refused or never sent expects nothing
  const refused = { ...allOk, s1: { outcome: "refused", status: 401, answeredAtMs: 0 } };
  const noS1 = frames(STEPS.map((s) => s.id).filter((id) => id !== "s1"));
  assert.deepEqual(run({ writes: refused, frames: noS1 }), []);
  assert.deepEqual(run({ writes: { s2: ok }, frames: frames(["s2"]) }), []);
});

test("frames with a member the fixture did not name are a reason, whichever generation", () => {
  const v2 = run({
    frames: frames(undefined, (f) => {
      if (f.generation === 2) f.event.eventKeys = [...(f.event.eventKeys ?? []), "location"];
      return f;
    }),
  });
  assert.equal(v2.length, 1);
  assert.match(v2[0], /members the fixture did not name/);
  assert.match(v2[0], /location/);
  const v1 = run({
    frames: frames(undefined, (f) => {
      if (f.generation === 1) f.event.context.contextKeys = ["eventId", "auth"];
      return f;
    }),
  });
  assert.match(v1[0], /auth/);
  const extras = run({
    frames: frames(undefined, (f) => {
      if (f.generation === 2) f.event.extras = { ref: "/x" };
      return f;
    }),
  });
  assert.match(extras[0], /ref/);
  // named members only, in any order, and missing ones, are fine
  const named = run({
    frames: frames(undefined, (f) => {
      if (f.generation === 2) f.event.eventKeys = ["data", "id"];
      else f.event.context.contextKeys = ["params"];
      f.event.extras = {};
      return f;
    }),
  });
  assert.deepEqual(named, []);
});

test("several findings are several reasons", () => {
  const reasons = run({ frames: [], ignored: { unparsed: 1 } });
  assert.ok(reasons.length >= 2);
});

test("the counts per reason are counts, and a long list of missing deliveries is cut", () => {
  const strangers = [1, 2].map((seq) =>
    frameForTransition("rtdbWrittenV2", "a", { n: 9 }, { n: 10 }, { seq: 90 + seq }),
  );
  const reasons = run({ frames: [...frames(), ...strangers] });
  assert.match(reasons[0], /2 frame\(s\) could not be attributed to a write \(no-match: 2\)/);
  // no frame at all: every documented delivery is missing, and the list is cut after eight
  const none = run({ frames: [] });
  const missing = none.find((r) => /documented delivery received no frame/.test(r));
  assert.match(missing, /and \d+ more/);
  assert.equal(missing.split(", ").length, 8 + 0, missing);
});
