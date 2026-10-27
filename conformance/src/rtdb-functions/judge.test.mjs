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
  // nothing answered ok, and nothing else wrong: nothing to report
  assert.deepEqual(run({ frames: [], writes: {} }), []);
  assert.deepEqual(
    run({ frames: [], writes: { s1: { outcome: "unknown", status: 0, answeredAtMs: null } } }),
    [],
  );
});

test("a run with no write answered ok still has its frames, its dropped entries and its members judged", () => {
  const stranger = frameForTransition("rtdbWrittenV2", "a", { n: 9 }, { n: 10 }, { seq: 99 });
  const reasons = run({ frames: [stranger], writes: {}, ignored: { foreignOrigin: 2 } });
  assert.equal(reasons.length, 2, reasons.join("|"));
  assert.match(
    reasons.join("|"),
    /1 frame\(s\) could not be attributed to a write \(no-match: 1\)/,
  );
  assert.match(reasons.join("|"), /foreignOrigin 2/);
  const odd = frameForTransition("rtdbWrittenV2", "a", { n: 9 }, { n: 10 }, { seq: 98 });
  odd.event.eventKeys = ["id", "traceparent"];
  assert.match(run({ frames: [odd], writes: {} }).join("|"), /traceparent/);
});

test("every write that was not answered ok is a reason of its own, an unknown one aside (the flow reports that)", () => {
  const refused = (status) => ({ outcome: "refused", status, answeredAtMs: 0 });
  const reasons = run({
    writes: { ...allOk, s8: refused(401), s9: refused(403) },
    frames: frames(["s1", "s2", "s3", "s4", "s5", "s6", "s7"]),
  });
  assert.deepEqual(reasons, [
    "write s8 was not answered ok (refused, status 401)",
    "write s9 was not answered ok (refused, status 403)",
  ]);
  // all nine refused, nothing delivered: nine reasons and no "no frame" reason (nothing was answered ok)
  const all = run({
    writes: Object.fromEntries(STEPS.map((s) => [s.id, refused(401)])),
    frames: [],
  });
  assert.equal(all.length, 9);
  assert.ok(all.every((r) => /was not answered ok \(refused, status 401\)/.test(r)));
  // an unexpected status is one too
  const odd = run({
    writes: { ...allOk, s7: { outcome: "moved", status: 302, answeredAtMs: 0 } },
    frames: frames(["s1", "s2", "s3", "s4", "s5", "s6", "s8", "s9"]),
  });
  assert.deepEqual(odd, ["write s7 was not answered ok (moved, status 302)"]);
  // an unknown answer is not reported here, and the frames of that step are not judged against the documentation
  assert.deepEqual(
    run({
      writes: { s1: { outcome: "unknown", status: 0, answeredAtMs: null } },
      frames: frames(["s1"]),
    }),
    [],
  );
});

test("a frame on a write that was refused or never sent is a delivery nobody expected", () => {
  const refused = { ...allOk, s1: { outcome: "refused", status: 401, answeredAtMs: 0 } };
  const reasons = run({ writes: refused });
  assert.equal(reasons.length, 2, reasons.join("|"));
  assert.match(reasons[1], /does not expect: s1 /);
  const unsent = run({ writes: { s1: ok }, frames: frames(["s1", "s2"]) });
  assert.match(unsent.join("|"), /does not expect: s2 /);
});

test("a delivery on a step the documentation says delivers nothing, a repeat and a second event are reasons", () => {
  // the no-op write s3 delivers nothing: a frame there is unexpected
  const noop = frameForTransition("rtdbWrittenV2", "a", T.s3.before, T.s3.after, {
    seq: 97,
    eventId: "extra",
  });
  const extra = run({ frames: [...frames(), noop] });
  assert.equal(extra.length, 1);
  assert.match(extra[0], /does not expect: s3 rtdbWrittenV2 \(1 frames\)/);
  // the same event printed twice
  const base = frames();
  const again = structuredClone(
    base.find((f) => f.handler === "rtdbWrittenV1" && f.event.context.params.id === "a"),
  );
  const repeat = run({ frames: [...base, again] });
  assert.equal(repeat.length, 1);
  assert.match(
    repeat[0],
    /came more than once \(a repeat or a second event\): s1 rtdbWrittenV1 \(2 frames, 1 event ids\)/,
  );
  // two events for one write
  const second = structuredClone(again);
  second.event.context.eventId = "second-event";
  const two = run({ frames: [...base, second] });
  assert.match(two[0], /s1 rtdbWrittenV1 \(2 frames, 2 event ids\)/);
});

test("a documented delivery that received no frame is a reason that names the write and the handler", () => {
  const without = frames().filter(
    (f) => !(f.handler === "rtdbCreatedV2" && f.event.params.id === "a"),
  );
  const reasons = run({ frames: without });
  assert.equal(reasons.length, 1);
  assert.match(reasons[0], /documented delivery received no frame/);
  assert.match(reasons[0], /s1 rtdbCreatedV2/);
  assert.deepEqual(run({ writes: { s2: ok }, frames: frames(["s2"]) }), []);
});

test("frames with a member the fixture did not name are a reason, per generation", () => {
  const withKeys = (generation, keys) =>
    run({
      frames: frames(undefined, (f) => {
        if (f.generation !== generation) return f;
        if (generation === 2) f.event.eventKeys = keys;
        else f.event.context.contextKeys = keys;
        return f;
      }),
    });
  const v2 = withKeys(2, ["id", "traceparent"]);
  assert.equal(v2.length, 1);
  assert.match(v2[0], /members the fixture did not name: traceparent/);
  const v1 = withKeys(1, ["eventId", "domain"]);
  assert.match(v1[0], /members the fixture did not name: domain/);
  // a member named for one generation is not named for the other
  assert.match(withKeys(2, ["id", "auth"])[0], /auth/);
  for (const member of ["location", "ref", "instance", "firebaseDatabaseHost"]) {
    assert.match(withKeys(1, ["eventId", member])[0], new RegExp(member), member);
    assert.deepEqual(withKeys(2, ["id", member]), [], member);
  }
  assert.deepEqual(withKeys(1, ["eventId", "auth"]), []);
  const extras = run({
    frames: frames(undefined, (f) => {
      if (f.generation === 2) f.event.extras = { traceparent: "x" };
      return f;
    }),
  });
  assert.match(extras[0], /traceparent/);
  // named members only, in any order, and missing ones, are fine
  const named = run({
    frames: frames(undefined, (f) => {
      if (f.generation === 2) f.event.eventKeys = ["data", "id", "location"];
      else f.event.context.contextKeys = ["params", "auth"];
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
