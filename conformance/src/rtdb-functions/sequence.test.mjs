// The CV14 write sequence and what it is judged on: a model of the tree under each write, the events a
// trigger is documented to deliver for it, the attribution of printed frames to writes, and the
// per-handler observations. Production is the oracle: the documented column only tells where an
// observation departs from the documentation, it never decides what production did.

import assert from "node:assert/strict";
import { test } from "node:test";

import { FIXTURE_HANDLERS, PREFIX } from "./frames.mjs";
import {
  STEPS,
  applyWrite,
  documentedFires,
  itemTransitions,
  matchFrame,
  observe,
} from "./sequence.mjs";

const HANDLERS = Object.fromEntries(FIXTURE_HANDLERS.map((h) => [h.name, h]));

/** The frame a handler prints for an item that goes from `before` to `after` (the fixture's own shape). */
function frameFor(handler, id, before, after, extra = {}) {
  const spec = HANDLERS[handler];
  const snap = (value) => ({ exists: value !== null, key: id, value });
  const data =
    spec.event === "create"
      ? snap(after)
      : spec.event === "delete"
        ? snap(before)
        : { before: snap(before), after: snap(after) };
  const event =
    spec.generation === 1
      ? { context: { eventId: extra.eventId ?? `e-${handler}-${id}`, params: { id } }, data }
      : { id: extra.eventId ?? `e-${handler}-${id}`, params: { id }, data };
  return {
    handler,
    generation: spec.generation,
    seq: extra.seq ?? 1,
    receivedAt: extra.receivedAt ?? "2026-10-27T00:00:10.000Z",
    event,
  };
}

test("the sequence is nine writes under the run prefix, the last two without a token", () => {
  assert.deepEqual(
    STEPS.map((s) => s.id),
    ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9"],
  );
  assert.ok(STEPS.every((s) => s.path.startsWith(`${PREFIX}/`)));
  assert.deepEqual(
    STEPS.map((s) => s.context),
    ["admin", "admin", "admin", "admin", "admin", "admin", "admin", "anonymous", "anonymous"],
  );
  assert.deepEqual(
    STEPS.map((s) => s.method),
    ["PUT", "PATCH", "PUT", "DELETE", "PUT", "PATCH", "PUT", "PUT", "DELETE"],
  );
});

test("the model of the tree gives each item's value before and after every write", () => {
  const transitions = itemTransitions(STEPS);
  const v1 = { n: 1, tag: "one" };
  const v2 = { n: 2, tag: "one" };
  const b1 = { n: 1, nested: { x: 1, y: { z: 1 } } };
  const b2 = { n: 1, nested: { x: 2, y: { z: 1 } } };
  assert.deepEqual(transitions, [
    { step: "s1", id: "a", before: null, after: v1 },
    { step: "s2", id: "a", before: v1, after: v2 },
    { step: "s3", id: "a", before: v2, after: v2 },
    { step: "s4", id: "a", before: v2, after: null },
    { step: "s5", id: "b", before: null, after: b1 },
    { step: "s6", id: "b", before: b1, after: b2 },
    { step: "s7", id: null, before: null, after: null },
    { step: "s8", id: "c", before: null, after: { n: 1 } },
    { step: "s9", id: "c", before: { n: 1 }, after: null },
  ]);
});

test("a write onto a tree: PUT replaces, PATCH merges children, null removes and empty objects vanish", () => {
  const tree = {};
  assert.deepEqual(applyWrite(tree, "PUT", ["a"], { x: 1, y: { z: 2 } }), {
    a: { x: 1, y: { z: 2 } },
  });
  assert.deepEqual(applyWrite({ a: { x: 1 } }, "PATCH", ["a"], { y: 2 }), { a: { x: 1, y: 2 } });
  assert.deepEqual(applyWrite({ a: { x: 1, y: { z: 2 } } }, "PATCH", ["a", "y"], { z: null }), {
    a: { x: 1 },
  });
  assert.deepEqual(applyWrite({ a: { y: { z: 2 } } }, "PATCH", ["a", "y"], { z: null }), {});
  assert.deepEqual(applyWrite({ a: 1 }, "DELETE", ["a"], undefined), {});
  assert.deepEqual(applyWrite({ a: { x: 1 } }, "PUT", ["a", "x"], null), {});
  // the input is never changed
  const before = { a: { x: 1 } };
  applyWrite(before, "PUT", ["a", "x"], 2);
  assert.deepEqual(before, { a: { x: 1 } });
});

test("what the documentation says each event kind delivers", () => {
  const cases = [
    // [before, after, create, update, delete, write]
    [null, { n: 1 }, true, false, false, true],
    [{ n: 1 }, { n: 2 }, false, true, false, true],
    [{ n: 1 }, { n: 1 }, false, false, false, false],
    [{ n: 1 }, null, false, false, true, true],
    [null, null, false, false, false, false],
  ];
  for (const [before, after, create, update, del, write] of cases) {
    assert.equal(documentedFires("create", before, after), create);
    assert.equal(documentedFires("update", before, after), update);
    assert.equal(documentedFires("delete", before, after), del);
    assert.equal(documentedFires("write", before, after), write);
  }
  assert.throws(() => documentedFires("nope", null, null), /unknown event kind/);
});

test("a printed frame belongs to the one write whose transition it shows", () => {
  const t = Object.fromEntries(itemTransitions(STEPS).map((x) => [x.step, x]));
  for (const handler of Object.keys(HANDLERS)) {
    for (const step of ["s1", "s2", "s4", "s5", "s6", "s8", "s9"]) {
      const { id, before, after } = t[step];
      if (!documentedFires(HANDLERS[handler].event, before, after)) continue;
      assert.deepEqual(matchFrame(frameFor(handler, id, before, after)), {
        step,
        candidates: [step],
        reason: null,
      });
    }
  }
});

test("a frame that fits no write, several writes or no known shape is reported, not guessed", () => {
  const none = matchFrame(frameFor("rtdbWrittenV2", "a", { n: 9 }, { n: 10 }));
  assert.deepEqual(none, { step: null, candidates: [], reason: "no-match" });
  // the same transition twice in one sequence cannot be told apart by its content
  const twice = ["PUT", "DELETE", "PUT", "DELETE"].map((method, index) => ({
    id: `t${index + 1}`,
    method,
    path: `${PREFIX}/items/a`,
    body: method === "PUT" ? { n: 1 } : undefined,
    context: "admin",
  }));
  assert.deepEqual(matchFrame(frameFor("rtdbCreatedV1", "a", null, { n: 1 }), twice), {
    step: null,
    candidates: ["t1", "t3"],
    reason: "ambiguous",
  });
  // a created handler is only told of a transition from nothing, a deleted one of a transition to nothing
  assert.equal(
    matchFrame(frameFor("rtdbCreatedV1", "a", null, { n: 2, tag: "one" })).reason,
    "no-match",
  );
  assert.equal(matchFrame(frameFor("rtdbDeletedV2", "a", { n: 2, tag: "one" }, null)).step, "s4");
  const broken = frameFor("rtdbWrittenV2", "a", null, { n: 1, tag: "one" });
  broken.event.data = "text";
  assert.deepEqual(matchFrame(broken), { step: null, candidates: [], reason: "shape" });
  const unknown = { ...frameFor("rtdbWrittenV2", "a", null, null), handler: "other" };
  assert.deepEqual(matchFrame(unknown), { step: null, candidates: [], reason: "handler" });
});

const ok = (answeredAtMs = Date.parse("2026-10-27T00:00:00.000Z")) => ({
  outcome: "ok",
  status: 200,
  answeredAtMs,
});

test("observations count frames, distinct event ids and duplicates per handler and write", () => {
  const t = Object.fromEntries(itemTransitions(STEPS).map((x) => [x.step, x]));
  const frames = [
    frameFor("rtdbCreatedV2", "a", null, t.s1.after, { eventId: "ev1" }),
    frameFor("rtdbCreatedV2", "a", null, t.s1.after, { eventId: "ev1", seq: 2 }), // a redelivery
    frameFor("rtdbWrittenV2", "a", null, t.s1.after, { eventId: "ev2" }),
    frameFor("rtdbWrittenV1", "a", null, t.s1.after, { eventId: "ev3" }),
    frameFor("rtdbWrittenV2", "a", t.s3.before, t.s3.after, { eventId: "ev4" }), // a no-op that fired
    frameFor("rtdbWrittenV2", "a", { n: 9 }, { n: 8 }, { eventId: "ev5" }), // fits nothing
  ];
  const writes = { s1: ok(), s3: ok() };
  const report = observe({ writes, frames });
  const s1 = report.steps.find((s) => s.id === "s1");
  assert.deepEqual(s1.handlers.rtdbCreatedV2, {
    frames: 2,
    distinctEventIds: 1,
    duplicateFrames: 1,
    documented: 1,
    matchesDocumented: false,
    firstLatencyMs: 10000,
  });
  assert.equal(s1.handlers.rtdbWrittenV2.matchesDocumented, true);
  assert.equal(s1.handlers.rtdbWrittenV1.matchesDocumented, true);
  // delivered: no frame, documented: yes
  assert.deepEqual(s1.handlers.rtdbCreatedV1, {
    frames: 0,
    distinctEventIds: 0,
    duplicateFrames: 0,
    documented: 1,
    matchesDocumented: false,
    firstLatencyMs: null,
  });
  // not documented and not delivered: matches
  assert.equal(s1.handlers.rtdbDeletedV2.matchesDocumented, true);
  const s3 = report.steps.find((s) => s.id === "s3");
  assert.equal(s3.handlers.rtdbWrittenV2.frames, 1);
  assert.equal(s3.handlers.rtdbWrittenV2.documented, 0);
  assert.equal(s3.handlers.rtdbWrittenV2.matchesDocumented, false);
  assert.equal(report.unattributed.length, 1);
  assert.equal(report.unattributed[0].reason, "no-match");
  assert.deepEqual(report.totals, { frames: 6, attributed: 5, unattributed: 1 });
});

test("a write whose answer is not known is reported unknown and its frames are still attributed", () => {
  const t = itemTransitions(STEPS)[0];
  const report = observe({
    writes: { s1: { outcome: "unknown", status: 0, answeredAtMs: null } },
    frames: [frameFor("rtdbCreatedV1", "a", null, t.after)],
  });
  const s1 = report.steps.find((s) => s.id === "s1");
  assert.equal(s1.write.outcome, "unknown");
  assert.equal(s1.handlers.rtdbCreatedV1.frames, 1);
  assert.equal(s1.handlers.rtdbCreatedV1.firstLatencyMs, null);
  const unsent = report.steps.find((s) => s.id === "s2");
  assert.equal(unsent.write, null);
});

// ---- generated: the documented event kinds over random before and after values ----

function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

test("generated values: create, update and delete exclude each other and write is their union", () => {
  const next = prng(0xc0ffee14);
  const values = [null, 0, 1, "s", { a: 1 }, { a: 2 }, { a: { b: 1 } }, { a: { b: 1 } }, true];
  for (let i = 0; i < 400; i += 1) {
    const before = values[Math.floor(next() * values.length)];
    const after = values[Math.floor(next() * values.length)];
    const fires = ["create", "update", "delete"].filter((k) => documentedFires(k, before, after));
    assert.ok(fires.length <= 1, JSON.stringify({ before, after, fires }));
    assert.equal(documentedFires("write", before, after), fires.length === 1);
    const same = JSON.stringify(before) === JSON.stringify(after);
    assert.equal(fires.length === 0, same || (before === null && after === null));
  }
});

test("generated frames: every documented delivery of the sequence is attributed to its own write", () => {
  const next = prng(0x14c0de);
  const transitions = itemTransitions(STEPS);
  for (let i = 0; i < 200; i += 1) {
    const step = transitions[Math.floor(next() * transitions.length)];
    if (step.id === null) continue;
    const handler = FIXTURE_HANDLERS[Math.floor(next() * FIXTURE_HANDLERS.length)];
    if (!documentedFires(handler.event, step.before, step.after)) continue;
    const match = matchFrame(frameFor(handler.name, step.id, step.before, step.after));
    assert.equal(match.step, step.step, JSON.stringify({ handler: handler.name, step: step.step }));
  }
});

// ---- near misses of the attribution and the observations ----

test("the same transition on two items is told apart by the item id", () => {
  const steps = ["a", "b"].map((id, index) => ({
    id: `t${index + 1}`,
    method: "PUT",
    path: `${PREFIX}/items/${id}`,
    body: { n: 1 },
    context: "admin",
  }));
  assert.equal(matchFrame(frameFor("rtdbCreatedV2", "b", null, { n: 1 }), steps).step, "t2");
  assert.equal(matchFrame(frameFor("rtdbCreatedV2", "a", null, { n: 1 }), steps).step, "t1");
  assert.equal(
    matchFrame(frameFor("rtdbCreatedV2", "c", null, { n: 1 }), steps).reason,
    "no-match",
  );
});

test("frames without an event id are not taken for repeats of one another", () => {
  const t = itemTransitions(STEPS)[0];
  const bare = (seq) => {
    const frame = frameFor("rtdbCreatedV2", "a", null, t.after, { seq });
    delete frame.event.id;
    return frame;
  };
  const report = observe({ writes: { s1: ok() }, frames: [bare(1), bare(2)] });
  const created = report.steps[0].handlers.rtdbCreatedV2;
  assert.equal(created.frames, 2);
  assert.equal(created.distinctEventIds, 2);
  assert.equal(created.duplicateFrames, 0);
});

test("the latency is that of the earliest delivery, not of a later repeat", () => {
  const t = itemTransitions(STEPS)[0];
  const frames = [
    frameFor("rtdbCreatedV2", "a", null, t.after, {
      eventId: "e",
      receivedAt: "2026-10-27T00:00:30.000Z",
    }),
    frameFor("rtdbCreatedV2", "a", null, t.after, {
      eventId: "e",
      receivedAt: "2026-10-27T00:00:04.000Z",
      seq: 2,
    }),
  ];
  const report = observe({ writes: { s1: ok() }, frames });
  assert.equal(report.steps[0].handlers.rtdbCreatedV2.firstLatencyMs, 4000);
  const none = observe({
    writes: { s1: { outcome: "ok", status: 200, answeredAtMs: null } },
    frames,
  });
  assert.equal(none.steps[0].handlers.rtdbCreatedV2.firstLatencyMs, null);
});

test("a frame whose generation is not the handler's, or whose snapshot is not one, is not attributed", () => {
  const wrongGeneration = { ...frameFor("rtdbCreatedV1", "a", null, { n: 1 }), generation: 2 };
  assert.deepEqual(matchFrame(wrongGeneration), { step: null, candidates: [], reason: "handler" });
  const odd = frameFor("rtdbCreatedV2", "a", null, { n: 1, tag: "one" });
  odd.event.data = { exists: "yes", key: "a", value: { n: 1, tag: "one" } };
  assert.deepEqual(matchFrame(odd), { step: null, candidates: [], reason: "shape" });
  const missingValue = frameFor("rtdbCreatedV2", "a", null, { n: 1, tag: "one" });
  delete missingValue.event.data.value;
  assert.equal(matchFrame(missingValue).reason, "shape");
  const noId = frameFor("rtdbCreatedV2", "a", null, { n: 1, tag: "one" });
  noId.event.params = {};
  assert.equal(matchFrame(noId).reason, "shape");
});
