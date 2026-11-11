import { test } from "node:test";
import assert from "node:assert/strict";
import { isDeepStrictEqual } from "node:util";
import { FIXTURE_HANDLERS, PREFIX } from "./kinds-frames.mjs";
import {
  STEPS,
  buildSteps,
  kindOf,
  plain,
  matchFrame,
  observe,
  reduceBig,
  transitions,
} from "./kinds-sequence.mjs";

const leafList = (t) => t.leaves.map((l) => `${l.kind} ${l.group}/${l.id}`);
const groupList = (t) => t.groups.map((g) => g.group);

test("every step is named, ordered and carries a context", () => {
  assert.deepEqual(
    STEPS.map((s) => s.id),
    Array.from({ length: STEPS.length }, (_, i) => `k${i + 1}`),
  );
  assert.deepEqual([...new Set(STEPS.map((s) => s.context))].sort(), [
    "admin",
    "user-rest",
    "user-sdk",
  ]);
  for (const step of STEPS) assert.ok(step.path.startsWith(PREFIX));
});

test("the kind split under ancestor and multi-path writes is the planned one", () => {
  const t = transitions(STEPS);
  const byId = Object.fromEntries(t.map((x) => [x.step, x]));
  assert.deepEqual(leafList(byId.k1), ["create ga/a1"]);
  assert.deepEqual(leafList(byId.k2), ["update ga/a1"]);
  // a1 is unchanged by the ancestor write: no event for it
  assert.deepEqual(leafList(byId.k3), ["create ga/b1", "create ga/b2"]);
  assert.deepEqual(leafList(byId.k4), [
    "delete ga/a1",
    "update ga/b1",
    "delete ga/b2",
    "create ga/b3",
  ]);
  assert.deepEqual(leafList(byId.k5), [
    "update ga/b1",
    "delete ga/b3",
    "create ga/b4",
    "create gb/c1",
  ]);
  assert.deepEqual(leafList(byId.k6), ["delete ga/b1", "delete ga/b4"]);
  assert.deepEqual(groupList(byId.k5), ["ga", "gb"]);
  assert.deepEqual(groupList(byId.k6), ["ga"]);
});

test("priority, .value and subtree steps are modelled as nodes with a priority", () => {
  const t = Object.fromEntries(transitions(buildSteps("N")).map((x) => [x.step, x]));
  assert.deepEqual(leafList(t.k7), ["create gp/p1"]);
  assert.deepEqual(leafList(t.k8), ["update gp/p1"]);
  assert.deepEqual(t.k8.leaves[0].before, { value: 1, run: "N", ".priority": 7 });
  assert.deepEqual(t.k8.leaves[0].after, { value: 1, run: "N", ".priority": 9 });
  // the priority-only write leaves the plain form of the node as it was
  assert.deepEqual(t.k8.leaves[0].plainBefore, t.k8.leaves[0].plainAfter);
  assert.deepEqual(t.k9.leaves[0].after, { ".value": 3, ".priority": 2 });
  assert.equal(t.k9.leaves[0].plainAfter, 3);
  assert.deepEqual(leafList(t.k10), ["delete gp/p1", "delete gp/p2"]);
});

test("large writes carry the reduced form of the blob", () => {
  const steps = buildSteps("N");
  const large = steps.filter((s) => s.path.startsWith(`${PREFIX}/gl`));
  assert.deepEqual(
    large.map((s) => s.observeOnly),
    [true, true, true, true],
  );
  const body = large[1].body;
  assert.equal(body.blob.length, 600 * 1024);
  const t = transitions(steps).find((x) => x.step === large[1].id);
  assert.deepEqual(t.leaves[0].after.blob, { type: "string", length: 600 * 1024 });
});

test("user writes and SDK steps are the planned ones", () => {
  const byId = Object.fromEntries(STEPS.map((s) => [s.id, s]));
  const t = Object.fromEntries(transitions(STEPS).map((x) => [x.step, x]));
  assert.deepEqual(
    STEPS.filter((s) => s.context === "user-rest").map((s) => `${s.method} ${s.path}`),
    [`PUT ${PREFIX}/gc/items/u1`, `PATCH ${PREFIX}/gc/items/u1`, `DELETE ${PREFIX}/gc/items/u1`],
  );
  const sdk = STEPS.filter((s) => s.context === "user-sdk");
  assert.deepEqual(
    sdk.map((s) => s.id),
    ["k18", "k19", "k20", "k21"],
  );
  assert.deepEqual(leafList(t.k18), ["create gs/s1"]);
  assert.deepEqual(leafList(t.k19), ["update gs/s1"]);
  assert.deepEqual(leafList(t.k20), ["create gs/s2"]);
  // the onDisconnect step removes s1 and creates s3 when the connection ends
  assert.deepEqual(leafList(t.k21), ["delete gs/s1", "create gs/s3"]);
  assert.equal(byId.k21.via, "onDisconnect");
  assert.deepEqual(
    sdk.map((x) => x.via),
    ["set", "transaction", "transaction", "onDisconnect"],
  );
});

test("no transition repeats across steps, so a frame names one step", () => {
  const t = transitions(STEPS);
  const seen = new Map();
  for (const x of t)
    for (const l of x.leaves) {
      const key = JSON.stringify([l.group, l.id, l.plainBefore, l.plainAfter]);
      assert.ok(!seen.has(key), `${key} repeats in ${seen.get(key)} and ${x.step}`);
      seen.set(key, x.step);
    }
  const groups = new Map();
  for (const x of t)
    for (const g of x.groups) {
      const key = JSON.stringify([g.group, g.before, g.after]);
      assert.ok(!groups.has(key), `${key} repeats in ${groups.get(key)} and ${x.step}`);
      groups.set(key, x.step);
    }
});

test("kindOf, plain and reduceBig", () => {
  assert.equal(kindOf(null, { a: 1 }), "create");
  assert.equal(kindOf({ a: 1 }, null), "delete");
  assert.equal(kindOf({ a: 1 }, { a: 2 }), "update");
  assert.equal(kindOf({ a: 1 }, { a: 1 }), null);
  assert.equal(kindOf(null, null), null);
  assert.deepEqual(plain({ a: 1, ".priority": 3 }), { a: 1 });
  assert.equal(plain({ ".value": 5, ".priority": "p" }), 5);
  assert.deepEqual(plain({ x: { ".value": 5, ".priority": 1 }, y: { z: 1, ".priority": 2 } }), {
    x: 5,
    y: { z: 1 },
  });
  assert.equal(plain(null), null);
  assert.equal(plain(4), 4);
  assert.equal(reduceBig("x".repeat(256)), "x".repeat(256));
  assert.deepEqual(reduceBig("x".repeat(257)), { type: "string", length: 257 });
  assert.deepEqual(reduceBig({ a: ["y".repeat(300)] }), { a: [{ type: "string", length: 300 }] });
});

// Frames show the node as the service sent it: `.priority` and `.value` members stay in the value.
const frameFor = (handler, leaf, { strip = false } = {}) => {
  const snap = (v) =>
    v === null
      ? { exists: false, key: leaf.id, value: null }
      : { exists: true, key: leaf.id, value: strip ? plain(v) : v };
  const params = { group: leaf.group, id: leaf.id };
  const data =
    handler.event === "create"
      ? snap(leaf.after)
      : handler.event === "delete"
        ? snap(leaf.before)
        : { before: snap(leaf.before), after: snap(leaf.after) };
  return {
    handler: handler.name,
    generation: handler.generation,
    event: handler.generation === 1 ? { context: { params }, data } : { params, data },
  };
};

test("every expected delivery of the plan is attributed to its own step", () => {
  const steps = buildSteps("N");
  for (const x of transitions(steps))
    for (const leaf of x.leaves)
      for (const handler of FIXTURE_HANDLERS.filter(
        (h) => h.level === "item" && (h.event === "write" || h.event === leaf.kind),
      )) {
        for (const strip of [false, true]) {
          const match = matchFrame(frameFor(handler, leaf, { strip }), steps);
          assert.equal(
            match.step,
            x.step,
            `${handler.name} ${x.step} ${leaf.group}/${leaf.id} strip=${strip}`,
          );
        }
      }
});

test("a frame that fits no step is left unattributed with a reason", () => {
  const steps = buildSteps("N");
  const handler = FIXTURE_HANDLERS.find((h) => h.name === "k9CreatedV2");
  const odd = frameFor(handler, { group: "ga", id: "zz", before: null, after: { value: 99 } });
  assert.equal(matchFrame(odd, steps).reason, "no-match");
  assert.equal(matchFrame({ handler: "other", generation: 2 }, steps).reason, "handler");
  assert.equal(
    matchFrame({ handler: handler.name, generation: 2, event: { params: {} } }, steps).reason,
    "shape",
  );
});

test("observe expects exactly the handlers of the changed kind", () => {
  const steps = buildSteps("N");
  const report = observe({ writes: {}, frames: [], steps });
  const k4 = report.steps.find((s) => s.id === "k4");
  const a1 = k4.leaves.find((l) => l.id === "a1");
  assert.equal(a1.kind, "delete");
  const exp = Object.fromEntries(Object.entries(a1.handlers).map(([n, h]) => [n, h.expected]));
  assert.deepEqual(exp, {
    k9CreatedV1: 0,
    k9UpdatedV1: 0,
    k9DeletedV1: 1,
    k9CreatedV2: 0,
    k9UpdatedV2: 0,
    k9DeletedV2: 1,
    k9AnyWrittenV2: 1,
  });
  // group handlers have group entries, not leaf entries
  assert.deepEqual(
    k4.groups.map((g) => [g.group, Object.keys(g.handlers)]),
    [["ga", ["k9GroupWrittenV2"]]],
  );
});

test("observe counts frames, event ids and repeats per handler and leaf", () => {
  const steps = buildSteps("N");
  const t = transitions(steps).find((x) => x.step === "k1");
  const handler = FIXTURE_HANDLERS.find((h) => h.name === "k9CreatedV2");
  const once = frameFor(handler, t.leaves[0]);
  once.event.id = "e1";
  const twice = structuredClone(once);
  const other = structuredClone(once);
  other.event.id = "e2";
  const report = observe({ writes: {}, frames: [once, twice, other], steps });
  const seen = report.steps[0].leaves[0].handlers.k9CreatedV2;
  assert.equal(seen.frames, 3);
  assert.equal(seen.distinctEventIds, 2);
  assert.equal(seen.duplicateFrames, 1);
});

test("seeded random writes agree with an independent reference of the leaves", () => {
  let state = 4242;
  const random = () => (state = (state * 1664525 + 1013904223) >>> 0);
  let ref = {};
  const steps = [];
  for (let n = 0; n < 200; n++) {
    const group = ["ga", "gb"][random() % 2];
    const id = ["a", "b", "c"][random() % 3];
    const value = { value: random() % 4, ...(random() % 2 ? { ".priority": random() % 3 } : {}) };
    const kindOfWrite = random() % 3;
    const path = `${PREFIX}/${group}/items/${id}`;
    steps.push(
      kindOfWrite === 0
        ? { id: `r${n}`, method: "DELETE", path }
        : { id: `r${n}`, method: "PUT", path, body: value },
    );
  }
  let last = {};
  for (const x of transitions(steps)) {
    const step = steps.find((s) => s.id === x.step);
    const [, group, , id] = step.path.split("/");
    const before = ref[`${group}/${id}`] ?? null;
    const after = step.method === "DELETE" ? null : step.body;
    if (after === null) delete ref[`${group}/${id}`];
    else ref[`${group}/${id}`] = after;
    const changed = !isDeepStrictEqual(before, after);
    assert.equal(x.leaves.length, changed ? 1 : 0, x.step);
    if (changed) {
      assert.equal(x.leaves[0].kind, kindOf(before, after));
      assert.deepEqual(x.leaves[0].before, before);
      assert.deepEqual(x.leaves[0].after, after);
    }
    last = ref;
  }
  assert.ok(last);
});

test("plain keeps arrays as arrays and unwraps inside them", () => {
  assert.deepEqual(plain([1, { ".value": 2, ".priority": 3 }, { a: 1, ".priority": 2 }]), [
    1,
    2,
    { a: 1 },
  ]);
  assert.ok(Array.isArray(plain([1, 2])));
  assert.deepEqual(plain({ list: [{ ".value": 4, ".priority": 1 }] }), { list: [4] });
});

test("the planned payload sizes and the observation-only steps are pinned", () => {
  const byId = Object.fromEntries(buildSteps("N").map((s) => [s.id, s]));
  assert.equal(byId.k11.body.blob.length, 100 * 1024);
  assert.equal(byId.k12.body.blob.length, 600 * 1024);
  assert.equal(byId.k13.body.blob.length, 2 * 1024 * 1024);
  assert.deepEqual(
    buildSteps("N")
      .filter((s) => s.observeOnly)
      .map((s) => s.id),
    ["k8", "k11", "k12", "k13", "k14"],
  );
});

test("groups of one step are listed in name order", () => {
  const steps = [
    {
      id: "a",
      method: "PATCH",
      path: PREFIX,
      body: { "gz/items/x": { v: 1 }, "ga/items/x": { v: 1 } },
      context: "admin",
    },
  ];
  assert.deepEqual(groupList(transitions(steps)[0]), ["ga", "gz"]);
  assert.deepEqual(leafList(transitions(steps)[0]), ["create ga/x", "create gz/x"]);
});

test("a frame is accepted only in the shape its handler prints", () => {
  const steps = buildSteps("N");
  const handler = (name) => FIXTURE_HANDLERS.find((h) => h.name === name);
  const params = { group: "ga", id: "a1" };
  const snap = { exists: true, key: "a1", value: { value: 1, run: "N" } };
  const make = (name, event) => ({
    handler: name,
    generation: handler(name).generation,
    event:
      handler(name).generation === 1
        ? { context: { params: event.params }, data: event.data }
        : event,
  });
  const reason = (name, event) => matchFrame(make(name, event), steps).reason;
  // a single-node handler needs `exists`; a change handler needs both sides
  assert.equal(reason("k9CreatedV2", { params, data: { key: "a1", value: {} } }), "shape");
  assert.equal(reason("k9DeletedV1", { params, data: { before: snap, after: snap } }), "shape");
  assert.equal(reason("k9UpdatedV2", { params, data: snap }), "shape");
  assert.equal(reason("k9UpdatedV2", { params, data: { before: snap } }), "shape");
  assert.equal(reason("k9AnyWrittenV2", { params, data: { after: snap } }), "shape");
  // an item handler needs the id, every handler the group
  assert.equal(reason("k9CreatedV2", { params: { group: "ga" }, data: snap }), "shape");
  assert.equal(reason("k9CreatedV2", { params: { id: "a1" }, data: snap }), "shape");
  assert.equal(
    reason("k9GroupWrittenV2", { params: {}, data: { before: snap, after: snap } }),
    "shape",
  );
  // the group handler does not need an id
  assert.notEqual(
    reason("k9GroupWrittenV2", { params: { group: "ga" }, data: { before: snap, after: snap } }),
    "shape",
  );
  // `exists` decides what a snapshot says, not the value next to it
  const gone = { exists: false, key: "a1", value: { value: 1, run: "N" } };
  assert.equal(reason("k9CreatedV2", { params, data: gone }), "no-match");
});

test("two writes with the same node, or two groups with the same content, are told apart or left ambiguous", () => {
  const step = (id, path, body) => ({
    id,
    method: "PUT",
    path: `${PREFIX}/${path}`,
    body,
    context: "admin",
  });
  const handler = FIXTURE_HANDLERS.find((h) => h.name === "k9AnyWrittenV2");
  const frame = (group, before, after) => ({
    handler: handler.name,
    generation: 2,
    event: {
      params: { group, id: "x" },
      data: {
        before: before === null ? { exists: false, value: null } : { exists: true, value: before },
        after: after === null ? { exists: false, value: null } : { exists: true, value: after },
      },
    },
  });
  // the same node content in two groups: the group in the frame names the write
  const groups = [step("one", "ga/items/x", { v: 1 }), step("two", "gb/items/x", { v: 1 })];
  assert.equal(matchFrame(frame("ga", null, { v: 1 }), groups).step, "one");
  assert.equal(matchFrame(frame("gb", null, { v: 1 }), groups).step, "two");
  // the same node, the same transition, in two steps: ambiguous, never the first
  const twice = [
    step("one", "ga/items/x", { v: 1 }),
    step("gap", "ga/items/x", { v: 2 }),
    step("back", "ga/items/x", { v: 1 }),
    step("again", "ga/items/x", { v: 2 }),
  ];
  const ambiguous = matchFrame(frame("ga", { v: 1 }, { v: 2 }), twice);
  assert.equal(ambiguous.step, null);
  assert.equal(ambiguous.reason, "ambiguous");
  assert.deepEqual(ambiguous.candidates, ["gap", "again"]);
  // the item id names the write too
  const ids = [step("x", "ga/items/x", { v: 1 }), step("y", "ga/items/y", { v: 1 })];
  const other = frame("ga", null, { v: 1 });
  other.event.params.id = "y";
  assert.equal(matchFrame(other, ids).step, "y");
  // the group handler is matched on the group's content, and on the group
  const groupHandler = FIXTURE_HANDLERS.find((h) => h.name === "k9GroupWrittenV2");
  const group = (name, before, after) => ({
    handler: groupHandler.name,
    generation: 2,
    event: {
      params: { group: name },
      data: {
        before: before === null ? { exists: false, value: null } : { exists: true, value: before },
        after: { exists: true, value: after },
      },
    },
  });
  assert.equal(matchFrame(group("ga", null, { items: { x: { v: 1 } } }), groups).step, "one");
  assert.equal(matchFrame(group("gb", null, { items: { x: { v: 1 } } }), groups).step, "two");
  assert.equal(
    matchFrame(group("ga", null, { items: { x: { v: 9 } } }), groups).reason,
    "no-match",
  );
  assert.equal(
    matchFrame(group("ga", { items: { x: { v: 1 } } }, { items: { x: { v: 1 } } }), groups).reason,
    "no-match",
  );
});

test("observe counts what it attributed and what it could not", () => {
  const steps = buildSteps("N");
  const handler = FIXTURE_HANDLERS.find((h) => h.name === "k9CreatedV2");
  const good = frameFor(handler, transitions(steps)[0].leaves[0]);
  const stray = structuredClone(good);
  stray.event.params.id = "nobody";
  const report = observe({ writes: {}, frames: [good, stray], steps });
  assert.deepEqual(report.totals, { frames: 2, attributed: 1, unattributed: 1 });
  assert.deepEqual(report.unattributed, [
    { handler: "k9CreatedV2", reason: "no-match", candidates: [] },
  ]);
});
