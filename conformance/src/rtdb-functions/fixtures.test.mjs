// The CV14 fixture declares the eight RTDB trigger handlers (four 1st gen, four 2nd gen) on the run
// prefix, and each prints exactly one typed frame per event. The firebase-functions modules are
// replaced by recorders here, so the test checks what the fixture declares and prints, not the SDK.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";

import {
  FIXTURE_HANDLERS,
  FRAME_MARKER,
  INSTANCE,
  ITEM_PATH,
  LOCATION,
  NAMED_CONTEXT_MEMBERS,
  NAMED_EVENT_MEMBERS,
} from "./frames.mjs";

const require = createRequire(import.meta.url);
const fixtureDir = new URL("./fixtures/", import.meta.url).pathname;

function loadFixture() {
  const trigger = (generation, event, options) => (handler) => ({
    handler,
    generation,
    event,
    ...options,
  });
  const v1Ref = (region, instance) => (ref) => {
    const options = { region, instance, ref };
    return {
      onCreate: trigger(1, "create", options),
      onUpdate: trigger(1, "update", options),
      onDelete: trigger(1, "delete", options),
      onWrite: trigger(1, "write", options),
    };
  };
  const registry = {
    "firebase-functions/v1": {
      region: (region) => ({
        database: { instance: (instance) => ({ ref: v1Ref(region, instance) }) },
      }),
    },
    "firebase-functions/v2/database": Object.fromEntries(
      [
        ["onValueCreated", "create"],
        ["onValueUpdated", "update"],
        ["onValueDeleted", "delete"],
        ["onValueWritten", "write"],
      ].map(([name, event]) => [
        name,
        (options, handler) => ({ handler, generation: 2, event, ...options }),
      ]),
    ),
    "firebase-admin/app": { initializeApp: () => {}, getApps: () => [] },
  };
  const exports = {};
  const module = { exports };
  const localRequire = (name) => {
    if (name === "./frames") return require(`${fixtureDir}frames.js`);
    if (name in registry) return registry[name];
    throw new Error(`unexpected require ${name}`);
  };
  const source = readFileSync(`${fixtureDir}index.js`, "utf8");
  new Function("require", "module", "exports", source)(localRequire, module, exports);
  return { exports };
}

const snapshot = (value, key = "a") => ({
  exists: () => value !== null,
  key,
  val: () => value,
});

test("the fixture declares the eight handlers on the run prefix of the one instance", () => {
  const { exports } = loadFixture();
  assert.deepEqual(Object.keys(exports).toSorted(), FIXTURE_HANDLERS.map((h) => h.name).toSorted());
  for (const handler of FIXTURE_HANDLERS) {
    const trigger = exports[handler.name];
    assert.equal(trigger.generation, handler.generation, handler.name);
    assert.equal(trigger.event, handler.event, handler.name);
    assert.equal(trigger.instance, INSTANCE, handler.name);
    assert.equal(trigger.region ?? LOCATION, LOCATION, handler.name);
    assert.equal(trigger.ref, ITEM_PATH, handler.name);
  }
  assert.equal(FIXTURE_HANDLERS.filter((h) => h.generation === 1).length, 4);
  assert.equal(FIXTURE_HANDLERS.filter((h) => h.generation === 2).length, 4);
  assert.equal(ITEM_PATH, "/cv14-rtdb/items/{id}");
});

test("a 2nd gen handler prints one frame with the whole event and its before and after", async () => {
  const printed = [];
  const original = console.log;
  console.log = (line) => printed.push(String(line));
  const { exports } = loadFixture();
  try {
    await exports.rtdbWrittenV2.handler({
      id: "evt-1",
      time: "2026-10-27T00:00:00Z",
      type: "google.firebase.database.ref.v1.written",
      source: "//firebasedatabase.googleapis.com/projects/_/locations/us-central1/instances/x",
      subject: "refs/cv14-rtdb/items/a",
      specversion: "1.0",
      params: { id: "a" },
      location: "us-central1",
      instance: "x",
      ref: "/cv14-rtdb/items/a",
      firebaseDatabaseHost: "x.firebaseio.com",
      authType: "admin",
      authId: null,
      data: { before: snapshot(null), after: snapshot({ n: 1 }) },
    });
  } finally {
    console.log = original;
  }
  assert.equal(printed.length, 1);
  assert.ok(printed[0].startsWith(FRAME_MARKER));
  const frame = JSON.parse(printed[0].slice(FRAME_MARKER.length));
  assert.equal(frame.handler, "rtdbWrittenV2");
  assert.equal(frame.generation, 2);
  assert.equal(frame.event.id, "evt-1");
  assert.deepEqual(frame.event.params, { id: "a" });
  assert.deepEqual(frame.event.data.before, { exists: false, key: "a", value: null });
  assert.deepEqual(frame.event.data.after, { exists: true, key: "a", value: { n: 1 } });
  // every member of the event outside the named ones is listed, not lost
  assert.deepEqual(frame.event.extras.location, "us-central1");
  assert.ok(Array.isArray(frame.event.eventKeys));
  assert.equal(typeof frame.seq, "number");
});

test("a 1st gen handler prints the context and the snapshot or change", async () => {
  const printed = [];
  const original = console.log;
  console.log = (line) => printed.push(String(line));
  const { exports } = loadFixture();
  try {
    await exports.rtdbCreatedV1.handler(snapshot({ n: 1 }), {
      eventId: "ctx-1",
      timestamp: "2026-10-27T00:00:00Z",
      eventType: "providers/google.firebase.database/eventTypes/ref.create",
      resource: "projects/_/instances/x/refs/cv14-rtdb/items/a",
      params: { id: "a" },
      authType: "ADMIN",
      auth: { admin: true },
    });
    await exports.rtdbUpdatedV1.handler(
      { before: snapshot({ n: 1 }), after: snapshot({ n: 2 }) },
      { eventId: "ctx-2", eventType: "t", resource: "r", params: { id: "a" }, timestamp: "t" },
    );
  } finally {
    console.log = original;
  }
  const frames = printed.map((line) => JSON.parse(line.slice(FRAME_MARKER.length)));
  assert.equal(frames[0].handler, "rtdbCreatedV1");
  assert.equal(frames[0].generation, 1);
  assert.equal(frames[0].event.context.eventId, "ctx-1");
  assert.deepEqual(frames[0].event.data, { exists: true, key: "a", value: { n: 1 } });
  assert.equal(frames[0].event.context.extras.auth.type, "object");
  assert.deepEqual(frames[1].event.data.after.value, { n: 2 });
  assert.equal(frames[1].seq > frames[0].seq, true);
});

test("the member sets the judge knows are the ones the fixture names", () => {
  const frames = require(`${fixtureDir}frames.js`);
  assert.deepEqual([...frames.CONTEXT_MEMBERS].toSorted(), [...NAMED_CONTEXT_MEMBERS].toSorted());
  assert.deepEqual([...frames.EVENT_MEMBERS].toSorted(), [...NAMED_EVENT_MEMBERS].toSorted());
});
